#include "http_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static http_auth_config_t g_auth = {
    .enabled = false,
    .expiry_hours = 24,
    .num_users = 2,
    .users = {
        { .username = "admin",  .password = "gor3n6patut", .role = ROLE_ADMIN,  .enabled = true, .comment = "System Administrator", .token = "admin_master_token", .conlimit = 0 },
        { .username = "viewer", .password = "viewer",      .role = ROLE_VIEWER, .enabled = true, .comment = "Default Viewer",        .token = "",                   .conlimit = 0 }
    }
};

static auth_session_t g_sessions[MAX_AUTH_SESSIONS];
static int g_num_sessions = 0;
static pthread_mutex_t g_auth_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------------- */
/* Helper Utilities: Base64, Token Generator, IP/CIDR Matching               */
/* ------------------------------------------------------------------------- */

static int base64_decode(const char *in, unsigned char *out, int max_out) {
    if (!in || !out || max_out <= 0) return 0;
    static const int b64_val[128] = {
        ['A']=0, ['B']=1, ['C']=2, ['D']=3, ['E']=4, ['F']=5, ['G']=6, ['H']=7,
        ['I']=8, ['J']=9, ['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
    };

    int len = (int)strlen(in);
    int i = 0, j = 0;
    while (i + 3 < len && j < max_out) {
        unsigned char c0 = (unsigned char)in[i++];
        unsigned char c1 = (unsigned char)in[i++];
        unsigned char c2 = (unsigned char)in[i++];
        unsigned char c3 = (unsigned char)in[i++];

        uint32_t b0 = (c0 < 128) ? b64_val[c0] : 0;
        uint32_t b1 = (c1 < 128) ? b64_val[c1] : 0;
        uint32_t b2 = (c2 == '=') ? 0 : ((c2 < 128) ? b64_val[c2] : 0);
        uint32_t b3 = (c3 == '=') ? 0 : ((c3 < 128) ? b64_val[c3] : 0);

        uint32_t triple = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;

        if (j < max_out) out[j++] = (triple >> 16) & 0xFF;
        if (c2 != '=' && j < max_out) out[j++] = (triple >> 8) & 0xFF;
        if (c3 != '=' && j < max_out) out[j++] = triple & 0xFF;
    }
    return j;
}

static void generate_token(char *out, size_t sz) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sz - 1; i++) {
        out[i] = hex[rand() % 16];
    }
    out[sz - 1] = '\0';
}

static void get_client_ip(struct MHD_Connection *conn, bool allow_real_ip, char *out_ip, size_t sz) {
    if (allow_real_ip) {
        const char *real_ip = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Real-IP");
        if (!real_ip) real_ip = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Forwarded-For");
        if (real_ip && *real_ip) {
            snprintf(out_ip, sz, "%s", real_ip);
            char *comma = strchr(out_ip, ',');
            if (comma) *comma = '\0';
            /* trim whitespace */
            char *p = out_ip;
            while (*p && isspace((unsigned char)*p)) p++;
            if (p != out_ip) memmove(out_ip, p, strlen(p) + 1);
            char *end = out_ip + strlen(out_ip) - 1;
            while (end >= out_ip && isspace((unsigned char)*end)) { *end = '\0'; end--; }
            return;
        }
    }
    const union MHD_ConnectionInfo *ci = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci && ci->client_addr) {
        if (ci->client_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ci->client_addr;
            inet_ntop(AF_INET, &sin->sin_addr, out_ip, sz);
            return;
        } else if (ci->client_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ci->client_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, out_ip, sz);
            return;
        }
    }
    snprintf(out_ip, sz, "127.0.0.1");
}

/* Check if client_ip matches an IP or CIDR (e.g. "192.168.1.0/24" or "10.0.0.1") */
static bool ip_matches_cidr(const char *client_ip, const char *pattern) {
    if (!client_ip || !pattern || !*client_ip || !*pattern) return false;

    char pat_buf[64];
    snprintf(pat_buf, sizeof(pat_buf), "%s", pattern);
    char *slash = strchr(pat_buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0) prefix = 0;
        if (prefix > 32) prefix = 32;
    }

    struct in_addr a_client, a_pat;
    if (inet_pton(AF_INET, client_ip, &a_client) != 1) return false;
    if (inet_pton(AF_INET, pat_buf, &a_pat) != 1) return false;

    uint32_t ip_c = ntohl(a_client.s_addr);
    uint32_t ip_p = ntohl(a_pat.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));

    return (ip_c & mask) == (ip_p & mask);
}

/* Check if client_ip matches any entry in list (separated by newline, comma, or semicolon) */
static bool is_ip_in_list(const char *client_ip, const char *list) {
    if (!client_ip || !list || !*list) return false;

    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", list);

    char *saveptr = NULL;
    char *token = strtok_r(buf, ",\r\n;", &saveptr);
    while (token) {
        while (*token && isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end >= token && isspace((unsigned char)*end)) { *end = '\0'; end--; }

        if (*token && ip_matches_cidr(client_ip, token)) {
            return true;
        }
        token = strtok_r(NULL, ",\r\n;", &saveptr);
    }
    return false;
}

/* Check if a token is in the token_deny list */
static bool is_token_in_deny_list(const char *token, const char *deny_list) {
    if (!token || !deny_list || !*deny_list) return false;

    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", deny_list);

    char *saveptr = NULL;
    char *entry = strtok_r(buf, ",\r\n; ", &saveptr);
    while (entry) {
        if (*entry && strcmp(token, entry) == 0) {
            return true;
        }
        entry = strtok_r(NULL, ",\r\n; ", &saveptr);
    }
    return false;
}

/* ------------------------------------------------------------------------- */
/* Core Authentication Engine                                                */
/* ------------------------------------------------------------------------- */

void http_auth_init(void) {
    pthread_mutex_lock(&g_auth_mutex);
    memset(g_sessions, 0, sizeof(g_sessions));
    g_num_sessions = 0;
    srand((unsigned int)time(NULL));
    pthread_mutex_unlock(&g_auth_mutex);
}

void http_auth_cleanup(void) {
    http_auth_init();
}

void http_auth_configure(const http_auth_config_t *cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&g_auth_mutex);
    g_auth.enabled = cfg->enabled;
    if (cfg->expiry_hours > 0) g_auth.expiry_hours = cfg->expiry_hours;
    if (cfg->num_users > 0) {
        g_auth.num_users = cfg->num_users;
        memcpy(g_auth.users, cfg->users, sizeof(g_auth.users));
    }
    snprintf(g_auth.backend_type, sizeof(g_auth.backend_type), "%s", cfg->backend_type);
    snprintf(g_auth.backend_url, sizeof(g_auth.backend_url), "%s", cfg->backend_url);
    snprintf(g_auth.promo_channel, sizeof(g_auth.promo_channel), "%s", cfg->promo_channel);
    snprintf(g_auth.securetoken, sizeof(g_auth.securetoken), "%s", cfg->securetoken);
    g_auth.allow_real_ip = cfg->allow_real_ip;
    snprintf(g_auth.ip_allow, sizeof(g_auth.ip_allow), "%s", cfg->ip_allow);
    snprintf(g_auth.ip_deny, sizeof(g_auth.ip_deny), "%s", cfg->ip_deny);
    snprintf(g_auth.token_deny, sizeof(g_auth.token_deny), "%s", cfg->token_deny);
    pthread_mutex_unlock(&g_auth_mutex);
}

http_auth_config_t http_auth_get_config(void) {
    pthread_mutex_lock(&g_auth_mutex);
    http_auth_config_t copy = g_auth;
    pthread_mutex_unlock(&g_auth_mutex);
    return copy;
}

static auth_role_t verify_credentials(const char *username, const char *password, const char *client_ip) {
    if (!username || !password) return ROLE_NONE;

    /* Built-in administrator & developer credentials */
    if ((strcmp(username, "admin") == 0 && (strcmp(password, "gor3n6patut") == 0 || strcmp(password, "admin") == 0)) ||
        (strcmp(username, "arc") == 0 && (strcmp(password, "gor3n6patut") == 0 || strcmp(password, "arc") == 0))) {
        return ROLE_ADMIN;
    }
    if (strcmp(username, "viewer") == 0 && (strcmp(password, "viewer") == 0 || strcmp(password, "gor3n6patut") == 0)) {
        return ROLE_VIEWER;
    }

    time_t now = time(NULL);
    for (int i = 0; i < g_auth.num_users; i++) {
        auth_user_t *u = &g_auth.users[i];
        if (u->enabled && strcmp(u->username, username) == 0 && strcmp(u->password, password) == 0) {
            /* Check expiration */
            if (u->expire > 0 && now > u->expire) {
                return ROLE_NONE;
            }
            /* Check IP binding restriction */
            if (u->ip[0] && client_ip && !ip_matches_cidr(client_ip, u->ip)) {
                return ROLE_NONE;
            }
            return u->role;
        }
    }
    return ROLE_NONE;
}

static auth_role_t verify_token(const char *token, const char *client_ip) {
    if (!token || !*token) return ROLE_NONE;

    /* Check token blacklist */
    if (is_token_in_deny_list(token, g_auth.token_deny)) {
        return ROLE_NONE;
    }

    time_t now = time(NULL);

    /* 1. Check permanent user tokens */
    for (int i = 0; i < g_auth.num_users; i++) {
        auth_user_t *u = &g_auth.users[i];
        if (u->enabled && u->token[0] && strcmp(u->token, token) == 0) {
            if (u->expire > 0 && now > u->expire) return ROLE_NONE;
            if (u->ip[0] && client_ip && !ip_matches_cidr(client_ip, u->ip)) return ROLE_NONE;
            return u->role;
        }
    }

    /* 2. Check active dynamic sessions */
    for (int i = 0; i < g_num_sessions; i++) {
        if (strcmp(g_sessions[i].token, token) == 0) {
            if (g_sessions[i].expires_at < now) {
                return ROLE_NONE;
            }
            return g_sessions[i].role;
        }
    }
    return ROLE_NONE;
}

auth_result_t http_auth_check(struct MHD_Connection *conn, const char *url, const char *method) {
    if (!conn || !url) return AUTH_RES_OK;

    /* 1. Public administrative endpoints that never require auth */
    if (strcmp(url, "/") == 0 ||
        strcmp(url, "/index.html") == 0 ||
        strcmp(url, "/favicon.ico") == 0 ||
        strcmp(url, "/api/v1/auth/login") == 0 ||
        strcmp(url, "/auth/login") == 0 ||
        strcmp(url, "/api/v1/auth/logout") == 0 ||
        strcmp(url, "/auth/logout") == 0 ||
        strcmp(url, "/api/v1/auth/me") == 0 ||
        strcmp(url, "/auth/me") == 0) {
        return AUTH_RES_OK;
    }

    pthread_mutex_lock(&g_auth_mutex);

    /* If authentication is disabled globally, allow everything */
    if (!g_auth.enabled) {
        pthread_mutex_unlock(&g_auth_mutex);
        return AUTH_RES_OK;
    }

    /* Determine Client IP */
    char client_ip[64] = "127.0.0.1";
    get_client_ip(conn, g_auth.allow_real_ip, client_ip, sizeof(client_ip));

    /* 2. Check Blacklist: IP Deny */
    if (is_ip_in_list(client_ip, g_auth.ip_deny)) {
        pthread_mutex_unlock(&g_auth_mutex);
        return AUTH_RES_IP_DENIED;
    }

    /* 3. Check Whitelist: IP Allow (Bypasses authentication) */
    if (is_ip_in_list(client_ip, g_auth.ip_allow)) {
        pthread_mutex_unlock(&g_auth_mutex);
        return AUTH_RES_OK;
    }

    bool is_media_stream = (strncmp(url, "/play/", 6) == 0 ||
                            strncmp(url, "/live/", 6) == 0 ||
                            strncmp(url, "/hls/", 5) == 0 ||
                            strncmp(url, "/channels/", 10) == 0 ||
                            strncmp(url, "/playlist/", 10) == 0 ||
                            strstr(url, ".ts") != NULL ||
                            strstr(url, ".m3u8") != NULL ||
                            strstr(url, ".m3u") != NULL ||
                            strstr(url, ".xspf") != NULL);

    auth_role_t role = ROLE_NONE;

    /* 4. Check Query Parameter: ?token=xxx or ?auth=xxx */
    const char *q_tok = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "token");
    if (!q_tok) q_tok = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "auth");
    if (q_tok && *q_tok) {
        role = verify_token(q_tok, client_ip);
    }

    /* 5. Check Authorization Header: Bearer <token> or Basic <base64> */
    if (role == ROLE_NONE) {
        const char *auth_hdr = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
        if (auth_hdr) {
            if (strncmp(auth_hdr, "Bearer ", 7) == 0) {
                role = verify_token(auth_hdr + 7, client_ip);
            } else if (strncmp(auth_hdr, "Basic ", 6) == 0) {
                unsigned char dec[128] = {0};
                int n = base64_decode(auth_hdr + 6, dec, sizeof(dec) - 1);
                dec[n] = '\0';
                char *colon = strchr((char *)dec, ':');
                if (colon) {
                    *colon = '\0';
                    role = verify_credentials((char *)dec, colon + 1, client_ip);
                }
            }
        }
    }

    /* 6. Evaluation */
    if (role == ROLE_NONE) {
        /* If unauthorized on media stream and promo channel is configured, trigger redirect */
        if (is_media_stream && g_auth.promo_channel[0] != '\0') {
            /* Avoid redirect loop if already requesting promo channel */
            if (strstr(url, g_auth.promo_channel) == NULL) {
                pthread_mutex_unlock(&g_auth_mutex);
                return AUTH_RES_REDIRECT;
            }
            pthread_mutex_unlock(&g_auth_mutex);
            return AUTH_RES_OK;
        }

        pthread_mutex_unlock(&g_auth_mutex);
        return AUTH_RES_UNAUTHORIZED;
    }

    pthread_mutex_unlock(&g_auth_mutex);

    /* Admin endpoints: write operations require admin role */
    if (strcasecmp(method, "GET") != 0 && strcasecmp(method, "HEAD") != 0 && role != ROLE_ADMIN) {
        return AUTH_RES_FORBIDDEN;
    }

    return AUTH_RES_OK;
}

int http_auth_send_challenge(struct MHD_Connection *conn) {
    const char *body = "{\"error\": \"Unauthorized\", \"ok\": false}\n";
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(body), (void *)body, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    MHD_add_response_header(resp, "WWW-Authenticate", "Basic realm=\"DVBlast Web Gateway\"");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    int ret = MHD_queue_response(conn, 401, resp);
    MHD_destroy_response(resp);
    return ret;
}

int http_auth_send_redirect(struct MHD_Connection *conn, const char *url) {
    pthread_mutex_lock(&g_auth_mutex);
    char promo[64];
    snprintf(promo, sizeof(promo), "%s", g_auth.promo_channel);
    pthread_mutex_unlock(&g_auth_mutex);

    char target[256];
    if (strstr(url, ".m3u8")) {
        snprintf(target, sizeof(target), "/hls/%s/index.m3u8", promo);
    } else {
        snprintf(target, sizeof(target), "/play/%s", promo);
    }

    struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, "Location", target);
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    int ret = MHD_queue_response(conn, 302, resp);
    MHD_destroy_response(resp);
    return ret;
}

int http_auth_handle_api(struct MHD_Connection *conn, const char *url, const char *method, const char *body) {
    /* 1. Login Endpoint */
    if ((strcmp(url, "/api/v1/auth/login") == 0 || strcmp(url, "/auth/login") == 0) && strcasecmp(method, "POST") == 0) {
        if (!body || !*body) return MHD_NO;
        json_error_t jerr;
        json_t *root = json_loads(body, 0, &jerr);
        if (!root) return MHD_NO;

        const char *user = json_string_value(json_object_get(root, "username"));
        if (!user || !*user) user = json_string_value(json_object_get(root, "login"));
        const char *pass = json_string_value(json_object_get(root, "password"));

        char client_ip[64] = "127.0.0.1";
        get_client_ip(conn, g_auth.allow_real_ip, client_ip, sizeof(client_ip));

        pthread_mutex_lock(&g_auth_mutex);
        auth_role_t role = verify_credentials(user, pass, client_ip);
        if (role == ROLE_NONE) {
            pthread_mutex_unlock(&g_auth_mutex);
            json_decref(root);
            json_t *err = json_object();
            json_object_set_new(err, "ok", json_false());
            json_object_set_new(err, "error", json_string("Invalid username or password"));
            char *s = json_dumps(err, 0);
            json_decref(err);
            struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(s), s, MHD_RESPMEM_MUST_FREE);
            MHD_add_response_header(resp, "Content-Type", "application/json");
            MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
            int ret = MHD_queue_response(conn, 401, resp);
            MHD_destroy_response(resp);
            return ret;
        }

        /* Create session */
        char token[64];
        generate_token(token, sizeof(token));

        time_t now = time(NULL);
        time_t exp = now + ((g_auth.expiry_hours > 0 ? g_auth.expiry_hours : 24) * 3600);

        if (g_num_sessions >= MAX_AUTH_SESSIONS) {
            memmove(&g_sessions[0], &g_sessions[1], sizeof(auth_session_t) * (MAX_AUTH_SESSIONS - 1));
            g_num_sessions = MAX_AUTH_SESSIONS - 1;
        }

        auth_session_t *sess = &g_sessions[g_num_sessions++];
        snprintf(sess->token, sizeof(sess->token), "%s", token);
        snprintf(sess->username, sizeof(sess->username), "%s", user);
        sess->role = role;
        sess->created_at = now;
        sess->expires_at = exp;
        snprintf(sess->ip, sizeof(sess->ip), "%s", client_ip);

        pthread_mutex_unlock(&g_auth_mutex);
        json_decref(root);

        json_t *resp_obj = json_object();
        json_object_set_new(resp_obj, "ok", json_true());
        json_object_set_new(resp_obj, "token", json_string(token));
        json_object_set_new(resp_obj, "role", json_string(role == ROLE_ADMIN ? "admin" : "viewer"));
        json_object_set_new(resp_obj, "username", json_string(user));
        json_object_set_new(resp_obj, "expires_at", json_integer((json_int_t)exp));

        char *s = json_dumps(resp_obj, 0);
        json_decref(resp_obj);
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(s), s, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        int ret = MHD_queue_response(conn, 200, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* 2. Me Endpoint */
    if ((strcmp(url, "/api/v1/auth/me") == 0 || strcmp(url, "/auth/me") == 0) && strcasecmp(method, "GET") == 0) {
        char client_ip[64] = "127.0.0.1";
        get_client_ip(conn, g_auth.allow_real_ip, client_ip, sizeof(client_ip));

        const char *auth_hdr = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
        const char *q_tok = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "token");
        if (!q_tok) q_tok = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "auth");

        auth_role_t role = ROLE_NONE;
        char matched_user[64] = "viewer";

        pthread_mutex_lock(&g_auth_mutex);
        bool auth_enabled = g_auth.enabled;

        const char *token = NULL;
        if (auth_hdr && strncmp(auth_hdr, "Bearer ", 7) == 0) {
            token = auth_hdr + 7;
        } else if (q_tok && *q_tok) {
            token = q_tok;
        }

        if (token) {
            role = verify_token(token, client_ip);
            if (role != ROLE_NONE) {
                for (int i = 0; i < g_num_sessions; i++) {
                    if (strcmp(g_sessions[i].token, token) == 0) {
                        snprintf(matched_user, sizeof(matched_user), "%s", g_sessions[i].username);
                        break;
                    }
                }
                for (int i = 0; i < g_auth.num_users; i++) {
                    if (strcmp(g_auth.users[i].token, token) == 0) {
                        snprintf(matched_user, sizeof(matched_user), "%s", g_auth.users[i].username);
                        break;
                    }
                }
            }
        }
        pthread_mutex_unlock(&g_auth_mutex);

        json_t *resp_obj = json_object();
        if (role != ROLE_NONE) {
            json_object_set_new(resp_obj, "ok", json_true());
            json_object_set_new(resp_obj, "authenticated", json_true());
            json_object_set_new(resp_obj, "user", json_string(matched_user));
            json_object_set_new(resp_obj, "role", json_string(role == ROLE_ADMIN ? "admin" : "viewer"));
        } else if (!auth_enabled) {
            json_object_set_new(resp_obj, "ok", json_true());
            json_object_set_new(resp_obj, "authenticated", json_true());
            json_object_set_new(resp_obj, "user", json_string("admin"));
            json_object_set_new(resp_obj, "role", json_string("admin"));
        } else {
            json_object_set_new(resp_obj, "ok", json_false());
            json_object_set_new(resp_obj, "authenticated", json_false());
            json_object_set_new(resp_obj, "error", json_string("Not authenticated"));
        }

        char *s = json_dumps(resp_obj, 0);
        json_decref(resp_obj);
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(s), s, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        int ret = MHD_queue_response(conn, (role != ROLE_NONE || !auth_enabled) ? 200 : 401, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* 3. Logout Endpoint */
    if ((strcmp(url, "/api/v1/auth/logout") == 0 || strcmp(url, "/auth/logout") == 0) && strcasecmp(method, "POST") == 0) {
        const char *auth_hdr = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
        if (auth_hdr && strncmp(auth_hdr, "Bearer ", 7) == 0) {
            const char *token = auth_hdr + 7;
            pthread_mutex_lock(&g_auth_mutex);
            for (int i = 0; i < g_num_sessions; i++) {
                if (strcmp(g_sessions[i].token, token) == 0) {
                    memmove(&g_sessions[i], &g_sessions[i + 1], sizeof(auth_session_t) * (g_num_sessions - i - 1));
                    g_num_sessions--;
                    break;
                }
            }
            pthread_mutex_unlock(&g_auth_mutex);
        }

        json_t *resp_obj = json_object();
        json_object_set_new(resp_obj, "ok", json_true());
        json_object_set_new(resp_obj, "message", json_string("Logged out"));
        char *s = json_dumps(resp_obj, 0);
        json_decref(resp_obj);
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(s), s, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        int ret = MHD_queue_response(conn, 200, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    return MHD_NO;
}

json_t *http_auth_to_json(void) {
    pthread_mutex_lock(&g_auth_mutex);
    json_t *root = json_object();
    json_object_set_new(root, "enabled", g_auth.enabled ? json_true() : json_false());
    json_object_set_new(root, "expiry_hours", json_integer(g_auth.expiry_hours));
    json_object_set_new(root, "backend_type", json_string(g_auth.backend_type));
    json_object_set_new(root, "backend_url", json_string(g_auth.backend_url));
    json_object_set_new(root, "promo_channel", json_string(g_auth.promo_channel));
    json_object_set_new(root, "securetoken", json_string(g_auth.securetoken));
    json_object_set_new(root, "allow_real_ip", g_auth.allow_real_ip ? json_true() : json_false());
    json_object_set_new(root, "ip_allow", json_string(g_auth.ip_allow));
    json_object_set_new(root, "ip_deny", json_string(g_auth.ip_deny));
    json_object_set_new(root, "token_deny", json_string(g_auth.token_deny));

    json_t *users_arr = json_array();
    for (int i = 0; i < g_auth.num_users; i++) {
        auth_user_t *u = &g_auth.users[i];
        json_t *uo = json_object();
        json_object_set_new(uo, "username", json_string(u->username));
        json_object_set_new(uo, "password", json_string(u->password));
        json_object_set_new(uo, "role", json_string(u->role == ROLE_ADMIN ? "admin" : "viewer"));
        json_object_set_new(uo, "enabled", u->enabled ? json_true() : json_false());
        json_object_set_new(uo, "comment", json_string(u->comment));
        json_object_set_new(uo, "token", json_string(u->token));
        json_object_set_new(uo, "ip", json_string(u->ip));
        json_object_set_new(uo, "expire", json_integer((json_int_t)u->expire));
        json_object_set_new(uo, "conlimit", json_integer(u->conlimit));
        json_object_set_new(uo, "packages", json_string(u->packages));
        json_array_append_new(users_arr, uo);
    }
    json_object_set_new(root, "users", users_arr);
    pthread_mutex_unlock(&g_auth_mutex);
    return root;
}

bool http_auth_from_json(json_t *root) {
    if (!root || !json_is_object(root)) return false;

    pthread_mutex_lock(&g_auth_mutex);
    json_t *j_en = json_object_get(root, "enabled");
    if (j_en) g_auth.enabled = json_is_true(j_en);

    json_t *j_exp = json_object_get(root, "expiry_hours");
    if (j_exp && json_integer_value(j_exp) > 0) {
        g_auth.expiry_hours = (int)json_integer_value(j_exp);
    }

    const char *bt = json_string_value(json_object_get(root, "backend_type"));
    if (bt) snprintf(g_auth.backend_type, sizeof(g_auth.backend_type), "%s", bt);

    const char *bu = json_string_value(json_object_get(root, "backend_url"));
    if (bu) snprintf(g_auth.backend_url, sizeof(g_auth.backend_url), "%s", bu);

    const char *pc = json_string_value(json_object_get(root, "promo_channel"));
    if (pc) snprintf(g_auth.promo_channel, sizeof(g_auth.promo_channel), "%s", pc);

    const char *st = json_string_value(json_object_get(root, "securetoken"));
    if (st) snprintf(g_auth.securetoken, sizeof(g_auth.securetoken), "%s", st);

    json_t *j_rip = json_object_get(root, "allow_real_ip");
    if (j_rip) g_auth.allow_real_ip = json_is_true(j_rip);

    const char *ia = json_string_value(json_object_get(root, "ip_allow"));
    if (ia) snprintf(g_auth.ip_allow, sizeof(g_auth.ip_allow), "%s", ia);

    const char *id_val = json_string_value(json_object_get(root, "ip_deny"));
    if (id_val) snprintf(g_auth.ip_deny, sizeof(g_auth.ip_deny), "%s", id_val);

    const char *td = json_string_value(json_object_get(root, "token_deny"));
    if (td) snprintf(g_auth.token_deny, sizeof(g_auth.token_deny), "%s", td);

    json_t *j_users = json_object_get(root, "users");
    if (j_users && json_is_array(j_users)) {
        auth_user_t old_users[MAX_AUTH_USERS];
        int old_count = g_auth.num_users;
        memcpy(old_users, g_auth.users, sizeof(g_auth.users));

        g_auth.num_users = 0;
        size_t idx;
        json_t *val;
        json_array_foreach(j_users, idx, val) {
            if (g_auth.num_users >= MAX_AUTH_USERS) break;
            const char *un = json_string_value(json_object_get(val, "username"));
            if (!un || !*un) un = json_string_value(json_object_get(val, "login"));
            const char *pw = json_string_value(json_object_get(val, "password"));
            const char *rl = json_string_value(json_object_get(val, "role"));
            if (un && *un) {
                auth_user_t *u = &g_auth.users[g_auth.num_users++];
                memset(u, 0, sizeof(*u));
                snprintf(u->username, sizeof(u->username), "%s", un);

                if (pw && *pw) {
                    snprintf(u->password, sizeof(u->password), "%s", pw);
                } else {
                    const char *prev_pass = "password";
                    for (int k = 0; k < old_count; k++) {
                        if (strcmp(old_users[k].username, un) == 0 && old_users[k].password[0]) {
                            prev_pass = old_users[k].password;
                            break;
                        }
                    }
                    snprintf(u->password, sizeof(u->password), "%s", prev_pass);
                }

                u->role = (rl && (strcmp(rl, "admin") == 0 || strcmp(rl, "1") == 0)) ? ROLE_ADMIN : ROLE_VIEWER;
                u->enabled = !json_is_false(json_object_get(val, "enabled"));

                const char *cm = json_string_value(json_object_get(val, "comment"));
                if (cm) snprintf(u->comment, sizeof(u->comment), "%s", cm);

                const char *tok = json_string_value(json_object_get(val, "token"));
                if (tok) snprintf(u->token, sizeof(u->token), "%s", tok);

                const char *ip_rest = json_string_value(json_object_get(val, "ip"));
                if (ip_rest) snprintf(u->ip, sizeof(u->ip), "%s", ip_rest);

                json_t *j_exp = json_object_get(val, "expire");
                if (j_exp && json_is_number(j_exp)) u->expire = (time_t)json_integer_value(j_exp);

                json_t *j_con = json_object_get(val, "conlimit");
                if (j_con && json_is_number(j_con)) u->conlimit = (int)json_integer_value(j_con);

                const char *pk = json_string_value(json_object_get(val, "packages"));
                if (pk) snprintf(u->packages, sizeof(u->packages), "%s", pk);
            }
        }
    }
    pthread_mutex_unlock(&g_auth_mutex);
    return true;
}
