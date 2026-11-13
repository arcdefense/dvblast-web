#include "ws.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct ws_client_internal {
    int                              id;
    MHD_socket                       sock;
    struct MHD_UpgradeResponseHandle *urh;
    pthread_t                        thread;
    volatile bool                    alive;
    char                             remote_ip[64];
    char                             user_agent[128];
    char                             login[64];
    time_t                           connected_at;
    uint64_t                         messages_sent;
    uint64_t                         bytes_sent;
    struct ws_client_internal        *next;
} ws_client_internal_t;

static pthread_mutex_t g_ws_mutex = PTHREAD_MUTEX_INITIALIZER;
static ws_client_internal_t *g_ws_clients = NULL;
static int g_ws_next_id = 1;
static int g_ws_active_count = 0;

/* Base64 encoding table */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *data, size_t input_len) {
    size_t output_len = 4 * ((input_len + 2) / 3);
    char *encoded = malloc(output_len + 1);
    if (!encoded) return NULL;

    size_t i, j = 0;
    for (i = 0; i < input_len;) {
        uint32_t octet_a = i < input_len ? data[i++] : 0;
        uint32_t octet_b = i < input_len ? data[i++] : 0;
        uint32_t octet_c = i < input_len ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded[j++] = b64_table[(triple >> 18) & 0x3F];
        encoded[j++] = b64_table[(triple >> 12) & 0x3F];
        encoded[j++] = (i > input_len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        encoded[j++] = (i > input_len) ? '=' : b64_table[triple & 0x3F];
    }
    encoded[output_len] = '\0';
    return encoded;
}

static char *calc_websocket_accept(const char *client_key) {
    if (!client_key) return NULL;
    static const char *ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    size_t key_len = strlen(client_key);
    size_t guid_len = strlen(ws_guid);

    char *buf = malloc(key_len + guid_len + 1);
    if (!buf) return NULL;

    memcpy(buf, client_key, key_len);
    memcpy(buf + key_len, ws_guid, guid_len);
    buf[key_len + guid_len] = '\0';

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)buf, key_len + guid_len, digest);
    free(buf);

    return base64_encode(digest, SHA_DIGEST_LENGTH);
}

static bool ws_send_frame(MHD_socket sock, uint8_t opcode, const uint8_t *payload, size_t len) {
    uint8_t header[10];
    size_t hlen = 0;
    header[0] = 0x80 | (opcode & 0x0F);

    if (len < 126) {
        header[1] = (uint8_t)len;
        hlen = 2;
    } else if (len <= 65535) {
        header[1] = 126;
        header[2] = (uint8_t)((len >> 8) & 0xFF);
        header[3] = (uint8_t)(len & 0xFF);
        hlen = 4;
    } else {
        header[1] = 127;
        for (int i = 0; i < 8; i++) {
            header[2 + i] = (uint8_t)((len >> (56 - i * 8)) & 0xFF);
        }
        hlen = 10;
    }

    if (send(sock, header, hlen, MSG_NOSIGNAL) < 0) return false;

    if (len > 0 && payload) {
        size_t total_sent = 0;
        while (total_sent < len) {
            ssize_t n = send(sock, payload + total_sent, len - total_sent, MSG_NOSIGNAL);
            if (n <= 0) return false;
            total_sent += (size_t)n;
        }
    }
    return true;
}

static void *ws_worker_thread(void *arg) {
    ws_client_internal_t *c = (ws_client_internal_t *)arg;
    if (!c) return NULL;

    /* Set socket non-blocking for event loop reads */
    int flags = fcntl(c->sock, F_GETFL, 0);
    if (flags >= 0) fcntl(c->sock, F_SETFL, flags | O_NONBLOCK);

    /* Send initial welcome message */
    const char *welcome = "{\"event\":\"connected\",\"server\":\"DVBlast Web Gateway\",\"version\":\"2.0\"}";
    ws_send_frame(c->sock, 0x01, (const uint8_t *)welcome, strlen(welcome));

    uint8_t in_buf[1024];
    while (c->alive) {
        ssize_t n = recv(c->sock, in_buf, sizeof(in_buf), 0);
        if (n > 0) {
            /* Parse simple client frames */
            uint8_t opcode = in_buf[0] & 0x0F;
            if (opcode == 0x08) {
                /* Connection Close */
                c->alive = false;
                break;
            } else if (opcode == 0x09) {
                /* Ping -> Send Pong */
                ws_send_frame(c->sock, 0x0A, in_buf + 2, (size_t)(in_buf[1] & 0x7F));
            }
        } else if (n == 0) {
            /* Clean client disconnect */
            c->alive = false;
            break;
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                c->alive = false;
                break;
            }
        }
        usleep(100000); /* 100ms idle wait */
    }

    /* Unlink and cleanup client */
    pthread_mutex_lock(&g_ws_mutex);
    ws_client_internal_t **curr = &g_ws_clients;
    while (*curr) {
        if (*curr == c) {
            *curr = c->next;
            g_ws_active_count--;
            break;
        }
        curr = &(*curr)->next;
    }
    pthread_mutex_unlock(&g_ws_mutex);

    if (c->urh) {
        MHD_upgrade_action(c->urh, MHD_UPGRADE_ACTION_CLOSE);
    } else {
        close(c->sock);
    }
    free(c);
    return NULL;
}

typedef struct {
    char login[64];
    char user_agent[128];
    char remote_ip[64];
} ws_upgrade_info_t;

static void ws_upgrade_handler(void *cls, struct MHD_Connection *conn,
                               void *con_cls, const char *extra_in,
                               size_t extra_in_size, MHD_socket sock,
                               struct MHD_UpgradeResponseHandle *urh) {
    (void)conn; (void)con_cls; (void)extra_in; (void)extra_in_size;
    ws_upgrade_info_t *info = (ws_upgrade_info_t *)cls;

    ws_client_internal_t *client = calloc(1, sizeof(ws_client_internal_t));
    if (!client) {
        if (info) free(info);
        MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
        return;
    }

    pthread_mutex_lock(&g_ws_mutex);
    if (g_ws_active_count >= WS_MAX_CLIENTS) {
        pthread_mutex_unlock(&g_ws_mutex);
        if (info) free(info);
        free(client);
        MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
        return;
    }

    client->id = g_ws_next_id++;
    client->sock = sock;
    client->urh = urh;
    client->alive = true;
    client->connected_at = time(NULL);

    if (info) {
        snprintf(client->login, sizeof(client->login), "%s", info->login);
        snprintf(client->user_agent, sizeof(client->user_agent), "%s", info->user_agent);
        snprintf(client->remote_ip, sizeof(client->remote_ip), "%s", info->remote_ip);
        free(info);
    }

    client->next = g_ws_clients;
    g_ws_clients = client;
    g_ws_active_count++;
    pthread_mutex_unlock(&g_ws_mutex);

    pthread_create(&client->thread, NULL, ws_worker_thread, client);
    pthread_detach(client->thread);
}

void ws_init(void) {
    pthread_mutex_lock(&g_ws_mutex);
    g_ws_clients = NULL;
    g_ws_active_count = 0;
    pthread_mutex_unlock(&g_ws_mutex);
}

void ws_cleanup(void) {
    pthread_mutex_lock(&g_ws_mutex);
    ws_client_internal_t *c = g_ws_clients;
    while (c) {
        c->alive = false;
        c = c->next;
    }
    pthread_mutex_unlock(&g_ws_mutex);
}

bool ws_is_upgrade_request(struct MHD_Connection *conn) {
    if (!conn) return false;
    const char *up = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Upgrade");
    const char *ck = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    return (up && strcasecmp(up, "websocket") == 0 && ck && *ck);
}

struct MHD_Response *ws_create_upgrade_response(struct MHD_Connection *conn, const char *login) {
    if (!conn) return NULL;
    const char *key = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    if (!key) return NULL;

    char *accept_hdr = calc_websocket_accept(key);
    if (!accept_hdr) return NULL;

    ws_upgrade_info_t *info = calloc(1, sizeof(ws_upgrade_info_t));
    if (info) {
        if (login) snprintf(info->login, sizeof(info->login), "%s", login);
        const char *ua = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "User-Agent");
        if (ua) snprintf(info->user_agent, sizeof(info->user_agent), "%s", ua);

        const union MHD_ConnectionInfo *ci = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        if (ci && ci->client_addr) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ci->client_addr;
            inet_ntop(AF_INET, &sin->sin_addr, info->remote_ip, sizeof(info->remote_ip));
        } else {
            snprintf(info->remote_ip, sizeof(info->remote_ip), "127.0.0.1");
        }
    }

    struct MHD_Response *resp = MHD_create_response_for_upgrade(ws_upgrade_handler, info);
    if (!resp) {
        if (info) free(info);
        free(accept_hdr);
        return NULL;
    }

    MHD_add_response_header(resp, "Upgrade", "websocket");
    MHD_add_response_header(resp, "Connection", "Upgrade");
    MHD_add_response_header(resp, "Sec-WebSocket-Accept", accept_hdr);
    free(accept_hdr);

    return resp;
}

int ws_handle_upgrade(struct MHD_Connection *conn, const char *login) {
    struct MHD_Response *resp = ws_create_upgrade_response(conn, login);
    if (!resp) return MHD_NO;
    int ret = MHD_queue_response(conn, 101, resp);
    MHD_destroy_response(resp);
    return ret;
}

void ws_broadcast_text(const char *text) {
    if (!text || !*text) return;

    /* Create snapshot of sockets to avoid holding lock during send */
    MHD_socket socks[WS_MAX_CLIENTS];
    ws_client_internal_t *ptrs[WS_MAX_CLIENTS];
    int count = 0;

    pthread_mutex_lock(&g_ws_mutex);
    for (ws_client_internal_t *c = g_ws_clients; c && count < WS_MAX_CLIENTS; c = c->next) {
        if (c->alive) {
            socks[count] = c->sock;
            ptrs[count] = c;
            count++;
        }
    }
    pthread_mutex_unlock(&g_ws_mutex);

    size_t len = strlen(text);
    for (int i = 0; i < count; i++) {
        if (!ws_send_frame(socks[i], 0x01, (const uint8_t *)text, len)) {
            ptrs[i]->alive = false;
        } else {
            __sync_fetch_and_add(&ptrs[i]->messages_sent, 1);
            __sync_fetch_and_add(&ptrs[i]->bytes_sent, len);
        }
    }
}

void ws_broadcast_json(json_t *event) {
    if (!event) return;
    char *s = json_dumps(event, JSON_COMPACT);
    if (!s) return;
    ws_broadcast_text(s);
    free(s);
}

json_t *ws_get_sessions_json(void) {
    pthread_mutex_lock(&g_ws_mutex);
    json_t *arr = json_array();
    time_t now = time(NULL);

    for (ws_client_internal_t *c = g_ws_clients; c; c = c->next) {
        if (!c->alive) continue;
        json_t *item = json_object();
        json_object_set_new(item, "id", json_integer(c->id));
        json_object_set_new(item, "remote_ip", json_string(c->remote_ip[0] ? c->remote_ip : "127.0.0.1"));
        json_object_set_new(item, "user_agent", json_string(c->user_agent[0] ? c->user_agent : "Web Browser"));
        json_object_set_new(item, "login", json_string(c->login[0] ? c->login : "admin"));
        json_object_set_new(item, "uptime_sec", json_integer(now - c->connected_at));
        json_object_set_new(item, "messages_sent", json_integer(c->messages_sent));
        json_object_set_new(item, "bytes_sent", json_integer(c->bytes_sent));
        json_array_append_new(arr, item);
    }
    pthread_mutex_unlock(&g_ws_mutex);
    return arr;
}

bool ws_kick_session(int session_id) {
    bool found = false;
    pthread_mutex_lock(&g_ws_mutex);
    for (ws_client_internal_t *c = g_ws_clients; c; c = c->next) {
        if (c->id == session_id && c->alive) {
            c->alive = false;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_ws_mutex);
    return found;
}

int ws_client_count(void) {
    return g_ws_active_count;
}
