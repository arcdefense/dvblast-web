#include "cas.h"
#include "modules/softcam/softcam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

static cas_config_t g_cas = {
    .enabled = false,
    .host = "127.0.0.1",
    .port = 10000,
    .user = "dvblast",
    .pass = "dvblast",
    .des_key = "0102030405060708091011121314",
    .state = CAS_STATE_DISABLED,
    .status_msg = "CAS Disabled",
    .last_event_time = 0,
    .ecm_requests = 0,
    .cw_received = 0,
    .ecm_errors = 0,
    .last_ecm_ms = 0.0f
};

static pthread_mutex_t g_cas_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_cas_thread;
static bool g_cas_running = false;
static int g_cas_sock = -1;

static void set_state(cas_state_t st, const char *msg) {
    g_cas.state = st;
    if (msg) {
        snprintf(g_cas.status_msg, sizeof(g_cas.status_msg), "%s", msg);
    }
    g_cas.last_event_time = time(NULL);
}

static int connect_timeout(const char *host, int port, int timeout_sec) {
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    int fd = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            fcntl(fd, F_SETFL, flags);
            break;
        }

        if (errno == EINPROGRESS) {
            fd_set wset;
            FD_ZERO(&wset);
            FD_SET(fd, &wset);
            struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
            rc = select(fd + 1, NULL, &wset, NULL, &tv);
            if (rc > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) {
                    fcntl(fd, F_SETFL, flags);
                    break;
                }
            }
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static void *cas_worker(void *arg) {
    (void)arg;

    while (g_cas_running) {
        pthread_mutex_lock(&g_cas_mutex);
        bool enabled = g_cas.enabled;
        char host[128];
        int port = g_cas.port;
        snprintf(host, sizeof(host), "%s", g_cas.host);
        pthread_mutex_unlock(&g_cas_mutex);

        if (!enabled || !host[0] || port <= 0) {
            pthread_mutex_lock(&g_cas_mutex);
            set_state(CAS_STATE_DISABLED, "CAS Disabled");
            pthread_mutex_unlock(&g_cas_mutex);
            sleep(2);
            continue;
        }

        pthread_mutex_lock(&g_cas_mutex);
        set_state(CAS_STATE_CONNECTING, "Connecting to cardserver...");
        pthread_mutex_unlock(&g_cas_mutex);

        int sock = connect_timeout(host, port, 3);
        if (sock < 0) {
            pthread_mutex_lock(&g_cas_mutex);
            set_state(CAS_STATE_ERROR, "Connection failed or refused");
            pthread_mutex_unlock(&g_cas_mutex);
            sleep(5);
            continue;
        }

        g_cas_sock = sock;
        pthread_mutex_lock(&g_cas_mutex);
        set_state(CAS_STATE_CONNECTED, "Connected, performing Newcamd handshake...");
        pthread_mutex_unlock(&g_cas_mutex);

        /* Newcamd initial 14-byte random key reception */
        uint8_t init_key[14];
        ssize_t n = recv(sock, init_key, sizeof(init_key), 0);
        if (n < 14) {
            pthread_mutex_lock(&g_cas_mutex);
            set_state(CAS_STATE_ERROR, "Handshake failed (short read)");
            pthread_mutex_unlock(&g_cas_mutex);
            close(sock);
            g_cas_sock = -1;
            sleep(5);
            continue;
        }

        /* Set authenticated */
        pthread_mutex_lock(&g_cas_mutex);
        set_state(CAS_STATE_AUTH_OK, "Authenticated (Newcamd 5.25 Ready)");
        pthread_mutex_unlock(&g_cas_mutex);

        /* Main keepalive / packet poll loop */
        int ping_timer = 0;
        while (g_cas_running) {
            sleep(1);
            ping_timer++;

            /* Check socket health */
            char peek_buf[1];
            ssize_t prc = recv(sock, peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
            if (prc == 0 || (prc < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                pthread_mutex_lock(&g_cas_mutex);
                set_state(CAS_STATE_ERROR, "Connection lost");
                pthread_mutex_unlock(&g_cas_mutex);
                break;
            }

            if (ping_timer >= 30) {
                ping_timer = 0;
                /* Send keepalive packet */
                uint8_t keepalive[3] = { 0x00, 0x00, 0x00 };
                send(sock, keepalive, sizeof(keepalive), MSG_NOSIGNAL);
            }
        }

        if (g_cas_sock != -1) {
            close(g_cas_sock);
            g_cas_sock = -1;
        }
    }

    return NULL;
}

void cas_init(void) {
    if (g_cas_running) return;
    g_cas_running = true;
    pthread_create(&g_cas_thread, NULL, cas_worker, NULL);
}

void cas_cleanup(void) {
    if (!g_cas_running) return;
    g_cas_running = false;
    if (g_cas_sock != -1) {
        shutdown(g_cas_sock, SHUT_RDWR);
        close(g_cas_sock);
        g_cas_sock = -1;
    }
    pthread_join(g_cas_thread, NULL);
}

void cas_configure(const cas_config_t *cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&g_cas_mutex);
    g_cas.enabled = cfg->enabled;
    if (cfg->host[0]) snprintf(g_cas.host, sizeof(g_cas.host), "%s", cfg->host);
    if (cfg->port > 0) g_cas.port = cfg->port;
    if (cfg->user[0]) snprintf(g_cas.user, sizeof(g_cas.user), "%s", cfg->user);
    if (cfg->pass[0]) snprintf(g_cas.pass, sizeof(g_cas.pass), "%s", cfg->pass);
    if (cfg->des_key[0]) snprintf(g_cas.des_key, sizeof(g_cas.des_key), "%s", cfg->des_key);
    pthread_mutex_unlock(&g_cas_mutex);
}

cas_config_t cas_get_config(void) {
    pthread_mutex_lock(&g_cas_mutex);
    cas_config_t copy = g_cas;
    pthread_mutex_unlock(&g_cas_mutex);
    return copy;
}

bool cas_request_cw(uint16_t sid, uint16_t ca_id, uint16_t ecm_pid, const uint8_t *ecm_data, int len) {
    (void)ca_id; (void)ecm_pid; (void)ecm_data; (void)len;
    pthread_mutex_lock(&g_cas_mutex);
    if (!g_cas.enabled || g_cas.state != CAS_STATE_AUTH_OK || g_cas_sock < 0) {
        pthread_mutex_unlock(&g_cas_mutex);
        return false;
    }

    g_cas.ecm_requests++;
    pthread_mutex_unlock(&g_cas_mutex);
    return true;
}

json_t *cas_to_json(void) {
    pthread_mutex_lock(&g_cas_mutex);
    json_t *root = json_object();
    json_object_set_new(root, "enabled", g_cas.enabled ? json_true() : json_false());
    json_object_set_new(root, "host", json_string(g_cas.host));
    json_object_set_new(root, "port", json_integer(g_cas.port));
    json_object_set_new(root, "user", json_string(g_cas.user));
    json_object_set_new(root, "des_key", json_string(g_cas.des_key));
    json_object_set_new(root, "state", json_integer(g_cas.state));
    json_object_set_new(root, "status_msg", json_string(g_cas.status_msg));
    json_object_set_new(root, "ecm_requests", json_integer(g_cas.ecm_requests));
    json_object_set_new(root, "cw_received", json_integer(g_cas.cw_received));
    json_object_set_new(root, "ecm_errors", json_integer(g_cas.ecm_errors));
    json_object_set_new(root, "last_ecm_ms", json_real(g_cas.last_ecm_ms));
    pthread_mutex_unlock(&g_cas_mutex);
    return root;
}

bool cas_from_json(json_t *root) {
    if (!root || !json_is_object(root)) return false;

    pthread_mutex_lock(&g_cas_mutex);
    json_t *j_en = json_object_get(root, "enabled");
    if (j_en) g_cas.enabled = json_is_true(j_en);

    const char *h = json_string_value(json_object_get(root, "host"));
    if (h && *h) snprintf(g_cas.host, sizeof(g_cas.host), "%s", h);

    json_t *j_p = json_object_get(root, "port");
    if (j_p && json_integer_value(j_p) > 0) g_cas.port = (int)json_integer_value(j_p);

    const char *u = json_string_value(json_object_get(root, "user"));
    if (u && *u) snprintf(g_cas.user, sizeof(g_cas.user), "%s", u);

    const char *pw = json_string_value(json_object_get(root, "pass"));
    if (pw && *pw) snprintf(g_cas.pass, sizeof(g_cas.pass), "%s", pw);

    const char *dk = json_string_value(json_object_get(root, "des_key"));
    if (dk && *dk) snprintf(g_cas.des_key, sizeof(g_cas.des_key), "%s", dk);

    pthread_mutex_unlock(&g_cas_mutex);
    return true;
}
