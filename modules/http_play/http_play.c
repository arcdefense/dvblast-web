#include "http_play.h"
#include "web_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct http_client_node {
    int                     client_id;
    char                    stream_id[64];
    uint16_t                service_id;
    uint8_t                *buffer;
    size_t                  capacity;
    size_t                  write_pos;
    size_t                  read_pos;
    size_t                  available;
    bool                    active;
    time_t                  connected_at;
    uint64_t                bytes_sent;
    pthread_mutex_t         lock;
    pthread_cond_t          cond;
    struct http_client_node *next;
} http_client_node_t;

static http_play_config_t g_cfg = {
    .enabled = true,
    .buffer_kb = HTTP_PLAY_DEFAULT_BUF_KB,
    .max_clients = HTTP_PLAY_MAX_CLIENTS,
    .active_clients = 0,
    .total_clients_served = 0,
    .total_bytes_streamed = 0
};

static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static http_client_node_t *g_client_list = NULL;
static int g_next_client_id = 1;

void http_play_init(void) {
    pthread_mutex_lock(&g_clients_mutex);
    http_client_node_t *curr = g_client_list;
    while (curr) {
        http_client_node_t *next = curr->next;
        pthread_mutex_destroy(&curr->lock);
        pthread_cond_destroy(&curr->cond);
        if (curr->buffer) free(curr->buffer);
        free(curr);
        curr = next;
    }
    g_client_list = NULL;
    g_cfg.active_clients = 0;
    pthread_mutex_unlock(&g_clients_mutex);
}

void http_play_cleanup(void) {
    http_play_init();
}

void http_play_configure(const http_play_config_t *cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&g_clients_mutex);
    g_cfg.enabled = cfg->enabled;
    if (cfg->buffer_kb >= 128 && cfg->buffer_kb <= 16384) {
        g_cfg.buffer_kb = cfg->buffer_kb;
    }
    if (cfg->max_clients >= 1 && cfg->max_clients <= 256) {
        g_cfg.max_clients = cfg->max_clients;
    }
    pthread_mutex_unlock(&g_clients_mutex);
}

http_play_config_t http_play_get_config(void) {
    pthread_mutex_lock(&g_clients_mutex);
    http_play_config_t copy = g_cfg;
    pthread_mutex_unlock(&g_clients_mutex);
    return copy;
}

void http_play_push_packet(uint16_t sid, const uint8_t *ts_packet, size_t len) {
    if (!g_cfg.enabled || !ts_packet || len == 0) return;

    pthread_mutex_lock(&g_clients_mutex);
    http_client_node_t *c = g_client_list;
    while (c) {
        if (c->active && (c->service_id == 0 || c->service_id == sid)) {
            pthread_mutex_lock(&c->lock);
            
            /* If buffer is full, drop oldest packets to prevent unbounded latency */
            if (c->available + len > c->capacity) {
                size_t drop = len * 4;
                if (drop > c->available) drop = c->available;
                c->read_pos = (c->read_pos + drop) % c->capacity;
                c->available -= drop;
            }

            /* Write into circular ring buffer */
            size_t first_chunk = c->capacity - c->write_pos;
            if (first_chunk >= len) {
                memcpy(c->buffer + c->write_pos, ts_packet, len);
                c->write_pos = (c->write_pos + len) % c->capacity;
            } else {
                memcpy(c->buffer + c->write_pos, ts_packet, first_chunk);
                memcpy(c->buffer, ts_packet + first_chunk, len - first_chunk);
                c->write_pos = len - first_chunk;
            }

            c->available += len;
            pthread_cond_signal(&c->cond);
            pthread_mutex_unlock(&c->lock);
        }
        c = c->next;
    }
    pthread_mutex_unlock(&g_clients_mutex);
}

static ssize_t http_play_content_reader(void *cls, uint64_t pos, char *buf, size_t max) {
    (void)pos;
    http_client_node_t *client = (http_client_node_t *)cls;
    if (!client || !client->active) {
        return MHD_CONTENT_READER_END_OF_STREAM;
    }

    pthread_mutex_lock(&client->lock);

    /* If no data yet, wait up to 100ms */
    if (client->available == 0) {
        struct timeval now;
        gettimeofday(&now, NULL);
        struct timespec timeout;
        timeout.tv_sec = now.tv_sec;
        timeout.tv_nsec = (now.tv_usec + 100000) * 1000;
        if (timeout.tv_nsec >= 1000000000) {
            timeout.tv_sec += 1;
            timeout.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&client->cond, &client->lock, &timeout);
    }

    if (client->available == 0) {
        pthread_mutex_unlock(&client->lock);
        return 0; /* No data right now, MHD will retry */
    }

    size_t to_read = client->available < max ? client->available : max;
    size_t first_chunk = client->capacity - client->read_pos;

    if (first_chunk >= to_read) {
        memcpy(buf, client->buffer + client->read_pos, to_read);
        client->read_pos = (client->read_pos + to_read) % client->capacity;
    } else {
        memcpy(buf, client->buffer + client->read_pos, first_chunk);
        memcpy(buf + first_chunk, client->buffer, to_read - first_chunk);
        client->read_pos = to_read - first_chunk;
    }

    client->available -= to_read;
    client->bytes_sent += to_read;

    pthread_mutex_lock(&g_clients_mutex);
    g_cfg.total_bytes_streamed += to_read;
    pthread_mutex_unlock(&g_clients_mutex);

    pthread_mutex_unlock(&client->lock);
    return (ssize_t)to_read;
}

static void http_play_free_client(void *cls) {
    http_client_node_t *client = (http_client_node_t *)cls;
    if (!client) return;

    pthread_mutex_lock(&g_clients_mutex);
    http_client_node_t **curr = &g_client_list;
    while (*curr) {
        if (*curr == client) {
            *curr = client->next;
            break;
        }
        curr = &(*curr)->next;
    }
    if (g_cfg.active_clients > 0) g_cfg.active_clients--;
    pthread_mutex_unlock(&g_clients_mutex);

    pthread_mutex_destroy(&client->lock);
    pthread_cond_destroy(&client->cond);
    if (client->buffer) free(client->buffer);
    free(client);
}

static int handle_playlist_m3u(struct MHD_Connection *conn, const char *host_header) {
    char base_host[128];
    if (host_header && *host_header) {
        snprintf(base_host, sizeof(base_host), "%s", host_header);
    } else {
        snprintf(base_host, sizeof(base_host), "%s:%d",
                 g_gateway.http_host[0] ? g_gateway.http_host : "127.0.0.1",
                 g_gateway.http_port ? g_gateway.http_port : 8088);
    }

    size_t alloc_sz = 8192;
    char *buf = malloc(alloc_sz);
    if (!buf) return MHD_NO;

    int offset = snprintf(buf, alloc_sz, "#EXTM3U\n#EXT-X-VERSION:3\n\n");

    pthread_mutex_lock(&g_gateway.lock);
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        if (!s->enabled) continue;

        web_adapter_t *ad = web_state_find_adapter_by_idx(s->adapter_idx);
        const char *group = ad ? ad->name : "DVBlast";

        char line[512];
        int n = snprintf(line, sizeof(line),
            "#EXTINF:-1 tvg-id=\"%s\" tvg-name=\"%s\" tvg-chno=\"%u\" group-title=\"%s\",%s\nhttp://%s/play/%s\n\n",
            s->id, s->name, s->service_id, group, s->name, base_host, s->id);

        if (offset + n >= (int)alloc_sz - 64) {
            alloc_sz *= 2;
            char *newbuf = realloc(buf, alloc_sz);
            if (!newbuf) break;
            buf = newbuf;
        }
        memcpy(buf + offset, line, n);
        offset += n;
    }
    pthread_mutex_unlock(&g_gateway.lock);

    struct MHD_Response *resp = MHD_create_response_from_buffer(offset, buf, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(buf);
        return MHD_NO;
    }
    MHD_add_response_header(resp, "Content-Type", "application/x-mpegurl; charset=utf-8");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Content-Disposition", "inline; filename=\"dvblast.m3u\"");
    int ret = MHD_queue_response(conn, 200, resp);
    MHD_destroy_response(resp);
    return ret;
}

int http_play_handle_request(struct MHD_Connection *conn, const char *url, const char *host_header) {
    if (!g_cfg.enabled) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(23, "HTTP Play is disabled\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 503, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strcmp(url, "/playlist.m3u") == 0 || strcmp(url, "/api/v1/http_play/playlist.m3u") == 0) {
        return handle_playlist_m3u(conn, host_header);
    }

    /* Extract stream_id or service_id from /play/{id} or /live/{sid}.ts */
    char stream_id[64] = {0};
    uint16_t service_id = 0;

    if (strncmp(url, "/play/", 6) == 0) {
        snprintf(stream_id, sizeof(stream_id), "%s", url + 6);
    } else if (strncmp(url, "/live/", 6) == 0) {
        const char *p = url + 6;
        service_id = (uint16_t)atoi(p);
    } else {
        return MHD_NO;
    }

    /* Verify stream exists in gateway */
    pthread_mutex_lock(&g_gateway.lock);
    bool found = false;
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        if (stream_id[0] && strcmp(s->id, stream_id) == 0) {
            service_id = s->service_id;
            found = true;
            break;
        }
        if (service_id != 0 && s->service_id == service_id) {
            snprintf(stream_id, sizeof(stream_id), "%s", s->id);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_gateway.lock);

    if (!found && service_id == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(17, "Stream Not Found\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 404, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* Check max client capacity */
    pthread_mutex_lock(&g_clients_mutex);
    if (g_cfg.active_clients >= g_cfg.max_clients) {
        pthread_mutex_unlock(&g_clients_mutex);
        struct MHD_Response *resp = MHD_create_response_from_buffer(28, "Max clients capacity reached\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 503, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* Allocate client state */
    http_client_node_t *client = calloc(1, sizeof(http_client_node_t));
    if (!client) {
        pthread_mutex_unlock(&g_clients_mutex);
        return MHD_NO;
    }

    client->client_id = g_next_client_id++;
    snprintf(client->stream_id, sizeof(client->stream_id), "%s", stream_id);
    client->service_id = service_id;
    client->capacity = (size_t)g_cfg.buffer_kb * 1024;
    client->buffer = malloc(client->capacity);
    if (!client->buffer) {
        free(client);
        pthread_mutex_unlock(&g_clients_mutex);
        return MHD_NO;
    }

    client->active = true;
    client->connected_at = time(NULL);
    pthread_mutex_init(&client->lock, NULL);
    pthread_cond_init(&client->cond, NULL);

    client->next = g_client_list;
    g_client_list = client;
    g_cfg.active_clients++;
    g_cfg.total_clients_served++;
    pthread_mutex_unlock(&g_clients_mutex);

    struct MHD_Response *resp = MHD_create_response_from_callback(
        MHD_SIZE_UNKNOWN,
        32 * 1024,
        http_play_content_reader,
        client,
        http_play_free_client
    );

    if (!resp) {
        http_play_free_client(client);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "video/mp2t");
    MHD_add_response_header(resp, "Cache-Control", "no-cache, no-store, must-revalidate");
    MHD_add_response_header(resp, "Pragma", "no-cache");
    MHD_add_response_header(resp, "Connection", "keep-alive");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");

    int ret = MHD_queue_response(conn, 200, resp);
    MHD_destroy_response(resp);
    return ret;
}

json_t *http_play_to_json(void) {
    pthread_mutex_lock(&g_clients_mutex);
    json_t *root = json_object();
    json_object_set_new(root, "enabled", g_cfg.enabled ? json_true() : json_false());
    json_object_set_new(root, "buffer_kb", json_integer(g_cfg.buffer_kb));
    json_object_set_new(root, "max_clients", json_integer(g_cfg.max_clients));
    json_object_set_new(root, "active_clients", json_integer(g_cfg.active_clients));
    json_object_set_new(root, "total_clients_served", json_integer(g_cfg.total_clients_served));
    json_object_set_new(root, "total_bytes_streamed", json_integer(g_cfg.total_bytes_streamed));

    json_t *clients_arr = json_array();
    http_client_node_t *c = g_client_list;
    while (c) {
        json_t *co = json_object();
        json_object_set_new(co, "id", json_integer(c->client_id));
        json_object_set_new(co, "stream_id", json_string(c->stream_id));
        json_object_set_new(co, "service_id", json_integer(c->service_id));
        json_object_set_new(co, "connected_at", json_integer(c->connected_at));
        json_object_set_new(co, "bytes_sent", json_integer(c->bytes_sent));
        json_array_append_new(clients_arr, co);
        c = c->next;
    }
    json_object_set_new(root, "clients", clients_arr);

    pthread_mutex_unlock(&g_clients_mutex);
    return root;
}

bool http_play_from_json(json_t *root) {
    if (!root || !json_is_object(root)) return false;

    pthread_mutex_lock(&g_clients_mutex);
    json_t *j_en = json_object_get(root, "enabled");
    if (j_en) g_cfg.enabled = json_is_true(j_en);

    json_t *j_buf = json_object_get(root, "buffer_kb");
    if (j_buf && json_integer_value(j_buf) >= 128) {
        g_cfg.buffer_kb = (int)json_integer_value(j_buf);
    }

    json_t *j_mc = json_object_get(root, "max_clients");
    if (j_mc && json_integer_value(j_mc) > 0) {
        g_cfg.max_clients = (int)json_integer_value(j_mc);
    }
    pthread_mutex_unlock(&g_clients_mutex);
    return true;
}
