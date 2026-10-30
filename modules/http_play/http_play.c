#include "http_play.h"
#include "web_state.h"
#include "dvblast.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

typedef struct http_client_node {
    int                     client_id;
    char                    stream_id[64];
    uint16_t                service_id;
    char                    remote_ip[64];
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

/* Secondary adapter UDP multicast relay */
typedef struct udp_relay_node {
    uint16_t               service_id;
    char                   ip[64];
    int                    port;
    int                    refcount;
    int                    sock_fd;
    pthread_t              thread;
    volatile bool          running;
    struct udp_relay_node *next;
} udp_relay_node_t;

/* Fast startup PAT/PMT PSI cache */
#define MAX_PSI_CACHE 64
typedef struct {
    uint16_t service_id;
    uint16_t pmt_pid;
    uint8_t  pat_pkt[188];
    uint8_t  pmt_pkt[188];
    bool     has_pat;
    bool     has_pmt;
} psi_cache_entry_t;

static http_play_config_t g_cfg = {
    .enabled = true,
    .port = 0,
    .playlist_name = "playlist",
    .buffer_kb = 2048,
    .max_clients = HTTP_PLAY_MAX_CLIENTS,
    .m3u_header = "",
    .xspf_title = "DVBlast Web Gateway",
    .tv_logos_path = "",
    .allow_http = true,
    .allow_hls = true,
    .disable_tls = false,
    .active_clients = 0,
    .total_clients_served = 0,
    .total_bytes_streamed = 0
};

static pthread_mutex_t g_clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static http_client_node_t *g_client_list = NULL;
static int g_next_client_id = 1;

static pthread_mutex_t g_relay_mutex = PTHREAD_MUTEX_INITIALIZER;
static udp_relay_node_t *g_relay_list = NULL;

static pthread_mutex_t g_psi_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static psi_cache_entry_t g_psi_cache[MAX_PSI_CACHE];

/* Forward declarations */
static void relay_unsubscribe(uint16_t sid);
static void relay_subscribe(uint16_t sid, const char *ip, int port);

/* --------------------------------------------------------------------------
 * PAT / PMT Cache Helpers for Instant Stream Startup
 * -------------------------------------------------------------------------- */
static void update_psi_cache(uint16_t sid, const uint8_t *pkt, uint16_t pid) {
    if (!pkt || sid == 0) return;

    pthread_mutex_lock(&g_psi_cache_mutex);
    psi_cache_entry_t *entry = NULL;
    for (int i = 0; i < MAX_PSI_CACHE; i++) {
        if (g_psi_cache[i].service_id == sid) {
            entry = &g_psi_cache[i];
            break;
        }
    }
    if (!entry) {
        for (int i = 0; i < MAX_PSI_CACHE; i++) {
            if (g_psi_cache[i].service_id == 0) {
                entry = &g_psi_cache[i];
                entry->service_id = sid;
                break;
            }
        }
    }

    if (entry) {
        if (pid == 0) {
            /* PAT Packet */
            memcpy(entry->pat_pkt, pkt, 188);
            entry->has_pat = true;

            /* Parse PAT section to extract PMT PID for this sid */
            int pusi = (pkt[1] & 0x40) ? 1 : 0;
            int offset = 4;
            if (pkt[3] & 0x20) {
                offset += 1 + pkt[4];
            }
            if (pusi && offset < 188) {
                offset += 1 + pkt[offset];
            }
            if (offset + 8 <= 188 && pkt[offset] == 0x00) {
                int sec_len = ((pkt[offset + 1] & 0x0F) << 8) | pkt[offset + 2];
                int prog_start = offset + 8;
                int prog_end = offset + 3 + sec_len - 4;
                if (prog_end > 188) prog_end = 188;
                for (int p = prog_start; p + 4 <= prog_end; p += 4) {
                    uint16_t prog_num = (pkt[p] << 8) | pkt[p + 1];
                    uint16_t pmt_pid = ((pkt[p + 2] & 0x1F) << 8) | pkt[p + 3];
                    if (prog_num == sid) {
                        entry->pmt_pid = pmt_pid;
                        break;
                    }
                }
            }
        } else if (entry->pmt_pid != 0 && pid == entry->pmt_pid) {
            /* PMT Packet */
            memcpy(entry->pmt_pkt, pkt, 188);
            entry->has_pmt = true;
        }
    }
    pthread_mutex_unlock(&g_psi_cache_mutex);
}

static void inject_psi_preamble(http_client_node_t *client) {
    if (!client) return;

    pthread_mutex_lock(&g_psi_cache_mutex);
    for (int i = 0; i < MAX_PSI_CACHE; i++) {
        if (g_psi_cache[i].service_id == client->service_id) {
            if (g_psi_cache[i].has_pat) {
                memcpy(client->buffer + client->write_pos, g_psi_cache[i].pat_pkt, 188);
                client->write_pos = (client->write_pos + 188) % client->capacity;
                client->available += 188;
            }
            if (g_psi_cache[i].has_pmt) {
                memcpy(client->buffer + client->write_pos, g_psi_cache[i].pmt_pkt, 188);
                client->write_pos = (client->write_pos + 188) % client->capacity;
                client->available += 188;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_psi_cache_mutex);
}

/* --------------------------------------------------------------------------
 * Secondary Adapter UDP Multicast Relay Worker
 * -------------------------------------------------------------------------- */
static void *udp_relay_worker(void *arg) {
    udp_relay_node_t *r = (udp_relay_node_t *)arg;
    uint8_t buf[65536];

    while (r->running) {
        ssize_t n = recv(r->sock_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (!r->running) break;
            usleep(2000);
            continue;
        }

        /* Detect TS offset (Raw UDP: offset 0, RTP: offset 12, or scan for 0x47) */
        ssize_t offset = -1;
        if (n >= 188 && buf[0] == 0x47 && (n % 188) == 0) {
            offset = 0;
        } else if (n >= 200 && buf[12] == 0x47 && ((n - 12) % 188) == 0) {
            offset = 12;
        } else {
            for (ssize_t k = 0; k < 64 && k + 188 <= n; k++) {
                if (buf[k] == 0x47 && ((n - k) % 188) == 0) {
                    offset = k;
                    break;
                }
            }
        }

        if (offset >= 0) {
            for (ssize_t i = offset; i + 188 <= n; i += 188) {
                if (buf[i] == 0x47) {
                    http_play_push_packet(r->service_id, buf + i, 188);
                }
            }
        }
    }
    return NULL;
}

static void relay_subscribe(uint16_t sid, const char *ip, int port) {
    if (!ip || !*ip || port <= 0 || sid == 0) return;

    pthread_mutex_lock(&g_relay_mutex);
    udp_relay_node_t *r = g_relay_list;
    while (r) {
        if (r->service_id == sid) {
            r->refcount++;
            pthread_mutex_unlock(&g_relay_mutex);
            return;
        }
        r = r->next;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        pthread_mutex_unlock(&g_relay_mutex);
        return;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = inet_addr(ip);
    bind_addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            close(fd);
            pthread_mutex_unlock(&g_relay_mutex);
            return;
        }
    }

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        close(fd);
        pthread_mutex_unlock(&g_relay_mutex);
        return;
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    r = calloc(1, sizeof(udp_relay_node_t));
    if (!r) {
        close(fd);
        pthread_mutex_unlock(&g_relay_mutex);
        return;
    }

    r->service_id = sid;
    snprintf(r->ip, sizeof(r->ip), "%s", ip);
    r->port = port;
    r->refcount = 1;
    r->sock_fd = fd;
    r->running = true;

    pthread_create(&r->thread, NULL, udp_relay_worker, r);

    r->next = g_relay_list;
    g_relay_list = r;
    pthread_mutex_unlock(&g_relay_mutex);
}

static void relay_unsubscribe(uint16_t sid) {
    if (sid == 0) return;

    pthread_mutex_lock(&g_relay_mutex);
    udp_relay_node_t **curr = &g_relay_list;
    while (*curr) {
        if ((*curr)->service_id == sid) {
            (*curr)->refcount--;
            if ((*curr)->refcount <= 0) {
                udp_relay_node_t *victim = *curr;
                *curr = victim->next;
                victim->running = false;
                pthread_mutex_unlock(&g_relay_mutex);

                shutdown(victim->sock_fd, SHUT_RDWR);
                close(victim->sock_fd);
                pthread_join(victim->thread, NULL);
                free(victim);
                return;
            }
            break;
        }
        curr = &(*curr)->next;
    }
    pthread_mutex_unlock(&g_relay_mutex);
}

/* --------------------------------------------------------------------------
 * Lifecycle & Configuration
 * -------------------------------------------------------------------------- */
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

    /* Clean up any running relays */
    pthread_mutex_lock(&g_relay_mutex);
    udp_relay_node_t *r = g_relay_list;
    while (r) {
        udp_relay_node_t *next = r->next;
        r->running = false;
        shutdown(r->sock_fd, SHUT_RDWR);
        close(r->sock_fd);
        pthread_join(r->thread, NULL);
        free(r);
        r = next;
    }
    g_relay_list = NULL;
    pthread_mutex_unlock(&g_relay_mutex);

    pthread_mutex_lock(&g_psi_cache_mutex);
    memset(g_psi_cache, 0, sizeof(g_psi_cache));
    pthread_mutex_unlock(&g_psi_cache_mutex);
}

void http_play_cleanup(void) {
    http_play_init();
}

void http_play_configure(const http_play_config_t *cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&g_clients_mutex);
    g_cfg.enabled = cfg->enabled;
    if (cfg->port >= 0 && cfg->port <= 65535) g_cfg.port = cfg->port;
    if (cfg->playlist_name[0]) snprintf(g_cfg.playlist_name, sizeof(g_cfg.playlist_name), "%s", cfg->playlist_name);
    if (cfg->buffer_kb >= 128 && cfg->buffer_kb <= 32768) g_cfg.buffer_kb = cfg->buffer_kb;
    if (cfg->max_clients >= 1 && cfg->max_clients <= 512) g_cfg.max_clients = cfg->max_clients;
    if (cfg->m3u_header[0]) snprintf(g_cfg.m3u_header, sizeof(g_cfg.m3u_header), "%s", cfg->m3u_header);
    if (cfg->xspf_title[0]) snprintf(g_cfg.xspf_title, sizeof(g_cfg.xspf_title), "%s", cfg->xspf_title);
    if (cfg->tv_logos_path[0]) snprintf(g_cfg.tv_logos_path, sizeof(g_cfg.tv_logos_path), "%s", cfg->tv_logos_path);
    g_cfg.allow_http = cfg->allow_http;
    g_cfg.allow_hls = cfg->allow_hls;
    g_cfg.disable_tls = cfg->disable_tls;
    pthread_mutex_unlock(&g_clients_mutex);
}

http_play_config_t http_play_get_config(void) {
    pthread_mutex_lock(&g_clients_mutex);
    http_play_config_t copy = g_cfg;
    pthread_mutex_unlock(&g_clients_mutex);
    return copy;
}

/* --------------------------------------------------------------------------
 * TS Packet Push (Ring Buffer)
 * -------------------------------------------------------------------------- */
void http_play_push_packet(uint16_t sid, const uint8_t *ts_packet, size_t len) {
    if (!g_cfg.enabled || !ts_packet || len == 0) return;

    /* Update PSI cache */
    for (size_t i = 0; i + 188 <= len; i += 188) {
        const uint8_t *pkt = ts_packet + i;
        if (pkt[0] == 0x47) {
            uint16_t pid = ((pkt[1] & 0x1F) << 8) | pkt[2];
            update_psi_cache(sid, pkt, pid);
        }
    }

    if (g_cfg.active_clients <= 0) return;

    pthread_mutex_lock(&g_clients_mutex);
    http_client_node_t *c = g_client_list;
    while (c) {
        if (c->active && (c->service_id == 0 || c->service_id == sid)) {
            pthread_mutex_lock(&c->lock);

            /* If buffer is full, drop a clean 188-byte aligned block (~128KB) */
            if (c->available + len > c->capacity) {
                size_t drop = (131072 / 188) * 188;
                if (drop > c->available) drop = (c->available / 188) * 188;
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

/* --------------------------------------------------------------------------
 * MHD Content Reader Callback
 * -------------------------------------------------------------------------- */
static ssize_t http_play_content_reader(void *cls, uint64_t pos, char *buf, size_t max) {
    (void)pos;
    http_client_node_t *client = (http_client_node_t *)cls;
    if (!client || !client->active) {
        return MHD_CONTENT_READER_END_OF_STREAM;
    }

    pthread_mutex_lock(&client->lock);

    /* Wait with timedwait until data is available or client becomes inactive */
    while (client->available == 0 && client->active) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000; /* 100ms timeout */
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&client->cond, &client->lock, &ts);
    }

    if (!client->active) {
        pthread_mutex_unlock(&client->lock);
        return MHD_CONTENT_READER_END_OF_STREAM;
    }

    size_t to_read = client->available < max ? client->available : max;
    /* Maintain 188-byte alignment if possible */
    if (to_read >= 188) {
        to_read = (to_read / 188) * 188;
    }

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
    pthread_mutex_unlock(&client->lock);

    __sync_fetch_and_add(&g_cfg.total_bytes_streamed, to_read);
    return (ssize_t)to_read;
}

static void http_play_free_client(void *cls) {
    http_client_node_t *client = (http_client_node_t *)cls;
    if (!client) return;

    /* Mark inactive and broadcast cond to unblock any waiting thread */
    pthread_mutex_lock(&client->lock);
    client->active = false;
    pthread_cond_broadcast(&client->cond);
    uint16_t sid = client->service_id;
    pthread_mutex_unlock(&client->lock);

    /* Unsubscribe relay if secondary adapter stream */
    relay_unsubscribe(sid);

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

/* --------------------------------------------------------------------------
 * M3U and XSPF Playlist Handlers
 * -------------------------------------------------------------------------- */
static enum MHD_Result check_arg_cb(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
    (void)kind;
    bool *flags = (bool *)cls; /* flags[0]=ts, flags[1]=hls, flags[2]=udp */
    if (key) {
        if (strcasecmp(key, "udp") == 0) flags[2] = true;
        else if (strcasecmp(key, "hls") == 0) flags[1] = true;
        else if (strcasecmp(key, "ts") == 0) flags[0] = true;
    }
    if (value) {
        if (strcasecmp(value, "udp") == 0) flags[2] = true;
        else if (strcasecmp(value, "hls") == 0) flags[1] = true;
        else if (strcasecmp(value, "ts") == 0) flags[0] = true;
    }
    return MHD_YES;
}

static int handle_playlist_m3u(struct MHD_Connection *conn, const char *host_header, bool is_m3u8) {
    char base_host[128];
    if (host_header && *host_header) {
        snprintf(base_host, sizeof(base_host), "%s", host_header);
    } else {
        snprintf(base_host, sizeof(base_host), "%s:%d",
                 g_gateway.http_host[0] ? g_gateway.http_host : "127.0.0.1",
                 g_cfg.port > 0 ? g_cfg.port : (g_gateway.http_port ? g_gateway.http_port : 8088));
    }

    /* Check format query params: ?ts, ?hls, ?udp */
    bool flags[3] = {false, false, false};
    MHD_get_connection_values(conn, MHD_GET_ARGUMENT_KIND, check_arg_cb, flags);
    bool mode_hls = flags[1];
    bool mode_udp = flags[2];

    size_t alloc_sz = 16384;
    char *buf = malloc(alloc_sz);
    if (!buf) return MHD_NO;

    int offset = snprintf(buf, alloc_sz,
        "#EXTM3U url-tvg=\"http://%s/epg.xml\" x-tvg-url=\"http://%s/epg.xml\"%s%s\n#EXT-X-VERSION:3\n\n",
        base_host, base_host,
        g_cfg.m3u_header[0] ? " " : "",
        g_cfg.m3u_header[0] ? g_cfg.m3u_header : "");

    pthread_mutex_lock(&g_gateway.lock);
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        if (!s->enabled) continue;

        web_adapter_t *ad = web_state_find_adapter_by_idx(s->adapter_idx);
        const char *group = ad ? ad->name : "DVBlast";

        char stream_url[256];
        if (mode_udp) {
            snprintf(stream_url, sizeof(stream_url), "udp://@%s:%d", s->ip, s->port);
        } else if (mode_hls) {
            snprintf(stream_url, sizeof(stream_url), "http://%s/hls/%s/index.m3u8", base_host, s->id);
        } else {
            snprintf(stream_url, sizeof(stream_url), "http://%s/play/%s", base_host, s->id);
        }

        char line[512];
        int n = snprintf(line, sizeof(line),
            "#EXTINF:-1 tvg-id=\"%s\" tvg-name=\"%s\" tvg-chno=\"%u\" group-title=\"%s\",%s\n%s\n\n",
            s->id, s->name, s->service_id, group, s->name, stream_url);

        if (offset + n >= (int)alloc_sz - 128) {
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
    MHD_add_response_header(resp, "Content-Type", is_m3u8 ? "application/vnd.apple.mpegurl; charset=utf-8" : "application/x-mpegurl; charset=utf-8");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Content-Disposition", is_m3u8 ? "inline; filename=\"playlist.m3u8\"" : "inline; filename=\"playlist.m3u\"");
    int ret = MHD_queue_response(conn, 200, resp);
    MHD_destroy_response(resp);
    return ret;
}

static int handle_playlist_xspf(struct MHD_Connection *conn, const char *host_header) {
    char base_host[128];
    if (host_header && *host_header) {
        snprintf(base_host, sizeof(base_host), "%s", host_header);
    } else {
        snprintf(base_host, sizeof(base_host), "%s:%d",
                 g_gateway.http_host[0] ? g_gateway.http_host : "127.0.0.1",
                 g_cfg.port > 0 ? g_cfg.port : (g_gateway.http_port ? g_gateway.http_port : 8088));
    }

    size_t alloc_sz = 16384;
    char *buf = malloc(alloc_sz);
    if (!buf) return MHD_NO;

    int offset = snprintf(buf, alloc_sz,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<playlist version=\"1\" xmlns=\"http://xspf.org/ns/0/\" xmlns:vlc=\"http://www.videolan.org/vlc/playlist/0\">\n"
        "  <title>%s</title>\n"
        "  <trackList>\n",
        g_cfg.xspf_title[0] ? g_cfg.xspf_title : "DVBlast Live Streams");

    pthread_mutex_lock(&g_gateway.lock);
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        if (!s->enabled) continue;

        char track[512];
        int n = snprintf(track, sizeof(track),
            "    <track>\n"
            "      <title>%s</title>\n"
            "      <location>http://%s/play/%s</location>\n"
            "      <extension application=\"http://www.videolan.org/vlc/playlist/0\">\n"
            "        <vlc:id>%u</vlc:id>\n"
            "        <vlc:option>network-caching=1000</vlc:option>\n"
            "      </extension>\n"
            "    </track>\n",
            s->name, base_host, s->id, s->service_id);

        if (offset + n >= (int)alloc_sz - 128) {
            alloc_sz *= 2;
            char *newbuf = realloc(buf, alloc_sz);
            if (!newbuf) break;
            buf = newbuf;
        }
        memcpy(buf + offset, track, n);
        offset += n;
    }
    pthread_mutex_unlock(&g_gateway.lock);

    int end_n = snprintf(buf + offset, alloc_sz - offset, "  </trackList>\n</playlist>\n");
    offset += end_n;

    struct MHD_Response *resp = MHD_create_response_from_buffer(offset, buf, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(buf);
        return MHD_NO;
    }
    MHD_add_response_header(resp, "Content-Type", "application/xspf+xml; charset=utf-8");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Content-Disposition", "inline; filename=\"playlist.xspf\"");
    int ret = MHD_queue_response(conn, 200, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* --------------------------------------------------------------------------
 * Main HTTP Play Request Router
 * -------------------------------------------------------------------------- */
int http_play_handle_request(struct MHD_Connection *conn, const char *url, const char *host_header) {
    if (!g_cfg.enabled) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(23, "HTTP Play is disabled\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 503, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* 1. M3U / M3U8 Playlists */
    if (strcmp(url, "/playlist.m3u") == 0 ||
        strcmp(url, "/playlist.m3u8") == 0 ||
        strcmp(url, "/api/v1/http_play/playlist.m3u") == 0 ||
        strcmp(url, "/api/v1/http_play/playlist.m3u8") == 0 ||
        strstr(url, ".m3u8") != NULL ||
        strstr(url, ".m3u") != NULL) {
        bool is_m3u8 = (strstr(url, ".m3u8") != NULL);
        return handle_playlist_m3u(conn, host_header, is_m3u8);
    }

    /* 2. XSPF Playlist */
    if (strcmp(url, "/playlist.xspf") == 0 ||
        strcmp(url, "/api/v1/http_play/playlist.xspf") == 0 ||
        strstr(url, ".xspf") != NULL) {
        return handle_playlist_xspf(conn, host_header);
    }

    /* 3. Extract stream_id or service_id from /play/{id} or /live/{sid} */
    char stream_id[64] = {0};
    uint16_t service_id = 0;

    if (strncmp(url, "/play/", 6) == 0 || strncmp(url, "/live/", 6) == 0) {
        snprintf(stream_id, sizeof(stream_id), "%s", url + 6);
        char *q = strchr(stream_id, '?');
        if (q) *q = '\0';
        char *dot = strstr(stream_id, ".ts");
        if (dot) *dot = '\0';

        /* If numeric SID given (e.g. 30266) */
        int parsed_num = atoi(stream_id);
        if (parsed_num > 0 && strncmp(stream_id, "spts_", 5) != 0) {
            service_id = (uint16_t)parsed_num;
        }
    } else {
        return MHD_NO;
    }

    /* Verify stream exists in gateway */
    pthread_mutex_lock(&g_gateway.lock);
    bool found = false;
    web_stream_config_t matched_stream;
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        if (stream_id[0] && strcmp(s->id, stream_id) == 0) {
            matched_stream = *s;
            service_id = s->service_id;
            found = true;
            break;
        }
        if (service_id != 0 && s->service_id == service_id) {
            matched_stream = *s;
            snprintf(stream_id, sizeof(stream_id), "%s", s->id);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_gateway.lock);

    if (found && !matched_stream.enabled) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(20, "Stream is disabled\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 503, resp);
        MHD_destroy_response(resp);
        return ret;
    }

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

    /* Capture client remote IP address */
    const union MHD_ConnectionInfo *ci = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (ci && ci->client_addr) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ci->client_addr;
        inet_ntop(AF_INET, &sin->sin_addr, client->remote_ip, sizeof(client->remote_ip));
    } else {
        snprintf(client->remote_ip, sizeof(client->remote_ip), "127.0.0.1");
    }

    client->active = true;
    client->connected_at = time(NULL);
    pthread_mutex_init(&client->lock, NULL);
    pthread_cond_init(&client->cond, NULL);

    /* Fast startup: inject cached PAT & PMT packets if available */
    inject_psi_preamble(client);

    /* If stream is on a secondary adapter (handled by isolated worker), subscribe UDP multicast relay */
    if (found && matched_stream.adapter_idx != i_adapter) {
        relay_subscribe(service_id, matched_stream.ip, matched_stream.port);
    }

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
    MHD_add_response_header(resp, "Accept-Ranges", "none");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Content-Disposition", "inline; filename=\"stream.ts\"");

    int ret = MHD_queue_response(conn, 200, resp);
    MHD_destroy_response(resp);
    return ret;
}

/* --------------------------------------------------------------------------
 * JSON Serialization & Deserialization
 * -------------------------------------------------------------------------- */
json_t *http_play_to_json(void) {
    pthread_mutex_lock(&g_clients_mutex);
    json_t *root = json_object();
    json_object_set_new(root, "enabled", g_cfg.enabled ? json_true() : json_false());
    json_object_set_new(root, "port", json_integer(g_cfg.port));
    json_object_set_new(root, "playlist_name", json_string(g_cfg.playlist_name));
    json_object_set_new(root, "buffer_kb", json_integer(g_cfg.buffer_kb));
    json_object_set_new(root, "max_clients", json_integer(g_cfg.max_clients));
    json_object_set_new(root, "m3u_header", json_string(g_cfg.m3u_header));
    json_object_set_new(root, "xspf_title", json_string(g_cfg.xspf_title));
    json_object_set_new(root, "tv_logos_path", json_string(g_cfg.tv_logos_path));
    json_object_set_new(root, "allow_http", g_cfg.allow_http ? json_true() : json_false());
    json_object_set_new(root, "allow_hls", g_cfg.allow_hls ? json_true() : json_false());
    json_object_set_new(root, "disable_tls", g_cfg.disable_tls ? json_true() : json_false());
    json_object_set_new(root, "active_clients", json_integer(g_cfg.active_clients));
    json_object_set_new(root, "total_clients_served", json_integer(g_cfg.total_clients_served));
    json_object_set_new(root, "total_bytes_streamed", json_integer(g_cfg.total_bytes_streamed));

    time_t now = time(NULL);
    json_t *clients_arr = json_array();
    http_client_node_t *c = g_client_list;
    while (c) {
        json_t *co = json_object();
        json_object_set_new(co, "id", json_integer(c->client_id));
        json_object_set_new(co, "stream_id", json_string(c->stream_id));
        json_object_set_new(co, "service_id", json_integer(c->service_id));
        json_object_set_new(co, "remote_ip", json_string(c->remote_ip[0] ? c->remote_ip : "127.0.0.1"));
        json_object_set_new(co, "connected_at", json_integer(c->connected_at));
        json_object_set_new(co, "uptime_sec", json_integer(now - c->connected_at));
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

    json_t *j_port = json_object_get(root, "port");
    if (j_port) g_cfg.port = (int)json_integer_value(j_port);

    json_t *j_name = json_object_get(root, "playlist_name");
    if (j_name && json_is_string(j_name)) {
        snprintf(g_cfg.playlist_name, sizeof(g_cfg.playlist_name), "%s", json_string_value(j_name));
    }

    json_t *j_buf = json_object_get(root, "buffer_kb");
    if (j_buf && json_integer_value(j_buf) >= 128) {
        g_cfg.buffer_kb = (int)json_integer_value(j_buf);
    }

    json_t *j_mc = json_object_get(root, "max_clients");
    if (j_mc && json_integer_value(j_mc) > 0) {
        g_cfg.max_clients = (int)json_integer_value(j_mc);
    }

    json_t *j_m3u = json_object_get(root, "m3u_header");
    if (j_m3u && json_is_string(j_m3u)) {
        snprintf(g_cfg.m3u_header, sizeof(g_cfg.m3u_header), "%s", json_string_value(j_m3u));
    }

    json_t *j_xspf = json_object_get(root, "xspf_title");
    if (j_xspf && json_is_string(j_xspf)) {
        snprintf(g_cfg.xspf_title, sizeof(g_cfg.xspf_title), "%s", json_string_value(j_xspf));
    }

    json_t *j_logos = json_object_get(root, "tv_logos_path");
    if (j_logos && json_is_string(j_logos)) {
        snprintf(g_cfg.tv_logos_path, sizeof(g_cfg.tv_logos_path), "%s", json_string_value(j_logos));
    }

    json_t *j_http = json_object_get(root, "allow_http");
    if (j_http) g_cfg.allow_http = json_is_true(j_http);

    json_t *j_hls = json_object_get(root, "allow_hls");
    if (j_hls) g_cfg.allow_hls = json_is_true(j_hls);

    json_t *j_tls = json_object_get(root, "disable_tls");
    if (j_tls) g_cfg.disable_tls = json_is_true(j_tls);

    pthread_mutex_unlock(&g_clients_mutex);
    return true;
}
