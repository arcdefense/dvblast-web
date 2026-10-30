#ifndef MODULES_HTTP_PLAY_H
#define MODULES_HTTP_PLAY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <microhttpd.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HTTP_PLAY_MAX_CLIENTS 64
#define HTTP_PLAY_DEFAULT_BUF_KB 1024

typedef struct {
    bool     enabled;
    int      port;                    /* Custom HTTP Play port (0 = inherit main port) */
    char     playlist_name[64];       /* Custom playlist name, default: "playlist" */
    int      buffer_kb;               /* Ring buffer size in KB, default: 2048 */
    int      max_clients;             /* Max concurrent clients, default: 64 */
    char     m3u_header[256];         /* Custom M3U header params */
    char     xspf_title[128];         /* XSPF playlist title */
    char     tv_logos_path[256];      /* Path to channel logos */
    bool     allow_http;              /* Allow HTTP TS streaming */
    bool     allow_hls;               /* Allow HLS streaming */
    bool     disable_tls;             /* Disable TLS on playlist links */
    int      active_clients;
    uint64_t total_clients_served;
    uint64_t total_bytes_streamed;
} http_play_config_t;

void http_play_init(void);
void http_play_cleanup(void);

void http_play_configure(const http_play_config_t *cfg);
http_play_config_t http_play_get_config(void);

/* Push a demuxed TS packet (188 bytes) to active HTTP streaming clients */
void http_play_push_packet(uint16_t sid, const uint8_t *ts_packet, size_t len);

/* Handle incoming HTTP request: /play/{stream_id}, /live/{sid}.ts, /playlist.m3u */
int  http_play_handle_request(struct MHD_Connection *conn, const char *url, const char *host_header);

json_t *http_play_to_json(void);
bool    http_play_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_HTTP_PLAY_H */
