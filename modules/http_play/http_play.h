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
    int      buffer_kb;
    int      max_clients;
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
