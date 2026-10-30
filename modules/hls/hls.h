#ifndef MODULES_HLS_H
#define MODULES_HLS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <microhttpd.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HLS_DEFAULT_SEGMENT_SEC 3
#define HLS_DEFAULT_WINDOW_SIZE 5
#define HLS_DEFAULT_STORAGE_PATH "/dev/shm/hls"

typedef struct {
    bool     enabled;
    int      segment_sec;
    int      window_size;
    char     storage_path[128];
    uint64_t total_segments_created;
    int      active_streams;
} hls_config_t;

void hls_init(void);
void hls_cleanup(void);

void hls_configure(const hls_config_t *cfg);
hls_config_t hls_get_config(void);

/* Feed demuxed TS packet to active HLS segmenters */
void hls_push_packet(uint16_t sid, const uint8_t *ts_packet, size_t len);

/* Handle HTTP request for /hls/{stream_id}/index.m3u8 or chunk */
int  hls_handle_request(struct MHD_Connection *conn, const char *url);

json_t *hls_to_json(void);
bool    hls_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_HLS_H */
