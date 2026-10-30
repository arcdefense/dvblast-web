#include "hls.h"
#include "web_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>

#define MAX_HLS_SEGMENTS 32
#define MAX_HLS_STREAMS  32

typedef struct {
    uint64_t sequence;
    double   duration;
    char     filename[64];
    char     filepath[512];
} hls_segment_item_t;

typedef struct {
    char               stream_id[32];
    uint16_t           service_id;
    bool               active;
    uint64_t           current_seq;
    struct timeval     seg_start_time;
    FILE              *current_fp;
    char               current_filename[64];
    char               current_filepath[512];
    
    hls_segment_item_t segments[MAX_HLS_SEGMENTS];
    int                seg_head;
    int                seg_count;
    pthread_mutex_t    lock;
} hls_stream_ctx_t;

static hls_config_t g_hls = {
    .enabled = false,
    .segment_sec = HLS_DEFAULT_SEGMENT_SEC,
    .window_size = HLS_DEFAULT_WINDOW_SIZE,
    .storage_path = HLS_DEFAULT_STORAGE_PATH,
    .total_segments_created = 0,
    .active_streams = 0
};

static hls_stream_ctx_t g_hls_streams[MAX_HLS_STREAMS];
static pthread_mutex_t  g_hls_mutex = PTHREAD_MUTEX_INITIALIZER;

static void ensure_dir(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

void hls_init(void) {
    pthread_mutex_lock(&g_hls_mutex);
    for (int i = 0; i < MAX_HLS_STREAMS; i++) {
        pthread_mutex_init(&g_hls_streams[i].lock, NULL);
        if (g_hls_streams[i].current_fp) {
            fclose(g_hls_streams[i].current_fp);
            g_hls_streams[i].current_fp = NULL;
        }
        g_hls_streams[i].active = false;
        g_hls_streams[i].seg_count = 0;
    }
    g_hls.active_streams = 0;
    pthread_mutex_unlock(&g_hls_mutex);
}

void hls_cleanup(void) {
    pthread_mutex_lock(&g_hls_mutex);
    for (int i = 0; i < MAX_HLS_STREAMS; i++) {
        if (g_hls_streams[i].current_fp) {
            fclose(g_hls_streams[i].current_fp);
            g_hls_streams[i].current_fp = NULL;
        }
        pthread_mutex_destroy(&g_hls_streams[i].lock);
    }
    pthread_mutex_unlock(&g_hls_mutex);
}

void hls_configure(const hls_config_t *cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&g_hls_mutex);
    g_hls.enabled = cfg->enabled;
    if (cfg->segment_sec >= 1 && cfg->segment_sec <= 10) g_hls.segment_sec = cfg->segment_sec;
    if (cfg->window_size >= 3 && cfg->window_size <= 20) g_hls.window_size = cfg->window_size;
    if (cfg->storage_path[0]) snprintf(g_hls.storage_path, sizeof(g_hls.storage_path), "%s", cfg->storage_path);
    if (g_hls.enabled) ensure_dir(g_hls.storage_path);
    pthread_mutex_unlock(&g_hls_mutex);
}

hls_config_t hls_get_config(void) {
    pthread_mutex_lock(&g_hls_mutex);
    hls_config_t copy = g_hls;
    pthread_mutex_unlock(&g_hls_mutex);
    return copy;
}

static hls_stream_ctx_t *find_or_create_stream(uint16_t sid) {
    for (int i = 0; i < MAX_HLS_STREAMS; i++) {
        if (g_hls_streams[i].active && g_hls_streams[i].service_id == sid) {
            return &g_hls_streams[i];
        }
    }

    for (int i = 0; i < MAX_HLS_STREAMS; i++) {
        if (!g_hls_streams[i].active) {
            hls_stream_ctx_t *ctx = &g_hls_streams[i];
            ctx->active = true;
            ctx->service_id = sid;
            snprintf(ctx->stream_id, sizeof(ctx->stream_id), "spts_%u", sid);
            ctx->current_seq = 1;
            ctx->current_fp = NULL;
            ctx->seg_count = 0;
            ctx->seg_head = 0;
            g_hls.active_streams++;
            return ctx;
        }
    }
    return NULL;
}

static void rotate_segment(hls_stream_ctx_t *ctx, double duration) {
    if (ctx->current_fp) {
        fclose(ctx->current_fp);
        ctx->current_fp = NULL;

        /* Store into ring */
        int idx = (ctx->seg_head + ctx->seg_count) % MAX_HLS_SEGMENTS;
        if (ctx->seg_count >= g_hls.window_size) {
            /* Remove oldest file */
            unlink(ctx->segments[ctx->seg_head].filepath);
            ctx->seg_head = (ctx->seg_head + 1) % MAX_HLS_SEGMENTS;
        } else {
            ctx->seg_count++;
        }

        hls_segment_item_t *item = &ctx->segments[idx];
        item->sequence = ctx->current_seq;
        item->duration = duration > 0.1 ? duration : (double)g_hls.segment_sec;
        snprintf(item->filename, sizeof(item->filename), "%s", ctx->current_filename);
        snprintf(item->filepath, sizeof(item->filepath), "%s", ctx->current_filepath);

        ctx->current_seq++;
        g_hls.total_segments_created++;
    }

    /* Start new segment */
    char stream_dir[300];
    snprintf(stream_dir, sizeof(stream_dir), "%s/%s", g_hls.storage_path, ctx->stream_id);
    ensure_dir(stream_dir);

    snprintf(ctx->current_filename, sizeof(ctx->current_filename), "segment_%lu.ts", (unsigned long)ctx->current_seq);
    snprintf(ctx->current_filepath, sizeof(ctx->current_filepath), "%s/%s", stream_dir, ctx->current_filename);

    ctx->current_fp = fopen(ctx->current_filepath, "wb");
    gettimeofday(&ctx->seg_start_time, NULL);
}

void hls_push_packet(uint16_t sid, const uint8_t *ts_packet, size_t len) {
    if (!g_hls.enabled || !ts_packet || len == 0) return;

    pthread_mutex_lock(&g_hls_mutex);
    hls_stream_ctx_t *ctx = find_or_create_stream(sid);
    if (!ctx) {
        pthread_mutex_unlock(&g_hls_mutex);
        return;
    }

    pthread_mutex_lock(&ctx->lock);
    pthread_mutex_unlock(&g_hls_mutex);

    struct timeval now;
    gettimeofday(&now, NULL);

    if (!ctx->current_fp) {
        rotate_segment(ctx, 0.0);
    } else {
        double elapsed = (now.tv_sec - ctx->seg_start_time.tv_sec) +
                         (now.tv_usec - ctx->seg_start_time.tv_usec) / 1000000.0;
        if (elapsed >= (double)g_hls.segment_sec) {
            rotate_segment(ctx, elapsed);
        }
    }

    if (ctx->current_fp) {
        fwrite(ts_packet, 1, len, ctx->current_fp);
    }

    pthread_mutex_unlock(&ctx->lock);
}

int hls_handle_request(struct MHD_Connection *conn, const char *url) {
    if (!g_hls.enabled) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(17, "HLS is disabled\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 503, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strncmp(url, "/hls/", 5) != 0) return MHD_NO;

    const char *p = url + 5;
    char stream_id[64] = {0};
    const char *slash = strchr(p, '/');
    if (!slash) return MHD_NO;

    int sid_len = (int)(slash - p);
    if (sid_len >= (int)sizeof(stream_id)) sid_len = sizeof(stream_id) - 1;
    strncpy(stream_id, p, sid_len);
    stream_id[sid_len] = '\0';
    const char *req_file = slash + 1;

    /* Find stream context */
    pthread_mutex_lock(&g_hls_mutex);
    hls_stream_ctx_t *ctx = NULL;
    for (int i = 0; i < MAX_HLS_STREAMS; i++) {
        if (g_hls_streams[i].active && strcmp(g_hls_streams[i].stream_id, stream_id) == 0) {
            ctx = &g_hls_streams[i];
            break;
        }
    }

    if (!ctx) {
        pthread_mutex_unlock(&g_hls_mutex);
        struct MHD_Response *resp = MHD_create_response_from_buffer(17, "Stream Not Found\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 404, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    pthread_mutex_lock(&ctx->lock);
    pthread_mutex_unlock(&g_hls_mutex);

    /* Playlist request: index.m3u8 */
    if (strcmp(req_file, "index.m3u8") == 0 || strcmp(req_file, "live.m3u8") == 0) {
        size_t alloc_sz = 4096;
        char *buf = malloc(alloc_sz);
        if (!buf) {
            pthread_mutex_unlock(&ctx->lock);
            return MHD_NO;
        }

        uint64_t first_seq = (ctx->seg_count > 0) ? ctx->segments[ctx->seg_head].sequence : 1;
        int target_dur = g_hls.segment_sec + 1;

        int offset = snprintf(buf, alloc_sz,
            "#EXTM3U\n"
            "#EXT-X-VERSION:3\n"
            "#EXT-X-TARGETDURATION:%d\n"
            "#EXT-X-MEDIA-SEQUENCE:%lu\n\n",
            target_dur, (unsigned long)first_seq);

        for (int i = 0; i < ctx->seg_count; i++) {
            int idx = (ctx->seg_head + i) % MAX_HLS_SEGMENTS;
            hls_segment_item_t *item = &ctx->segments[idx];
            char line[256];
            int n = snprintf(line, sizeof(line), "#EXTINF:%.3f,\n%s\n", item->duration, item->filename);
            if (offset + n >= (int)alloc_sz - 64) {
                alloc_sz *= 2;
                char *newbuf = realloc(buf, alloc_sz);
                if (!newbuf) break;
                buf = newbuf;
            }
            memcpy(buf + offset, line, n);
            offset += n;
        }

        pthread_mutex_unlock(&ctx->lock);

        struct MHD_Response *resp = MHD_create_response_from_buffer(offset, buf, MHD_RESPMEM_MUST_FREE);
        if (!resp) {
            free(buf);
            return MHD_NO;
        }
        MHD_add_response_header(resp, "Content-Type", "application/vnd.apple.mpegurl");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Cache-Control", "no-cache");
        int ret = MHD_queue_response(conn, 200, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* TS segment chunk file request */
    char fullpath[350];
    snprintf(fullpath, sizeof(fullpath), "%s/%s/%s", g_hls.storage_path, stream_id, req_file);
    pthread_mutex_unlock(&ctx->lock);

    FILE *fp = fopen(fullpath, "rb");
    if (!fp) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(18, "Segment Not Found\n", MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(conn, 404, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *fbuf = malloc(fsize > 0 ? fsize : 1);
    if (!fbuf) {
        fclose(fp);
        return MHD_NO;
    }

    size_t rd = fread(fbuf, 1, fsize, fp);
    fclose(fp);

    struct MHD_Response *resp = MHD_create_response_from_buffer(rd, fbuf, MHD_RESPMEM_MUST_FREE);
    if (!resp) {
        free(fbuf);
        return MHD_NO;
    }

    MHD_add_response_header(resp, "Content-Type", "video/mp2t");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    int ret = MHD_queue_response(conn, 200, resp);
    MHD_destroy_response(resp);
    return ret;
}

json_t *hls_to_json(void) {
    pthread_mutex_lock(&g_hls_mutex);
    json_t *root = json_object();
    json_object_set_new(root, "enabled", g_hls.enabled ? json_true() : json_false());
    json_object_set_new(root, "segment_sec", json_integer(g_hls.segment_sec));
    json_object_set_new(root, "window_size", json_integer(g_hls.window_size));
    json_object_set_new(root, "storage_path", json_string(g_hls.storage_path));
    json_object_set_new(root, "total_segments_created", json_integer(g_hls.total_segments_created));
    json_object_set_new(root, "active_streams", json_integer(g_hls.active_streams));
    pthread_mutex_unlock(&g_hls_mutex);
    return root;
}

bool hls_from_json(json_t *root) {
    if (!root || !json_is_object(root)) return false;

    pthread_mutex_lock(&g_hls_mutex);
    json_t *j_en = json_object_get(root, "enabled");
    if (j_en) g_hls.enabled = json_is_true(j_en);

    json_t *j_sec = json_object_get(root, "segment_sec");
    if (j_sec && json_integer_value(j_sec) >= 1) g_hls.segment_sec = (int)json_integer_value(j_sec);

    json_t *j_win = json_object_get(root, "window_size");
    if (j_win && json_integer_value(j_win) >= 3) g_hls.window_size = (int)json_integer_value(j_win);

    const char *sp = json_string_value(json_object_get(root, "storage_path"));
    if (sp && *sp) snprintf(g_hls.storage_path, sizeof(g_hls.storage_path), "%s", sp);

    if (g_hls.enabled) ensure_dir(g_hls.storage_path);
    pthread_mutex_unlock(&g_hls_mutex);
    return true;
}
