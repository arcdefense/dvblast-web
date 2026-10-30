#ifndef DVBLAST_WEB_STATE_H
#define DVBLAST_WEB_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <jansson.h>
#include <pthread.h>

#define MAX_DISCOVERED_CHANNELS 128
#define MAX_WEB_STREAMS         128
#define MAX_AUDIO_PIDS          16
#define MAX_LOG_ENTRIES         256
#define LOG_MSG_MAX             256

/* Log entry structure */
typedef struct {
    uint64_t id;
    time_t timestamp;
    char level[12];     /* "INFO", "WARN", "ERROR", "DEBUG" */
    char message[LOG_MSG_MAX];
} web_log_entry_t;

/* Discovered channel structure */
typedef struct {
    uint16_t service_id;
    char name[128];
    char provider[128];
    uint16_t pmt_pid;
    uint16_t video_pid;
    uint8_t  video_type;   /* 0x02 = MPEG-2, 0x1B = H.264, 0x24 = HEVC, etc. */
    uint16_t audio_pids[MAX_AUDIO_PIDS];
    uint8_t  audio_types[MAX_AUDIO_PIDS];
    int      num_audio_pids;
    bool     scrambled;
    uint32_t bitrate_bps;
    uint64_t packet_count;
    time_t   last_seen;
} channel_info_t;

/* Stream output configuration */
typedef struct {
    char     id[64];
    char     name[128];
    bool     enabled;
    uint16_t service_id;        /* 0 = all/passthrough */
    char     ip[64];            /* Multicast / Unicast target IP */
    int      port;
    char     iface[64];         /* Output interface IP or name */
    int      ttl;
    bool     is_rtp;            /* false = raw UDP, true = RTP */
    bool     pacing;            /* Enable packet pacing */
    uint32_t bitrate_bps;       /* Configured/measured bitrate */
    uint64_t packets_sent;
    uint64_t bytes_sent;
    time_t   created_at;
} web_stream_config_t;

/* Tuner state and settings */
typedef struct {
    int      adapter;
    int      frontend;
    char     delsys[16];        /* "DVBT", "DVBT2", "DVBS", "DVBS2", "DVBC" */
    uint64_t frequency;         /* Hz */
    uint32_t symbol_rate;       /* S/s */
    int      bandwidth;         /* MHz (6, 7, 8) */
    char     polarization[4];   /* "V", "H", "13", "18" */
    int      voltage;
    int      tone;
    int      diseqc;
    char     lnb_type[32];      /* "universal", "c-band", etc. */
    char     modulation[16];    /* "qpsk", "psk_8", "16qam", etc. */
    int      multistream_id;    /* MIS ID */
    
    /* Live Tuner Signal Telemetry */
    bool     locked;
    uint16_t snr_raw;
    float    snr_db;
    uint16_t signal_percent;
    uint32_t ber;
    uint32_t ucb;
    time_t   last_status_time;
} tuner_state_t;

/* Global Gateway State */
typedef struct {
    pthread_mutex_t lock;
    
    /* Server Preferences */
    char     server_name[128];
    int      http_port;
    char     http_host[64];
    char     config_file[256];
    char     access_log[256];
    time_t   start_time;

    /* Telemetry */
    tuner_state_t tuner;
    uint64_t total_input_packets;
    uint64_t total_input_bytes;
    uint32_t input_bitrate_bps;
    time_t   last_bitrate_calc;
    uint64_t last_calc_bytes;

    /* Channels */
    channel_info_t channels[MAX_DISCOVERED_CHANNELS];
    int      num_channels;

    /* Multicast Output Streams */
    web_stream_config_t streams[MAX_WEB_STREAMS];
    int      num_streams;

    /* Log Ring Buffer */
    web_log_entry_t logs[MAX_LOG_ENTRIES];
    int      log_head;
    int      log_count;
    uint64_t next_log_id;
} gateway_state_t;

extern gateway_state_t g_gateway;

void web_state_init(int http_port, const char *http_host, const char *config_file);
void web_state_cleanup(void);

void web_state_log(const char *level, const char *fmt, ...);

/* Tuner & Telemetry */
void web_state_update_tuner(const tuner_state_t *tuner);
void web_state_update_input_stats(uint64_t bytes, uint64_t packets);
void web_state_calc_bitrates(void);

/* Channels */
void web_state_add_channel(const channel_info_t *ch);
void web_state_clear_channels(void);
channel_info_t *web_state_find_channel(uint16_t sid);

/* Streams */
bool web_state_add_or_update_stream(const web_stream_config_t *stream);
bool web_state_delete_stream(const char *id);
web_stream_config_t *web_state_find_stream(const char *id);

/* Persistence */
bool web_state_save_json(const char *path);
bool web_state_load_json(const char *path);

/* JSON Serializers for REST API */
json_t *web_state_telemetry_to_json(void);
json_t *web_state_tuners_to_json(void);
json_t *web_state_channels_to_json(void);
json_t *web_state_streams_to_json(void);
json_t *web_state_config_to_json(void);
json_t *web_state_logs_to_json(int max_entries);

#endif /* DVBLAST_WEB_STATE_H */
