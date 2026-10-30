#ifndef MODULES_GENERAL_H
#define MODULES_GENERAL_H

#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* Monitoring */
    char instance_name[64];
    char tsdb_url[128];
    char tsdb_org[64];
    char tsdb_token[128];
    int  tsdb_interval;
    char event_request[256];
    char sessions_url[256];
    int  sessions_time;

    /* HTTP Server */
    char http_server_name[64];
    char http_access_log[256];
    bool http_disable_sessions;
    char allow_real_ip[128];
    char crt_chain[256];
    char crt_key[256];
    bool http_disable_tls;
    int  control_port;
    char control_path[64];

    /* Stream defaults */
    char epg_export_format[16];   /* "xmltv" or "json" */
    char epg_export[256];
    bool http_keep_active_demand;
    int  http_keep_active;
    int  backup_start_delay;
    int  backup_return_delay;
    char textcode[32];
    char service_provider[64];
    char network_name[64];
    char http_congestion[32];
    int  cc_limit;
    bool udp_threads;

    /* Adapter defaults */
    bool dvb_bind_by_mac;
} general_config_t;

void general_init(void);
void general_cleanup(void);

void general_configure(const general_config_t *cfg);
general_config_t general_get_config(void);

json_t *general_to_json(void);
bool    general_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_GENERAL_H */
