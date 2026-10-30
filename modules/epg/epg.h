#ifndef MODULES_EPG_H
#define MODULES_EPG_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <microhttpd.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EPG_MAX_EVENTS_PER_SERVICE 64
#define EPG_MAX_SERVICES           64

typedef struct {
    uint16_t event_id;
    time_t   start_time;
    uint32_t duration_sec;
    char     title[128];
    char     description[256];
    char     lang[4];
    uint8_t  running_status;
    bool     scrambled;
} epg_event_t;

typedef struct {
    uint16_t    service_id;
    char        channel_name[128];
    epg_event_t events[EPG_MAX_EVENTS_PER_SERVICE];
    int         num_events;
    time_t      last_updated;
} epg_service_schedule_t;

typedef struct {
    bool     enabled;
    int      interval_sec;
    int      retention_hours;
    char     preferred_lang[8];
    int      total_events_cached;
    time_t   last_parse_time;
} epg_config_t;

void epg_init(void);
void epg_cleanup(void);

void epg_configure(const epg_config_t *cfg);
epg_config_t epg_get_config(void);

/* Process an assembled DVB EIT section (called from demux.c HandleEIT) */
void epg_handle_eit_section(const uint8_t *p_eit, size_t length);

/* Serve HTTP XMLTV or JSON schedule endpoints */
int  epg_handle_request(struct MHD_Connection *conn, const char *url);

/* Generate XMLTV format string (caller must free) */
char *epg_generate_xmltv(void);

json_t *epg_to_json(void);
bool    epg_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_EPG_H */
