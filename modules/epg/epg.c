#include "epg.h"
#include "web_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include <bitstream/dvb/si/eit.h>
#include <bitstream/dvb/si/desc_4d.h>

static epg_config_t g_epg = {
    .enabled = true,
    .interval_sec = 60,
    .retention_hours = 24,
    .preferred_lang = "all",
    .total_events_cached = 0,
    .last_parse_time = 0
};

static epg_service_schedule_t g_services[EPG_MAX_SERVICES];
static int g_num_services = 0;
static pthread_mutex_t g_epg_mutex = PTHREAD_MUTEX_INITIALIZER;

static int bcd_to_dec(uint8_t bcd) {
    return ((bcd >> 4) * 10) + (bcd & 0x0F);
}

static time_t dvb_time_to_unix(const uint8_t *p) {
    if (!p) return 0;
    uint16_t mjd = (p[0] << 8) | p[1];
    if (mjd < 40587) return 0; /* Before Unix epoch 1970-01-01 */

    int hour = bcd_to_dec(p[2]);
    int min  = bcd_to_dec(p[3]);
    int sec  = bcd_to_dec(p[4]);

    if (hour > 23 || min > 59 || sec > 59) return 0;

    time_t t = (time_t)(mjd - 40587) * 86400;
    t += (hour * 3600) + (min * 60) + sec;
    return t;
}

static uint32_t dvb_duration_to_sec(uint32_t bcd) {
    uint8_t h = (bcd >> 16) & 0xFF;
    uint8_t m = (bcd >> 8) & 0xFF;
    uint8_t s = bcd & 0xFF;

    int hour = bcd_to_dec(h);
    int min  = bcd_to_dec(m);
    int sec  = bcd_to_dec(s);

    return (hour * 3600) + (min * 60) + sec;
}

void epg_init(void) {
    pthread_mutex_lock(&g_epg_mutex);
    memset(g_services, 0, sizeof(g_services));
    g_num_services = 0;
    g_epg.total_events_cached = 0;
    pthread_mutex_unlock(&g_epg_mutex);
}

void epg_cleanup(void) {
    epg_init();
}

void epg_configure(const epg_config_t *cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&g_epg_mutex);
    g_epg.enabled = cfg->enabled;
    if (cfg->interval_sec > 0) g_epg.interval_sec = cfg->interval_sec;
    if (cfg->retention_hours > 0) g_epg.retention_hours = cfg->retention_hours;
    if (cfg->preferred_lang[0]) snprintf(g_epg.preferred_lang, sizeof(g_epg.preferred_lang), "%s", cfg->preferred_lang);
    pthread_mutex_unlock(&g_epg_mutex);
}

epg_config_t epg_get_config(void) {
    pthread_mutex_lock(&g_epg_mutex);
    epg_config_t copy = g_epg;
    pthread_mutex_unlock(&g_epg_mutex);
    return copy;
}

static epg_service_schedule_t *find_or_add_service(uint16_t sid) {
    for (int i = 0; i < g_num_services; i++) {
        if (g_services[i].service_id == sid) {
            return &g_services[i];
        }
    }

    if (g_num_services >= EPG_MAX_SERVICES) {
        return NULL;
    }

    epg_service_schedule_t *s = &g_services[g_num_services++];
    s->service_id = sid;
    snprintf(s->channel_name, sizeof(s->channel_name), "Service %u", sid);
    s->num_events = 0;
    s->last_updated = time(NULL);

    /* Lookup friendly name from gateway streams */
    pthread_mutex_lock(&g_gateway.lock);
    for (int i = 0; i < g_gateway.num_streams; i++) {
        if (g_gateway.streams[i].service_id == sid) {
            snprintf(s->channel_name, sizeof(s->channel_name), "%s", g_gateway.streams[i].name);
            break;
        }
    }
    pthread_mutex_unlock(&g_gateway.lock);

    return s;
}

void epg_handle_eit_section(const uint8_t *p_eit, size_t length) {
    if (!g_epg.enabled || !p_eit || length < PSI_HEADER_SIZE) return;

    if (!eit_validate(p_eit)) return;

    uint16_t sid = eit_get_sid(p_eit);

    pthread_mutex_lock(&g_epg_mutex);
    epg_service_schedule_t *svc = find_or_add_service(sid);
    if (!svc) {
        pthread_mutex_unlock(&g_epg_mutex);
        return;
    }

    uint8_t n = 0;
    uint8_t *p_event;

    while ((p_event = eit_get_event((uint8_t *)p_eit, n++)) != NULL) {
        uint16_t event_id = eitn_get_event_id(p_event);
        uint64_t start_bcd = eitn_get_start_time(p_event);
        uint32_t dur_bcd = eitn_get_duration_bcd(p_event);

        uint8_t raw_time[5];
        raw_time[0] = (start_bcd >> 32) & 0xFF;
        raw_time[1] = (start_bcd >> 24) & 0xFF;
        raw_time[2] = (start_bcd >> 16) & 0xFF;
        raw_time[3] = (start_bcd >> 8) & 0xFF;
        raw_time[4] = start_bcd & 0xFF;

        time_t start_time = dvb_time_to_unix(raw_time);
        uint32_t dur_sec = dvb_duration_to_sec(dur_bcd);

        /* Parse descriptors to find Short Event Descriptor (0x4D) */
        char title[128] = {0};
        char desc[256] = {0};
        char lang[4] = {0};

        uint8_t *p_descs = eitn_get_descs(p_event);
        uint16_t descs_len = eitn_get_desclength(p_event);
        uint8_t *p_desc = p_descs;

        while (p_desc && (p_desc + DESC_HEADER_SIZE - p_descs <= descs_len)) {
            uint8_t tag = desc_get_tag(p_desc);
            uint8_t d_len = desc_get_length(p_desc);
            if (p_desc + DESC_HEADER_SIZE + d_len - p_descs > descs_len) break;

            if (tag == 0x4D && desc4d_validate(p_desc)) {
                const uint8_t *l = desc4d_get_lang(p_desc);
                if (l) snprintf(lang, sizeof(lang), "%c%c%c", l[0], l[1], l[2]);

                uint8_t name_len = 0;
                const uint8_t *p_name = desc4d_get_event_name(p_desc, &name_len);
                if (p_name && name_len > 0) {
                    size_t cpy = (size_t)name_len < sizeof(title) - 1 ? (size_t)name_len : sizeof(title) - 1;
                    memcpy(title, p_name, cpy);
                    title[cpy] = '\0';
                }

                uint8_t text_len = 0;
                const uint8_t *p_text = desc4d_get_text(p_desc, &text_len);
                if (p_text && text_len > 0) {
                    size_t cpy = (size_t)text_len < sizeof(desc) - 1 ? (size_t)text_len : sizeof(desc) - 1;
                    memcpy(desc, p_text, cpy);
                    desc[cpy] = '\0';
                }
                break;
            }
            p_desc += DESC_HEADER_SIZE + d_len;
        }

        if (!title[0]) {
            snprintf(title, sizeof(title), "Event #%u", event_id);
        }

        /* Check if event already exists in service schedule */
        int ev_idx = -1;
        for (int i = 0; i < svc->num_events; i++) {
            if (svc->events[i].event_id == event_id ||
                (start_time > 0 && svc->events[i].start_time == start_time)) {
                ev_idx = i;
                break;
            }
        }

        if (ev_idx < 0) {
            if (svc->num_events < EPG_MAX_EVENTS_PER_SERVICE) {
                ev_idx = svc->num_events++;
                g_epg.total_events_cached++;
            } else {
                /* Replace oldest event */
                ev_idx = 0;
            }
        }

        epg_event_t *ev = &svc->events[ev_idx];
        ev->event_id = event_id;
        ev->start_time = start_time;
        ev->duration_sec = dur_sec;
        snprintf(ev->title, sizeof(ev->title), "%s", title);
        snprintf(ev->description, sizeof(ev->description), "%s", desc);
        snprintf(ev->lang, sizeof(ev->lang), "%s", lang[0] ? lang : "eng");
        ev->running_status = eitn_get_running(p_event);
        ev->scrambled = eitn_get_ca(p_event);
    }

    svc->last_updated = time(NULL);
    g_epg.last_parse_time = time(NULL);
    pthread_mutex_unlock(&g_epg_mutex);
}

char *epg_generate_xmltv(void) {
    pthread_mutex_lock(&g_epg_mutex);
    size_t alloc_sz = 32768;
    char *buf = malloc(alloc_sz);
    if (!buf) {
        pthread_mutex_unlock(&g_epg_mutex);
        return NULL;
    }

    int offset = snprintf(buf, alloc_sz,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE tv SYSTEM \"xmltv.dtd\">\n"
        "<tv generator-info-name=\"DVBlast-Web-Gateway/2.0\">\n");

    /* Channel tags */
    for (int i = 0; i < g_num_services; i++) {
        epg_service_schedule_t *s = &g_services[i];
        char line[512];
        int n = snprintf(line, sizeof(line),
            "  <channel id=\"spts_%u\">\n    <display-name>%s</display-name>\n  </channel>\n",
            s->service_id, s->channel_name);
        if (offset + n >= (int)alloc_sz - 512) {
            alloc_sz *= 2;
            char *nb = realloc(buf, alloc_sz);
            if (!nb) break;
            buf = nb;
        }
        memcpy(buf + offset, line, n);
        offset += n;
    }

    /* Programme tags */
    for (int i = 0; i < g_num_services; i++) {
        epg_service_schedule_t *s = &g_services[i];
        for (int j = 0; j < s->num_events; j++) {
            epg_event_t *ev = &s->events[j];
            if (ev->start_time <= 0) continue;

            time_t stop_time = ev->start_time + (time_t)ev->duration_sec;
            struct tm tm_start, tm_stop;
            gmtime_r(&ev->start_time, &tm_start);
            gmtime_r(&stop_time, &tm_stop);

            char str_start[32], str_stop[32];
            strftime(str_start, sizeof(str_start), "%Y%m%d%H%M%S +0000", &tm_start);
            strftime(str_stop, sizeof(str_stop), "%Y%m%d%H%M%S +0000", &tm_stop);

            char line[1024];
            int n = snprintf(line, sizeof(line),
                "  <programme start=\"%s\" stop=\"%s\" channel=\"spts_%u\">\n"
                "    <title lang=\"%s\">%s</title>\n"
                "    <desc lang=\"%s\">%s</desc>\n"
                "  </programme>\n",
                str_start, str_stop, s->service_id,
                ev->lang, ev->title, ev->lang, ev->description);

            if (offset + n >= (int)alloc_sz - 512) {
                alloc_sz *= 2;
                char *nb = realloc(buf, alloc_sz);
                if (!nb) break;
                buf = nb;
            }
            memcpy(buf + offset, line, n);
            offset += n;
        }
    }

    int end_n = snprintf(buf + offset, alloc_sz - offset, "</tv>\n");
    offset += end_n;

    pthread_mutex_unlock(&g_epg_mutex);
    return buf;
}

int epg_handle_request(struct MHD_Connection *conn, const char *url) {
    if (strcmp(url, "/epg.xml") == 0 || strcmp(url, "/api/v1/epg/xmltv") == 0) {
        char *xml = epg_generate_xmltv();
        if (!xml) return MHD_NO;
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(xml), xml, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(resp, "Content-Type", "application/xml; charset=utf-8");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(resp, "Content-Disposition", "inline; filename=\"epg.xml\"");
        int ret = MHD_queue_response(conn, 200, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strcmp(url, "/api/v1/epg") == 0) {
        json_t *root = epg_to_json();
        char *s = json_dumps(root, JSON_INDENT(2));
        json_decref(root);
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(s), s, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(resp, "Content-Type", "application/json");
        MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
        int ret = MHD_queue_response(conn, 200, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    return MHD_NO;
}

json_t *epg_to_json(void) {
    pthread_mutex_lock(&g_epg_mutex);
    json_t *root = json_object();
    json_object_set_new(root, "enabled", g_epg.enabled ? json_true() : json_false());
    json_object_set_new(root, "interval_sec", json_integer(g_epg.interval_sec));
    json_object_set_new(root, "retention_hours", json_integer(g_epg.retention_hours));
    json_object_set_new(root, "preferred_lang", json_string(g_epg.preferred_lang));
    json_object_set_new(root, "total_events_cached", json_integer(g_epg.total_events_cached));
    json_object_set_new(root, "last_parse_time", json_integer(g_epg.last_parse_time));

    json_t *services_arr = json_array();
    for (int i = 0; i < g_num_services; i++) {
        epg_service_schedule_t *s = &g_services[i];
        json_t *so = json_object();
        json_object_set_new(so, "service_id", json_integer(s->service_id));
        json_object_set_new(so, "channel_name", json_string(s->channel_name));
        json_object_set_new(so, "last_updated", json_integer(s->last_updated));

        json_t *ev_arr = json_array();
        for (int j = 0; j < s->num_events; j++) {
            epg_event_t *ev = &s->events[j];
            json_t *eo = json_object();
            json_object_set_new(eo, "event_id", json_integer(ev->event_id));
            json_object_set_new(eo, "start_time", json_integer(ev->start_time));
            json_object_set_new(eo, "duration_sec", json_integer(ev->duration_sec));
            json_object_set_new(eo, "title", json_string(ev->title));
            json_object_set_new(eo, "description", json_string(ev->description));
            json_object_set_new(eo, "lang", json_string(ev->lang));
            json_object_set_new(eo, "scrambled", ev->scrambled ? json_true() : json_false());
            json_array_append_new(ev_arr, eo);
        }
        json_object_set_new(so, "events", ev_arr);
        json_array_append_new(services_arr, so);
    }
    json_object_set_new(root, "services", services_arr);

    pthread_mutex_unlock(&g_epg_mutex);
    return root;
}

bool epg_from_json(json_t *root) {
    if (!root || !json_is_object(root)) return false;

    pthread_mutex_lock(&g_epg_mutex);
    json_t *j_en = json_object_get(root, "enabled");
    if (j_en) g_epg.enabled = json_is_true(j_en);

    json_t *j_int = json_object_get(root, "interval_sec");
    if (j_int && json_integer_value(j_int) > 0) g_epg.interval_sec = (int)json_integer_value(j_int);

    json_t *j_ret = json_object_get(root, "retention_hours");
    if (j_ret && json_integer_value(j_ret) > 0) g_epg.retention_hours = (int)json_integer_value(j_ret);

    const char *pl = json_string_value(json_object_get(root, "preferred_lang"));
    if (pl && *pl) snprintf(g_epg.preferred_lang, sizeof(g_epg.preferred_lang), "%s", pl);

    pthread_mutex_unlock(&g_epg_mutex);
    return true;
}
