#include "web_state.h"
#include "softcam_csa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>

gateway_state_t g_gateway;

void web_state_init(int http_port, const char *http_host, const char *config_file) {
    memset(&g_gateway, 0, sizeof(g_gateway));
    pthread_mutex_init(&g_gateway.lock, NULL);

    snprintf(g_gateway.server_name, sizeof(g_gateway.server_name), "DVBlast Web Gateway");
    g_gateway.http_port = (http_port > 0) ? http_port : 8088;
    snprintf(g_gateway.http_host, sizeof(g_gateway.http_host), "%s", (http_host && *http_host) ? http_host : "0.0.0.0");
    snprintf(g_gateway.config_file, sizeof(g_gateway.config_file), "%s", (config_file && *config_file) ? config_file : "dvblast.json");
    snprintf(g_gateway.access_log, sizeof(g_gateway.access_log), "/var/log/dvblast_web.log");
    g_gateway.start_time = time(NULL);
    g_gateway.last_bitrate_calc = g_gateway.start_time;

    /* Default tuner values */
    g_gateway.tuner.adapter = 0;
    g_gateway.tuner.frontend = 0;
    snprintf(g_gateway.tuner.delsys, sizeof(g_gateway.tuner.delsys), "DVBT2");
    g_gateway.tuner.bandwidth = 8;
    g_gateway.tuner.frequency = 698000000;
    g_gateway.tuner.symbol_rate = 27500000;
    snprintf(g_gateway.tuner.polarization, sizeof(g_gateway.tuner.polarization), "H");
    g_gateway.tuner.voltage = 18;

    web_state_log("INFO", "DVBlast Gateway State initialized on port %d", g_gateway.http_port);
}

void web_state_cleanup(void) {
    pthread_mutex_destroy(&g_gateway.lock);
}

void web_state_log(const char *level, const char *fmt, ...) {
    char buf[LOG_MSG_MAX];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    time_t now = time(NULL);

    pthread_mutex_lock(&g_gateway.lock);
    int idx = (g_gateway.log_head + g_gateway.log_count) % MAX_LOG_ENTRIES;
    if (g_gateway.log_count >= MAX_LOG_ENTRIES) {
        /* Overwrite oldest */
        g_gateway.log_head = (g_gateway.log_head + 1) % MAX_LOG_ENTRIES;
    } else {
        g_gateway.log_count++;
    }

    web_log_entry_t *entry = &g_gateway.logs[idx];
    entry->id = ++g_gateway.next_log_id;
    entry->timestamp = now;
    snprintf(entry->level, sizeof(entry->level), "%s", level ? level : "INFO");
    snprintf(entry->message, sizeof(entry->message), "%s", buf);
    pthread_mutex_unlock(&g_gateway.lock);

    /* Also print to stderr for console visibility */
    char timestr[32];
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(stderr, "[%s] [%s] %s\n", timestr, level ? level : "INFO", buf);
}

void web_state_update_tuner(const tuner_state_t *tuner) {
    if (!tuner) return;
    pthread_mutex_lock(&g_gateway.lock);
    g_gateway.tuner.locked = tuner->locked;
    g_gateway.tuner.snr_raw = tuner->snr_raw;
    g_gateway.tuner.snr_db = tuner->snr_db;
    g_gateway.tuner.signal_percent = tuner->signal_percent;
    g_gateway.tuner.ber = tuner->ber;
    g_gateway.tuner.ucb = tuner->ucb;
    g_gateway.tuner.last_status_time = time(NULL);
    if (tuner->frequency > 0) g_gateway.tuner.frequency = tuner->frequency;
    if (tuner->bandwidth > 0) g_gateway.tuner.bandwidth = tuner->bandwidth;
    if (tuner->symbol_rate > 0) g_gateway.tuner.symbol_rate = tuner->symbol_rate;
    if (tuner->delsys[0]) snprintf(g_gateway.tuner.delsys, sizeof(g_gateway.tuner.delsys), "%s", tuner->delsys);
    pthread_mutex_unlock(&g_gateway.lock);
}

void web_state_update_input_stats(uint64_t bytes, uint64_t packets) {
    pthread_mutex_lock(&g_gateway.lock);
    g_gateway.total_input_bytes += bytes;
    g_gateway.total_input_packets += packets;
    pthread_mutex_unlock(&g_gateway.lock);
}

void web_state_calc_bitrates(void) {
    pthread_mutex_lock(&g_gateway.lock);
    time_t now = time(NULL);
    double elapsed = difftime(now, g_gateway.last_bitrate_calc);
    if (elapsed >= 1.0) {
        uint64_t delta_bytes = g_gateway.total_input_bytes - g_gateway.last_calc_bytes;
        g_gateway.input_bitrate_bps = (uint32_t)((delta_bytes * 8) / elapsed);
        g_gateway.last_calc_bytes = g_gateway.total_input_bytes;
        g_gateway.last_bitrate_calc = now;
    }
    pthread_mutex_unlock(&g_gateway.lock);
}

void web_state_clear_channels(void) {
    pthread_mutex_lock(&g_gateway.lock);
    g_gateway.num_channels = 0;
    memset(g_gateway.channels, 0, sizeof(g_gateway.channels));
    pthread_mutex_unlock(&g_gateway.lock);
}

void web_state_add_channel(const channel_info_t *ch) {
    if (!ch || ch->service_id == 0) return;
    pthread_mutex_lock(&g_gateway.lock);

    channel_info_t *existing = NULL;
    for (int i = 0; i < g_gateway.num_channels; i++) {
        if (g_gateway.channels[i].service_id == ch->service_id) {
            existing = &g_gateway.channels[i];
            break;
        }
    }

    if (!existing) {
        if (g_gateway.num_channels < MAX_DISCOVERED_CHANNELS) {
            existing = &g_gateway.channels[g_gateway.num_channels++];
        } else {
            pthread_mutex_unlock(&g_gateway.lock);
            return;
        }
    }

    existing->service_id = ch->service_id;
    if (ch->name[0]) snprintf(existing->name, sizeof(existing->name), "%s", ch->name);
    else if (!existing->name[0]) snprintf(existing->name, sizeof(existing->name), "Service %u", ch->service_id);

    if (ch->provider[0]) snprintf(existing->provider, sizeof(existing->provider), "%s", ch->provider);
    if (ch->pmt_pid > 0) existing->pmt_pid = ch->pmt_pid;
    if (ch->video_pid > 0) existing->video_pid = ch->video_pid;
    if (ch->video_type > 0) existing->video_type = ch->video_type;
    if (ch->num_audio_pids > 0) {
        existing->num_audio_pids = ch->num_audio_pids;
        memcpy(existing->audio_pids, ch->audio_pids, sizeof(existing->audio_pids));
        memcpy(existing->audio_types, ch->audio_types, sizeof(existing->audio_types));
    }
    existing->scrambled = ch->scrambled;
    existing->last_seen = time(NULL);

    pthread_mutex_unlock(&g_gateway.lock);
}

channel_info_t *web_state_find_channel(uint16_t sid) {
    for (int i = 0; i < g_gateway.num_channels; i++) {
        if (g_gateway.channels[i].service_id == sid) return &g_gateway.channels[i];
    }
    return NULL;
}

bool web_state_add_or_update_stream(const web_stream_config_t *stream) {
    if (!stream || !stream->id[0] || !stream->ip[0] || stream->port <= 0) return false;
    pthread_mutex_lock(&g_gateway.lock);

    web_stream_config_t *target = NULL;
    for (int i = 0; i < g_gateway.num_streams; i++) {
        if (strcmp(g_gateway.streams[i].id, stream->id) == 0) {
            target = &g_gateway.streams[i];
            break;
        }
    }

    if (!target) {
        if (g_gateway.num_streams >= MAX_WEB_STREAMS) {
            pthread_mutex_unlock(&g_gateway.lock);
            return false;
        }
        target = &g_gateway.streams[g_gateway.num_streams++];
        target->created_at = time(NULL);
    }

    snprintf(target->id, sizeof(target->id), "%s", stream->id);
    snprintf(target->name, sizeof(target->name), "%s", stream->name[0] ? stream->name : stream->id);
    target->enabled = stream->enabled;
    target->service_id = stream->service_id;
    snprintf(target->ip, sizeof(target->ip), "%s", stream->ip);
    target->port = stream->port;
    snprintf(target->iface, sizeof(target->iface), "%s", stream->iface);
    target->ttl = (stream->ttl > 0) ? stream->ttl : 16;
    target->is_rtp = stream->is_rtp;
    target->pacing = stream->pacing;
    target->bitrate_bps = stream->bitrate_bps;

    pthread_mutex_unlock(&g_gateway.lock);
    web_state_log("INFO", "Stream %s (%s:%d, SID: %u) saved", target->id, target->ip, target->port, target->service_id);
    return true;
}

bool web_state_delete_stream(const char *id) {
    if (!id) return false;
    pthread_mutex_lock(&g_gateway.lock);

    int idx = -1;
    for (int i = 0; i < g_gateway.num_streams; i++) {
        if (strcmp(g_gateway.streams[i].id, id) == 0) {
            idx = i;
            break;
        }
    }

    if (idx >= 0) {
        for (int i = idx; i < g_gateway.num_streams - 1; i++) {
            g_gateway.streams[i] = g_gateway.streams[i + 1];
        }
        g_gateway.num_streams--;
        memset(&g_gateway.streams[g_gateway.num_streams], 0, sizeof(web_stream_config_t));
        pthread_mutex_unlock(&g_gateway.lock);
        web_state_log("INFO", "Stream %s deleted", id);
        return true;
    }

    pthread_mutex_unlock(&g_gateway.lock);
    return false;
}

web_stream_config_t *web_state_find_stream(const char *id) {
    if (!id) return NULL;
    for (int i = 0; i < g_gateway.num_streams; i++) {
        if (strcmp(g_gateway.streams[i].id, id) == 0) return &g_gateway.streams[i];
    }
    return NULL;
}

bool web_state_save_json(const char *path) {
    pthread_mutex_lock(&g_gateway.lock);
    const char *save_file = (path && *path) ? path : g_gateway.config_file;

    json_t *root = json_object();
    json_object_set_new(root, "version", json_string("DVBlast-Web-1.0"));
    json_object_set_new(root, "server_name", json_string(g_gateway.server_name));
    json_object_set_new(root, "http_port", json_integer(g_gateway.http_port));
    json_object_set_new(root, "http_host", json_string(g_gateway.http_host));

    /* Tuner section */
    json_t *tuner_obj = json_object();
    json_object_set_new(tuner_obj, "adapter", json_integer(g_gateway.tuner.adapter));
    json_object_set_new(tuner_obj, "frontend", json_integer(g_gateway.tuner.frontend));
    json_object_set_new(tuner_obj, "delsys", json_string(g_gateway.tuner.delsys));
    json_object_set_new(tuner_obj, "frequency", json_integer((json_int_t)g_gateway.tuner.frequency));
    json_object_set_new(tuner_obj, "symbol_rate", json_integer(g_gateway.tuner.symbol_rate));
    json_object_set_new(tuner_obj, "bandwidth", json_integer(g_gateway.tuner.bandwidth));
    json_object_set_new(tuner_obj, "polarization", json_string(g_gateway.tuner.polarization));
    json_object_set_new(tuner_obj, "voltage", json_integer(g_gateway.tuner.voltage));
    json_object_set_new(tuner_obj, "tone", json_integer(g_gateway.tuner.tone));
    json_object_set_new(tuner_obj, "diseqc", json_integer(g_gateway.tuner.diseqc));
    json_object_set_new(tuner_obj, "lnb_type", json_string(g_gateway.tuner.lnb_type));
    json_object_set_new(tuner_obj, "modulation", json_string(g_gateway.tuner.modulation));
    json_object_set_new(tuner_obj, "multistream_id", json_integer(g_gateway.tuner.multistream_id));
    json_object_set_new(root, "tuner", tuner_obj);

    /* Streams section */
    json_t *streams_arr = json_array();
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        json_t *s_obj = json_object();
        json_object_set_new(s_obj, "id", json_string(s->id));
        json_object_set_new(s_obj, "name", json_string(s->name));
        json_object_set_new(s_obj, "enabled", json_boolean(s->enabled));
        json_object_set_new(s_obj, "service_id", json_integer(s->service_id));
        json_object_set_new(s_obj, "ip", json_string(s->ip));
        json_object_set_new(s_obj, "port", json_integer(s->port));
        json_object_set_new(s_obj, "iface", json_string(s->iface));
        json_object_set_new(s_obj, "ttl", json_integer(s->ttl));
        json_object_set_new(s_obj, "is_rtp", json_boolean(s->is_rtp));
        json_object_set_new(s_obj, "pacing", json_boolean(s->pacing));
        json_object_set_new(s_obj, "bitrate_bps", json_integer(s->bitrate_bps));
        json_array_append_new(streams_arr, s_obj);
    }
    json_object_set_new(root, "streams", streams_arr);

    /* SoftCAM Keys */
    json_t *softcam_arr = softcam_csa_to_json();
    json_object_set_new(root, "descramble", softcam_arr);

    char tmp_path[300];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", save_file);
    int res = json_dump_file(root, tmp_path, JSON_INDENT(2) | JSON_PRESERVE_ORDER);
    json_decref(root);

    if (res == 0) {
        rename(tmp_path, save_file);
        pthread_mutex_unlock(&g_gateway.lock);
        web_state_log("INFO", "Configuration saved to %s", save_file);
        return true;
    }

    pthread_mutex_unlock(&g_gateway.lock);
    web_state_log("ERROR", "Failed to save configuration to %s", save_file);
    return false;
}

bool web_state_load_json(const char *path) {
    const char *load_file = (path && *path) ? path : g_gateway.config_file;
    json_error_t err;
    json_t *root = json_load_file(load_file, 0, &err);
    if (!root) {
        web_state_log("WARN", "Config file %s not loaded (%s)", load_file, err.text);
        return false;
    }

    pthread_mutex_lock(&g_gateway.lock);

    const char *s_name = json_string_value(json_object_get(root, "server_name"));
    if (s_name) snprintf(g_gateway.server_name, sizeof(g_gateway.server_name), "%s", s_name);

    json_t *t_obj = json_object_get(root, "tuner");
    if (json_is_object(t_obj)) {
        g_gateway.tuner.adapter = (int)json_integer_value(json_object_get(t_obj, "adapter"));
        g_gateway.tuner.frontend = (int)json_integer_value(json_object_get(t_obj, "frontend"));
        const char *del = json_string_value(json_object_get(t_obj, "delsys"));
        if (del) snprintf(g_gateway.tuner.delsys, sizeof(g_gateway.tuner.delsys), "%s", del);
        g_gateway.tuner.frequency = (uint64_t)json_integer_value(json_object_get(t_obj, "frequency"));
        g_gateway.tuner.symbol_rate = (uint32_t)json_integer_value(json_object_get(t_obj, "symbol_rate"));
        g_gateway.tuner.bandwidth = (int)json_integer_value(json_object_get(t_obj, "bandwidth"));
        const char *pol = json_string_value(json_object_get(t_obj, "polarization"));
        if (pol) snprintf(g_gateway.tuner.polarization, sizeof(g_gateway.tuner.polarization), "%s", pol);
        g_gateway.tuner.voltage = (int)json_integer_value(json_object_get(t_obj, "voltage"));
        g_gateway.tuner.tone = (int)json_integer_value(json_object_get(t_obj, "tone"));
        g_gateway.tuner.diseqc = (int)json_integer_value(json_object_get(t_obj, "diseqc"));
        const char *lnb = json_string_value(json_object_get(t_obj, "lnb_type"));
        if (lnb) snprintf(g_gateway.tuner.lnb_type, sizeof(g_gateway.tuner.lnb_type), "%s", lnb);
        const char *mod = json_string_value(json_object_get(t_obj, "modulation"));
        if (mod) snprintf(g_gateway.tuner.modulation, sizeof(g_gateway.tuner.modulation), "%s", mod);
        g_gateway.tuner.multistream_id = (int)json_integer_value(json_object_get(t_obj, "multistream_id"));
    }

    json_t *s_arr = json_object_get(root, "streams");
    if (json_is_array(s_arr)) {
        g_gateway.num_streams = 0;
        size_t idx;
        json_t *val;
        json_array_foreach(s_arr, idx, val) {
            if (g_gateway.num_streams >= MAX_WEB_STREAMS) break;
            web_stream_config_t *s = &g_gateway.streams[g_gateway.num_streams++];
            memset(s, 0, sizeof(*s));
            const char *id = json_string_value(json_object_get(val, "id"));
            const char *nm = json_string_value(json_object_get(val, "name"));
            const char *ip = json_string_value(json_object_get(val, "ip"));
            const char *ifc = json_string_value(json_object_get(val, "iface"));

            if (id) snprintf(s->id, sizeof(s->id), "%s", id);
            if (nm) snprintf(s->name, sizeof(s->name), "%s", nm);
            if (ip) snprintf(s->ip, sizeof(s->ip), "%s", ip);
            if (ifc) snprintf(s->iface, sizeof(s->iface), "%s", ifc);

            s->enabled = !json_is_false(json_object_get(val, "enabled"));
            s->service_id = (uint16_t)json_integer_value(json_object_get(val, "service_id"));
            s->port = (int)json_integer_value(json_object_get(val, "port"));
            s->ttl = (int)json_integer_value(json_object_get(val, "ttl"));
            if (s->ttl <= 0) s->ttl = 16;
            s->is_rtp = json_is_true(json_object_get(val, "is_rtp"));
            s->pacing = !json_is_false(json_object_get(val, "pacing"));
            s->bitrate_bps = (uint32_t)json_integer_value(json_object_get(val, "bitrate_bps"));
            s->created_at = time(NULL);
        }
    }

    json_t *desc = json_object_get(root, "descramble");
    if (json_is_array(desc)) {
        softcam_csa_from_json(desc);
    }

    pthread_mutex_unlock(&g_gateway.lock);
    json_decref(root);
    web_state_log("INFO", "Configuration successfully loaded from %s", load_file);
    return true;
}

json_t *web_state_telemetry_to_json(void) {
    web_state_calc_bitrates();
    pthread_mutex_lock(&g_gateway.lock);

    json_t *root = json_object();
    json_object_set_new(root, "server_name", json_string(g_gateway.server_name));
    json_object_set_new(root, "uptime_seconds", json_integer((json_int_t)(time(NULL) - g_gateway.start_time)));
    json_object_set_new(root, "total_input_bytes", json_integer((json_int_t)g_gateway.total_input_bytes));
    json_object_set_new(root, "total_input_packets", json_integer((json_int_t)g_gateway.total_input_packets));
    json_object_set_new(root, "input_bitrate_bps", json_integer(g_gateway.input_bitrate_bps));
    json_object_set_new(root, "input_bitrate_mbps", json_real((double)g_gateway.input_bitrate_bps / 1000000.0));
    json_object_set_new(root, "active_streams_count", json_integer(g_gateway.num_streams));
    json_object_set_new(root, "discovered_channels_count", json_integer(g_gateway.num_channels));

    /* Tuner signal telemetry */
    json_t *t = json_object();
    json_object_set_new(t, "adapter", json_integer(g_gateway.tuner.adapter));
    json_object_set_new(t, "frontend", json_integer(g_gateway.tuner.frontend));
    json_object_set_new(t, "delsys", json_string(g_gateway.tuner.delsys));
    json_object_set_new(t, "frequency_hz", json_integer((json_int_t)g_gateway.tuner.frequency));
    json_object_set_new(t, "frequency_mhz", json_real((double)g_gateway.tuner.frequency / 1000000.0));
    json_object_set_new(t, "symbol_rate", json_integer(g_gateway.tuner.symbol_rate));
    json_object_set_new(t, "bandwidth_mhz", json_integer(g_gateway.tuner.bandwidth));
    json_object_set_new(t, "polarization", json_string(g_gateway.tuner.polarization));
    json_object_set_new(t, "locked", json_boolean(g_gateway.tuner.locked));
    json_object_set_new(t, "snr_raw", json_integer(g_gateway.tuner.snr_raw));
    json_object_set_new(t, "snr_db", json_real((double)g_gateway.tuner.snr_db));
    json_object_set_new(t, "signal_percent", json_integer(g_gateway.tuner.signal_percent));
    json_object_set_new(t, "ber", json_integer(g_gateway.tuner.ber));
    json_object_set_new(t, "ucb", json_integer(g_gateway.tuner.ucb));
    json_object_set_new(root, "tuner", t);

    pthread_mutex_unlock(&g_gateway.lock);
    return root;
}

json_t *web_state_tuners_to_json(void) {
    json_t *arr = json_array();
    /* Detect /dev/dvb/adapter* */
    DIR *d = opendir("/dev/dvb");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strncmp(de->d_name, "adapter", 7) == 0) {
                int adapter_num = atoi(de->d_name + 7);
                char fe_path[512];
                snprintf(fe_path, sizeof(fe_path), "/dev/dvb/%s/frontend0", de->d_name);
                bool fe_exists = (access(fe_path, F_OK) == 0);

                json_t *item = json_object();
                json_object_set_new(item, "adapter", json_integer(adapter_num));
                json_object_set_new(item, "path", json_string(de->d_name));
                json_object_set_new(item, "frontend_path", json_string(fe_path));
                json_object_set_new(item, "available", json_boolean(fe_exists));
                json_object_set_new(item, "active", json_boolean(adapter_num == g_gateway.tuner.adapter));
                json_array_append_new(arr, item);
            }
        }
        closedir(d);
    }
    return arr;
}

json_t *web_state_channels_to_json(void) {
    pthread_mutex_lock(&g_gateway.lock);
    json_t *arr = json_array();
    for (int i = 0; i < g_gateway.num_channels; i++) {
        channel_info_t *c = &g_gateway.channels[i];
        json_t *obj = json_object();
        json_object_set_new(obj, "service_id", json_integer(c->service_id));
        json_object_set_new(obj, "name", json_string(c->name));
        json_object_set_new(obj, "provider", json_string(c->provider));
        json_object_set_new(obj, "pmt_pid", json_integer(c->pmt_pid));
        json_object_set_new(obj, "video_pid", json_integer(c->video_pid));
        json_object_set_new(obj, "video_type", json_integer(c->video_type));
        json_object_set_new(obj, "scrambled", json_boolean(c->scrambled));

        json_t *audio_arr = json_array();
        for (int a = 0; a < c->num_audio_pids; a++) {
            json_t *a_obj = json_object();
            json_object_set_new(a_obj, "pid", json_integer(c->audio_pids[a]));
            json_object_set_new(a_obj, "type", json_integer(c->audio_types[a]));
            json_array_append_new(audio_arr, a_obj);
        }
        json_object_set_new(obj, "audio_pids", audio_arr);

        /* Check if softcam key exists for this channel */
        const softcam_entry_t *k = softcam_csa_find(c->service_id);
        json_object_set_new(obj, "has_softcam_key", json_boolean(k != NULL));

        json_array_append_new(arr, obj);
    }
    pthread_mutex_unlock(&g_gateway.lock);
    return arr;
}

json_t *web_state_streams_to_json(void) {
    pthread_mutex_lock(&g_gateway.lock);
    json_t *arr = json_array();
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        json_t *obj = json_object();
        json_object_set_new(obj, "id", json_string(s->id));
        json_object_set_new(obj, "name", json_string(s->name));
        json_object_set_new(obj, "enabled", json_boolean(s->enabled));
        json_object_set_new(obj, "service_id", json_integer(s->service_id));
        json_object_set_new(obj, "ip", json_string(s->ip));
        json_object_set_new(obj, "port", json_integer(s->port));
        json_object_set_new(obj, "iface", json_string(s->iface));
        json_object_set_new(obj, "ttl", json_integer(s->ttl));
        json_object_set_new(obj, "is_rtp", json_boolean(s->is_rtp));
        json_object_set_new(obj, "pacing", json_boolean(s->pacing));
        json_object_set_new(obj, "bitrate_bps", json_integer(s->bitrate_bps));
        json_object_set_new(obj, "packets_sent", json_integer((json_int_t)s->packets_sent));
        json_object_set_new(obj, "bytes_sent", json_integer((json_int_t)s->bytes_sent));

        /* Channel name lookup */
        channel_info_t *ch = web_state_find_channel(s->service_id);
        if (ch) {
            json_object_set_new(obj, "channel_name", json_string(ch->name));
            json_object_set_new(obj, "channel_provider", json_string(ch->provider));
        } else {
            json_object_set_new(obj, "channel_name", json_string(s->service_id == 0 ? "Full Transponder (MPTS)" : ""));
        }

        json_array_append_new(arr, obj);
    }
    pthread_mutex_unlock(&g_gateway.lock);
    return arr;
}

json_t *web_state_config_to_json(void) {
    pthread_mutex_lock(&g_gateway.lock);
    json_t *root = json_object();
    json_object_set_new(root, "server_name", json_string(g_gateway.server_name));
    json_object_set_new(root, "http_port", json_integer(g_gateway.http_port));
    json_object_set_new(root, "http_host", json_string(g_gateway.http_host));
    json_object_set_new(root, "config_file", json_string(g_gateway.config_file));

    json_t *t = json_object();
    json_object_set_new(t, "adapter", json_integer(g_gateway.tuner.adapter));
    json_object_set_new(t, "frontend", json_integer(g_gateway.tuner.frontend));
    json_object_set_new(t, "delsys", json_string(g_gateway.tuner.delsys));
    json_object_set_new(t, "frequency", json_integer((json_int_t)g_gateway.tuner.frequency));
    json_object_set_new(t, "symbol_rate", json_integer(g_gateway.tuner.symbol_rate));
    json_object_set_new(t, "bandwidth", json_integer(g_gateway.tuner.bandwidth));
    json_object_set_new(t, "polarization", json_string(g_gateway.tuner.polarization));
    json_object_set_new(t, "voltage", json_integer(g_gateway.tuner.voltage));
    json_object_set_new(t, "tone", json_integer(g_gateway.tuner.tone));
    json_object_set_new(t, "diseqc", json_integer(g_gateway.tuner.diseqc));
    json_object_set_new(t, "lnb_type", json_string(g_gateway.tuner.lnb_type));
    json_object_set_new(t, "modulation", json_string(g_gateway.tuner.modulation));
    json_object_set_new(t, "multistream_id", json_integer(g_gateway.tuner.multistream_id));
    json_object_set_new(root, "tuner", t);

    json_t *s_arr = json_array();
    for (int i = 0; i < g_gateway.num_streams; i++) {
        web_stream_config_t *s = &g_gateway.streams[i];
        json_t *so = json_object();
        json_object_set_new(so, "id", json_string(s->id));
        json_object_set_new(so, "name", json_string(s->name));
        json_object_set_new(so, "enabled", json_boolean(s->enabled));
        json_object_set_new(so, "service_id", json_integer(s->service_id));
        json_object_set_new(so, "ip", json_string(s->ip));
        json_object_set_new(so, "port", json_integer(s->port));
        json_object_set_new(so, "iface", json_string(s->iface));
        json_object_set_new(so, "ttl", json_integer(s->ttl));
        json_object_set_new(so, "is_rtp", json_boolean(s->is_rtp));
        json_object_set_new(so, "pacing", json_boolean(s->pacing));
        json_object_set_new(so, "bitrate_bps", json_integer(s->bitrate_bps));
        json_array_append_new(s_arr, so);
    }
    json_object_set_new(root, "streams", s_arr);
    json_object_set_new(root, "descramble", softcam_csa_to_json());

    pthread_mutex_unlock(&g_gateway.lock);
    return root;
}

json_t *web_state_logs_to_json(int max_entries) {
    pthread_mutex_lock(&g_gateway.lock);
    json_t *arr = json_array();
    int count = (max_entries > 0 && max_entries < g_gateway.log_count) ? max_entries : g_gateway.log_count;
    int start_idx = (g_gateway.log_head + g_gateway.log_count - count + MAX_LOG_ENTRIES) % MAX_LOG_ENTRIES;

    for (int i = 0; i < count; i++) {
        int idx = (start_idx + i) % MAX_LOG_ENTRIES;
        web_log_entry_t *l = &g_gateway.logs[idx];
        json_t *obj = json_object();
        json_object_set_new(obj, "id", json_integer((json_int_t)l->id));
        json_object_set_new(obj, "timestamp", json_integer((json_int_t)l->timestamp));
        json_object_set_new(obj, "level", json_string(l->level));
        json_object_set_new(obj, "message", json_string(l->message));
        json_array_append_new(arr, obj);
    }
    pthread_mutex_unlock(&g_gateway.lock);
    return arr;
}
