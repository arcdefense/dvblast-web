#include "web_manager.h"
#include "dvblast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void demux_ExtractDiscoveredChannels(void);

bool web_manager_add_stream(const web_stream_config_t *stream) {
    if (!stream || !stream->ip[0] || stream->port <= 0) return false;

    char host_str[256];
    if (stream->is_rtp) {
        snprintf(host_str, sizeof(host_str), "%s:%d", stream->ip, stream->port);
    } else {
        snprintf(host_str, sizeof(host_str), "%s:%d/udp", stream->ip, stream->port);
    }

    output_config_t config;
    config_Defaults(&config);

    if (!config_ParseHost(&config, host_str)) {
        config_Free(&config);
        web_state_log("ERROR", "Failed to parse stream destination %s", host_str);
        return false;
    }

    config.i_sid = stream->service_id;
    if (stream->service_id == 0) {
        config.b_passthrough = true;
    }
    if (stream->ttl > 0) {
        config.i_ttl = stream->ttl;
    }
    config.i_config |= OUTPUT_WATCH | OUTPUT_VALID | OUTPUT_STILL_PRESENT;

    output_t *p_output = output_Find(&config);
    if (!p_output) {
        p_output = output_Create(&config);
    }

    if (p_output) {
        free(p_output->config.psz_displayname);
        p_output->config.psz_displayname = strdup(stream->name[0] ? stream->name : stream->id);
        p_output->b_pacing = stream->pacing;
        output_Change(p_output, &config);
        demux_Change(p_output, &config);
    }

    config_Free(&config);

    web_state_add_or_update_stream(stream);
    web_state_save_json(NULL);
    return (p_output != NULL);
}

bool web_manager_delete_stream(const char *id) {
    if (!id) return false;
    web_stream_config_t *s = web_state_find_stream(id);
    if (!s) return false;

    char host_str[256];
    snprintf(host_str, sizeof(host_str), "%s:%d", s->ip, s->port);
    output_config_t config;
    config_Defaults(&config);
    if (config_ParseHost(&config, host_str)) {
        config.i_sid = s->service_id;
        output_t *p_output = output_Find(&config);
        if (p_output) {
            output_config_t blank_config;
            config_Init(&blank_config);
            demux_Change(p_output, &blank_config);
            config_Free(&blank_config);

            output_Close(p_output);
        }
    }
    config_Free(&config);

    bool ok = web_state_delete_stream(id);
    web_state_save_json(NULL);
    return ok;
}

bool web_manager_tune(const tuner_state_t *tuner) {
    if (!tuner) return false;

    web_state_log("INFO", "Tuning frontend: Freq=%lu Hz, BW=%d MHz, Delsys=%s",
                  (unsigned long)tuner->frequency, tuner->bandwidth, tuner->delsys);

    i_frequency = (int)tuner->frequency;
    i_bandwidth = tuner->bandwidth;
    if (tuner->symbol_rate > 0) i_srate = (int)tuner->symbol_rate;
    if (tuner->delsys[0]) {
        free(psz_delsys);
        psz_delsys = strdup(tuner->delsys);
    }
    if (tuner->voltage > 0) i_voltage = tuner->voltage;
    i_satnum = tuner->diseqc;
    b_tone = tuner->tone;

    dvb_Reset();

    web_state_update_tuner(tuner);
    web_state_save_json(NULL);
    return true;
}

void web_manager_sync_outputs(void) {
    pthread_mutex_lock(&g_gateway.lock);
    int count = g_gateway.num_streams;
    web_stream_config_t streams_copy[MAX_WEB_STREAMS];
    memcpy(streams_copy, g_gateway.streams, count * sizeof(web_stream_config_t));
    pthread_mutex_unlock(&g_gateway.lock);

    for (int i = 0; i < count; i++) {
        if (streams_copy[i].enabled) {
            web_manager_add_stream(&streams_copy[i]);
        }
    }
}

void web_manager_trigger_scan(void) {
    web_state_log("INFO", "Transponder channel scan triggered");
    demux_ExtractDiscoveredChannels();
}
