#include "web_manager.h"
#include "dvblast.h"
#include "softcam_csa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int i_frontend;
void demux_ExtractDiscoveredChannels(void);

/* ========================================================================= */
/*  ADAPTER MANAGEMENT                                                       */
/* ========================================================================= */

bool web_manager_tune_adapter(int adapter_idx) {
    web_adapter_t *ad = web_state_find_adapter_by_idx(adapter_idx);
    if (!ad) return false;

    web_state_log("INFO", "Tuning Adapter %d (%s): Freq=%llu Hz, BW=%d MHz, Delsys=%s",
                  ad->adapter_idx, ad->name, (unsigned long long)ad->frequency, ad->bandwidth, ad->delsys);

    i_adapter = ad->adapter_idx;
    i_fenum = ad->frontend_idx;
    i_frequency = (int)ad->frequency;
    i_bandwidth = ad->bandwidth;
    if (ad->symbol_rate > 0) i_srate = (int)ad->symbol_rate;
    if (ad->delsys[0]) {
        free(psz_delsys);
        psz_delsys = strdup(ad->delsys);
    }
    if (ad->voltage > 0) i_voltage = ad->voltage;
    i_satnum = ad->diseqc;
    b_tone = ad->tone;

    bool ok = dvb_TuneFrontend(ad->adapter_idx, ad->frontend_idx, ad->frequency,
                               ad->bandwidth, ad->delsys, ad->multistream_id,
                               ad->modulation, NULL, NULL, (int)ad->symbol_rate,
                               ad->voltage, ad->diseqc, ad->tone);
    if (ok) {
        demux_ExtractDiscoveredChannels();
    }
    return ok;
}

bool web_manager_add_adapter(const web_adapter_t *ad) {
    if (!ad || !ad->id[0]) return false;

    bool ok = web_state_add_or_update_adapter(ad);
    if (ok && ad->enabled) {
        web_manager_tune_adapter(ad->adapter_idx);
    }
    web_state_save_json(NULL);
    return ok;
}

bool web_manager_delete_adapter(const char *id) {
    if (!id || !*id) return false;

    web_adapter_t *ad = web_state_find_adapter(id);
    if (!ad) return false;

    if (i_adapter == ad->adapter_idx) {
        dvb_CloseDevices();
        i_frequency = 0;
    }

    bool ok = web_state_delete_adapter(id);
    web_state_save_json(NULL);
    return ok;
}

void web_manager_trigger_scan(int adapter_idx) {
    web_state_log("INFO", "Channel scan triggered for Adapter %d", adapter_idx);
    demux_ExtractDiscoveredChannels();
}

/* ========================================================================= */
/*  STREAM MANAGEMENT                                                        */
/* ========================================================================= */

bool web_manager_add_stream(const web_stream_config_t *stream) {
    if (!stream || !stream->ip[0] || stream->port <= 0) return false;

    /* Register SoftCAM BISS key if provided */
    if (stream->biss_key[0] && stream->service_id > 0) {
        softcam_csa_set_key(stream->id, stream->name, stream->service_id, stream->biss_key, true);
    }

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

    if (stream->enabled) {
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
    } else {
        /* Stream is disabled: Close if currently active */
        if (p_output) {
            output_config_t blank_config;
            config_Init(&blank_config);
            demux_Change(p_output, &blank_config);
            config_Free(&blank_config);

            output_Close(p_output);
        }
    }

    config_Free(&config);

    web_state_add_or_update_stream(stream);
    web_state_save_json(NULL);
    return true;
}

bool web_manager_delete_stream(const char *id) {
    if (!id || !*id) return false;
    web_stream_config_t *s = web_state_find_stream(id);
    if (!s) return false;

    char host_str[256];
    if (s->is_rtp) {
        snprintf(host_str, sizeof(host_str), "%s:%d", s->ip, s->port);
    } else {
        snprintf(host_str, sizeof(host_str), "%s:%d/udp", s->ip, s->port);
    }

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

    /* Delete SoftCAM key if tied to this stream */
    softcam_csa_del_key(id);

    bool ok = web_state_delete_stream(id);
    web_state_save_json(NULL);
    return ok;
}

bool web_manager_toggle_stream(const char *id, bool enabled) {
    if (!id || !*id) return false;
    web_stream_config_t *s = web_state_find_stream(id);
    if (!s) return false;

    s->enabled = enabled;
    return web_manager_add_stream(s);
}

void web_manager_sync_outputs(void) {
    pthread_mutex_lock(&g_gateway.lock);
    int count = g_gateway.num_streams;
    web_stream_config_t streams_copy[MAX_WEB_STREAMS];
    memcpy(streams_copy, g_gateway.streams, count * sizeof(web_stream_config_t));

    int ad_count = g_gateway.num_adapters;
    web_adapter_t adapters_copy[MAX_WEB_ADAPTERS];
    memcpy(adapters_copy, g_gateway.adapters, ad_count * sizeof(web_adapter_t));
    pthread_mutex_unlock(&g_gateway.lock);

    /* Tune primary adapter if any */
    for (int i = 0; i < ad_count; i++) {
        if (adapters_copy[i].enabled) {
            web_manager_tune_adapter(adapters_copy[i].adapter_idx);
            break;
        }
    }

    /* Start active streams */
    for (int i = 0; i < count; i++) {
        if (streams_copy[i].enabled) {
            web_manager_add_stream(&streams_copy[i]);
        }
    }
}
