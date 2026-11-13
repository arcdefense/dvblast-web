#include "web_server.h"
#include "web_state.h"
#include "web_manager.h"
#include "web_ui_embed.h"
#include "modules/softcam/softcam.h"
#include "modules/cas/cas.h"
#include "modules/http_play/http_play.h"
#include "modules/http_auth/http_auth.h"
#include "modules/hls/hls.h"
#include "modules/epg/epg.h"
#include "modules/general/general.h"
#include "modules/groups/groups.h"
#include "modules/ws/ws.h"
#include "modules/analyzer/analyzer.h"

#include <microhttpd.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define POST_BUFFER_MAX (1024 * 1024)

typedef struct {
    char *data;
    size_t size;
    char method[16];
    char url[256];
} http_request_ctx_t;

static struct MHD_Daemon *g_mhd_daemon = NULL;

static void add_cors_headers(struct MHD_Response *response) {
    if (!response) return;
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS, HEAD");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    general_config_t gcfg = general_get_config();
    const char *srv = (gcfg.http_server_name[0]) ? gcfg.http_server_name : "DVBlast-Web-Gateway/2.0";
    MHD_add_response_header(response, "Server", srv);
}

static pthread_mutex_t g_access_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void write_access_log(struct MHD_Connection *conn, const char *method, const char *url, int status_code) {
    general_config_t gcfg = general_get_config();
    if (!gcfg.http_access_log[0]) return;

    char client_ip[64] = "127.0.0.1";
    if (gcfg.allow_real_ip[0]) {
        const char *rip = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Real-IP");
        if (!rip) rip = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "X-Forwarded-For");
        if (rip && *rip) {
            snprintf(client_ip, sizeof(client_ip), "%s", rip);
            char *comma = strchr(client_ip, ',');
            if (comma) *comma = '\0';
        } else {
            const union MHD_ConnectionInfo *ci = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
            if (ci && ci->client_addr && ci->client_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ci->client_addr;
                inet_ntop(AF_INET, &sin->sin_addr, client_ip, sizeof(client_ip));
            }
        }
    } else {
        const union MHD_ConnectionInfo *ci = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        if (ci && ci->client_addr && ci->client_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ci->client_addr;
            inet_ntop(AF_INET, &sin->sin_addr, client_ip, sizeof(client_ip));
        }
    }

    const char *ua = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "User-Agent");
    if (!ua) ua = "-";

    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", &tm_info);

    pthread_mutex_lock(&g_access_log_mutex);
    FILE *fp = fopen(gcfg.http_access_log, "a");
    if (fp) {
        fprintf(fp, "%s - - [%s] \"%s %s HTTP/1.1\" %d - \"-\" \"%s\"\n",
                client_ip, time_str, method ? method : "GET", url ? url : "/", status_code, ua);
        fclose(fp);
    }
    pthread_mutex_unlock(&g_access_log_mutex);
}

static int send_response(struct MHD_Connection *conn, int status_code,
                         const char *content_type, const void *data, size_t len) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(len, (void *)data, MHD_RESPMEM_MUST_COPY);
    if (!resp) return MHD_NO;
    MHD_add_response_header(resp, "Content-Type", content_type);
    if (strstr(content_type, "text/html")) {
        MHD_add_response_header(resp, "Cache-Control", "no-cache, no-store, must-revalidate");
        MHD_add_response_header(resp, "Pragma", "no-cache");
        MHD_add_response_header(resp, "Expires", "0");
    }
    add_cors_headers(resp);
    int ret = MHD_queue_response(conn, status_code, resp);
    MHD_destroy_response(resp);
    return ret;
}

static int send_json(struct MHD_Connection *conn, int status_code, json_t *root) {
    char *str = json_dumps(root, JSON_INDENT(2) | JSON_PRESERVE_ORDER);
    json_decref(root);
    if (!str) return send_response(conn, 500, "text/plain", "JSON Encoding Error", 19);

    int ret = send_response(conn, status_code, "application/json", str, strlen(str));
    free(str);
    return ret;
}

static int send_json_ok(struct MHD_Connection *conn, const char *msg) {
    json_t *r = json_object();
    json_object_set_new(r, "ok", json_true());
    if (msg) json_object_set_new(r, "message", json_string(msg));
    return send_json(conn, 200, r);
}

static int send_json_error(struct MHD_Connection *conn, int status_code, const char *err) {
    json_t *r = json_object();
    json_object_set_new(r, "ok", json_false());
    json_object_set_new(r, "error", json_string(err ? err : "Unknown Error"));
    return send_json(conn, status_code, r);
}

static int handle_get_request(struct MHD_Connection *conn, const char *url) {
    /* UI Page */
    if (strcmp(url, "/") == 0 || strcmp(url, "/index.html") == 0) {
        return send_response(conn, 200, "text/html; charset=utf-8", web_ui_html, web_ui_html_len);
    }

    /* System Telemetry */
    if (strcmp(url, "/api/v1/system") == 0 || strcmp(url, "/api/v1/telemetry") == 0) {
        return send_json(conn, 200, web_state_telemetry_to_json());
    }

    /* Configured Adapters */
    if (strcmp(url, "/api/v1/adapters") == 0 || strcmp(url, "/api/v1/frontend/channels") == 0) {
        return send_json(conn, 200, web_state_adapters_to_json());
    }

    /* Hardware Detection */
    if (strcmp(url, "/api/v1/hardware") == 0 || strcmp(url, "/api/v1/hardware/tuners") == 0) {
        return send_json(conn, 200, web_state_hardware_to_json());
    }

    /* Configured Streams */
    if (strcmp(url, "/api/v1/streams") == 0 || strcmp(url, "/api/v1/mux/outputs") == 0) {
        return send_json(conn, 200, web_state_streams_to_json());
    }

    /* SoftCAM Keys */
    if (strcmp(url, "/api/v1/softcam") == 0 || strcmp(url, "/api/v1/descramble/keys") == 0 ||
        strcmp(url, "/api/v1/modules/softcam") == 0) {
        return send_json(conn, 200, softcam_to_json());
    }

    /* Module Configurations */
    if (strcmp(url, "/api/v1/modules/http_play") == 0) {
        return send_json(conn, 200, http_play_to_json());
    }
    if (strcmp(url, "/api/v1/modules/http_auth") == 0) {
        return send_json(conn, 200, http_auth_to_json());
    }
    if (strcmp(url, "/api/v1/modules/hls") == 0) {
        return send_json(conn, 200, hls_to_json());
    }
    if (strcmp(url, "/api/v1/modules/epg") == 0) {
        return send_json(conn, 200, epg_to_json());
    }
    if (strcmp(url, "/api/v1/modules/cas") == 0) {
        return send_json(conn, 200, cas_to_json());
    }
    if (strcmp(url, "/api/v1/modules/general") == 0 || strcmp(url, "/api/v1/settings/general") == 0) {
        return send_json(conn, 200, general_to_json());
    }
    if (strcmp(url, "/api/v1/modules/groups") == 0 || strcmp(url, "/api/v1/categories") == 0) {
        return send_json(conn, 200, groups_to_json());
    }
    if (strcmp(url, "/api/v1/servers") == 0 || strcmp(url, "/api/v1/modules/servers") == 0) {
        return send_json(conn, 200, web_state_servers_to_json());
    }
    if (strcmp(url, "/api/v1/modules/softcam_profiles") == 0 || strcmp(url, "/api/v1/softcam/profiles") == 0) {
        return send_json(conn, 200, web_state_softcam_profiles_to_json());
    }

    /* MPEG-TS Stream & Adapter Analyzer */
    if (strcmp(url, "/api/v1/analyze") == 0 || strcmp(url, "/api/v1/analyzer") == 0) {
        const char *sid_arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "stream_id");
        if (!sid_arg) sid_arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "id");
        const char *ad_arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "adapter");
        if (!ad_arg) ad_arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "adapter_idx");

        json_t *res = NULL;
        if (sid_arg && *sid_arg) {
            res = analyzer_get_stream(sid_arg);
        } else if (ad_arg && *ad_arg) {
            res = analyzer_get_adapter(atoi(ad_arg));
        } else {
            res = analyzer_get_stream(NULL);
        }
        return send_json(conn, 200, res);
    }

    /* Active Streaming Clients & Sessions */
    if (strcmp(url, "/api/v1/sessions") == 0 || strcmp(url, "/api/v1/clients") == 0) {
        return send_json(conn, 200, http_play_get_sessions_json());
    }

    /* Active WebSocket Telemetry Sessions */
    if (strcmp(url, "/api/v1/ws/sessions") == 0) {
        return send_json(conn, 200, ws_get_sessions_json());
    }

    /* Full System Configuration */
    if (strcmp(url, "/api/v1/config") == 0 || strcmp(url, "/api/v1/system/config") == 0) {
        return send_json(conn, 200, web_state_config_to_json());
    }

    /* Logs */
    if (strcmp(url, "/api/v1/logs") == 0 || strncmp(url, "/api/v1/system/logs", 19) == 0) {
        return send_json(conn, 200, web_state_logs_to_json(100));
    }

    return send_json_error(conn, 404, "Endpoint Not Found");
}

static int handle_post_request(struct MHD_Connection *conn, const char *url, const char *body) {
    json_error_t jerr;
    json_t *payload = NULL;
    if (body && *body) {
        payload = json_loads(body, 0, &jerr);
    }

    /* ===================================================================== */
    /*  ADAPTERS API                                                         */
    /* ===================================================================== */

    if (strcmp(url, "/api/v1/adapters") == 0 || strcmp(url, "/api/v1/frontend/tune") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body for adapter configuration");
        }

        web_adapter_t ad;
        memset(&ad, 0, sizeof(ad));

        const char *id = json_string_value(json_object_get(payload, "id"));
        const char *nm = json_string_value(json_object_get(payload, "name"));
        const char *del = json_string_value(json_object_get(payload, "delsys"));
        const char *pol = json_string_value(json_object_get(payload, "polarization"));
        const char *lnb = json_string_value(json_object_get(payload, "lnb_type"));
        const char *lnb_mode = json_string_value(json_object_get(payload, "lnb_mode"));
        const char *uni_pos = json_string_value(json_object_get(payload, "uni_pos"));
        const char *dcmd = json_string_value(json_object_get(payload, "diseqc_cmd"));
        const char *sat_url = json_string_value(json_object_get(payload, "satip_url"));
        const char *sat_pids = json_string_value(json_object_get(payload, "satip_pids"));
        const char *mod = json_string_value(json_object_get(payload, "modulation"));

        if (!id || !*id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required field: 'id'");
        }

        if (json_is_true(json_object_get(payload, "remove"))) {
            bool ok = web_manager_delete_adapter(id);
            json_decref(payload);
            return ok ? send_json_ok(conn, "Adapter removed") : send_json_error(conn, 404, "Adapter not found");
        }

        snprintf(ad.id, sizeof(ad.id), "%s", id);
        snprintf(ad.name, sizeof(ad.name), "%s", (nm && *nm) ? nm : id);
        ad.enabled = !json_is_false(json_object_get(payload, "enabled"));
        ad.adapter_idx = (int)json_integer_value(json_object_get(payload, "adapter_idx"));
        ad.frontend_idx = (int)json_integer_value(json_object_get(payload, "frontend_idx"));
        snprintf(ad.delsys, sizeof(ad.delsys), "%s", (del && *del) ? del : "DVBT2");

        /* Prevent duplicate adapter_idx conflict across different physical adapters */
        if (ad.enabled && strcasecmp(ad.delsys, "SATIP") != 0 && (!sat_url || !*sat_url)) {
            web_adapter_t *existing = web_state_find_adapter_by_idx(ad.adapter_idx);
            if (existing && strcmp(existing->id, ad.id) != 0 && existing->enabled) {
                char err_msg[256];
                snprintf(err_msg, sizeof(err_msg), "Physical DVB adapter %d is already in use by adapter '%s'",
                         ad.adapter_idx, existing->name);
                json_decref(payload);
                return send_json_error(conn, 400, err_msg);
            }
        }

        json_t *j_freq = json_object_get(payload, "frequency");
        double freq_val = 0.0;
        if (json_is_string(j_freq)) {
            freq_val = atof(json_string_value(j_freq));
        } else if (json_is_number(j_freq)) {
            freq_val = json_number_value(j_freq);
        }
        if (freq_val > 0.0 && freq_val < 1000.0) {
            freq_val *= 1000000.0; /* e.g. 498 MHz -> 498000000 Hz */
        } else if (freq_val >= 1000.0 && freq_val < 1000000.0) {
            freq_val *= 1000.0;    /* e.g. 498000 kHz -> 498000000 Hz */
        }
        ad.frequency = (uint64_t)freq_val;

        ad.symbol_rate = (uint32_t)json_integer_value(json_object_get(payload, "symbol_rate"));
        ad.bandwidth = (int)json_integer_value(json_object_get(payload, "bandwidth"));
        if (ad.bandwidth <= 0) ad.bandwidth = 8;
        snprintf(ad.polarization, sizeof(ad.polarization), "%s", (pol && *pol) ? pol : "H");

        if (strcmp(ad.polarization, "V") == 0 || strcmp(ad.polarization, "13") == 0) {
            ad.voltage = 13;
        } else {
            ad.voltage = 18;
        }

        ad.tone = (int)json_integer_value(json_object_get(payload, "tone"));
        ad.diseqc = (int)json_integer_value(json_object_get(payload, "diseqc"));
        if (lnb) snprintf(ad.lnb_type, sizeof(ad.lnb_type), "%s", lnb);
        if (lnb_mode) snprintf(ad.lnb_mode, sizeof(ad.lnb_mode), "%s", lnb_mode);
        ad.uni_scr = (int)json_integer_value(json_object_get(payload, "uni_scr"));
        if (uni_pos) snprintf(ad.uni_pos, sizeof(ad.uni_pos), "%s", uni_pos);
        ad.uni_frequency = (uint32_t)json_integer_value(json_object_get(payload, "uni_frequency"));
        ad.uncommitted = (int)json_integer_value(json_object_get(payload, "uncommitted"));
        if (dcmd) snprintf(ad.diseqc_cmd, sizeof(ad.diseqc_cmd), "%s", dcmd);
        if (sat_url) snprintf(ad.satip_url, sizeof(ad.satip_url), "%s", sat_url);
        if (sat_pids) snprintf(ad.satip_pids, sizeof(ad.satip_pids), "%s", sat_pids);
        if (mod) snprintf(ad.modulation, sizeof(ad.modulation), "%s", mod);
        ad.multistream_id = (int)json_integer_value(json_object_get(payload, "multistream_id"));
        uint32_t l1 = (uint32_t)json_integer_value(json_object_get(payload, "lof1"));
        uint32_t l2 = (uint32_t)json_integer_value(json_object_get(payload, "lof2"));
        uint32_t sl = (uint32_t)json_integer_value(json_object_get(payload, "slof"));
        ad.lof1 = l1 ? l1 : 9750;
        ad.lof2 = l2 ? l2 : 10600;
        ad.slof = sl ? sl : 11700;
        ad.fec = (int)json_integer_value(json_object_get(payload, "fec"));
        ad.rolloff = (int)json_integer_value(json_object_get(payload, "rolloff"));
        uint32_t buf = (uint32_t)json_integer_value(json_object_get(payload, "buffer_size"));
        ad.buffer_size = buf ? buf : 64;

        bool ok = web_manager_add_adapter(&ad);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Adapter saved and configured") : send_json_error(conn, 500, "Failed to configure adapter");
    }

    if (strcmp(url, "/api/v1/adapters/delete") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        if (!id || !*id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required field: 'id'");
        }
        bool ok = web_manager_delete_adapter(id);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Adapter deleted") : send_json_error(conn, 404, "Adapter not found");
    }

    if (strcmp(url, "/api/v1/adapters/toggle") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        bool enabled = !json_is_false(json_object_get(payload, "enabled"));
        if (!id || !*id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required field: 'id'");
        }
        bool ok = web_manager_toggle_adapter(id, enabled);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Adapter state toggled") : send_json_error(conn, 404, "Adapter not found");
    }

    if (strcmp(url, "/api/v1/adapters/restart") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        if (!id || !*id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required field: 'id'");
        }
        bool ok = web_manager_restart_adapter(id);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Adapter restart triggered") : send_json_error(conn, 404, "Adapter not found");
    }

    if (strcmp(url, "/api/v1/adapters/scan") == 0 || strcmp(url, "/api/v1/frontend/scan") == 0) {
        int adapter_idx = 0;
        if (payload && json_is_object(payload)) {
            const char *id = json_string_value(json_object_get(payload, "id"));
            if (id) {
                web_adapter_t *ad = web_state_find_adapter(id);
                if (ad) adapter_idx = ad->adapter_idx;
            } else {
                adapter_idx = (int)json_integer_value(json_object_get(payload, "adapter_idx"));
            }
        }
        if (payload) json_decref(payload);

        web_manager_trigger_scan(adapter_idx);
        json_t *res = json_object();
        json_object_set_new(res, "ok", json_true());
        json_object_set_new(res, "adapters", web_state_adapters_to_json());
        return send_json(conn, 200, res);
    }

    /* ===================================================================== */
    /*  STREAMS API                                                          */
    /* ===================================================================== */

    if (strcmp(url, "/api/v1/streams") == 0 || strcmp(url, "/api/v1/mux/outputs") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body for stream");
        }

        web_stream_config_t st;
        memset(&st, 0, sizeof(st));

        const char *id = json_string_value(json_object_get(payload, "id"));
        const char *nm = json_string_value(json_object_get(payload, "name"));
        const char *tp = json_string_value(json_object_get(payload, "type"));
        const char *in = json_string_value(json_object_get(payload, "input_url"));
        const char *out = json_string_value(json_object_get(payload, "output_url"));
        const char *ip = json_string_value(json_object_get(payload, "ip"));
        const char *bk = json_string_value(json_object_get(payload, "biss_key"));
        const char *bu = json_string_value(json_object_get(payload, "backup_url"));
        const char *bt = json_string_value(json_object_get(payload, "backup_type"));

        if (!id || !*id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required field: 'id'");
        }

        snprintf(st.id, sizeof(st.id), "%s", id);
        snprintf(st.name, sizeof(st.name), "%s", (nm && *nm) ? nm : id);
        snprintf(st.type, sizeof(st.type), "%s", (tp && *tp) ? tp : "spts");
        if (in) snprintf(st.input_url, sizeof(st.input_url), "%s", in);
        if (out) snprintf(st.output_url, sizeof(st.output_url), "%s", out);
        if (bk) snprintf(st.biss_key, sizeof(st.biss_key), "%s", bk);
        if (bu) snprintf(st.backup_url, sizeof(st.backup_url), "%s", bu);
        if (bt) {
            if (strcmp(bt, "http") == 0 || strcmp(bt, "hls") == 0) st.backup_type = 1;
            else if (strcmp(bt, "udp") == 0 || strcmp(bt, "rtp") == 0) st.backup_type = 2;
            else st.backup_type = atoi(bt);
        } else if (bu && *bu) {
            st.backup_type = 1;
        }
        st.backup_start_delay = (int)json_integer_value(json_object_get(payload, "backup_start_delay"));
        st.backup_return_delay = (int)json_integer_value(json_object_get(payload, "backup_return_delay"));

        st.enabled = !json_is_false(json_object_get(payload, "enabled"));
        st.adapter_idx = (int)json_integer_value(json_object_get(payload, "adapter_idx"));
        st.service_id = (uint16_t)json_integer_value(json_object_get(payload, "service_id"));
        st.port = (int)json_integer_value(json_object_get(payload, "port"));
        if (st.port <= 0) st.port = 5000;

        if (ip && *ip) {
            snprintf(st.ip, sizeof(st.ip), "%s", ip);
        } else if (out && *out) {
            /* Parse IP from output_url e.g. udp://239.255.1.1:5000 */
            const char *p = strstr(out, "://");
            p = p ? (p + 3) : out;
            char hostbuf[64];
            snprintf(hostbuf, sizeof(hostbuf), "%s", p);
            char *colon = strchr(hostbuf, ':');
            if (colon) {
                *colon = '\0';
                st.port = atoi(colon + 1);
            }
            snprintf(st.ip, sizeof(st.ip), "%s", hostbuf);
        } else {
            snprintf(st.ip, sizeof(st.ip), "239.255.1.1");
        }

        st.ttl = (int)json_integer_value(json_object_get(payload, "ttl"));
        if (st.ttl <= 0) st.ttl = 16;
        st.is_rtp = json_is_true(json_object_get(payload, "is_rtp"));
        st.pacing = !json_is_false(json_object_get(payload, "pacing"));
        const char *grp = json_string_value(json_object_get(payload, "groups"));
        if (grp) snprintf(st.groups, sizeof(st.groups), "%s", grp);

        bool ok = web_manager_add_stream(&st);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Stream saved and route configured") : send_json_error(conn, 500, "Failed to configure stream");
    }

    if (strcmp(url, "/api/v1/streams/delete") == 0 || strcmp(url, "/api/v1/mux/outputs/delete") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        if (!id || !*id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required field: 'id'");
        }
        bool ok = web_manager_delete_stream(id);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Stream deleted") : send_json_error(conn, 404, "Stream not found");
    }

    if (strcmp(url, "/api/v1/streams/toggle") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        bool enabled = !json_is_false(json_object_get(payload, "enabled"));
        if (!id || !*id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required field: 'id'");
        }
        bool ok = web_manager_toggle_stream(id, enabled);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Stream state toggled") : send_json_error(conn, 404, "Stream not found");
    }

    if (strcmp(url, "/api/v1/sessions/kick") == 0 || strcmp(url, "/api/v1/clients/kick") == 0) {
        int id = 0;
        if (payload && json_is_object(payload)) {
            id = (int)json_integer_value(json_object_get(payload, "id"));
        }
        if (payload) json_decref(payload);
        if (id <= 0) {
            return send_json_error(conn, 400, "Missing or invalid client 'id'");
        }
        bool ok = http_play_kick_client(id);
        ws_kick_session(id);
        return ok ? send_json_ok(conn, "Client disconnected") : send_json_error(conn, 404, "Session not found");
    }

    /* ===================================================================== */
    /*  SOFTCAM API                                                          */
    /* ===================================================================== */

    if (strcmp(url, "/api/v1/softcam") == 0 || strcmp(url, "/api/v1/descramble/keys") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body for SoftCAM key");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        const char *nm = json_string_value(json_object_get(payload, "name"));
        uint16_t sid = (uint16_t)json_integer_value(json_object_get(payload, "service_id"));
        const char *key = json_string_value(json_object_get(payload, "key"));
        bool en = !json_is_false(json_object_get(payload, "enabled"));

        if (!id || !key) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing 'id' or 'key'");
        }
        bool ok = softcam_set_key(id, nm, sid, key, en);
        web_state_save_json(NULL);
        json_decref(payload);
        return ok ? send_json_ok(conn, "SoftCAM key saved") : send_json_error(conn, 500, "Failed to set SoftCAM key");
    }

    if (strcmp(url, "/api/v1/softcam/delete") == 0 || strcmp(url, "/api/v1/descramble/keys/delete") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        if (!id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing key 'id'");
        }
        bool ok = softcam_del_key(id);
        web_state_save_json(NULL);
        json_decref(payload);
        return ok ? send_json_ok(conn, "SoftCAM key deleted") : send_json_error(conn, 404, "Key not found");
    }

    /* ===================================================================== */
    /*  MODULE CONFIGURATION APIS                                            */
    /* ===================================================================== */

    if (strcmp(url, "/api/v1/modules/http_play") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        http_play_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "HTTP Play settings saved");
    }

    if (strcmp(url, "/api/v1/modules/http_auth") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        http_auth_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "Authentication settings saved");
    }

    if (strcmp(url, "/api/v1/modules/hls") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        hls_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "HLS settings saved");
    }

    if (strcmp(url, "/api/v1/modules/epg") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        epg_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "EPG settings saved");
    }

    if (strcmp(url, "/api/v1/modules/cas") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        cas_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "CAS settings saved");
    }

    if (strcmp(url, "/api/v1/modules/general") == 0 || strcmp(url, "/api/v1/settings/general") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        general_from_json(payload);
        extern void dvblast_set_network_provider(const char *net_name, const char *prov_name);
        general_config_t gcfg = general_get_config();
        dvblast_set_network_provider(gcfg.network_name, gcfg.service_provider);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "General settings saved");
    }

    if (strcmp(url, "/api/v1/modules/groups") == 0 || strcmp(url, "/api/v1/categories") == 0) {
        if (!payload || !json_is_array(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON array body for groups/categories");
        }
        groups_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "Categories & groups saved");
    }

    if (strcmp(url, "/api/v1/categories/assign") == 0 || strcmp(url, "/api/v1/groups/assign") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *group = json_string_value(json_object_get(payload, "group"));
        const char *single_id = json_string_value(json_object_get(payload, "stream_id"));
        json_t *sids = json_object_get(payload, "stream_ids");

        pthread_mutex_lock(&g_gateway.lock);
        if (single_id && *single_id) {
            for (int i = 0; i < g_gateway.num_streams; i++) {
                if (strcmp(g_gateway.streams[i].id, single_id) == 0) {
                    snprintf(g_gateway.streams[i].groups, sizeof(g_gateway.streams[i].groups), "%s", group ? group : "");
                    break;
                }
            }
        }
        if (json_is_array(sids)) {
            for (int i = 0; i < g_gateway.num_streams; i++) {
                size_t idx;
                json_t *val;
                bool match = false;
                json_array_foreach(sids, idx, val) {
                    const char *sid_str = json_string_value(val);
                    if (sid_str && strcmp(g_gateway.streams[i].id, sid_str) == 0) {
                        match = true;
                        break;
                    }
                }
                if (match) {
                    snprintf(g_gateway.streams[i].groups, sizeof(g_gateway.streams[i].groups), "%s", group ? group : "");
                } else if (group && *group && strcmp(g_gateway.streams[i].groups, group) == 0) {
                    g_gateway.streams[i].groups[0] = '\0';
                }
            }
        }
        pthread_mutex_unlock(&g_gateway.lock);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "Stream groups mapped");
    }

    if (strcmp(url, "/api/v1/servers") == 0 || strcmp(url, "/api/v1/modules/servers") == 0) {
        if (!payload || !json_is_array(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON array body for servers");
        }
        web_state_servers_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "Cluster servers saved");
    }

    if (strcmp(url, "/api/v1/servers/test") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *host = json_string_value(json_object_get(payload, "host"));
        int port = (int)json_integer_value(json_object_get(payload, "port"));
        if (!host || !*host || port <= 0) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing host or port");
        }

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        struct addrinfo hints, *res = NULL, *rp;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int sock = -1;
        if (getaddrinfo(host, port_str, &hints, &res) == 0) {
            for (rp = res; rp != NULL; rp = rp->ai_next) {
                sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sock == -1) continue;
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);
                int rc = connect(sock, rp->ai_addr, rp->ai_addrlen);
                if (rc == 0) {
                    break;
                }
                if (errno == EINPROGRESS) {
                    fd_set wset;
                    FD_ZERO(&wset);
                    FD_SET(sock, &wset);
                    struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
                    rc = select(sock + 1, NULL, &wset, NULL, &tv);
                    if (rc > 0) {
                        int err = 0;
                        socklen_t len = sizeof(err);
                        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
                        if (err == 0) break;
                    }
                }
                close(sock);
                sock = -1;
            }
            freeaddrinfo(res);
        }

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double latency_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0;
        json_decref(payload);

        json_t *resp = json_object();
        if (sock >= 0) {
            close(sock);
            json_object_set_new(resp, "ok", json_true());
            json_object_set_new(resp, "latency_ms", json_real(latency_ms));
            return send_json(conn, 200, resp);
        } else {
            json_object_set_new(resp, "ok", json_false());
            json_object_set_new(resp, "error", json_string("Connection failed or timed out"));
            return send_json(conn, 200, resp);
        }
    }

    if (strcmp(url, "/api/v1/modules/softcam_profiles") == 0 || strcmp(url, "/api/v1/softcam/profiles") == 0) {
        if (!payload || !json_is_array(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON array body for softcam profiles");
        }
        web_state_softcam_profiles_from_json(payload);
        web_state_save_json(NULL);
        json_decref(payload);
        return send_json_ok(conn, "Softcam profiles saved");
    }

    if (strcmp(url, "/api/v1/import/streams") == 0) {
        if (!payload || !json_is_array(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Expected JSON array of streams");
        }
        size_t idx;
        json_t *item;
        int imported_count = 0;
        json_array_foreach(payload, idx, item) {
            if (!json_is_object(item)) continue;
            web_stream_config_t st;
            memset(&st, 0, sizeof(st));
            const char *id = json_string_value(json_object_get(item, "id"));
            const char *nm = json_string_value(json_object_get(item, "name"));
            const char *in = json_string_value(json_object_get(item, "input_url"));
            const char *out = json_string_value(json_object_get(item, "output_url"));
            const char *ip = json_string_value(json_object_get(item, "ip"));
            if (id && *id) snprintf(st.id, sizeof(st.id), "%s", id);
            else snprintf(st.id, sizeof(st.id), "stream_imp_%d", (int)idx + 1);
            if (nm && *nm) snprintf(st.name, sizeof(st.name), "%s", nm);
            else snprintf(st.name, sizeof(st.name), "Imported Stream %d", (int)idx + 1);
            const char *grp = json_string_value(json_object_get(item, "groups"));
            if (!grp) grp = json_string_value(json_object_get(item, "group"));
            if (grp && *grp) snprintf(st.groups, sizeof(st.groups), "%s", grp);
            if (in && *in) snprintf(st.input_url, sizeof(st.input_url), "%s", in);
            if (out && *out) snprintf(st.output_url, sizeof(st.output_url), "%s", out);
            st.adapter_idx = (int)json_integer_value(json_object_get(item, "adapter_idx"));
            st.service_id = (uint16_t)json_integer_value(json_object_get(item, "service_id"));
            st.port = (int)json_integer_value(json_object_get(item, "port"));
            if (st.port <= 0) st.port = 5000 + (int)idx;
            if (ip && *ip) snprintf(st.ip, sizeof(st.ip), "%s", ip);
            else snprintf(st.ip, sizeof(st.ip), "239.1.2.%d", 100 + (int)idx);
            st.ttl = (int)json_integer_value(json_object_get(item, "ttl"));
            if (st.ttl <= 0) st.ttl = 16;
            st.enabled = true;
            st.pacing = true;
            if (web_manager_add_stream(&st)) {
                imported_count++;
            }
        }
        web_state_save_json(NULL);
        json_decref(payload);
        json_t *res = json_object();
        json_object_set_new(res, "ok", json_true());
        json_object_set_new(res, "imported", json_integer(imported_count));
        return send_json(conn, 200, res);
    }

    if (strcmp(url, "/api/v1/system/restart") == 0) {
        if (payload) json_decref(payload);
        web_state_log("WARN", "System daemon restart initiated from Web UI");
        return send_json_ok(conn, "System daemon restarting...");
    }

    /* ===================================================================== */
    /*  CONFIGURATION API                                                    */
    /* ===================================================================== */

    if (strcmp(url, "/api/v1/config") == 0 || strcmp(url, "/api/v1/system/config") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON payload for config");
        }
        char tmp_path[300];
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_gateway.config_file);
        int res = json_dump_file(payload, tmp_path, JSON_INDENT(2));
        json_decref(payload);

        if (res == 0) {
            rename(tmp_path, g_gateway.config_file);
            web_state_load_json(g_gateway.config_file);
            web_manager_sync_outputs();
            return send_json_ok(conn, "Configuration saved and applied");
        }
        return send_json_error(conn, 500, "Failed to write configuration file");
    }

    if (payload) json_decref(payload);
    return send_json_error(conn, 404, "Endpoint Not Found");
}

static enum MHD_Result http_handler(void *cls, struct MHD_Connection *conn,
                                    const char *url, const char *method,
                                    const char *version, const char *upload_data,
                                    size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version;

    if (*con_cls == NULL) {
        http_request_ctx_t *ctx = calloc(1, sizeof(http_request_ctx_t));
        if (!ctx) return MHD_NO;
        snprintf(ctx->method, sizeof(ctx->method), "%s", method);
        snprintf(ctx->url, sizeof(ctx->url), "%s", url);
        *con_cls = ctx;
        return MHD_YES;
    }

    http_request_ctx_t *ctx = (http_request_ctx_t *)*con_cls;

    if (*upload_data_size != 0) {
        if (ctx->size + *upload_data_size > POST_BUFFER_MAX) {
            *upload_data_size = 0;
            return MHD_NO;
        }
        ctx->data = realloc(ctx->data, ctx->size + *upload_data_size + 1);
        memcpy(ctx->data + ctx->size, upload_data, *upload_data_size);
        ctx->size += *upload_data_size;
        ctx->data[ctx->size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* Handle OPTIONS pre-flight */
    if (strcasecmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        add_cors_headers(resp);
        int ret = MHD_queue_response(conn, 204, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* HTTP Authentication Check */
    auth_result_t ares = http_auth_check(conn, url, method);
    if (ares == AUTH_RES_REDIRECT) {
        return http_auth_send_redirect(conn, url);
    } else if (ares == AUTH_RES_UNAUTHORIZED) {
        return http_auth_send_challenge(conn);
    } else if (ares == AUTH_RES_IP_DENIED) {
        return send_json_error(conn, 403, "Access Forbidden: Client IP address is blocked by policy");
    } else if (ares == AUTH_RES_FORBIDDEN) {
        return send_json_error(conn, 403, "Access Forbidden: Administrative privileges required");
    }

    /* WebSocket Upgrade check */
    if (ws_is_upgrade_request(conn)) {
        if (strcmp(url, "/api/v1/ws") == 0 || strcmp(url, "/ws") == 0 || strcmp(url, "/control/event/") == 0) {
            return ws_handle_upgrade(conn, "admin");
        }
    }

    /* Auth API */
    if (strncmp(url, "/api/v1/auth/", 13) == 0 || strncmp(url, "/auth/", 6) == 0) {
        int ret = http_auth_handle_api(conn, url, method, ctx->data);
        if (ret != MHD_NO) return ret;
    }

    /* HLS Segmenter - Process before generic .m3u8 so /hls/ stream manifests are not intercepted */
    if (strncmp(url, "/hls/", 5) == 0) {
        int ret = hls_handle_request(conn, url);
        if (ret != MHD_NO) return ret;
    }

    /* HTTP Play TS Streaming & M3U/XSPF Playlist */
    if (strncmp(url, "/play/", 6) == 0 ||
        strncmp(url, "/live/", 6) == 0 ||
        strstr(url, ".m3u8") != NULL ||
        strstr(url, ".m3u") != NULL ||
        strstr(url, ".xspf") != NULL ||
        strncmp(url, "/playlist", 9) == 0 ||
        strncmp(url, "/channels", 9) == 0) {
        const char *host_hdr = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Host");
        int ret = http_play_handle_request(conn, url, host_hdr);
        if (ret != MHD_NO) return ret;
    }

    /* EPG Schedule & XMLTV */
    if (strcmp(url, "/epg.xml") == 0 ||
        strcmp(url, "/api/v1/epg/xmltv") == 0 ||
        strcmp(url, "/api/v1/epg") == 0) {
        int ret = epg_handle_request(conn, url);
        if (ret != MHD_NO) return ret;
    }

    if (strcasecmp(method, "GET") == 0 || strcasecmp(method, "HEAD") == 0) {
        return handle_get_request(conn, url);
    } else if (strcasecmp(method, "POST") == 0) {
        return handle_post_request(conn, url, ctx->data);
    }

    return send_json_error(conn, 405, "Method Not Allowed");
}

static void request_completed(void *cls, struct MHD_Connection *conn,
                              void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls;
    http_request_ctx_t *ctx = (http_request_ctx_t *)*con_cls;
    if (ctx) {
        write_access_log(conn, ctx->method, ctx->url, (toe == MHD_REQUEST_TERMINATED_COMPLETED_OK) ? 200 : 400);
        if (ctx->data) free(ctx->data);
        free(ctx);
        *con_cls = NULL;
    }
}

bool web_server_start(int port, const char *host) {
    if (g_mhd_daemon) {
        web_state_log("WARN", "Web server already running");
        return true;
    }

    /* Initialize Submodules */
    softcam_init();
    cas_init();
    http_play_init();
    http_auth_init();
    hls_init();
    epg_init();
    general_init();
    groups_init();
    ws_init();
    analyzer_init();

    (void)host;
    g_mhd_daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_THREAD_PER_CONNECTION | MHD_ALLOW_UPGRADE,
        port,
        NULL, NULL,
        &http_handler, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, &request_completed, NULL,
        MHD_OPTION_END
    );

    if (!g_mhd_daemon) {
        web_state_log("ERROR", "Failed to start HTTP server on port %d", port);
        return false;
    }

    web_state_log("INFO", "HTTP Server running at http://0.0.0.0:%d", port);
    return true;
}

void web_server_stop(void) {
    if (g_mhd_daemon) {
        MHD_stop_daemon(g_mhd_daemon);
        g_mhd_daemon = NULL;
        web_state_log("INFO", "HTTP Server stopped");

        /* Cleanup Submodules */
        analyzer_cleanup();
        ws_cleanup();
        cas_cleanup();
        hls_cleanup();
        epg_cleanup();
        http_play_cleanup();
        http_auth_cleanup();
        softcam_cleanup();
    }
}

void web_server_broadcast_telemetry(void) {
    json_t *root = json_object();
    json_object_set_new(root, "system", web_state_telemetry_to_json());
    json_object_set_new(root, "adapters", web_state_adapters_to_json());
    json_object_set_new(root, "streams", web_state_streams_to_json());
    ws_broadcast_json(root);
    json_decref(root);
}
