#include "web_server.h"
#include "web_state.h"
#include "web_manager.h"
#include "web_ui_embed.h"
#include "softcam_csa.h"

#include <microhttpd.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization");
    MHD_add_response_header(response, "Server", "DVBlast-Web-Gateway");
}

static int send_response(struct MHD_Connection *conn, int status_code,
                         const char *content_type, const void *data, size_t len) {
    struct MHD_Response *resp = MHD_create_response_from_buffer(len, (void *)data, MHD_RESPMEM_MUST_COPY);
    if (!resp) return MHD_NO;
    MHD_add_response_header(resp, "Content-Type", content_type);
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
    if (strcmp(url, "/") == 0 || strcmp(url, "/index.html") == 0) {
        return send_response(conn, 200, "text/html; charset=utf-8", web_ui_html, web_ui_html_len);
    }

    if (strcmp(url, "/api/v1/telemetry") == 0) {
        return send_json(conn, 200, web_state_telemetry_to_json());
    }

    if (strcmp(url, "/api/v1/hardware/tuners") == 0) {
        return send_json(conn, 200, web_state_tuners_to_json());
    }

    if (strcmp(url, "/api/v1/frontend/channels") == 0) {
        return send_json(conn, 200, web_state_channels_to_json());
    }

    if (strcmp(url, "/api/v1/mux/outputs") == 0) {
        return send_json(conn, 200, web_state_streams_to_json());
    }

    if (strcmp(url, "/api/v1/descramble/keys") == 0) {
        return send_json(conn, 200, softcam_csa_to_json());
    }

    if (strcmp(url, "/api/v1/system/config") == 0) {
        return send_json(conn, 200, web_state_config_to_json());
    }

    if (strncmp(url, "/api/v1/system/logs", 19) == 0) {
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

    if (strcmp(url, "/api/v1/frontend/tune") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body for tune");
        }
        tuner_state_t t;
        memset(&t, 0, sizeof(t));
        t.adapter = (int)json_integer_value(json_object_get(payload, "adapter"));
        const char *del = json_string_value(json_object_get(payload, "delsys"));
        if (del) snprintf(t.delsys, sizeof(t.delsys), "%s", del);
        t.frequency = (uint64_t)json_integer_value(json_object_get(payload, "frequency"));
        t.bandwidth = (int)json_integer_value(json_object_get(payload, "bandwidth"));
        t.symbol_rate = (uint32_t)json_integer_value(json_object_get(payload, "symbol_rate"));
        const char *pol = json_string_value(json_object_get(payload, "polarization"));
        if (pol) snprintf(t.polarization, sizeof(t.polarization), "%s", pol);
        if (strcmp(t.polarization, "V") == 0 || strcmp(t.polarization, "13") == 0) t.voltage = 13;
        else t.voltage = 18;

        bool ok = web_manager_tune(&t);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Frontend tuned successfully") : send_json_error(conn, 500, "Frontend tuning failed");
    }

    if (strcmp(url, "/api/v1/frontend/scan") == 0) {
        if (payload) json_decref(payload);
        web_manager_trigger_scan();
        json_t *res = json_object();
        json_object_set_new(res, "ok", json_true());
        json_object_set_new(res, "channels", web_state_channels_to_json());
        return send_json(conn, 200, res);
    }

    if (strcmp(url, "/api/v1/mux/outputs") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON payload for stream output");
        }
        web_stream_config_t st;
        memset(&st, 0, sizeof(st));
        const char *id = json_string_value(json_object_get(payload, "id"));
        const char *nm = json_string_value(json_object_get(payload, "name"));
        const char *ip = json_string_value(json_object_get(payload, "ip"));
        const char *ifc = json_string_value(json_object_get(payload, "iface"));

        if (!id || !ip) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing required stream fields: 'id' and 'ip'");
        }

        snprintf(st.id, sizeof(st.id), "%s", id);
        snprintf(st.name, sizeof(st.name), "%s", (nm && *nm) ? nm : id);
        snprintf(st.ip, sizeof(st.ip), "%s", ip);
        if (ifc) snprintf(st.iface, sizeof(st.iface), "%s", ifc);
        st.port = (int)json_integer_value(json_object_get(payload, "port"));
        if (st.port <= 0) st.port = 5000;
        st.service_id = (uint16_t)json_integer_value(json_object_get(payload, "service_id"));
        st.ttl = (int)json_integer_value(json_object_get(payload, "ttl"));
        if (st.ttl <= 0) st.ttl = 16;
        st.is_rtp = json_is_true(json_object_get(payload, "is_rtp"));
        st.pacing = !json_is_false(json_object_get(payload, "pacing"));
        st.enabled = !json_is_false(json_object_get(payload, "enabled"));

        bool ok = web_manager_add_stream(&st);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Stream created/updated") : send_json_error(conn, 500, "Failed to create stream");
    }

    if (strcmp(url, "/api/v1/mux/outputs/delete") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        if (!id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing stream 'id'");
        }
        bool ok = web_manager_delete_stream(id);
        json_decref(payload);
        return ok ? send_json_ok(conn, "Stream deleted") : send_json_error(conn, 404, "Stream not found");
    }

    if (strcmp(url, "/api/v1/descramble/keys") == 0) {
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
        bool ok = softcam_csa_set_key(id, nm, sid, key, en);
        web_state_save_json(NULL);
        json_decref(payload);
        return ok ? send_json_ok(conn, "SoftCAM key saved") : send_json_error(conn, 500, "Failed to set SoftCAM key");
    }

    if (strcmp(url, "/api/v1/descramble/keys/delete") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON body");
        }
        const char *id = json_string_value(json_object_get(payload, "id"));
        if (!id) {
            json_decref(payload);
            return send_json_error(conn, 400, "Missing key 'id'");
        }
        bool ok = softcam_csa_del_key(id);
        web_state_save_json(NULL);
        json_decref(payload);
        return ok ? send_json_ok(conn, "SoftCAM key deleted") : send_json_error(conn, 404, "Key not found");
    }

    if (strcmp(url, "/api/v1/system/config") == 0) {
        if (!payload || !json_is_object(payload)) {
            if (payload) json_decref(payload);
            return send_json_error(conn, 400, "Invalid JSON payload for config");
        }
        /* Save payload directly */
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

    if (strcmp(url, "/api/v1/system/reload") == 0) {
        if (payload) json_decref(payload);
        web_state_load_json(g_gateway.config_file);
        web_manager_sync_outputs();
        return send_json_ok(conn, "Gateway reloaded");
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
        /* New request */
        http_request_ctx_t *ctx = calloc(1, sizeof(http_request_ctx_t));
        if (!ctx) return MHD_NO;
        snprintf(ctx->method, sizeof(ctx->method), "%s", method);
        snprintf(ctx->url, sizeof(ctx->url), "%s", url);
        *con_cls = ctx;
        return MHD_YES;
    }

    http_request_ctx_t *ctx = (http_request_ctx_t *)*con_cls;

    /* Handle upload data for POST/PUT */
    if (*upload_data_size > 0) {
        if (ctx->size + *upload_data_size > POST_BUFFER_MAX) {
            *upload_data_size = 0;
            return MHD_NO;
        }
        char *new_buf = realloc(ctx->data, ctx->size + *upload_data_size + 1);
        if (!new_buf) return MHD_NO;
        ctx->data = new_buf;
        memcpy(ctx->data + ctx->size, upload_data, *upload_data_size);
        ctx->size += *upload_data_size;
        ctx->data[ctx->size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    /* Handle preflight CORS OPTIONS */
    if (strcasecmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        add_cors_headers(resp);
        int ret = MHD_queue_response(conn, 204, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    if (strcasecmp(method, "GET") == 0) {
        return handle_get_request(conn, url);
    } else if (strcasecmp(method, "POST") == 0) {
        return handle_post_request(conn, url, ctx->data);
    } else if (strcasecmp(method, "DELETE") == 0) {
        /* Support DELETE as well */
        return handle_post_request(conn, url, ctx->data);
    }

    return send_json_error(conn, 405, "Method Not Allowed");
}

static void request_completed_callback(void *cls, struct MHD_Connection *conn,
                                       void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls; (void)conn; (void)toe;
    http_request_ctx_t *ctx = (http_request_ctx_t *)*con_cls;
    if (ctx) {
        free(ctx->data);
        free(ctx);
        *con_cls = NULL;
    }
}

bool web_server_start(int port, const char *host) {
    if (g_mhd_daemon) return true;

    (void)host;
    int listen_port = (port > 0) ? port : 8088;

    g_mhd_daemon = MHD_start_daemon(
        MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG,
        (uint16_t)listen_port,
        NULL, NULL,
        &http_handler, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, &request_completed_callback, NULL,
        MHD_OPTION_END
    );

    if (!g_mhd_daemon) {
        web_state_log("ERROR", "Failed to start Web Server on port %d", listen_port);
        return false;
    }

    web_state_log("INFO", "Web Server started on http://0.0.0.0:%d/", listen_port);
    return true;
}

void web_server_stop(void) {
    if (g_mhd_daemon) {
        MHD_stop_daemon(g_mhd_daemon);
        g_mhd_daemon = NULL;
        web_state_log("INFO", "Web Server stopped");
    }
}

bool web_server_is_running(void) {
    return (g_mhd_daemon != NULL);
}
