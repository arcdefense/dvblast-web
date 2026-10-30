#include "general.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static general_config_t g_gen = {
    .instance_name = "AIA-Gateway-01",
    .tsdb_url = "http://127.0.0.1:8086",
    .tsdb_org = "aiastudio",
    .tsdb_token = "",
    .tsdb_interval = 60,
    .event_request = "https://bill.aiastudio.my.id/webhook/telegram?tenant_id=1",
    .sessions_url = "https://bill.aiastudio.my.id/webhook/telegram?tenant_id=1",
    .sessions_time = 10,

    .http_server_name = "DVBlast Web Gateway",
    .http_access_log = "/var/log/dvblast_access.log",
    .http_disable_sessions = false,
    .allow_real_ip = "127.0.0.1, 10.0.0.0/8, 192.168.0.0/16",
    .crt_chain = "",
    .crt_key = "",
    .http_disable_tls = true,
    .control_port = 8088,
    .control_path = "/",

    .epg_export_format = "xmltv",
    .epg_export = "/tmp/epg.xml",
    .http_keep_active_demand = false,
    .http_keep_active = 0,
    .backup_start_delay = 5,
    .backup_return_delay = 30,
    .textcode = "UTF-8",
    .service_provider = "AIA Broadcast",
    .network_name = "DVB-T2 Indonesia",
    .http_congestion = "cubic",
    .cc_limit = 0,
    .udp_threads = true,

    .dvb_bind_by_mac = false
};

static pthread_mutex_t g_gen_mutex = PTHREAD_MUTEX_INITIALIZER;

void general_init(void) {
    /* Ready */
}

void general_cleanup(void) {
    /* Cleanup */
}

void general_configure(const general_config_t *cfg) {
    if (!cfg) return;
    pthread_mutex_lock(&g_gen_mutex);
    memcpy(&g_gen, cfg, sizeof(general_config_t));
    pthread_mutex_unlock(&g_gen_mutex);
}

general_config_t general_get_config(void) {
    pthread_mutex_lock(&g_gen_mutex);
    general_config_t copy = g_gen;
    pthread_mutex_unlock(&g_gen_mutex);
    return copy;
}

json_t *general_to_json(void) {
    pthread_mutex_lock(&g_gen_mutex);
    json_t *o = json_object();

    /* Monitoring */
    json_object_set_new(o, "instance_name", json_string(g_gen.instance_name));
    json_object_set_new(o, "tsdb_url", json_string(g_gen.tsdb_url));
    json_object_set_new(o, "tsdb_org", json_string(g_gen.tsdb_org));
    json_object_set_new(o, "tsdb_token", json_string(g_gen.tsdb_token));
    json_object_set_new(o, "tsdb_interval", json_integer(g_gen.tsdb_interval));
    json_object_set_new(o, "event_request", json_string(g_gen.event_request));
    json_object_set_new(o, "sessions_url", json_string(g_gen.sessions_url));
    json_object_set_new(o, "sessions_time", json_integer(g_gen.sessions_time));

    /* HTTP */
    json_object_set_new(o, "http_server_name", json_string(g_gen.http_server_name));
    json_object_set_new(o, "http_access_log", json_string(g_gen.http_access_log));
    json_object_set_new(o, "http_disable_sessions", g_gen.http_disable_sessions ? json_true() : json_false());
    json_object_set_new(o, "allow_real_ip", json_string(g_gen.allow_real_ip));
    json_object_set_new(o, "crt_chain", json_string(g_gen.crt_chain));
    json_object_set_new(o, "crt_key", json_string(g_gen.crt_key));
    json_object_set_new(o, "http_disable_tls", g_gen.http_disable_tls ? json_true() : json_false());
    json_object_set_new(o, "control_port", json_integer(g_gen.control_port));
    json_object_set_new(o, "control_path", json_string(g_gen.control_path));

    /* Stream */
    json_object_set_new(o, "epg_export_format", json_string(g_gen.epg_export_format));
    json_object_set_new(o, "epg_export", json_string(g_gen.epg_export));
    json_object_set_new(o, "http_keep_active_demand", g_gen.http_keep_active_demand ? json_true() : json_false());
    json_object_set_new(o, "http_keep_active", json_integer(g_gen.http_keep_active));
    json_object_set_new(o, "backup_start_delay", json_integer(g_gen.backup_start_delay));
    json_object_set_new(o, "backup_return_delay", json_integer(g_gen.backup_return_delay));
    json_object_set_new(o, "textcode", json_string(g_gen.textcode));
    json_object_set_new(o, "service_provider", json_string(g_gen.service_provider));
    json_object_set_new(o, "network_name", json_string(g_gen.network_name));
    json_object_set_new(o, "http_congestion", json_string(g_gen.http_congestion));
    json_object_set_new(o, "cc_limit", json_integer(g_gen.cc_limit));
    json_object_set_new(o, "udp_threads", g_gen.udp_threads ? json_true() : json_false());

    /* Adapter */
    json_object_set_new(o, "dvb_bind_by_mac", g_gen.dvb_bind_by_mac ? json_true() : json_false());

    pthread_mutex_unlock(&g_gen_mutex);
    return o;
}

static void get_str(json_t *root, const char *key, char *dest, size_t sz) {
    const char *val = json_string_value(json_object_get(root, key));
    if (val) snprintf(dest, sz, "%s", val);
}

static void get_int(json_t *root, const char *key, int *dest) {
    json_t *val = json_object_get(root, key);
    if (val && json_is_number(val)) *dest = (int)json_integer_value(val);
}

static void get_bool(json_t *root, const char *key, bool *dest) {
    json_t *val = json_object_get(root, key);
    if (val) *dest = json_is_true(val);
}

bool general_from_json(json_t *root) {
    if (!root || !json_is_object(root)) return false;

    pthread_mutex_lock(&g_gen_mutex);
    get_str(root, "instance_name", g_gen.instance_name, sizeof(g_gen.instance_name));
    get_str(root, "tsdb_url", g_gen.tsdb_url, sizeof(g_gen.tsdb_url));
    get_str(root, "tsdb_org", g_gen.tsdb_org, sizeof(g_gen.tsdb_org));
    get_str(root, "tsdb_token", g_gen.tsdb_token, sizeof(g_gen.tsdb_token));
    get_int(root, "tsdb_interval", &g_gen.tsdb_interval);
    get_str(root, "event_request", g_gen.event_request, sizeof(g_gen.event_request));
    get_str(root, "sessions_url", g_gen.sessions_url, sizeof(g_gen.sessions_url));
    get_int(root, "sessions_time", &g_gen.sessions_time);

    get_str(root, "http_server_name", g_gen.http_server_name, sizeof(g_gen.http_server_name));
    get_str(root, "http_access_log", g_gen.http_access_log, sizeof(g_gen.http_access_log));
    get_bool(root, "http_disable_sessions", &g_gen.http_disable_sessions);
    get_str(root, "allow_real_ip", g_gen.allow_real_ip, sizeof(g_gen.allow_real_ip));
    get_str(root, "crt_chain", g_gen.crt_chain, sizeof(g_gen.crt_chain));
    get_str(root, "crt_key", g_gen.crt_key, sizeof(g_gen.crt_key));
    get_bool(root, "http_disable_tls", &g_gen.http_disable_tls);
    get_int(root, "control_port", &g_gen.control_port);
    get_str(root, "control_path", g_gen.control_path, sizeof(g_gen.control_path));

    get_str(root, "epg_export_format", g_gen.epg_export_format, sizeof(g_gen.epg_export_format));
    get_str(root, "epg_export", g_gen.epg_export, sizeof(g_gen.epg_export));
    get_bool(root, "http_keep_active_demand", &g_gen.http_keep_active_demand);
    get_int(root, "http_keep_active", &g_gen.http_keep_active);
    get_int(root, "backup_start_delay", &g_gen.backup_start_delay);
    get_int(root, "backup_return_delay", &g_gen.backup_return_delay);
    get_str(root, "textcode", g_gen.textcode, sizeof(g_gen.textcode));
    get_str(root, "service_provider", g_gen.service_provider, sizeof(g_gen.service_provider));
    get_str(root, "network_name", g_gen.network_name, sizeof(g_gen.network_name));
    get_str(root, "http_congestion", g_gen.http_congestion, sizeof(g_gen.http_congestion));
    get_int(root, "cc_limit", &g_gen.cc_limit);
    get_bool(root, "udp_threads", &g_gen.udp_threads);

    get_bool(root, "dvb_bind_by_mac", &g_gen.dvb_bind_by_mac);
    pthread_mutex_unlock(&g_gen_mutex);
    return true;
}
