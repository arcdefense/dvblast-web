#include "analyzer.h"
#include "dvblast.h"
#include "en50221.h"
#include "comm.h"
#include "web_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>

#include <bitstream/mpeg/psi.h>
#include <bitstream/mpeg/psi/descriptors.h>
#include <bitstream/mpeg/psi/pat.h>
#include <bitstream/mpeg/psi/pmt.h>
#include <bitstream/mpeg/psi/desc_09.h>
#include <bitstream/mpeg/psi/desc_0a.h>
#include <bitstream/dvb/si.h>
#include <bitstream/dvb/si/sdt.h>
#include <bitstream/dvb/si/nit.h>
#include <bitstream/dvb/si/desc_40.h>
#include <bitstream/dvb/si/desc_48.h>
#include <bitstream/dvb/si/desc_5a.h>
#include <bitstream/dvb/si/desc_83p28.h>

static const char *stream_type_to_name(uint8_t stream_type) {
    switch (stream_type) {
        case 0x01: return "MPEG-1 Video";
        case 0x02: return "MPEG-2 Video";
        case 0x03: return "MPEG-1 Audio (Layer II)";
        case 0x04: return "MPEG-2 Audio";
        case 0x06: return "Private Data / AC-3 / Subtitles";
        case 0x0f: return "ISO/IEC 13818-7 Audio (AAC ADTS)";
        case 0x11: return "ISO/IEC 14496-3 Audio (AAC LATM/LOAS)";
        case 0x1b: return "H.264 / MPEG-4 AVC Video";
        case 0x24: return "H.265 / HEVC Video";
        case 0x80: return "User Private / EWS";
        case 0x81: return "User Private Audio (AC-3/A52)";
        case 0x86: return "SCTE-35 Digital Splice";
        default:   return "Unknown Stream Type";
    }
}

static const char *stream_type_category(uint8_t stream_type) {
    switch (stream_type) {
        case 0x01:
        case 0x02:
        case 0x1b:
        case 0x24: return "video";
        case 0x03:
        case 0x04:
        case 0x0f:
        case 0x11:
        case 0x81: return "audio";
        case 0x06: return "data/sub";
        default:   return "data";
    }
}

/* Parse a single PSI/SI descriptor to JSON */
static json_t *parse_single_descriptor(const uint8_t *p_desc, uint16_t filter_sid) {
    if (!p_desc) return NULL;
    uint8_t tag = desc_get_tag(p_desc);
    uint8_t len = desc_get_length(p_desc);
    json_t *d = json_object();
    json_object_set_new(d, "type_id", json_integer(tag));

    switch (tag) {
        case 0x09: { /* CAS (Conditional Access) */
            if (desc09_validate(p_desc)) {
                json_object_set_new(d, "type_name", json_string("CAS"));
                json_object_set_new(d, "caid", json_integer(desc09_get_sysid(p_desc)));
                json_object_set_new(d, "pid", json_integer(desc09_get_pid(p_desc)));
                return d;
            }
            break;
        }
        case 0x0a: { /* ISO-639 Language */
            if (desc0a_validate(p_desc)) {
                json_object_set_new(d, "type_name", json_string("Language"));
                char lang[4] = {0};
                uint8_t *p_l = desc0a_get_language(p_desc, 0);
                if (p_l) {
                    const uint8_t *code = desc0an_get_code(p_l);
                    lang[0] = (char)code[0];
                    lang[1] = (char)code[1];
                    lang[2] = (char)code[2];
                    json_object_set_new(d, "audio_type", json_integer(desc0an_get_audiotype(p_l)));
                }
                json_object_set_new(d, "lang", json_string(lang));
                return d;
            }
            break;
        }
        case 0x40: { /* Network Name */
            if (desc40_validate(p_desc)) {
                json_object_set_new(d, "type_name", json_string("Network Name"));
                uint8_t nlen = 0;
                const uint8_t *pname = desc40_get_networkname(p_desc, &nlen);
                if (pname && nlen > 0) {
                    char *name = demux_Iconv(NULL, psz_native_charset, (char *)pname, nlen);
                    if (name) {
                        json_object_set_new(d, "network_name", json_string(name));
                        free(name);
                    } else {
                        char buf[128];
                        int clen = nlen < (int)sizeof(buf) - 1 ? nlen : (int)sizeof(buf) - 1;
                        memcpy(buf, pname, clen);
                        buf[clen] = '\0';
                        json_object_set_new(d, "network_name", json_string(buf));
                    }
                } else {
                    json_object_set_new(d, "network_name", json_string(""));
                }
                return d;
            }
            break;
        }
        case 0x48: { /* Service Descriptor */
            if (desc48_validate(p_desc)) {
                json_object_set_new(d, "type_name", json_string("Service"));
                json_object_set_new(d, "service_type", json_integer(desc48_get_type(p_desc)));
                uint8_t plen = 0, slen = 0;
                const uint8_t *pprov = desc48_get_provider(p_desc, &plen);
                const uint8_t *pserv = desc48_get_service(p_desc, &slen);
                if (pserv && slen > 0) {
                    char *sname = demux_Iconv(NULL, psz_native_charset, (char *)pserv, slen);
                    json_object_set_new(d, "service_name", json_string(sname ? sname : ""));
                    if (sname) free(sname);
                } else {
                    json_object_set_new(d, "service_name", json_string(""));
                }
                if (pprov && plen > 0) {
                    char *pname = demux_Iconv(NULL, psz_native_charset, (char *)pprov, plen);
                    json_object_set_new(d, "service_provider", json_string(pname ? pname : ""));
                    if (pname) free(pname);
                } else {
                    json_object_set_new(d, "service_provider", json_string(""));
                }
                return d;
            }
            break;
        }
        case 0x5a: { /* DVB-T Delivery System */
            if (desc5a_validate(p_desc)) {
                json_object_set_new(d, "type_name", json_string("DVB-T"));
                json_object_set_new(d, "frequency", json_integer(desc5a_get_frequency(p_desc)));
                int bw = desc5a_get_bandwidth(p_desc);
                const char *bw_str = (bw == 0) ? "8 MHz" : (bw == 1) ? "7 MHz" : (bw == 2) ? "6 MHz" : (bw == 3) ? "5 MHz" : "Unknown";
                json_object_set_new(d, "bandwidth", json_string(bw_str));
                int constel = desc5a_get_constellation(p_desc);
                const char *c_str = (constel == 0) ? "QPSK" : (constel == 1) ? "16-QAM" : (constel == 2) ? "64-QAM" : "Unknown";
                json_object_set_new(d, "modulation", json_string(c_str));
                int guard = desc5a_get_guard(p_desc);
                const char *g_str = (guard == 0) ? "1/32" : (guard == 1) ? "1/16" : (guard == 2) ? "1/8" : (guard == 3) ? "1/4" : "Unknown";
                json_object_set_new(d, "guard_interval", json_string(g_str));
                int trans = desc5a_get_transmission(p_desc);
                const char *t_str = (trans == 0) ? "2k" : (trans == 1) ? "8k" : (trans == 2) ? "4k" : "Unknown";
                json_object_set_new(d, "transmission", json_string(t_str));
                return d;
            }
            break;
        }
        case 0x83: { /* Logical Channel Number */
            if (desc83p28_validate(p_desc)) {
                json_object_set_new(d, "type_name", json_string("LCN"));
                json_t *lcn_arr = json_array();
                desc83p28_each_service(p_desc, p_serv) {
                    uint16_t pnr = desc83p28n_get_sid(p_serv);
                    if (filter_sid > 0 && pnr != filter_sid) continue;
                    json_t *item = json_object();
                    json_object_set_new(item, "pnr", json_integer(pnr));
                    json_object_set_new(item, "lcn", json_integer(desc83p28n_get_lcn(p_serv)));
                    json_object_set_new(item, "visible", json_boolean(desc83p28n_get_visible(p_serv)));
                    json_array_append_new(lcn_arr, item);
                }
                json_object_set_new(d, "lcn", lcn_arr);
                return d;
            }
            break;
        }
        default:
            break;
    }

    char tag_str[32];
    snprintf(tag_str, sizeof(tag_str), "Descriptor 0x%02X", tag);
    json_object_set_new(d, "type_name", json_string(tag_str));

    char hex_buf[512];
    int hex_len = 0;
    for (int i = 0; i < len && hex_len < (int)sizeof(hex_buf) - 3; i++) {
        hex_len += snprintf(hex_buf + hex_len, sizeof(hex_buf) - hex_len, "%02x", p_desc[2 + i]);
    }
    hex_buf[hex_len] = '\0';
    json_object_set_new(d, "data", json_string(hex_buf));

    return d;
}

/* Parse a descriptor list */
static json_t *parse_descs_to_json(const uint8_t *p_descs, uint16_t filter_sid) {
    json_t *arr = json_array();
    if (!p_descs || !descs_validate(p_descs)) return arr;
    descs_each_desc(p_descs, p_desc) {
        json_t *d = parse_single_descriptor(p_desc, filter_sid);
        if (d) json_array_append_new(arr, d);
    }
    return arr;
}

/* Parse PAT table to JSON (with optional filter_sid) */
static json_t *parse_pat_to_json(uint8_t *pat_data, size_t pat_len, uint16_t filter_sid) {
    if (!pat_data || pat_len < PSI_HEADER_SIZE) return NULL;
    uint8_t **pp_sections = psi_unpack_sections(pat_data, pat_len);
    if (!pp_sections) return NULL;

    uint8_t i_last_section = psi_table_get_lastsection(pp_sections);
    json_t *pat_obj = json_object();
    json_t *progs_arr = json_array();

    for (uint8_t s = 0; s <= i_last_section; s++) {
        uint8_t *p_section = psi_table_get_section(pp_sections, s);
        if (!p_section || !pat_validate(p_section)) continue;

        if (s == 0) {
            json_object_set_new(pat_obj, "tsid", json_integer(pat_get_tsid(p_section)));
            json_object_set_new(pat_obj, "version", json_integer(psi_get_version(p_section)));
        }

        int j = 0;
        uint8_t *p_prog;
        while ((p_prog = pat_get_program(p_section, j++)) != NULL) {
            uint16_t pnr = patn_get_program(p_prog);
            if (filter_sid > 0 && pnr != filter_sid) continue;
            uint16_t pid = patn_get_pid(p_prog);
            json_t *pr = json_object();
            json_object_set_new(pr, "pnr", json_integer(pnr));
            json_object_set_new(pr, "pid", json_integer(pid));
            json_array_append_new(progs_arr, pr);
        }
    }

    json_object_set_new(pat_obj, "programs", progs_arr);
    psi_table_free(pp_sections);
    free(pp_sections);
    return pat_obj;
}

/* Parse PMT table to JSON */
static json_t *parse_pmt_to_json(uint8_t *pmt_data, size_t pmt_len) {
    if (!pmt_data || pmt_len < PSI_HEADER_SIZE || !pmt_validate(pmt_data)) return NULL;

    json_t *pmt_obj = json_object();
    uint16_t pnr = pmt_get_program(pmt_data);
    uint16_t pcr_pid = pmt_get_pcrpid(pmt_data);
    uint8_t ver = psi_get_version(pmt_data);

    json_object_set_new(pmt_obj, "pnr", json_integer(pnr));
    json_object_set_new(pmt_obj, "version", json_integer(ver));
    json_object_set_new(pmt_obj, "pcr", json_integer(pcr_pid));

    json_object_set_new(pmt_obj, "descriptors", parse_descs_to_json(pmt_get_descs(pmt_data), 0));

    json_t *streams_arr = json_array();
    uint8_t n = 0;
    uint8_t *p_es;
    while ((p_es = pmt_get_es(pmt_data, n++)) != NULL) {
        uint16_t es_pid = pmtn_get_pid(p_es);
        uint8_t stype = pmtn_get_streamtype(p_es);

        json_t *es_obj = json_object();
        json_object_set_new(es_obj, "pid", json_integer(es_pid));
        json_object_set_new(es_obj, "type_id", json_integer(stype));
        json_object_set_new(es_obj, "type_name", json_string(stream_type_category(stype)));
        json_object_set_new(es_obj, "stream_type_name", json_string(stream_type_to_name(stype)));
        json_object_set_new(es_obj, "descriptors", parse_descs_to_json(pmtn_get_descs(p_es), 0));
        json_array_append_new(streams_arr, es_obj);
    }
    json_object_set_new(pmt_obj, "streams", streams_arr);
    return pmt_obj;
}

/* Parse SDT table to JSON (with optional filter_sid) */
static json_t *parse_sdt_to_json(uint8_t *sdt_data, size_t sdt_len, uint16_t filter_sid) {
    if (!sdt_data || sdt_len < PSI_HEADER_SIZE) return NULL;
    uint8_t **pp_sections = psi_unpack_sections(sdt_data, sdt_len);
    if (!pp_sections) return NULL;

    uint8_t i_last_section = psi_table_get_lastsection(pp_sections);
    json_t *sdt_obj = json_object();
    json_t *serv_arr = json_array();

    for (uint8_t s = 0; s <= i_last_section; s++) {
        uint8_t *p_section = psi_table_get_section(pp_sections, s);
        if (!p_section || !sdt_validate(p_section)) continue;

        if (s == 0) {
            json_object_set_new(sdt_obj, "tsid", json_integer(sdt_get_tsid(p_section)));
            json_object_set_new(sdt_obj, "onid", json_integer(sdt_get_onid(p_section)));
            json_object_set_new(sdt_obj, "version", json_integer(psi_get_version(p_section)));
        }

        int j = 0;
        uint8_t *p_service;
        while ((p_service = sdt_get_service(p_section, j++)) != NULL) {
            uint16_t sid = sdtn_get_sid(p_service);
            if (filter_sid > 0 && sid != filter_sid) continue;
            json_t *sv = json_object();
            json_object_set_new(sv, "sid", json_integer(sid));
            json_object_set_new(sv, "running", json_integer(sdtn_get_running(p_service)));
            json_object_set_new(sv, "ca", json_boolean(sdtn_get_ca(p_service)));
            json_object_set_new(sv, "descriptors", parse_descs_to_json(sdtn_get_descs(p_service), filter_sid));
            json_array_append_new(serv_arr, sv);
        }
    }

    json_object_set_new(sdt_obj, "services", serv_arr);
    psi_table_free(pp_sections);
    free(pp_sections);
    return sdt_obj;
}

/* Parse NIT table to JSON (with optional filter_sid) */
static json_t *parse_nit_to_json(uint8_t *nit_data, size_t nit_len, uint16_t filter_sid) {
    if (!nit_data || nit_len < PSI_HEADER_SIZE) return NULL;
    uint8_t **pp_sections = psi_unpack_sections(nit_data, nit_len);
    if (!pp_sections) return NULL;

    uint8_t i_last_section = psi_table_get_lastsection(pp_sections);
    json_t *nit_obj = json_object();
    json_t *ts_arr = json_array();

    for (uint8_t s = 0; s <= i_last_section; s++) {
        uint8_t *p_section = psi_table_get_section(pp_sections, s);
        if (!p_section || !nit_validate(p_section)) continue;

        if (s == 0) {
            json_object_set_new(nit_obj, "network_id", json_integer(nit_get_nid(p_section)));
            json_object_set_new(nit_obj, "version", json_integer(psi_get_version(p_section)));
            json_object_set_new(nit_obj, "descriptors", parse_descs_to_json(nit_get_descs(p_section), filter_sid));
        }

        int j = 0;
        uint8_t *p_ts;
        while ((p_ts = nit_get_ts(p_section, j++)) != NULL) {
            uint16_t tsid = nitn_get_tsid(p_ts);
            uint16_t onid = nitn_get_onid(p_ts);
            json_t *t = json_object();
            json_object_set_new(t, "tsid", json_integer(tsid));
            json_object_set_new(t, "onid", json_integer(onid));
            json_object_set_new(t, "descriptors", parse_descs_to_json(nitn_get_descs(p_ts), filter_sid));
            json_array_append_new(ts_arr, t);
        }
    }

    json_object_set_new(nit_obj, "streams", ts_arr);
    psi_table_free(pp_sections);
    free(pp_sections);
    return nit_obj;
}

/* Query worker UNIX socket for raw binary sections or stats */
static uint8_t *query_worker_socket(int adapter_idx, uint8_t cmd, const uint8_t *req_payload,
                                    size_t req_len, size_t *out_size) {
    *out_size = 0;
    char srv_path[64];
    snprintf(srv_path, sizeof(srv_path), "/tmp/dvblast_ad%d.sock", adapter_idx);
    if (access(srv_path, F_OK) != 0) return NULL;

    static volatile uint32_t s_query_seq = 0;
    uint32_t seq = __sync_fetch_and_add(&s_query_seq, 1);
    struct sockaddr_un sun_client, sun_server;
    char client_path[sizeof(sun_client.sun_path)];
    snprintf(client_path, sizeof(client_path), "/tmp/dvblast_ana_%d_%d_%lx_%u.sock",
             adapter_idx, getpid(), (unsigned long)pthread_self(), seq);
    unlink(client_path);

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return NULL;

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms timeout max */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int rcvbuf = 512 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    memset(&sun_client, 0, sizeof(sun_client));
    sun_client.sun_family = AF_UNIX;
    snprintf(sun_client.sun_path, sizeof(sun_client.sun_path), "%s", client_path);

    if (bind(fd, (struct sockaddr *)&sun_client, sizeof(sun_client)) < 0) {
        close(fd);
        unlink(client_path);
        return NULL;
    }

    memset(&sun_server, 0, sizeof(sun_server));
    sun_server.sun_family = AF_UNIX;
    strncpy(sun_server.sun_path, srv_path, sizeof(sun_server.sun_path) - 1);

    uint8_t send_buf[COMM_BUFFER_SIZE];
    send_buf[0] = COMM_HEADER_MAGIC;
    send_buf[1] = cmd;
    memset(send_buf + 2, 0, COMM_HEADER_SIZE - 2);

    size_t send_len = COMM_HEADER_SIZE;
    if (req_payload && req_len > 0) {
        if (send_len + req_len > sizeof(send_buf)) req_len = sizeof(send_buf) - send_len;
        memcpy(send_buf + send_len, req_payload, req_len);
        send_len += req_len;
    }

    if (sendto(fd, send_buf, send_len, 0, (struct sockaddr *)&sun_server, sizeof(sun_server)) < 0) {
        close(fd);
        unlink(client_path);
        return NULL;
    }

    size_t alloc_sz = 65536;
    uint8_t *res_buf = malloc(alloc_sz);
    if (!res_buf) {
        close(fd);
        unlink(client_path);
        return NULL;
    }

    uint8_t chunk[COMM_MAX_MSG_CHUNK + COMM_HEADER_SIZE];
    ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
    if (n <= (ssize_t)COMM_HEADER_SIZE) {
        free(res_buf);
        close(fd);
        unlink(client_path);
        return NULL;
    }

    uint32_t total_expected = *(uint32_t *)&chunk[4];
    size_t payload_len = (size_t)(n - COMM_HEADER_SIZE);
    memcpy(res_buf, chunk + COMM_HEADER_SIZE, payload_len);
    *out_size = payload_len;

    /* Handle multi-packet responses (e.g. full 8192 PIDs = 8192 * 48 bytes ~ 393KB) */
    while (*out_size + COMM_HEADER_SIZE < total_expected) {
        n = recv(fd, chunk, sizeof(chunk), 0);
        if (n <= 0) break;
        size_t c_len = (size_t)n;
        if (*out_size + c_len > alloc_sz) {
            alloc_sz = (*out_size + c_len) * 2;
            uint8_t *nb = realloc(res_buf, alloc_sz);
            if (!nb) break;
            res_buf = nb;
        }
        memcpy(res_buf + *out_size, chunk, c_len);
        *out_size += c_len;
    }

    close(fd);
    unlink(client_path);
    return res_buf;
}

void analyzer_init(void) {
}

void analyzer_cleanup(void) {
}

json_t *analyzer_get_stream(const char *stream_id) {
    if (!stream_id || !*stream_id) return NULL;

    web_stream_config_t st;
    bool found_st = false;
    pthread_mutex_lock(&g_gateway.lock);
    for (int i = 0; i < g_gateway.num_streams; i++) {
        if (strcmp(g_gateway.streams[i].id, stream_id) == 0 ||
            (g_gateway.streams[i].name[0] && strcmp(g_gateway.streams[i].name, stream_id) == 0)) {
            st = g_gateway.streams[i];
            found_st = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_gateway.lock);

    uint16_t sid = 0;
    int adapter_idx = 0;
    char channel_name[128] = "Unknown Channel";
    char provider_name[128] = "Unknown Provider";

    if (found_st) {
        sid = st.service_id;
        adapter_idx = st.adapter_idx;
        snprintf(channel_name, sizeof(channel_name), "%s", st.name);
    } else {
        /* Fallback: parse sid if stream_id is like 'spts_20' or number */
        if (strncmp(stream_id, "spts_", 5) == 0) sid = (uint16_t)atoi(stream_id + 5);
        else sid = (uint16_t)atoi(stream_id);
    }

    if (sid == 0) return NULL;

    /* Retrieve PID statistics and PMT, PAT, SDT, NIT tables */
    ts_pid_info_t *pids_table = NULL;
    uint8_t *pmt_data = NULL;
    size_t pmt_len = 0;
    uint8_t *pat_data = NULL;
    size_t pat_len = 0;
    uint8_t *sdt_data = NULL;
    size_t sdt_len = 0;
    uint8_t *nit_data = NULL;
    size_t nit_len = 0;

    if (adapter_idx == i_adapter) {
        /* Primary Adapter: read directly from Demux memory */
        pids_table = calloc(MAX_PIDS, sizeof(ts_pid_info_t));
        if (pids_table) {
            demux_get_PIDS_info((uint8_t *)pids_table);
        }
        pmt_data = demux_get_packed_PMT(sid, (unsigned int *)&pmt_len);
        pat_data = demux_get_current_packed_PAT((unsigned int *)&pat_len);
        sdt_data = demux_get_current_packed_SDT((unsigned int *)&sdt_len);
        nit_data = demux_get_current_packed_NIT((unsigned int *)&nit_len);
    } else {
        /* Secondary Adapter: query worker via UNIX socket */
        size_t pids_sz = 0;
        uint8_t *pids_raw = query_worker_socket(adapter_idx, CMD_GET_PIDS, NULL, 0, &pids_sz);
        if (pids_raw && pids_sz >= sizeof(ts_pid_info_t) * 100) {
            pids_table = (ts_pid_info_t *)pids_raw;
        }

        uint8_t sid_be[2] = { (uint8_t)((sid >> 8) & 0xFF), (uint8_t)(sid & 0xFF) };
        pmt_data = query_worker_socket(adapter_idx, CMD_GET_PMT, sid_be, 2, &pmt_len);
        pat_data = query_worker_socket(adapter_idx, CMD_GET_PAT, NULL, 0, &pat_len);
        sdt_data = query_worker_socket(adapter_idx, CMD_GET_SDT, NULL, 0, &sdt_len);
        nit_data = query_worker_socket(adapter_idx, CMD_GET_NIT, NULL, 0, &nit_len);
    }

    json_t *root = json_object();
    json_object_set_new(root, "ok", json_true());
    json_object_set_new(root, "stream_id", json_string(stream_id));
    json_object_set_new(root, "service_id", json_integer(sid));
    json_object_set_new(root, "adapter_idx", json_integer(adapter_idx));
    json_object_set_new(root, "channel_name", json_string(channel_name));

    /* Parse PSI/SI Tree (Astra Cesbo compatible structure) filtered to this analyzed stream */
    json_t *psi_obj = json_object();
    if (pat_data) {
        json_t *pat_json = parse_pat_to_json(pat_data, pat_len, sid);
        if (pat_json) json_object_set_new(psi_obj, "pat", pat_json);
        free(pat_data);
    }
    if (pmt_data) {
        json_t *pmt_json = parse_pmt_to_json(pmt_data, pmt_len);
        if (pmt_json) json_object_set_new(psi_obj, "pmt", pmt_json);
    }
    if (sdt_data) {
        json_t *sdt_json = parse_sdt_to_json(sdt_data, sdt_len, sid);
        if (sdt_json) json_object_set_new(psi_obj, "sdt", sdt_json);
        free(sdt_data);
    }
    if (nit_data) {
        json_t *nit_json = parse_nit_to_json(nit_data, nit_len, sid);
        if (nit_json) json_object_set_new(psi_obj, "nit", nit_json);
        free(nit_data);
    }
    json_object_set_new(root, "psi", psi_obj);

    /* Find channel details from adapter cache */
    web_adapter_t *ad = web_state_find_adapter_by_idx(adapter_idx);
    if (ad) {
        for (int i = 0; i < ad->num_channels; i++) {
            if (ad->channels[i].service_id == sid) {
                if (ad->channels[i].name[0]) snprintf(channel_name, sizeof(channel_name), "%s", ad->channels[i].name);
                if (ad->channels[i].provider[0]) snprintf(provider_name, sizeof(provider_name), "%s", ad->channels[i].provider);
                break;
            }
        }
    }
    json_object_set_new(root, "provider", json_string(provider_name));

    uint64_t total_bitrate_bps = 0;
    uint64_t total_cc_errors = 0;
    uint64_t total_ts_errors = 0;
    uint64_t total_packets = 0;
    bool is_scrambled = false;

    json_t *pids_arr = json_array();

    if (pmt_data && pmt_len >= PSI_HEADER_SIZE && pmt_validate(pmt_data)) {
        uint16_t pcr_pid = pmt_get_pcrpid(pmt_data);
        bool pcr_in_es = false;

        /* Elementary Streams */
        uint8_t n = 0;
        uint8_t *p_es;
        while ((p_es = pmt_get_es(pmt_data, n++)) != NULL) {
            uint16_t es_pid = pmtn_get_pid(p_es);
            uint8_t stype = pmtn_get_streamtype(p_es);
            if (es_pid == pcr_pid) pcr_in_es = true;

            uint64_t br = 0;
            uint64_t cc = 0;
            uint64_t ts_err = 0;
            uint64_t pkts = 0;
            bool sc = false;

            if (pids_table && es_pid < MAX_PIDS) {
                ts_pid_info_t *pi = &pids_table[es_pid];
                br = (uint64_t)pi->i_bytes_per_sec * 8;
                cc = pi->i_cc_errors;
                ts_err = pi->i_transport_errors;
                pkts = pi->i_packets;
                sc = (pi->i_scrambling != 0);

                total_bitrate_bps += br;
                total_cc_errors += cc;
                total_ts_errors += ts_err;
                total_packets += pkts;
                if (sc) is_scrambled = true;
            }

            char desc_buf[128];
            const char *type_name = stream_type_to_name(stype);
            if (es_pid == pcr_pid) {
                snprintf(desc_buf, sizeof(desc_buf), "%s (PCR)", type_name);
            } else {
                snprintf(desc_buf, sizeof(desc_buf), "%s", type_name);
            }

            json_t *pobj = json_object();
            json_object_set_new(pobj, "pid", json_integer(es_pid));
            char hex_pid[16]; snprintf(hex_pid, sizeof(hex_pid), "0x%04X", es_pid);
            json_object_set_new(pobj, "pid_hex", json_string(hex_pid));
            json_object_set_new(pobj, "stream_type", json_integer(stype));
            json_object_set_new(pobj, "stream_type_name", json_string(type_name));
            json_object_set_new(pobj, "type", json_string(stream_type_category(stype)));
            json_object_set_new(pobj, "desc", json_string(desc_buf));
            json_object_set_new(pobj, "is_pcr", json_boolean(es_pid == pcr_pid));
            json_object_set_new(pobj, "bitrate_bps", json_integer(br));
            json_object_set_new(pobj, "bitrate_kbps", json_integer(br / 1000));
            json_object_set_new(pobj, "packets", json_integer(pkts));
            json_object_set_new(pobj, "cc_errors", json_integer(cc));
            json_object_set_new(pobj, "ts_errors", json_integer(ts_err));
            json_object_set_new(pobj, "scrambled", json_boolean(sc));
            json_array_append_new(pids_arr, pobj);
        }

        /* If PCR PID is on a dedicated separate PID not in ES */
        if (!pcr_in_es && pcr_pid > 0 && pcr_pid < 0x1fff && pids_table && pcr_pid < MAX_PIDS) {
            ts_pid_info_t *pi = &pids_table[pcr_pid];
            uint64_t br = (uint64_t)pi->i_bytes_per_sec * 8;
            total_bitrate_bps += br;
            total_cc_errors += pi->i_cc_errors;
            total_ts_errors += pi->i_transport_errors;
            total_packets += pi->i_packets;

            json_t *pobj = json_object();
            json_object_set_new(pobj, "pid", json_integer(pcr_pid));
            char hex_pid[16]; snprintf(hex_pid, sizeof(hex_pid), "0x%04X", pcr_pid);
            json_object_set_new(pobj, "pid_hex", json_string(hex_pid));
            json_object_set_new(pobj, "type", json_string("pcr"));
            json_object_set_new(pobj, "desc", json_string("Program Clock Reference (PCR)"));
            json_object_set_new(pobj, "is_pcr", json_true());
            json_object_set_new(pobj, "bitrate_bps", json_integer(br));
            json_object_set_new(pobj, "bitrate_kbps", json_integer(br / 1000));
            json_object_set_new(pobj, "packets", json_integer(pi->i_packets));
            json_object_set_new(pobj, "cc_errors", json_integer(pi->i_cc_errors));
            json_object_set_new(pobj, "ts_errors", json_integer(pi->i_transport_errors));
            json_object_set_new(pobj, "scrambled", json_boolean(pi->i_scrambling != 0));
            json_array_append_new(pids_arr, pobj);
        }
    } else {
        /* Fallback if PMT was not packed: check if channel has known video/audio PIDs */
        if (ad) {
            for (int i = 0; i < ad->num_channels; i++) {
                if (ad->channels[i].service_id == sid) {
                    uint16_t vpid = ad->channels[i].video_pid;
                    if (vpid > 0 && pids_table && vpid < MAX_PIDS) {
                        ts_pid_info_t *pi = &pids_table[vpid];
                        uint64_t br = (uint64_t)pi->i_bytes_per_sec * 8;
                        total_bitrate_bps += br;
                        total_cc_errors += pi->i_cc_errors;

                        json_t *pobj = json_object();
                        json_object_set_new(pobj, "pid", json_integer(vpid));
                        char hex_pid[16]; snprintf(hex_pid, sizeof(hex_pid), "0x%04X", vpid);
                        json_object_set_new(pobj, "pid_hex", json_string(hex_pid));
                        json_object_set_new(pobj, "type", json_string("video"));
                        json_object_set_new(pobj, "desc", json_string(stream_type_to_name(ad->channels[i].video_type)));
                        json_object_set_new(pobj, "bitrate_bps", json_integer(br));
                        json_object_set_new(pobj, "bitrate_kbps", json_integer(br / 1000));
                        json_object_set_new(pobj, "packets", json_integer(pi->i_packets));
                        json_object_set_new(pobj, "cc_errors", json_integer(pi->i_cc_errors));
                        json_object_set_new(pobj, "ts_errors", json_integer(pi->i_transport_errors));
                        json_object_set_new(pobj, "scrambled", json_boolean(pi->i_scrambling != 0));
                        json_array_append_new(pids_arr, pobj);
                    }
                    break;
                }
            }
        }
    }

    json_object_set_new(root, "pids", pids_arr);
    json_object_set_new(root, "elementary_pids_count", json_integer(json_array_size(pids_arr)));
    json_object_set_new(root, "total_bitrate_bps", json_integer(total_bitrate_bps));
    json_object_set_new(root, "total_bitrate_kbps", json_integer(total_bitrate_bps / 1000));
    json_object_set_new(root, "total_bitrate_mbps", json_real((double)total_bitrate_bps / 1000000.0));
    json_object_set_new(root, "bitrate_mbps", json_real((double)total_bitrate_bps / 1000000.0));
    json_object_set_new(root, "total_cc_errors", json_integer(total_cc_errors));
    json_object_set_new(root, "total_ts_errors", json_integer(total_ts_errors));
    json_object_set_new(root, "total_transport_errors", json_integer(total_ts_errors));
    json_object_set_new(root, "total_packets", json_integer(total_packets));
    json_object_set_new(root, "scrambled", json_boolean(is_scrambled));

    /* Global Status Assessment */
    const char *status_str = "HEALTHY";
    if (total_cc_errors > 0 || total_ts_errors > 0) status_str = "DISCONTINUITY_WARNING";
    if (total_bitrate_bps == 0) status_str = "OFF_AIR";
    json_object_set_new(root, "health_status", json_string(status_str));

    if (pmt_data) free(pmt_data);
    if (pids_table) free(pids_table);

    return root;
}

json_t *analyzer_get_adapter(int adapter_idx) {
    web_adapter_t *ad = web_state_find_adapter_by_idx(adapter_idx);
    if (!ad) return NULL;

    json_t *root = json_object();
    json_object_set_new(root, "ok", json_true());
    json_object_set_new(root, "adapter_idx", json_integer(adapter_idx));
    json_object_set_new(root, "name", json_string(ad->name));
    json_object_set_new(root, "locked", json_boolean(ad->locked));
    json_object_set_new(root, "snr_db", json_real(ad->snr_db));
    json_object_set_new(root, "signal_percent", json_integer(ad->signal_percent));

    /* Fetch adapter PSI/SI tables */
    uint8_t *pat_data = NULL;
    size_t pat_len = 0;
    uint8_t *sdt_data = NULL;
    size_t sdt_len = 0;
    uint8_t *nit_data = NULL;
    size_t nit_len = 0;

    if (adapter_idx == i_adapter) {
        pat_data = demux_get_current_packed_PAT((unsigned int *)&pat_len);
        sdt_data = demux_get_current_packed_SDT((unsigned int *)&sdt_len);
        nit_data = demux_get_current_packed_NIT((unsigned int *)&nit_len);
    } else {
        pat_data = query_worker_socket(adapter_idx, CMD_GET_PAT, NULL, 0, &pat_len);
        sdt_data = query_worker_socket(adapter_idx, CMD_GET_SDT, NULL, 0, &sdt_len);
        nit_data = query_worker_socket(adapter_idx, CMD_GET_NIT, NULL, 0, &nit_len);
    }

    json_t *psi_obj = json_object();
    if (pat_data) {
        json_t *pat_json = parse_pat_to_json(pat_data, pat_len, 0);
        if (pat_json) json_object_set_new(psi_obj, "pat", pat_json);
        free(pat_data);
    }
    if (sdt_data) {
        json_t *sdt_json = parse_sdt_to_json(sdt_data, sdt_len, 0);
        if (sdt_json) json_object_set_new(psi_obj, "sdt", sdt_json);
        free(sdt_data);
    }
    if (nit_data) {
        json_t *nit_json = parse_nit_to_json(nit_data, nit_len, 0);
        if (nit_json) json_object_set_new(psi_obj, "nit", nit_json);
        free(nit_data);
    }

    json_t *channels_arr = json_array();
    json_t *pmt_list = json_array();
    for (int i = 0; i < ad->num_channels; i++) {
        char s_id[32];
        snprintf(s_id, sizeof(s_id), "%u", ad->channels[i].service_id);
        json_t *chan_analysis = analyzer_get_stream(s_id);
        if (chan_analysis) {
            json_t *ch_psi = json_object_get(chan_analysis, "psi");
            if (ch_psi) {
                json_t *ch_pmt = json_object_get(ch_psi, "pmt");
                if (ch_pmt) {
                    json_array_append(pmt_list, ch_pmt);
                }
            }
            json_array_append_new(channels_arr, chan_analysis);
        }
    }
    json_object_set_new(psi_obj, "pmt", pmt_list);
    json_object_set_new(root, "psi", psi_obj);
    json_object_set_new(root, "channels", channels_arr);

    return root;
}
