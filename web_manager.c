#include "web_manager.h"
#include "dvblast.h"
#include "modules/softcam/softcam.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/dvb/frontend.h>
#include <pthread.h>

#ifndef MAX_DTV_STATS
#define MAX_DTV_STATS 4
#endif

extern int i_frontend;
extern pthread_t g_main_thread_id;
void demux_ExtractDiscoveredChannels(void);
void demux_TriggerScan(void);
void web_manager_notify_async(void);

typedef struct {
    int adapter_idx;
    char adapter_id[64];
    pid_t pid;
    bool running;
    uint64_t frequency;
    int bandwidth;
    char delsys[16];
} dvb_worker_proc_t;

static dvb_worker_proc_t g_workers[MAX_WEB_ADAPTERS];

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    web_action_type_t type;
    int adapter_idx;
    char adapter_id[64];
    bool done;
    bool success;
} web_action_queue_t;

static web_action_queue_t g_async_action = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
    .type = WEB_ACTION_NONE,
};

static void web_manager_stop_worker_internal(int adapter_idx) {
    for (int i = 0; i < MAX_WEB_ADAPTERS; i++) {
        if (g_workers[i].adapter_idx == adapter_idx) {
            pid_t pid = g_workers[i].pid;
            if (pid > 0 && g_workers[i].running) {
                web_state_log("INFO", "Stopping worker PID %d for adapter %d", pid, adapter_idx);
                kill(pid, SIGTERM);
                /* Wait gracefully up to 1.5s for worker to release DVB hardware */
                bool exited = false;
                for (int wait_ms = 0; wait_ms < 1500; wait_ms += 50) {
                    int status = 0;
                    pid_t res = waitpid(pid, &status, WNOHANG);
                    if (res > 0 || (res < 0 && errno == ECHILD)) {
                        exited = true;
                        break;
                    }
                    usleep(50000);
                }
                if (!exited) {
                    web_state_log("WARN", "Worker PID %d did not exit on SIGTERM, sending SIGKILL", pid);
                    kill(pid, SIGKILL);
                    int status = 0;
                    waitpid(pid, &status, 0);
                }
            }
            g_workers[i].running = false;
            g_workers[i].pid = 0;
        }
    }
    char conf_path[64], sock_path[64];
    snprintf(conf_path, sizeof(conf_path), "/tmp/dvblast_ad%d.conf", adapter_idx);
    snprintf(sock_path, sizeof(sock_path), "/tmp/dvblast_ad%d.sock", adapter_idx);
    unlink(conf_path);
    unlink(sock_path);
}

static bool write_worker_config(int adapter_idx, const web_stream_config_t *streams, int active_streams) {
    char conf_path[64];
    snprintf(conf_path, sizeof(conf_path), "/tmp/dvblast_ad%d.conf", adapter_idx);
    FILE *fp = fopen(conf_path, "w");
    if (!fp) {
        web_state_log("ERROR", "Failed to write worker config file %s", conf_path);
        return false;
    }
    if (active_streams == 0) {
        fprintf(fp, "# idle\n");
    } else {
        for (int i = 0; i < active_streams; i++) {
            const char *proto = streams[i].is_rtp ? "" : "/udp";
            char ttl_str[32] = "";
            if (streams[i].ttl > 0) {
                snprintf(ttl_str, sizeof(ttl_str), "/ttl=%d", streams[i].ttl);
            }
            if (streams[i].service_id > 0) {
                fprintf(fp, "%s:%d%s%s/dvb/epg 1 %d\n", streams[i].ip, streams[i].port, proto, ttl_str, streams[i].service_id);
            } else {
                fprintf(fp, "%s:%d%s%s 1 *\n", streams[i].ip, streams[i].port, proto, ttl_str);
            }
        }
    }
    fclose(fp);
    return true;
}

void web_manager_sync_worker(int adapter_idx) {
    if (adapter_idx == i_adapter) {
        return; /* Primary adapter runs directly inside Master process */
    }

    web_adapter_t *ad = web_state_find_adapter_by_idx(adapter_idx);
    if (!ad || !ad->enabled) {
        web_manager_stop_worker_internal(adapter_idx);
        return;
    }

    /* Count active enabled streams for this adapter */
    pthread_mutex_lock(&g_gateway.lock);
    int active_streams = 0;
    web_stream_config_t streams_for_ad[MAX_WEB_STREAMS];
    for (int i = 0; i < g_gateway.num_streams; i++) {
        if (g_gateway.streams[i].enabled && g_gateway.streams[i].adapter_idx == adapter_idx) {
            streams_for_ad[active_streams++] = g_gateway.streams[i];
        }
    }
    pthread_mutex_unlock(&g_gateway.lock);

    const char *target_delsys = (ad->delsys[0] ? ad->delsys : "DVBT2");
    int target_bw = (ad->bandwidth > 0 ? ad->bandwidth : 8);

    char conf_path[64], sock_path[64];
    snprintf(conf_path, sizeof(conf_path), "/tmp/dvblast_ad%d.conf", adapter_idx);
    snprintf(sock_path, sizeof(sock_path), "/tmp/dvblast_ad%d.sock", adapter_idx);

    /* Check if worker is already running with matching RF parameters */
    dvb_worker_proc_t *existing_worker = NULL;
    for (int i = 0; i < MAX_WEB_ADAPTERS; i++) {
        if (g_workers[i].adapter_idx == adapter_idx && g_workers[i].running && g_workers[i].pid > 0) {
            existing_worker = &g_workers[i];
            break;
        }
    }

    if (existing_worker) {
        if (kill(existing_worker->pid, 0) == 0 &&
            existing_worker->frequency == ad->frequency &&
            existing_worker->bandwidth == target_bw &&
            strcmp(existing_worker->delsys, target_delsys) == 0) {
            /* Same RF tuning: write config and reload outputs via SIGHUP without dropping lock */
            write_worker_config(adapter_idx, streams_for_ad, active_streams);
            kill(existing_worker->pid, SIGHUP);
            web_state_log("INFO", "Sent SIGHUP reload to worker PID %d (Adapter %s, %d streams)",
                          existing_worker->pid, ad->id, active_streams);
            return;
        }
        /* Parameters changed or process dead: stop old worker before respawning */
        web_manager_stop_worker_internal(adapter_idx);
    }

    /* Write fresh worker configuration file */
    write_worker_config(adapter_idx, streams_for_ad, active_streams);

    char exe_path[1024];
    ssize_t exelen = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exelen > 0) {
        exe_path[exelen] = '\0';
    } else {
        snprintf(exe_path, sizeof(exe_path), "./dvblast");
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* Close all inherited descriptors except stdio */
        int max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0 || max_fd > 4096) max_fd = 1024;
        for (int fd = 3; fd < max_fd; fd++) {
            close(fd);
        }

        char sz_ad[16], sz_fe[16], sz_freq[32], sz_bw[16], sz_srate[32], sz_vol[16], sz_diseqc[16];
        char sz_uni_scr[16], sz_uni_freq[16], sz_uni_pos[16], sz_uncommitted[16];
        char sz_fec[16], sz_rolloff[16], sz_bufsize[32];
        char sz_lof1[16], sz_lof2[16], sz_slof[16];
        snprintf(sz_ad, sizeof(sz_ad), "%d", ad->adapter_idx);
        snprintf(sz_fe, sizeof(sz_fe), "%d", ad->frontend_idx);
        snprintf(sz_freq, sizeof(sz_freq), "%llu", (unsigned long long)ad->frequency);
        snprintf(sz_bw, sizeof(sz_bw), "%d", target_bw);
        snprintf(sz_srate, sizeof(sz_srate), "%u", ad->symbol_rate);
        snprintf(sz_vol, sizeof(sz_vol), "%d", ad->voltage);
        snprintf(sz_diseqc, sizeof(sz_diseqc), "%d", ad->diseqc);
        snprintf(sz_uni_scr, sizeof(sz_uni_scr), "%d", ad->uni_scr);
        snprintf(sz_uni_freq, sizeof(sz_uni_freq), "%u", ad->uni_frequency);
        snprintf(sz_uni_pos, sizeof(sz_uni_pos), "%s", ad->uni_pos[0] ? ad->uni_pos : "A");
        snprintf(sz_uncommitted, sizeof(sz_uncommitted), "%d", ad->uncommitted);
        snprintf(sz_fec, sizeof(sz_fec), "%d", ad->fec);
        snprintf(sz_rolloff, sizeof(sz_rolloff), "%d", ad->rolloff);
        snprintf(sz_bufsize, sizeof(sz_bufsize), "%llu", (unsigned long long)(ad->buffer_size > 0 ? (uint64_t)ad->buffer_size * 1048576ULL : 67108864ULL));
        snprintf(sz_lof1, sizeof(sz_lof1), "%u", ad->lof1 ? ad->lof1 : 9750);
        snprintf(sz_lof2, sizeof(sz_lof2), "%u", ad->lof2 ? ad->lof2 : 10600);
        snprintf(sz_slof, sizeof(sz_slof), "%u", ad->slof ? ad->slof : 11700);

        char *argv[64];
        int argc = 0;
        argv[argc++] = exe_path;
        argv[argc++] = "--disable-web";
        argv[argc++] = "-a"; argv[argc++] = sz_ad;

        char sz_satip_src[512] = {0};
        if (strcasecmp(target_delsys, "SATIP") == 0 || ad->satip_url[0]) {
            /* SAT>IP or Network TS Ingestion */
            if (ad->satip_url[0]) {
                const char *src = ad->satip_url;
                bool is_raw_udp = false;
                if (strncmp(src, "udp://", 6) == 0) {
                    src += 6;
                    is_raw_udp = true;
                } else if (strncmp(src, "rtp://", 6) == 0) {
                    src += 6;
                }
                char temp[512];
                if (*src != '@' && strchr(src, ':')) {
                    snprintf(temp, sizeof(temp), "@%s", src);
                } else {
                    snprintf(temp, sizeof(temp), "%s", src);
                }

                if (is_raw_udp && !strstr(temp, "/udp")) {
                    snprintf(sz_satip_src, sizeof(sz_satip_src), "%s/udp", temp);
                } else {
                    snprintf(sz_satip_src, sizeof(sz_satip_src), "%s", temp);
                }
                argv[argc++] = "-D"; argv[argc++] = sz_satip_src;
            }
        } else {
            /* Physical DVB Frontend Tuning */
            argv[argc++] = "-n"; argv[argc++] = sz_fe;
            argv[argc++] = "-f"; argv[argc++] = sz_freq;
            argv[argc++] = "-5"; argv[argc++] = (char *)target_delsys;
            if (strcasecmp(target_delsys, "DVBT") == 0 || strcasecmp(target_delsys, "DVBT2") == 0 || strcasecmp(target_delsys, "ISDBT") == 0) {
                argv[argc++] = "-b"; argv[argc++] = sz_bw;
            }
            if (ad->symbol_rate > 0) {
                argv[argc++] = "-s"; argv[argc++] = sz_srate;
            }
            if (ad->voltage > 0) {
                argv[argc++] = "-v"; argv[argc++] = sz_vol;
            }
            if (ad->diseqc > 0) {
                argv[argc++] = "-S"; argv[argc++] = sz_diseqc;
            }
            if (ad->uncommitted > 0) {
                argv[argc++] = "-k"; argv[argc++] = sz_uncommitted;
            }
            if (ad->lnb_mode[0]) {
                argv[argc++] = "--lnb-mode"; argv[argc++] = ad->lnb_mode;
            }
            if (ad->uni_scr > 0) {
                argv[argc++] = "--unicable-slot"; argv[argc++] = sz_uni_scr;
            }
            if (ad->uni_frequency > 0) {
                argv[argc++] = "--unicable-freq"; argv[argc++] = sz_uni_freq;
            }
            if (ad->uni_pos[0]) {
                argv[argc++] = "--unicable-pos"; argv[argc++] = sz_uni_pos;
            }
            if (ad->diseqc_cmd[0]) {
                argv[argc++] = "--diseqc-cmd"; argv[argc++] = ad->diseqc_cmd;
            }
            if (ad->modulation[0]) {
                argv[argc++] = "-m"; argv[argc++] = ad->modulation;
            }
            if (ad->fec > 0 && ad->fec != 999) {
                argv[argc++] = "-F"; argv[argc++] = sz_fec;
            }
            if (ad->rolloff > 0) {
                argv[argc++] = "-R"; argv[argc++] = sz_rolloff;
            }
            if (ad->lof1 > 0) {
                argv[argc++] = "--lof1"; argv[argc++] = sz_lof1;
            }
            if (ad->lof2 > 0) {
                argv[argc++] = "--lof2"; argv[argc++] = sz_lof2;
            }
            if (ad->slof > 0) {
                argv[argc++] = "--slof"; argv[argc++] = sz_slof;
            }
            if (ad->buffer_size > 0) {
                argv[argc++] = "-2"; argv[argc++] = sz_bufsize;
            }
        }
        argv[argc++] = "-C";
        argv[argc++] = "-e";
        argv[argc++] = "-u";
        argv[argc++] = "-w";
        argv[argc++] = "-c"; argv[argc++] = conf_path;
        argv[argc++] = "-r"; argv[argc++] = sock_path;
        argv[argc++] = "-q";
        argv[argc] = NULL;

        execv(exe_path, argv);
        _exit(127);
    } else if (pid > 0) {
        for (int i = 0; i < MAX_WEB_ADAPTERS; i++) {
            if (!g_workers[i].running || g_workers[i].adapter_idx == adapter_idx) {
                g_workers[i].adapter_idx = adapter_idx;
                snprintf(g_workers[i].adapter_id, sizeof(g_workers[i].adapter_id), "%s", ad->id);
                g_workers[i].pid = pid;
                g_workers[i].running = true;
                g_workers[i].frequency = ad->frequency;
                g_workers[i].bandwidth = target_bw;
                snprintf(g_workers[i].delsys, sizeof(g_workers[i].delsys), "%s", target_delsys);
                break;
            }
        }
        web_state_log("INFO", "Spawned isolated worker PID %d for Adapter %s (/dev/dvb/adapter%d, %d streams, freq=%llu Hz)",
                      pid, ad->id, ad->adapter_idx, active_streams, (unsigned long long)ad->frequency);
    }
}

void web_manager_sync_workers(void) {
    pthread_mutex_lock(&g_gateway.lock);
    int ad_count = g_gateway.num_adapters;
    int ad_indices[MAX_WEB_ADAPTERS];
    for (int i = 0; i < ad_count; i++) {
        ad_indices[i] = g_gateway.adapters[i].adapter_idx;
    }
    pthread_mutex_unlock(&g_gateway.lock);

    for (int i = 0; i < ad_count; i++) {
        if (ad_indices[i] != i_adapter) {
            web_manager_sync_worker(ad_indices[i]);
        }
    }
}

void web_manager_poll_secondary_telemetry(void) {
    /* Reap and auto-restart any died child worker processes */
    for (int i = 0; i < MAX_WEB_ADAPTERS; i++) {
        if (g_workers[i].running && g_workers[i].pid > 0) {
            int status = 0;
            pid_t res = waitpid(g_workers[i].pid, &status, WNOHANG);
            if (res > 0 || (res < 0 && errno == ECHILD)) {
                web_state_log("WARN", "Worker PID %d for adapter %d exited, restarting",
                              g_workers[i].pid, g_workers[i].adapter_idx);
                g_workers[i].running = false;
                g_workers[i].pid = 0;
                web_manager_sync_worker(g_workers[i].adapter_idx);
            }
        }
    }
}

void web_manager_cleanup(void) {
    for (int i = 0; i < MAX_WEB_ADAPTERS; i++) {
        if (g_workers[i].running && g_workers[i].pid > 0) {
            web_manager_stop_worker_internal(g_workers[i].adapter_idx);
        }
    }
}

static void parse_scan_line(int adapter_idx, const char *line, int *p_current_sid, int *p_current_pmt_sid) {
    /* SDT Service */
    char *p_sid = strstr(line, "service sid=");
    if (p_sid) {
        *p_current_sid = atoi(p_sid + 12);
    }
    char *p_desc = strstr(line, "desc 48 service");
    if (p_desc && *p_current_sid > 0) {
        char name[64] = {0};
        char provider[64] = {0};
        char *p_prov = strstr(p_desc, "provider=\"");
        if (p_prov) {
            p_prov += 10;
            char *end = strchr(p_prov, '"');
            if (end) {
                size_t plen = end - p_prov;
                if (plen >= sizeof(provider)) plen = sizeof(provider) - 1;
                strncpy(provider, p_prov, plen);
                provider[plen] = '\0';
            }
        }
        char *p_svc = strstr(p_desc, "service=\"");
        if (p_svc) {
            p_svc += 9;
            char *end = strchr(p_svc, '"');
            if (end) {
                size_t slen = end - p_svc;
                if (slen >= sizeof(name)) slen = sizeof(name) - 1;
                strncpy(name, p_svc, slen);
                name[slen] = '\0';
            }
        }
        if (name[0]) {
            channel_info_t ch;
            memset(&ch, 0, sizeof(ch));
            ch.service_id = (uint16_t)*p_current_sid;
            snprintf(ch.name, sizeof(ch.name), "%s", name);
            snprintf(ch.provider, sizeof(ch.provider), "%s", provider);
            web_state_add_adapter_channel(adapter_idx, &ch);
            *p_current_sid = 0;
        }
    }

    /* PAT Program to PMT PID */
    char *p_prog = strstr(line, "* program number=");
    if (p_prog) {
        int sid = 0, pmt = 0;
        if (sscanf(p_prog, "* program number=%d pid=%d", &sid, &pmt) == 2 && sid > 0) {
            channel_info_t ch;
            memset(&ch, 0, sizeof(ch));
            ch.service_id = (uint16_t)sid;
            ch.pmt_pid = (uint16_t)pmt;
            web_state_add_adapter_channel(adapter_idx, &ch);
        }
    }

    /* PMT Program */
    char *p_pmt = strstr(line, "new PMT program=");
    if (p_pmt) {
        *p_current_pmt_sid = atoi(p_pmt + 16);
    }
    if (*p_current_pmt_sid > 0) {
        char *p_es = strstr(line, "* ES pid=");
        if (p_es) {
            int es_pid = 0, stype = 0;
            if (sscanf(p_es, "* ES pid=%d streamtype=0x%x", &es_pid, &stype) == 2 && es_pid > 0) {
                channel_info_t ch;
                memset(&ch, 0, sizeof(ch));
                ch.service_id = (uint16_t)*p_current_pmt_sid;
                if (stype == 0x01 || stype == 0x02 || stype == 0x1B || stype == 0x24) {
                    ch.video_pid = (uint16_t)es_pid;
                    ch.video_type = (uint8_t)stype;
                } else if (stype == 0x03 || stype == 0x04 || stype == 0x0F || stype == 0x11 || stype == 0x06 || stype == 0x81) {
                    ch.audio_pids[0] = (uint16_t)es_pid;
                    ch.audio_types[0] = (uint8_t)stype;
                    ch.num_audio_pids = 1;
                }
                web_state_add_adapter_channel(adapter_idx, &ch);
            }
        }
        if (strstr(line, "end PMT")) {
            *p_current_pmt_sid = 0;
        }
    }
}

static void *scan_secondary_adapter_thread(void *arg) {
    int adapter_idx = (int)(intptr_t)arg;
    web_adapter_t *ad = web_state_find_adapter_by_idx(adapter_idx);
    if (!ad || (strcasecmp(ad->delsys, "SATIP") != 0 && ad->frequency <= 0)) return NULL;

    web_state_log("INFO", "Starting background scan for Adapter %s (/dev/dvb/adapter%d, freq=%llu Hz)",
                  ad->id, ad->adapter_idx, (unsigned long long)ad->frequency);

    char sock_path[64];
    snprintf(sock_path, sizeof(sock_path), "/tmp/dvblast_ad%d.sock", adapter_idx);

    bool worker_running = false;
    for (int i = 0; i < MAX_WEB_ADAPTERS; i++) {
        if (g_workers[i].adapter_idx == adapter_idx && g_workers[i].running && g_workers[i].pid > 0) {
            if (kill(g_workers[i].pid, 0) == 0 && access(sock_path, F_OK) == 0) {
                worker_running = true;
            }
            break;
        }
    }

    char exe_path[1024];
    ssize_t exelen = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exelen > 0) exe_path[exelen] = '\0';
    else snprintf(exe_path, sizeof(exe_path), "./dvblast");

    char ctl_path[1024];
    char *slash = strrchr(exe_path, '/');
    if (slash) {
        size_t dirlen = slash - exe_path;
        snprintf(ctl_path, sizeof(ctl_path), "%.*s/dvblastctl", (int)dirlen, exe_path);
    } else {
        snprintf(ctl_path, sizeof(ctl_path), "./dvblastctl");
    }

    if (worker_running && access(ctl_path, X_OK) == 0) {
        web_state_log("INFO", "Scanning Adapter %d via active worker socket %s (non-disruptive)", adapter_idx, sock_path);
        pthread_mutex_lock(&g_gateway.lock);
        ad->num_channels = 0;
        memset(ad->channels, 0, sizeof(ad->channels));
        pthread_mutex_unlock(&g_gateway.lock);

        char ctl_cmd[2048];
        char line[512];
        int cur_sid = 0, cur_pmt = 0;

        /* Get SDT */
        snprintf(ctl_cmd, sizeof(ctl_cmd), "%s -r %s get_sdt 2>&1", ctl_path, sock_path);
        FILE *fp = popen(ctl_cmd, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                parse_scan_line(adapter_idx, line, &cur_sid, &cur_pmt);
            }
            pclose(fp);
        }

        /* Get PAT */
        snprintf(ctl_cmd, sizeof(ctl_cmd), "%s -r %s get_pat 2>&1", ctl_path, sock_path);
        fp = popen(ctl_cmd, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                parse_scan_line(adapter_idx, line, &cur_sid, &cur_pmt);
            }
            pclose(fp);
        }

        /* Get PMT for each discovered channel */
        pthread_mutex_lock(&g_gateway.lock);
        int ch_count = ad->num_channels;
        uint16_t sids[MAX_DISCOVERED_CHANNELS];
        for (int i = 0; i < ch_count; i++) {
            sids[i] = ad->channels[i].service_id;
        }
        pthread_mutex_unlock(&g_gateway.lock);

        for (int i = 0; i < ch_count; i++) {
            snprintf(ctl_cmd, sizeof(ctl_cmd), "%s -r %s get_pmt %u 2>&1", ctl_path, sock_path, sids[i]);
            fp = popen(ctl_cmd, "r");
            if (fp) {
                while (fgets(line, sizeof(line), fp)) {
                    parse_scan_line(adapter_idx, line, &cur_sid, &cur_pmt);
                }
                pclose(fp);
            }
        }

        web_state_save_json(NULL);
        web_state_log("INFO", "Scan complete for Adapter %d, discovered %d services via worker socket",
                      adapter_idx, ad->num_channels);
        return NULL;
    }

    /* Fallback: worker not running or no socket. Stop worker gracefully to free frontend/dvr */
    web_manager_stop_worker_internal(adapter_idx);

    char cmd[1024];
    int target_bw = ad->bandwidth > 0 ? ad->bandwidth : 8;
    const char *target_delsys = ad->delsys[0] ? ad->delsys : "DVBT2";

    int off = snprintf(cmd, sizeof(cmd),
             "%s --disable-web -a %d -n %d -f %llu -5 %s -u -w -q -x text -Q 6000",
             exe_path, ad->adapter_idx, ad->frontend_idx,
             (unsigned long long)ad->frequency, target_delsys);

    if (strcasecmp(target_delsys, "DVBT") == 0 || strcasecmp(target_delsys, "DVBT2") == 0 || strcasecmp(target_delsys, "ISDBT") == 0) {
        off += snprintf(cmd + off, sizeof(cmd) - off, " -b %d", target_bw);
    }
    if (ad->symbol_rate > 0) off += snprintf(cmd + off, sizeof(cmd) - off, " -s %u", ad->symbol_rate);
    if (ad->voltage > 0) off += snprintf(cmd + off, sizeof(cmd) - off, " -v %d", ad->voltage);
    if (ad->diseqc > 0) off += snprintf(cmd + off, sizeof(cmd) - off, " -S %d", ad->diseqc);
    if (ad->modulation[0]) off += snprintf(cmd + off, sizeof(cmd) - off, " -m %s", ad->modulation);
    snprintf(cmd + off, sizeof(cmd) - off, " 2>&1");

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        web_state_log("ERROR", "Failed to start scanner on Adapter %d", adapter_idx);
        web_manager_sync_worker(adapter_idx);
        return NULL;
    }

    pthread_mutex_lock(&g_gateway.lock);
    ad->num_channels = 0;
    memset(ad->channels, 0, sizeof(ad->channels));
    pthread_mutex_unlock(&g_gateway.lock);

    char line[512];
    int current_sid = 0, current_pmt = 0;

    while (fgets(line, sizeof(line), fp)) {
        parse_scan_line(adapter_idx, line, &current_sid, &current_pmt);
    }
    pclose(fp);

    web_state_save_json(NULL);
    web_state_log("INFO", "Scan complete for Adapter %d, discovered %d services",
                  adapter_idx, ad->num_channels);

    /* Restore streaming worker if active streams exist */
    web_manager_sync_worker(adapter_idx);
    return NULL;
}

static bool web_manager_tune_adapter_internal(const char *adapter_id, int adapter_idx) {
    web_adapter_t *ad = NULL;
    if (adapter_id && *adapter_id) {
        ad = web_state_find_adapter(adapter_id);
    }
    if (!ad) {
        ad = web_state_find_adapter_by_idx(adapter_idx);
    }
    if (!ad) return false;

    /* If this is a secondary adapter, manage via worker process, NOT Master's frontend! */
    if (ad->adapter_idx != i_adapter) {
        web_manager_sync_worker(ad->adapter_idx);
        return true;
    }

    /* If primary adapter is already active on this frequency and bandwidth, skip redundant retune */
    if (i_frontend >= 0 && i_adapter == ad->adapter_idx && i_frequency == (int)ad->frequency &&
        i_bandwidth == ad->bandwidth) {
        web_state_log("INFO", "Primary Adapter %d already tuned to %llu Hz", ad->adapter_idx, (unsigned long long)ad->frequency);
        return true;
    }

    web_state_log("INFO", "Tuning Primary Adapter %d (%s, id=%s): Freq=%llu Hz, BW=%d MHz, Delsys=%s",
                  ad->adapter_idx, ad->name, ad->id, (unsigned long long)ad->frequency, ad->bandwidth, ad->delsys);

    /* Reset demux tables when tuning a new frequency */
    demux_ResetTables();

    pthread_mutex_lock(&g_gateway.lock);
    ad->num_channels = 0;
    memset(ad->channels, 0, sizeof(ad->channels));
    pthread_mutex_unlock(&g_gateway.lock);

    bool ok = dvb_TuneFrontend(ad->adapter_idx, ad->frontend_idx, ad->frequency,
                               ad->bandwidth, ad->delsys, ad->multistream_id,
                               ad->modulation, NULL, NULL, (int)ad->symbol_rate,
                               ad->voltage, ad->diseqc, ad->tone);
    if (ok) {
        demux_TriggerScan();
    }
    return ok;
}

static bool web_manager_disable_adapter_internal(const char *id) {
    if (!id || !*id) return false;
    web_adapter_t *ad = web_state_find_adapter(id);
    if (!ad) return false;

    ad->enabled = false;
    web_state_log("INFO", "Disabling Adapter %s (/dev/dvb/adapter%d), releasing hardware...", ad->id, ad->adapter_idx);
    if (i_adapter == ad->adapter_idx) {
        dvb_CloseDevices();
        demux_ResetTables();
    } else {
        web_manager_stop_worker_internal(ad->adapter_idx);
    }

    ad->locked = false;
    ad->signal_percent = 0;
    ad->signal_dbm = -100.0f;
    ad->snr_db = 0.0f;
    ad->snr_raw = 0;
    ad->ber = 0;
    ad->ucb = 0;
    ad->bitrate_bps = 0;
    ad->last_calc_bytes = ad->total_bytes;

    web_state_save_json(NULL);
    return true;
}

static bool web_manager_restart_adapter_internal(const char *id) {
    if (!id || !*id) return false;
    web_adapter_t *ad = web_state_find_adapter(id);
    if (!ad) return false;

    web_state_log("INFO", "Restarting Adapter %s (/dev/dvb/adapter%d)...", ad->id, ad->adapter_idx);

    if (i_adapter == ad->adapter_idx) {
        dvb_CloseDevices();
        demux_ResetTables();
    } else {
        web_manager_stop_worker_internal(ad->adapter_idx);
    }

    ad->locked = false;
    ad->signal_percent = 0;
    ad->signal_dbm = -100.0f;
    ad->snr_db = 0.0f;
    ad->snr_raw = 0;
    ad->ber = 0;
    ad->ucb = 0;
    ad->bitrate_bps = 0;
    ad->last_calc_bytes = ad->total_bytes;
    ad->num_channels = 0;
    memset(ad->channels, 0, sizeof(ad->channels));

    if (ad->enabled) {
        if (i_adapter == ad->adapter_idx) {
            web_manager_tune_adapter_internal(ad->id, ad->adapter_idx);
        } else {
            web_manager_sync_worker(ad->adapter_idx);
        }
    }

    web_state_save_json(NULL);
    return true;
}

void web_manager_handle_async_action(void) {
    pthread_mutex_lock(&g_async_action.mutex);
    if (g_async_action.type == WEB_ACTION_NONE) {
        pthread_mutex_unlock(&g_async_action.mutex);
        return;
    }

    bool ok = false;
    switch (g_async_action.type) {
        case WEB_ACTION_TUNE:
            ok = web_manager_tune_adapter_internal(g_async_action.adapter_id, g_async_action.adapter_idx);
            break;
        case WEB_ACTION_DISABLE:
            ok = web_manager_disable_adapter_internal(g_async_action.adapter_id);
            break;
        case WEB_ACTION_RESTART:
            ok = web_manager_restart_adapter_internal(g_async_action.adapter_id);
            break;
        case WEB_ACTION_SCAN:
            demux_TriggerScan();
            ok = true;
            break;
        default:
            break;
    }

    g_async_action.success = ok;
    g_async_action.done = true;
    pthread_cond_broadcast(&g_async_action.cond);
    pthread_mutex_unlock(&g_async_action.mutex);
}

bool web_manager_submit_action(web_action_type_t type, int adapter_idx, const char *adapter_id) {
    if (pthread_equal(pthread_self(), g_main_thread_id)) {
        switch (type) {
            case WEB_ACTION_TUNE:
                return web_manager_tune_adapter_internal(adapter_id, adapter_idx);
            case WEB_ACTION_DISABLE:
                return web_manager_disable_adapter_internal(adapter_id);
            case WEB_ACTION_RESTART:
                return web_manager_restart_adapter_internal(adapter_id);
            case WEB_ACTION_SCAN:
                demux_TriggerScan();
                return true;
            default:
                return false;
        }
    }

    pthread_mutex_lock(&g_async_action.mutex);
    while (g_async_action.type != WEB_ACTION_NONE) {
        pthread_cond_wait(&g_async_action.cond, &g_async_action.mutex);
    }

    g_async_action.type = type;
    g_async_action.adapter_idx = adapter_idx;
    if (adapter_id) snprintf(g_async_action.adapter_id, sizeof(g_async_action.adapter_id), "%s", adapter_id);
    else g_async_action.adapter_id[0] = '\0';
    g_async_action.done = false;
    g_async_action.success = false;

    web_manager_notify_async();

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 4;

    while (!g_async_action.done) {
        int rc = pthread_cond_timedwait(&g_async_action.cond, &g_async_action.mutex, &ts);
        if (rc != 0) {
            break;
        }
    }

    bool res = g_async_action.success;
    g_async_action.type = WEB_ACTION_NONE;
    pthread_mutex_unlock(&g_async_action.mutex);
    return res;
}

bool web_manager_tune_adapter(const char *id, int adapter_idx) {
    return web_manager_submit_action(WEB_ACTION_TUNE, adapter_idx, id);
}

bool web_manager_add_adapter(const web_adapter_t *ad) {
    if (!ad || !ad->id[0]) return false;

    bool ok = web_state_add_or_update_adapter(ad);
    if (ok && ad->enabled) {
        if (ad->adapter_idx == i_adapter) {
            web_manager_tune_adapter(ad->id, ad->adapter_idx);
        } else {
            /* Secondary adapter: sync worker, do NOT touch primary adapter or disrupt existing streams */
            web_manager_sync_worker(ad->adapter_idx);
        }
    }
    web_state_save_json(NULL);
    return ok;
}

bool web_manager_delete_adapter(const char *id) {
    if (!id || !*id) return false;

    web_adapter_t *ad = web_state_find_adapter(id);
    if (!ad) return false;

    if (i_adapter == ad->adapter_idx) {
        web_manager_submit_action(WEB_ACTION_DISABLE, ad->adapter_idx, id);
        i_frequency = 0;
    } else {
        web_manager_stop_worker_internal(ad->adapter_idx);
    }

    bool ok = web_state_delete_adapter(id);
    web_manager_sync_outputs();
    web_state_save_json(NULL);
    return ok;
}

bool web_manager_toggle_adapter(const char *id, bool enable) {
    if (!id || !*id) return false;
    web_adapter_t *ad = web_state_find_adapter(id);
    if (!ad) return false;

    ad->enabled = enable;
    web_state_save_json(NULL);

    if (ad->adapter_idx == i_adapter) {
        if (enable) {
            return web_manager_submit_action(WEB_ACTION_TUNE, ad->adapter_idx, id);
        } else {
            return web_manager_submit_action(WEB_ACTION_DISABLE, ad->adapter_idx, id);
        }
    } else {
        web_manager_sync_worker(ad->adapter_idx);
        return true;
    }
}

bool web_manager_restart_adapter(const char *id) {
    if (!id || !*id) return false;
    web_adapter_t *ad = web_state_find_adapter(id);
    if (!ad) return false;

    if (ad->adapter_idx == i_adapter) {
        return web_manager_submit_action(WEB_ACTION_RESTART, ad->adapter_idx, id);
    } else {
        web_manager_stop_worker_internal(ad->adapter_idx);
        if (ad->enabled) {
            web_manager_sync_worker(ad->adapter_idx);
        }
        return true;
    }
}

void web_manager_trigger_scan(int adapter_idx) {
    web_state_log("INFO", "Channel scan triggered for Adapter %d", adapter_idx);
    if (adapter_idx == i_adapter) {
        web_manager_submit_action(WEB_ACTION_SCAN, adapter_idx, NULL);
    } else {
        pthread_t scan_th;
        pthread_create(&scan_th, NULL, scan_secondary_adapter_thread, (void *)(intptr_t)adapter_idx);
        pthread_detach(scan_th);
    }
}

/* ========================================================================= */
/*  STREAM MANAGEMENT                                                        */
/* ========================================================================= */

static bool web_manager_add_stream_internal(const web_stream_config_t *stream, bool save_json) {
    if (!stream || !stream->ip[0] || stream->port <= 0) return false;

    /* Register SoftCAM BISS key if provided */
    if (stream->biss_key[0] && stream->service_id > 0) {
        softcam_set_key(stream->id, stream->name, stream->service_id, stream->biss_key, true);
    }

    if (stream->adapter_idx == i_adapter) {
        /* Primary adapter: output directly in Master */
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
        } else {
            config.i_config |= OUTPUT_DVB | OUTPUT_EPG;
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
                snprintf(p_output->sz_stream_id, sizeof(p_output->sz_stream_id), "%s", stream->id);
                demux_Change(p_output, &config);
                output_Change(p_output, &config);
            }
        } else {
            if (p_output) {
                output_config_t blank_config;
                config_Init(&blank_config);
                demux_Change(p_output, &blank_config);
                config_Free(&blank_config);

                output_Close(p_output);
            }
        }

        config_Free(&config);
    } else {
        /* Secondary adapter: sync worker */
        web_state_add_or_update_stream(stream);
        if (save_json) web_state_save_json(NULL);
        web_manager_sync_worker(stream->adapter_idx);
        return true;
    }

    web_state_add_or_update_stream(stream);
    if (save_json) web_state_save_json(NULL);
    return true;
}

bool web_manager_add_stream(const web_stream_config_t *stream) {
    return web_manager_add_stream_internal(stream, true);
}

bool web_manager_delete_stream(const char *id) {
    if (!id || !*id) return false;
    web_stream_config_t *s = web_state_find_stream(id);
    if (!s) return false;

    int ad_idx = s->adapter_idx;
    if (ad_idx == i_adapter) {
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
            config_Free(&config);
        }
    }

    bool ok = web_state_delete_stream(id);
    web_state_save_json(NULL);

    if (ad_idx != i_adapter) {
        web_manager_sync_worker(ad_idx);
    }
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
        if (adapters_copy[i].enabled && adapters_copy[i].adapter_idx == i_adapter) {
            web_manager_tune_adapter(adapters_copy[i].id, adapters_copy[i].adapter_idx);
            break;
        }
    }

    /* Start active streams on primary adapter */
    for (int i = 0; i < count; i++) {
        if (streams_copy[i].enabled && streams_copy[i].adapter_idx == i_adapter) {
            web_manager_add_stream_internal(&streams_copy[i], false);
        }
    }

    /* Sync workers for secondary adapters */
    web_manager_sync_workers();
}
