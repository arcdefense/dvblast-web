#include "softcam.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

static softcam_entry_t g_keys[SOFTCAM_MAX_KEYS];
static int g_num_keys = 0;
static pthread_mutex_t g_softcam_mutex = PTHREAD_MUTEX_INITIALIZER;

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_string(const char *hex, uint8_t *out, int max_bytes) {
    if (!hex || !out || max_bytes <= 0) return 0;
    char clean[128];
    int clean_len = 0;
    for (int i = 0; hex[i] && clean_len < (int)sizeof(clean) - 1; i++) {
        if (isxdigit((unsigned char)hex[i])) {
            clean[clean_len++] = hex[i];
        }
    }
    clean[clean_len] = '\0';

    int bytes = 0;
    for (int i = 0; i + 1 < clean_len && bytes < max_bytes; i += 2) {
        int hi = hex_nibble(clean[i]);
        int lo = hex_nibble(clean[i + 1]);
        if (hi < 0 || lo < 0) break;
        out[bytes++] = (uint8_t)((hi << 4) | lo);
    }
    return bytes;
}

static bool parse_cw_key(const char *key_hex, uint8_t *cw_out) {
    memset(cw_out, 0, 16);
    uint8_t raw[16] = {0};
    int n = parse_hex_string(key_hex, raw, 16);

    if (n >= 16) {
        /* Full 16-byte Constant CW (Even 8B + Odd 8B) */
        memcpy(cw_out, raw, 16);
        return true;
    } else if (n >= 8) {
        /* 8-byte BISS-1 key with parity already present (Even == Odd) */
        memcpy(cw_out, raw, 8);
        memcpy(cw_out + 8, raw, 8);
        return true;
    } else if (n >= 6) {
        /* 6-byte (12 hex digits) BISS-1: Calculate DVB-CSA parity bytes 3 and 7 */
        cw_out[0] = raw[0];
        cw_out[1] = raw[1];
        cw_out[2] = raw[2];
        cw_out[3] = (uint8_t)((raw[0] + raw[1] + raw[2]) & 0xFF);
        cw_out[4] = raw[3];
        cw_out[5] = raw[4];
        cw_out[6] = raw[5];
        cw_out[7] = (uint8_t)((raw[3] + raw[4] + raw[5]) & 0xFF);
        memcpy(cw_out + 8, cw_out, 8);
        return true;
    }
    return false;
}

void softcam_init(void) {
    pthread_mutex_lock(&g_softcam_mutex);
    for (int i = 0; i < g_num_keys; i++) {
        if (g_keys[i].csa_even) dvbcsa_key_free(g_keys[i].csa_even);
        if (g_keys[i].csa_odd) dvbcsa_key_free(g_keys[i].csa_odd);
    }
    memset(g_keys, 0, sizeof(g_keys));
    g_num_keys = 0;
    pthread_mutex_unlock(&g_softcam_mutex);
}

void softcam_cleanup(void) {
    softcam_init();
}

bool softcam_set_key(const char *id, const char *name, uint16_t sid, const char *key_hex, bool enabled) {
    if (!id || !*id || !key_hex || !*key_hex) return false;

    uint8_t cw[16];
    if (!parse_cw_key(key_hex, cw)) {
        return false;
    }

    pthread_mutex_lock(&g_softcam_mutex);

    int idx = -1;
    for (int i = 0; i < g_num_keys; i++) {
        if (strcmp(g_keys[i].id, id) == 0 || (sid != 0 && g_keys[i].service_id == sid)) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        if (g_num_keys >= SOFTCAM_MAX_KEYS) {
            pthread_mutex_unlock(&g_softcam_mutex);
            return false;
        }
        idx = g_num_keys++;
    } else {
        if (g_keys[idx].csa_even) { dvbcsa_key_free(g_keys[idx].csa_even); g_keys[idx].csa_even = NULL; }
        if (g_keys[idx].csa_odd)  { dvbcsa_key_free(g_keys[idx].csa_odd);  g_keys[idx].csa_odd = NULL; }
    }

    softcam_entry_t *e = &g_keys[idx];
    snprintf(e->id, sizeof(e->id), "%s", id);
    snprintf(e->name, sizeof(e->name), "%s", (name && *name) ? name : id);
    e->service_id = sid;
    snprintf(e->key_hex, sizeof(e->key_hex), "%s", key_hex);
    memcpy(e->cw, cw, 16);
    e->enabled = enabled;
    e->valid = true;

    if (enabled) {
        e->csa_even = dvbcsa_key_alloc();
        e->csa_odd  = dvbcsa_key_alloc();
        if (e->csa_even) dvbcsa_key_set(cw, e->csa_even);
        if (e->csa_odd)  dvbcsa_key_set(cw + 8, e->csa_odd);
    }

    pthread_mutex_unlock(&g_softcam_mutex);
    return true;
}

bool softcam_inject_cw(uint16_t sid, const uint8_t *cw16) {
    if (!cw16) return false;

    pthread_mutex_lock(&g_softcam_mutex);
    int idx = -1;
    for (int i = 0; i < g_num_keys; i++) {
        if (g_keys[i].service_id == sid) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        if (g_num_keys >= SOFTCAM_MAX_KEYS) {
            pthread_mutex_unlock(&g_softcam_mutex);
            return false;
        }
        idx = g_num_keys++;
        snprintf(g_keys[idx].id, sizeof(g_keys[idx].id), "cas_sid_%u", sid);
        snprintf(g_keys[idx].name, sizeof(g_keys[idx].name), "CAS SID %u", sid);
        g_keys[idx].service_id = sid;
    }

    softcam_entry_t *e = &g_keys[idx];
    memcpy(e->cw, cw16, 16);
    char hexbuf[64] = {0};
    for (int b = 0; b < 16; b++) {
        snprintf(hexbuf + (b * 2), 3, "%02X", cw16[b]);
    }
    snprintf(e->key_hex, sizeof(e->key_hex), "%s", hexbuf);
    e->enabled = true;
    e->valid = true;

    if (!e->csa_even) e->csa_even = dvbcsa_key_alloc();
    if (!e->csa_odd)  e->csa_odd  = dvbcsa_key_alloc();
    if (e->csa_even) dvbcsa_key_set(cw16, e->csa_even);
    if (e->csa_odd)  dvbcsa_key_set(cw16 + 8, e->csa_odd);

    pthread_mutex_unlock(&g_softcam_mutex);
    return true;
}

bool softcam_del_key(const char *id_or_sid) {
    if (!id_or_sid || !*id_or_sid) return false;

    pthread_mutex_lock(&g_softcam_mutex);
    int idx = -1;
    for (int i = 0; i < g_num_keys; i++) {
        if (strcmp(g_keys[i].id, id_or_sid) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0 && isdigit((unsigned char)id_or_sid[0])) {
        uint16_t sid = (uint16_t)atoi(id_or_sid);
        for (int i = 0; i < g_num_keys; i++) {
            if (g_keys[i].service_id == sid) {
                idx = i;
                break;
            }
        }
    }

    if (idx < 0) {
        pthread_mutex_unlock(&g_softcam_mutex);
        return false;
    }

    if (g_keys[idx].csa_even) dvbcsa_key_free(g_keys[idx].csa_even);
    if (g_keys[idx].csa_odd)  dvbcsa_key_free(g_keys[idx].csa_odd);

    for (int i = idx; i < g_num_keys - 1; i++) {
        g_keys[i] = g_keys[i + 1];
    }
    g_num_keys--;
    memset(&g_keys[g_num_keys], 0, sizeof(softcam_entry_t));

    pthread_mutex_unlock(&g_softcam_mutex);
    return true;
}

const softcam_entry_t *softcam_find(uint16_t sid) {
    for (int i = 0; i < g_num_keys; i++) {
        if (g_keys[i].enabled && g_keys[i].valid) {
            if (g_keys[i].service_id == sid || g_keys[i].service_id == 0) {
                return &g_keys[i];
            }
        }
    }
    return NULL;
}

const softcam_entry_t *softcam_get_at(int index) {
    if (index >= 0 && index < g_num_keys) {
        return &g_keys[index];
    }
    return NULL;
}

int softcam_count(void) {
    return g_num_keys;
}

int softcam_descramble(uint16_t sid, uint8_t *ts_packet) {
    if (!ts_packet) return 0;
    if (ts_packet[0] != 0x47) return 0;

    uint8_t scrambling_control = (ts_packet[3] >> 6) & 0x03;
    if (scrambling_control == 0) {
        return 0; /* Not scrambled */
    }

    pthread_mutex_lock(&g_softcam_mutex);
    const softcam_entry_t *entry = softcam_find(sid);
    if (!entry) {
        pthread_mutex_unlock(&g_softcam_mutex);
        return 0;
    }

    dvbcsa_key_t *key = (scrambling_control == 2) ? entry->csa_even :
                        (scrambling_control == 3) ? entry->csa_odd  : NULL;

    if (!key) {
        pthread_mutex_unlock(&g_softcam_mutex);
        return 0;
    }

    /* Calculate payload offset */
    int offset = 4;
    uint8_t adaptation_field_control = (ts_packet[3] >> 4) & 0x03;
    if (adaptation_field_control == 2) {
        /* Adaptation field only, no payload */
        pthread_mutex_unlock(&g_softcam_mutex);
        return 0;
    } else if (adaptation_field_control == 3) {
        offset += 1 + ts_packet[4];
    }

    if (offset >= 188) {
        pthread_mutex_unlock(&g_softcam_mutex);
        return 0;
    }

    /* Decrypt payload in place */
    dvbcsa_decrypt(key, ts_packet + offset, 188 - offset);

    /* Clear transport scrambling flags (bits 7-6 of byte 3) */
    ts_packet[3] &= 0x3F;

    ((softcam_entry_t *)entry)->packets_descrambled++;
    pthread_mutex_unlock(&g_softcam_mutex);

    return 1;
}

json_t *softcam_to_json(void) {
    pthread_mutex_lock(&g_softcam_mutex);
    json_t *arr = json_array();
    for (int i = 0; i < g_num_keys; i++) {
        json_t *o = json_object();
        json_object_set_new(o, "id", json_string(g_keys[i].id));
        json_object_set_new(o, "name", json_string(g_keys[i].name));
        json_object_set_new(o, "service_id", json_integer(g_keys[i].service_id));
        json_object_set_new(o, "key", json_string(g_keys[i].key_hex));
        json_object_set_new(o, "enabled", g_keys[i].enabled ? json_true() : json_false());
        json_object_set_new(o, "packets_descrambled", json_integer(g_keys[i].packets_descrambled));
        json_array_append_new(arr, o);
    }
    pthread_mutex_unlock(&g_softcam_mutex);
    return arr;
}

bool softcam_from_json(json_t *root) {
    if (!root || !json_is_array(root)) return false;

    softcam_init();

    size_t index;
    json_t *val;
    json_array_foreach(root, index, val) {
        if (!json_is_object(val)) continue;
        const char *id = json_string_value(json_object_get(val, "id"));
        const char *nm = json_string_value(json_object_get(val, "name"));
        uint16_t sid = (uint16_t)json_integer_value(json_object_get(val, "service_id"));
        const char *key = json_string_value(json_object_get(val, "key"));
        bool en = !json_is_false(json_object_get(val, "enabled"));

        if (id && key) {
            softcam_set_key(id, nm, sid, key, en);
        }
    }
    return true;
}
