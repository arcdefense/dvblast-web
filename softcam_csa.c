#include "softcam_csa.h"
#include "modules/softcam/softcam.h"

void softcam_csa_init(void) {
    softcam_init();
}

void softcam_csa_cleanup(void) {
    softcam_cleanup();
}

bool softcam_csa_set_key(const char *id, const char *name, uint16_t sid, const char *key_hex, bool enabled) {
    return softcam_set_key(id, name, sid, key_hex, enabled);
}

bool softcam_csa_del_key(const char *id_or_sid) {
    return softcam_del_key(id_or_sid);
}

const softcam_entry_t *softcam_csa_find(uint16_t sid) {
    return softcam_find(sid);
}

const softcam_entry_t *softcam_csa_get_at(int index) {
    return softcam_get_at(index);
}

int softcam_csa_count(void) {
    return softcam_count();
}

int softcam_csa_descramble(uint16_t sid, uint8_t *ts_packet) {
    return softcam_descramble(sid, ts_packet);
}

json_t *softcam_csa_to_json(void) {
    return softcam_to_json();
}

bool softcam_csa_from_json(json_t *root) {
    return softcam_from_json(root);
}
