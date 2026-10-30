#ifndef MODULES_SOFTCAM_H
#define MODULES_SOFTCAM_H

#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>
#include "dvbcsa/dvbcsa.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SOFTCAM_MAX_KEYS 64
#define SOFTCAM_NAME_LEN 64
#define SOFTCAM_HEX_LEN  64

typedef struct {
    char id[SOFTCAM_NAME_LEN];
    char name[SOFTCAM_NAME_LEN];
    uint16_t service_id;          /* 0 means wildcard, else specific SID */
    char key_hex[SOFTCAM_HEX_LEN];
    uint8_t cw[16];               /* 8 bytes Even CW + 8 bytes Odd CW */
    bool enabled;
    bool valid;
    dvbcsa_key_t *csa_even;
    dvbcsa_key_t *csa_odd;
    uint64_t packets_descrambled;
} softcam_entry_t;

void softcam_init(void);
void softcam_cleanup(void);

bool softcam_set_key(const char *id, const char *name, uint16_t sid, const char *key_hex, bool enabled);
bool softcam_del_key(const char *id_or_sid);
const softcam_entry_t *softcam_find(uint16_t sid);
const softcam_entry_t *softcam_get_at(int index);
int  softcam_count(void);

/* Descramble TS packet in place */
int  softcam_descramble(uint16_t sid, uint8_t *ts_packet);

/* Inject dynamic CW from CAS (Newcamd / ECM) */
bool softcam_inject_cw(uint16_t sid, const uint8_t *cw16);

json_t *softcam_to_json(void);
bool    softcam_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_SOFTCAM_H */
