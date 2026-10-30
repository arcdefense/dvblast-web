#ifndef DVBLAST_SOFTCAM_CSA_H
#define DVBLAST_SOFTCAM_CSA_H

#include "modules/softcam/softcam.h"

#ifdef __cplusplus
extern "C" {
#endif

void softcam_csa_init(void);
void softcam_csa_cleanup(void);

bool softcam_csa_set_key(const char *id, const char *name, uint16_t sid, const char *key_hex, bool enabled);
bool softcam_csa_del_key(const char *id_or_sid);
const softcam_entry_t *softcam_csa_find(uint16_t sid);
const softcam_entry_t *softcam_csa_get_at(int index);
int  softcam_csa_count(void);

int  softcam_csa_descramble(uint16_t sid, uint8_t *ts_packet);

json_t *softcam_csa_to_json(void);
bool    softcam_csa_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* DVBLAST_SOFTCAM_CSA_H */
