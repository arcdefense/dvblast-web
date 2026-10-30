#ifndef MODULES_LICENSE_H
#define MODULES_LICENSE_H

#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char customer[128];
    char package[128];
    char key[64];
    char machine_id[64];
    uint64_t valid_until;
    uint64_t created_at;
    char status[32];         /* "active", "trial", "grace_period", "unlicensed" */
    char message[128];
    bool is_valid;
    char license_file[256];
} license_info_t;

void license_init(void);
void license_cleanup(void);

license_info_t license_get_info(void);
json_t        *license_to_json(void);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_LICENSE_H */
