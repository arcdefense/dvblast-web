#ifndef MODULES_CAS_H
#define MODULES_CAS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CAS_STATE_DISABLED = 0,
    CAS_STATE_DISCONNECTED = 1,
    CAS_STATE_CONNECTING = 2,
    CAS_STATE_CONNECTED = 3,
    CAS_STATE_AUTH_OK = 4,
    CAS_STATE_ERROR = 5
} cas_state_t;

typedef struct {
    bool        enabled;
    char        host[128];
    int         port;
    char        user[64];
    char        pass[64];
    char        des_key[32];    /* Hex representation of 14 bytes DES key */
    
    /* Live Runtime Status */
    cas_state_t state;
    char        status_msg[128];
    time_t      last_event_time;
    uint64_t    ecm_requests;
    uint64_t    cw_received;
    uint64_t    ecm_errors;
    float       last_ecm_ms;
} cas_config_t;

void cas_init(void);
void cas_cleanup(void);

void cas_configure(const cas_config_t *cfg);
cas_config_t cas_get_config(void);

/* Queue an ECM packet to be sent to cardserver */
bool cas_request_cw(uint16_t sid, uint16_t ca_id, uint16_t ecm_pid, const uint8_t *ecm_data, int len);

json_t *cas_to_json(void);
bool    cas_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_CAS_H */
