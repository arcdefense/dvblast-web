#ifndef DVBLAST_WEB_MANAGER_H
#define DVBLAST_WEB_MANAGER_H

#include "web_state.h"

bool web_manager_add_stream(const web_stream_config_t *stream);
bool web_manager_delete_stream(const char *id);
bool web_manager_tune(const tuner_state_t *tuner);
void web_manager_sync_outputs(void);
void web_manager_trigger_scan(void);

#endif /* DVBLAST_WEB_MANAGER_H */
