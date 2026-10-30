#ifndef DVBLAST_WEB_MANAGER_H
#define DVBLAST_WEB_MANAGER_H

#include "web_state.h"

/* Adapter Management */
bool web_manager_add_adapter(const web_adapter_t *ad);
bool web_manager_delete_adapter(const char *id);
bool web_manager_tune_adapter(int adapter_idx);
void web_manager_trigger_scan(int adapter_idx);

/* Stream Management */
bool web_manager_add_stream(const web_stream_config_t *stream);
bool web_manager_delete_stream(const char *id);
bool web_manager_toggle_stream(const char *id, bool enabled);
void web_manager_sync_outputs(void);

#endif /* DVBLAST_WEB_MANAGER_H */
