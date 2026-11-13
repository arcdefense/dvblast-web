#ifndef MODULES_WS_H
#define MODULES_WS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <microhttpd.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WS_MAX_CLIENTS 128

typedef struct ws_session_info {
    int      id;
    char     remote_ip[64];
    char     user_agent[128];
    char     login[64];
    time_t   connected_at;
    uint64_t messages_sent;
    uint64_t bytes_sent;
} ws_session_info_t;

void ws_init(void);
void ws_cleanup(void);

/* Check if connection requested a WebSocket upgrade */
bool ws_is_upgrade_request(struct MHD_Connection *conn);

/* Handle WebSocket upgrade handshake, returns MHD result code */
int ws_handle_upgrade(struct MHD_Connection *conn, const char *login);

/* Create WebSocket upgrade response and register client */
struct MHD_Response *ws_create_upgrade_response(struct MHD_Connection *conn, const char *login);

/* Broadcast JSON event to all connected WebSocket clients */
void ws_broadcast_json(json_t *event);

/* Broadcast raw text/JSON string to all connected WebSocket clients */
void ws_broadcast_text(const char *text);

/* Get all active WebSocket sessions as JSON array */
json_t *ws_get_sessions_json(void);

/* Force disconnect a WebSocket session */
bool ws_kick_session(int session_id);

int ws_client_count(void);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_WS_H */
