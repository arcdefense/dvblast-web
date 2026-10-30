#ifndef MODULES_HTTP_AUTH_H
#define MODULES_HTTP_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <microhttpd.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ROLE_NONE   = 0,
    ROLE_VIEWER = 1,
    ROLE_ADMIN  = 2
} auth_role_t;

typedef enum {
    AUTH_RES_OK           = 0,
    AUTH_RES_UNAUTHORIZED = 1,
    AUTH_RES_FORBIDDEN    = 2
} auth_result_t;

#define MAX_AUTH_USERS 16
#define MAX_AUTH_SESSIONS 64

typedef struct {
    char        username[64];
    char        password[64];
    auth_role_t role;
    bool        enabled;
} auth_user_t;

typedef struct {
    char        token[64];
    char        username[64];
    auth_role_t role;
    time_t      created_at;
    time_t      expires_at;
    char        ip[64];
} auth_session_t;

typedef struct {
    bool        enabled;
    int         expiry_hours;
    auth_user_t users[MAX_AUTH_USERS];
    int         num_users;
} http_auth_config_t;

void http_auth_init(void);
void http_auth_cleanup(void);

void http_auth_configure(const http_auth_config_t *cfg);
http_auth_config_t http_auth_get_config(void);

/* Check if HTTP request is permitted. If not, can trigger HTTP 401 challenge */
auth_result_t http_auth_check(struct MHD_Connection *conn, const char *url, const char *method);

/* Request authentication challenge response (WWW-Authenticate: Basic realm="DVBlast") */
int http_auth_send_challenge(struct MHD_Connection *conn);

/* Handle REST login/logout endpoints */
int http_auth_handle_api(struct MHD_Connection *conn, const char *url, const char *method, const char *body);

json_t *http_auth_to_json(void);
bool    http_auth_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_HTTP_AUTH_H */
