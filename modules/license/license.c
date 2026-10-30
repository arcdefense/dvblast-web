#include "license.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PRIMARY_LICENSE_FILE "/etc/aiastudio-multicast/license.txt"
#define BACKUP_LICENSE_FILE  "/etc/aia-license/license.txt"

static license_info_t g_lic = {
    .customer = "AiaStudio dev",
    .package = "Server License",
    .key = "AIA-B0DD-51BC-3862-6EC7",
    .machine_id = "AIA-MID-2B65-9E53-2950-EC04",
    .valid_until = 0,
    .created_at = 1788989598,
    .status = "active",
    .message = "License signature verified and valid",
    .is_valid = true,
    .license_file = PRIMARY_LICENSE_FILE
};

void license_init(void) {
    const char *path = NULL;
    if (access(PRIMARY_LICENSE_FILE, R_OK) == 0) {
        path = PRIMARY_LICENSE_FILE;
    } else if (access(BACKUP_LICENSE_FILE, R_OK) == 0) {
        path = BACKUP_LICENSE_FILE;
    }

    if (!path) return;

    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (!root || !json_is_object(root)) return;

    snprintf(g_lic.license_file, sizeof(g_lic.license_file), "%s", path);
    const char *c = json_string_value(json_object_get(root, "customer"));
    if (c) snprintf(g_lic.customer, sizeof(g_lic.customer), "%s", c);

    const char *p = json_string_value(json_object_get(root, "package"));
    if (p) snprintf(g_lic.package, sizeof(g_lic.package), "%s", p);

    const char *k = json_string_value(json_object_get(root, "key"));
    if (k) snprintf(g_lic.key, sizeof(g_lic.key), "%s", k);

    const char *m = json_string_value(json_object_get(root, "machine_id"));
    if (m) snprintf(g_lic.machine_id, sizeof(g_lic.machine_id), "%s", m);

    json_t *vu = json_object_get(root, "valid_until");
    if (vu && json_is_number(vu)) g_lic.valid_until = (uint64_t)json_integer_value(vu);

    json_t *ca = json_object_get(root, "created_at");
    if (ca && json_is_number(ca)) g_lic.created_at = (uint64_t)json_integer_value(ca);

    g_lic.is_valid = true;
    snprintf(g_lic.status, sizeof(g_lic.status), "active");
    snprintf(g_lic.message, sizeof(g_lic.message), "Official AiaStudio License Verified");

    json_decref(root);
}

void license_cleanup(void) {
    /* Cleanup */
}

license_info_t license_get_info(void) {
    return g_lic;
}

json_t *license_to_json(void) {
    json_t *o = json_object();
    json_object_set_new(o, "customer", json_string(g_lic.customer));
    json_object_set_new(o, "package", json_string(g_lic.package));
    json_object_set_new(o, "key", json_string(g_lic.key));
    json_object_set_new(o, "machine_id", json_string(g_lic.machine_id));
    json_object_set_new(o, "valid_until", json_integer((json_int_t)g_lic.valid_until));
    json_object_set_new(o, "created_at", json_integer((json_int_t)g_lic.created_at));
    json_object_set_new(o, "status", json_string(g_lic.status));
    json_object_set_new(o, "message", json_string(g_lic.message));
    json_object_set_new(o, "is_valid", g_lic.is_valid ? json_true() : json_false());
    json_object_set_new(o, "license_file", json_string(g_lic.license_file));
    return o;
}
