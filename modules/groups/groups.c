#include "groups.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static category_entry_t g_categories[MAX_CATEGORIES];
static int g_num_categories = 0;

void groups_init(void) {
    memset(g_categories, 0, sizeof(g_categories));
    g_num_categories = 0;
}

void groups_cleanup(void) {
    memset(g_categories, 0, sizeof(g_categories));
    g_num_categories = 0;
}

json_t *groups_to_json(void) {
    json_t *arr = json_array();
    for (int i = 0; i < g_num_categories; i++) {
        json_t *cat = json_object();
        json_object_set_new(cat, "name", json_string(g_categories[i].name));
        json_t *groups_arr = json_array();
        for (int j = 0; j < g_categories[i].num_groups; j++) {
            json_t *g = json_object();
            json_object_set_new(g, "name", json_string(g_categories[i].groups[j]));
            json_array_append_new(groups_arr, g);
        }
        json_object_set_new(cat, "groups", groups_arr);
        json_array_append_new(arr, cat);
    }
    return arr;
}

bool groups_from_json(json_t *root) {
    if (!root || !json_is_array(root)) return false;

    g_num_categories = 0;
    size_t cat_idx;
    json_t *cat_val;
    json_array_foreach(root, cat_idx, cat_val) {
        if (g_num_categories >= MAX_CATEGORIES) break;
        if (!json_is_object(cat_val)) continue;

        category_entry_t *entry = &g_categories[g_num_categories];
        memset(entry, 0, sizeof(*entry));

        const char *name = json_string_value(json_object_get(cat_val, "name"));
        if (name) snprintf(entry->name, sizeof(entry->name), "%s", name);

        json_t *groups = json_object_get(cat_val, "groups");
        if (groups && json_is_array(groups)) {
            size_t g_idx;
            json_t *g_val;
            json_array_foreach(groups, g_idx, g_val) {
                if (entry->num_groups >= MAX_GROUPS_PER_CAT) break;
                if (json_is_string(g_val)) {
                    snprintf(entry->groups[entry->num_groups++], 64, "%s", json_string_value(g_val));
                } else if (json_is_object(g_val)) {
                    const char *gn = json_string_value(json_object_get(g_val, "name"));
                    if (gn) snprintf(entry->groups[entry->num_groups++], 64, "%s", gn);
                }
            }
        }
        g_num_categories++;
    }
    return true;
}
