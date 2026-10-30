#ifndef MODULES_GROUPS_H
#define MODULES_GROUPS_H

#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CATEGORIES 32
#define MAX_GROUPS_PER_CAT 32

typedef struct {
    char name[64];
    char groups[MAX_GROUPS_PER_CAT][64];
    int  num_groups;
} category_entry_t;

void groups_init(void);
void groups_cleanup(void);

json_t *groups_to_json(void);
bool    groups_from_json(json_t *root);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_GROUPS_H */
