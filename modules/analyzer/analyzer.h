#ifndef MODULES_ANALYZER_H
#define MODULES_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

void analyzer_init(void);
void analyzer_cleanup(void);

/* Generate full TS Analysis for a stream (elementary PIDs, CC errors, bitrate, PSI/SI tree) */
json_t *analyzer_get_stream(const char *stream_id);

/* Generate full TS Analysis for an entire adapter/transponder */
json_t *analyzer_get_adapter(int adapter_idx);

#ifdef __cplusplus
}
#endif

#endif /* MODULES_ANALYZER_H */
