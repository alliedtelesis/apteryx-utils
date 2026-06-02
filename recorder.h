#ifndef _RECORDER_H_
#define _RECORDER_H_

#include <glib.h>
#include <jansson.h>
#include <time.h>

typedef struct _config_data
{
    char *query;
    long frequency;
    char *destination;
    int max_samples;
    long max_size;

    /* Injectable query function for testability. Defaults to apteryx_query. */
    GNode *(*query_fn)(GNode *);

    guint initial_delay;
    GMainLoop *loop;
    GMainContext *context;
    GThread *thread;
    GMutex mutex;
    GCond cond;
    gboolean thread_ready;
    json_t *last_snapshot;
    GSource *poll_source;
} config_data;

/* Overrides the default logrotate output directory. Set via -l or in tests. NULL means use default */
extern const char *logrotate_dir_override;

#define LOGROTATE_DIR_DEFAULT "/etc/logrotate-conf.d"
#define LOGROTATE_INCLUDE_FILE "/etc/logrotate.d/recorder"

/* Convert apteryx GNode result into regular JSON */
json_t *gnode_to_json (const GNode *node);

/* Create directory path components */
int make_path (char *path);

/* Compare JSON objects, returning changed values for forward diff */
json_t *compare_json_deep (json_t *current_json, json_t *previous_json);
json_t *compare_objects (json_t *current_obj, json_t *previous_obj);

/* Apply a forward diff to a snapshot */
json_t *apply_forward_diff (json_t *snapshot, json_t *changes);

/* Rebuild latest snapshot from baseline + diffs array */
json_t *reconstruct_latest_snapshot (json_t *baseline, json_t *diffs);

/* Append a single diff entry to file via seek */
int append_diff_entry_to_file (const char *path, json_t *diff_entry);

/* Write (or create) JSON diff file with in-memory cache */
int write_diff (json_t *current_json, const char *path_to_diff, json_t **last_snapshot_cache);

/* Create a sanitized config filename from a path */
char *sanitize_path_for_config (const char *path);

/* Resolve a relative path to absolute */
char *resolve_absolute_path (const char *path);

/* Validate and register a destination path */
int validate_destination (GHashTable *registry, const char *destination_path,
                          const char *config_path);

/* Validate config JSON data and populate config_data struct */
int validate_and_set_data (json_t *data, config_data *config, GHashTable *registry,
                           const char *config_path);

/* Calculate initial polling delay after restart */
guint calculate_initial_delay_at (long frequency, time_t last_poll_timestamp, time_t now);

/* Read last poll timestamp from diff file */
time_t read_last_poll_timestamp (const char *path_to_diff);

/* Load configs from a directory */
int load_configs_from_directory (const char *config_dir, GHashTable *registry,
                                 GPtrArray *configs);

/* Create logrotate config for a recording config */
int create_logrotate_config (config_data *config);

/* Create logrotate include file */
int create_logrotate_include (void);

/* Polling callback - queries apteryx and writes diff (exposed for testing) */
gboolean polling_callback (gpointer user_data);

/* Free a config_data struct */
void config_data_free (config_data *config);

/* Free global destination registry and active configs */
void destination_registry_free_all (void);

/* Run unit tests (defined in test_recorder.c) */
int run_tests (void);

#endif /* _RECORDER_H_ */
