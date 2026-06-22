#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <apteryx.h>
#include <glib-unix.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <dirent.h>
#include <libgen.h>
#include <jansson.h>
#include <ftw.h>
#include <unistd.h>
#include <signal.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

static const int json_indent = 2;

/* Overrides the default logrotate output directory. Set via -l or in tests. NULL means use default */
static const char *logrotate_dir_override = NULL;
#define LOGROTATE_DIR_DEFAULT "/etc/logrotate-conf.d"
#define LOGROTATE_INCLUDE_FILE "/etc/logrotate.d/recorder"

static json_t *compare_json_deep (json_t *current_json, json_t *previous_json);

typedef struct _config_data
{
    char *query;
    long frequency;
    char *destination;
    int max_samples;
    long max_size;

    guint initial_delay;
    GMainLoop *loop;
    GMainContext *context;
    GThread *thread;
    GMutex mutex;
    GCond cond;
    gboolean thread_ready;
    json_t *last_snapshot;
} config_data;

static GHashTable *destination_registry = NULL;
static GPtrArray *active_configs = NULL;
static GMainLoop *main_loop = NULL;

/* Used to convert apteryx result into regular JSON */
json_t *
gnode_to_json (const GNode *node)
{
    json_t *obj = json_object ();
    if (!obj)
    {
        return NULL;
    }

    for (const GNode *child = node->children; child; child = child->next)
    {
        json_t *child_json = NULL;
        if (APTERYX_HAS_VALUE (child))
        {
            child_json = json_string (APTERYX_VALUE (child));
        }
        else
        {
            child_json = gnode_to_json (child);
            if (!child_json)
            {
                json_decref (obj);
                return NULL;
            }
        }

        json_object_set_new (obj, (char *) child->data, child_json);
    }

    return obj;
}

/* Generates destination directories if needed */
static int
make_path (char *path)
{
    char *p = path + (*path == '/');    // Skip leading /
    while ((p = strchr (p, '/')))
    {
        *p = '\0';
        if (mkdir (path, 0755) && errno != EEXIST)
        {
            return -1;
        }
        *p++ = '/';
    }
    return 0;
}


/* Compares JSON objects by comparing their individual values */
static json_t *
compare_objects (json_t *current_obj, json_t *previous_obj)
{
    json_t *changes = json_object ();
    const char *key;
    json_t *value;

    json_object_foreach (current_obj, key, value)
    {
        json_t *diff = compare_json_deep (value, json_object_get (previous_obj, key));
        if (diff)
        {
            json_object_set_new (changes, key, diff);
        }
    }

    json_object_foreach (previous_obj, key, value)
    {
        if (!json_object_get (current_obj, key))
        {
            json_object_set_new (changes, key, json_null ());
        }
    }

    if (!json_object_size (changes))
    {
        json_decref (changes);
        return NULL;
    }
    return changes;
}

/* Compares current against previous, returning changed values for use in a forward diff. */
static json_t *
compare_json_deep (json_t *current_json, json_t *previous_json)
{
    if (!current_json && !previous_json)
    {
        return NULL;
    }
    if (!current_json)
    {
        return json_null ();
    }
    if (!previous_json)
    {
        return json_incref (current_json);
    }

    if (json_typeof (current_json) != json_typeof (previous_json) ||
        json_typeof (current_json) != JSON_OBJECT)
    {
        return json_equal (current_json, previous_json) ? NULL : json_incref (current_json);
    }

    return compare_objects (current_json, previous_json);
}


/* Applies a forward diff to an older snapshot, determining a more recent state */
static json_t *
apply_forward_diff (json_t *snapshot, json_t *changes)
{
    if (!changes || !json_is_object (changes))
    {
        return json_deep_copy (snapshot);
    }

    json_t *result = json_deep_copy (snapshot);
    const char *key;
    json_t *value;

    json_object_foreach (changes, key, value)
    {
        if (json_is_null (value))
        {
            json_object_del (result, key);
        }
        else if (json_is_object (value) && json_is_object (json_object_get (result, key)))
        {
            json_t *nested = apply_forward_diff (json_object_get (result, key), value);
            json_object_set_new (result, key, nested);
        }
        else
        {
            json_object_set (result, key, value);
        }
    }

    return result;
}

/* Rebuilds the latest snapshot from a baseline + array of forward diffs */
static json_t *
reconstruct_latest_snapshot (json_t *baseline, json_t *diffs)
{
    json_t *snapshot = json_deep_copy (baseline);

    for (size_t i = 0; i < json_array_size (diffs); i++)
    {
        json_t *entry = json_array_get (diffs, i);
        json_t *changes = json_object_get (entry, "changes");
        json_t *next = apply_forward_diff (snapshot, changes);
        json_decref (snapshot);
        snapshot = next;
    }

    return snapshot;
}

/* Appends a single entry to the diffs array via seek, minimising disk write */
static int
append_diff_entry_to_file (const char *path, json_t *diff_entry)
{
    FILE *f = fopen (path, "r+");
    if (!f)
    {
        return -1;
    }

    // Find the last ']' in the file (closing the diffs array)
    fseek (f, 0, SEEK_END);
    long file_size = ftell (f);
    long pos = file_size - 1;

    while (pos >= 0)
    {
        fseek (f, pos, SEEK_SET);
        int ch = fgetc (f);
        if (ch == ']')
        {
            break;
        }
        pos--;
    }

    if (pos < 0)    // No ']' in file. Likely empty.
    {
        fclose (f);
        return -1;
    }

    long bracket_pos = pos;

    gboolean empty_array = FALSE;
    pos = bracket_pos - 1;
    while (pos >= 0)
    {
        fseek (f, pos, SEEK_SET);
        int ch = fgetc (f);
        if (ch == '[')
        {
            empty_array = TRUE;
            break;
        }
        if (!isspace (ch))
        {
            break;
        }
        pos--;
    }

    char *entry_str = json_dumps (diff_entry, JSON_COMPACT);
    if (!entry_str) // Shouldn't happen, but prevents undefined behaviour in fprintf if NULL.
    {
        fclose (f);
        return -1;
    }

    if (empty_array)
    {
        fseek (f, bracket_pos, SEEK_SET);
        fprintf (f, "\n    %s\n  ]\n  }\n", entry_str);
    }
    else
    {
        // Scan to find '}' of the previous entry, so the comma trails the previous entry
        pos = bracket_pos - 1;
        while (pos >= 0)
        {
            fseek (f, pos, SEEK_SET);
            int ch = fgetc (f);
            if (ch == '}')
            {
                break;
            }
            pos--;
        }
        fseek (f, pos + 1, SEEK_SET);
        fprintf (f, ",\n    %s\n  ]\n}\n", entry_str);
    }

    long new_end = ftell (f);
    if (ftruncate (fileno (f), new_end) != 0) // Redundant safety net.
    {
        free (entry_str);
        fclose (f);
        return -1;
    }

    free (entry_str);
    fclose (f);
    return 0;
}

/* Edits (or creates) JSON diff file. Uses an in-memory cache to optimise calculations */
static int
write_diff (json_t *current_json, const char *path_to_diff, json_t **last_snapshot_cache)
{
    int error_code;
    json_error_t error;
    json_t *storage = json_load_file (path_to_diff, 0, &error);

    if (!*last_snapshot_cache || !storage)
    {
        if (storage)
        {
            // Reconstruct latest state from existing file. Likely a SIGHUP reload
            json_t *baseline = json_object_get (storage, "baseline");
            json_t *diffs = json_object_get (storage, "diffs");
            *last_snapshot_cache = reconstruct_latest_snapshot (baseline, diffs);
            json_decref (storage);
            storage = NULL;
        }
        else
        {
            // No existing file: write baseline and set cache to current state
            json_t *new_storage = json_object ();
            json_object_set_new (new_storage, "baseline_timestamp",
                                 json_integer (time (NULL)));
            json_object_set_new (new_storage, "baseline", json_deep_copy (current_json));
            json_object_set_new (new_storage, "diffs", json_array ());

            error_code = json_dump_file (new_storage, path_to_diff,
                                         JSON_INDENT (json_indent));
            json_decref (new_storage);

            *last_snapshot_cache = json_deep_copy (current_json);
            return error_code;
        }
    }

    json_t *changes = compare_json_deep (current_json, *last_snapshot_cache);

    json_t *diff_entry = json_object ();
    json_object_set_new (diff_entry, "timestamp", json_integer (time (NULL)));
    json_object_set_new (diff_entry, "changes", changes ? changes : json_object ());

    error_code = append_diff_entry_to_file (path_to_diff, diff_entry);
    json_decref (diff_entry);

    if (error_code == 0 && changes != NULL) // Only update if there were valid changes
    {
        json_decref (*last_snapshot_cache);
        *last_snapshot_cache = json_deep_copy (current_json);
    }

    if (storage)
    {
        json_decref (storage);
    }

    return error_code;
}


/* Creates a unique name for logrotate config file based on specified diff destination */
static char *
sanitize_path_for_config (const char *path)
{
    char *result = malloc (strlen (path) + 8);
    strcpy (result, "config-");
    char *dst = result + 7;

    for (const char *src = path; *src; src++)
    {
        if (*src == '/' || *src == '.')
        {
            *dst++ = '-';
        }
        else if (isalnum (*src) || *src == '_')
        {
            *dst++ = *src;
        }
    }

    *dst = '\0';
    return result;
}

/* Turns a relative path into absolute for consistent comparison */
static char *
resolve_absolute_path (const char *path)
{
    /* Path should always exist, as it will crash earlier if not. File might not */
    char *resolved = realpath (path, NULL);
    if (resolved)
    {
        return resolved;
    }

    /* If there is no file, resolve parent directory, then append name */
    char *path_copy = strdup (path);
    char *resolved_dir = realpath (dirname (path_copy), NULL);
    free (path_copy);

    path_copy = strdup (path);
    char *result = malloc (strlen (resolved_dir) + strlen (basename (path_copy)) + 2);
    sprintf (result, "%s/%s", resolved_dir, basename (path_copy));

    free (path_copy);
    free (resolved_dir);
    return result;
}

/* Writes a single include directive, allowing logrotate to read from our logrotate config directory */
static int
create_logrotate_include (void)
{
    const char *out_dir = logrotate_dir_override ? logrotate_dir_override
        : LOGROTATE_DIR_DEFAULT;

    FILE *f = fopen (LOGROTATE_INCLUDE_FILE, "w");
    if (!f)
    {
        fprintf (stderr, "warning: failed to create logrotate include file %s: %s\n"
                 "         logrotate will not pick up recorder configs automatically\n",
                 LOGROTATE_INCLUDE_FILE, strerror (errno));
        return -1;
    }

    fprintf (f, "include %s\n", out_dir);
    fclose (f);
    return 0;
}

/* Makes a logrotate config based on user-specified settings */
static int
create_logrotate_config (config_data *config)
{
    char *absolute_path = resolve_absolute_path (config->destination);
    if (!absolute_path)
    {
        fprintf (stderr, "error: failed to resolve path: %s\n", config->destination);
        return -1;
    }

    char *config_name = sanitize_path_for_config (config->destination);
    const char *out_dir = logrotate_dir_override ? logrotate_dir_override
        : LOGROTATE_DIR_DEFAULT;

    int n = snprintf (NULL, 0, "%s/%s", out_dir, config_name);
    char *config_path = malloc (n + 1);
    snprintf (config_path, n + 1, "%s/%s", out_dir, config_name);

    char *directory_to_write = strdup (config_path);
    if (make_path (directory_to_write) != 0)
    {
        fprintf (stderr, "error: failed to build logrotate config path\n");
        free (absolute_path);
        free (config_name);
        free (directory_to_write);
        return -1;
    }
    free (directory_to_write);

    FILE *f = fopen (config_path, "w");
    if (!f)
    {
        fprintf (stderr, "error: failed to create logrotate config: %s\n", config_path);
        free (absolute_path);
        free (config_name);
        free (config_path);
        return -1;
    }

    fprintf (f, "%s {\n"
             "    size %ldk\n"
             "    rotate %d\n"
             "    missingok\n"
             "    notifempty\n"
             "    nocreate\n" "}\n", absolute_path, config->max_size, config->max_samples);

    fclose (f);
    free (absolute_path);
    free (config_name);
    free (config_path);
    return 0;
}


/* Main function called by the GLib thread */
static gboolean
polling_callback (gpointer user_data)
{
    config_data *config = (config_data *) user_data;

    GNode *root = g_node_new (g_strdup ("/"));
    apteryx_query_to_node (root, config->query);
    GNode *tree = apteryx_query (root);
    apteryx_free_tree (root);

    json_t *json_from_tree = tree ? gnode_to_json (tree) : NULL;
    apteryx_free_tree (tree);

    if (!json_from_tree)
    {
        fprintf (stderr, "warning: could not fetch JSON from query: %s\n", config->query);
        return G_SOURCE_CONTINUE;   // Continues in case it is a temporary apteryx issue
    }

    if (write_diff (json_from_tree, config->destination, &config->last_snapshot) != 0)
    {
        fprintf (stderr, "error: could not write diff. Check destination: %s\n",
                 config->destination);
        json_decref (json_from_tree);
        return G_SOURCE_REMOVE; // Breaks as the destination is likely significantly broken
    }

    json_decref (json_from_tree);

    return G_SOURCE_CONTINUE;
}

/* Helper to schedule a callback based on a delay */
static void
schedule_periodic_polling (config_data *config, GMainContext *context,
                           GSourceFunc callback_function, long delay)
{
    GSource *timeout = g_timeout_source_new_seconds (delay);
    g_source_set_callback (timeout, callback_function, config, NULL);
    g_source_attach (timeout, context);
    g_source_unref (timeout);
}

/* Used when a thread is interrupted and has to wait for a non-standard length */
static gboolean
initial_polling_callback (gpointer user_data)
{
    config_data *config = (config_data *) user_data;

    if (polling_callback (config) == G_SOURCE_CONTINUE)
    {
        schedule_periodic_polling (config, g_main_context_get_thread_default (),
                                   polling_callback, config->frequency);
    }

    return G_SOURCE_REMOVE;
}

/* Calculates the remaining delay for an interrupted thread */
static guint
calculate_initial_delay_at (long frequency, time_t last_poll_timestamp, time_t now)
{
    // If there is no record, or it is somehow in the future, just wait the full frequency
    if (last_poll_timestamp == 0 || now < last_poll_timestamp)
    {
        return (guint) frequency;
    }

    time_t elapsed = now - last_poll_timestamp;
    if (elapsed >= frequency)
    {
        return 0;
    }

    return (guint) (frequency - elapsed);
}

/* Determines when the last poll was.
 * Reads the timestamp from the last diff entry, or the baseline if no diffs exist. */
static time_t
read_last_poll_timestamp (const char *path_to_diff)
{
    json_error_t error;
    json_t *storage = json_load_file (path_to_diff, 0, &error);
    if (!storage)
    {
        return 0;
    }

    json_t *diffs = json_object_get (storage, "diffs");
    size_t diffs_len = json_is_array (diffs) ? json_array_size (diffs) : 0;

    if (diffs_len > 0)
    {
        json_t *last_diff = json_array_get (diffs, diffs_len - 1);
        json_t *ts = json_object_get (last_diff, "timestamp");
        time_t result = json_is_integer (ts) ? (time_t) json_integer_value (ts) : 0;
        json_decref (storage);
        return result;
    }

    json_t *ts = json_object_get (storage, "baseline_timestamp");
    time_t result = json_is_integer (ts) ? (time_t) json_integer_value (ts) : 0;

    json_decref (storage);
    return result;
}

/* Setup for the GLib thread */
static gboolean
quit_loop_cb (gpointer user_data)
{
    g_main_loop_quit ((GMainLoop *) user_data);
    return G_SOURCE_REMOVE;
}

/* Controls the setup and teardown of its config alongside poll rebooting */
static gpointer
thread_func (gpointer user_data)
{
    config_data *config = (config_data *) user_data;

    GMainContext *context = g_main_context_new ();
    GMainLoop *loop = g_main_loop_new (context, FALSE);

    g_mutex_lock (&config->mutex);
    config->context = context;
    config->loop = loop;
    config->thread_ready = TRUE;
    g_cond_signal (&config->cond);
    g_mutex_unlock (&config->mutex);

    g_main_context_push_thread_default (context);

    schedule_periodic_polling (config, context, initial_polling_callback,
                               config->initial_delay);
    g_main_loop_run (loop);

    g_main_context_pop_thread_default (context);

    g_mutex_lock (&config->mutex);
    config->loop = NULL;
    config->context = NULL;
    config->thread_ready = FALSE;
    g_mutex_unlock (&config->mutex);

    g_main_loop_unref (loop);
    g_main_context_unref (context);
    return NULL;
}

/* Frees data on error */
static void
config_data_free (config_data *config)
{
    if (config)
    {
        free (config->query);
        free (config->destination);
        if (config->last_snapshot)
        {
            json_decref (config->last_snapshot);
        }
        g_mutex_clear (&config->mutex);
        g_cond_clear (&config->cond);
        free (config);
    }
}

/* Frees provided objects (either local or global) */
static void
free_config_set (GHashTable *registry, GPtrArray *configs)
{
    if (configs)
    {
        g_ptr_array_free (configs, TRUE);
    }
    if (registry)
    {
        g_hash_table_destroy (registry);
    }
}

/* Controls the teardown of an entire thread  */
static void
stop_config_thread (config_data *config)
{
    if (!config || !config->thread)
    {
        return;
    }

    g_mutex_lock (&config->mutex);

    /* Wait for thread startup to publish context/loop */
    while (!config->thread_ready)
    {
        g_cond_wait (&config->cond, &config->mutex);
    }

    GMainContext *context = config->context ? g_main_context_ref (config->context) : NULL;
    GMainLoop *loop = config->loop ? g_main_loop_ref (config->loop) : NULL;
    g_mutex_unlock (&config->mutex);

    if (context && loop)
    {
        g_main_context_invoke_full (context,
                                    G_PRIORITY_DEFAULT,
                                    quit_loop_cb, loop, (GDestroyNotify) g_main_loop_unref);
    }
    else if (loop)
    {
        g_main_loop_quit (loop);
        g_main_loop_unref (loop);
    }

    if (context)
    {
        g_main_context_unref (context);
    }

    g_thread_join (config->thread); // Wait for thread to finish and clean itself up
    config->thread = NULL;
}

/* Iterates through configs and stops them */
static void
stop_config_set (GPtrArray *configs)
{
    if (!configs)
    {
        return;
    }

    for (guint i = 0; i < configs->len; i++)
    {
        stop_config_thread (g_ptr_array_index (configs, i));
    }
}

/* Iterates through configs and starts them */
static int
start_config_set (GPtrArray *configs)
{
    if (!configs)
    {
        return 0;
    }

    for (guint i = 0; i < configs->len; i++)
    {
        config_data *config = g_ptr_array_index (configs, i);

        config->thread = g_thread_new (NULL, thread_func, config);
        if (!config->thread)
        {
            fprintf (stderr, "error: failed to start config thread for %s\n",
                     config->destination);
            stop_config_set (configs);
            return -1;
        }
    }

    return 0;
}

/* Frees global variables */
static void
destination_registry_free_all ()
{
    free_config_set (destination_registry, active_configs);
    destination_registry = NULL;
    active_configs = NULL;
}

/* Adds destination to table. Throws error if it is already present */
static int
destination_registry_add (GHashTable *registry,
                          const char *destination, const char *config_path)
{
    gchar *key = resolve_absolute_path (destination);

    const char *first_seen = g_hash_table_lookup (registry, key);
    if (first_seen)
    {
        fprintf (stderr,
                 "error: duplicate destination '%s' in %s "
                 "(already registered by %s)\n",
                 key, config_path ? config_path : "(unknown)", first_seen);
        g_free (key);
        return -1;
    }

    g_hash_table_insert (registry, key, g_strdup (config_path ? config_path : "(unknown)"));
    return 0;
}

/* Ensures destination can be created, and has not already been claimed */
static int
validate_destination (GHashTable *registry,
                      const char *destination_path, const char *config_path)
{
    if (!destination_path || !*destination_path)
    {
        fprintf (stderr, "error: destination path not provided\n");
        return -1;
    }

    char *dest_str = strdup (destination_path);

    if (make_path (dest_str) != 0)
    {
        fprintf (stderr,
                 "error: failed to create destination path: %s\n", destination_path);
        free (dest_str);
        return -1;
    }
    free (dest_str);

    if (destination_registry_add (registry, destination_path, config_path) != 0)
    {
        return -1;
    }

    return 0;
}

/* Validates the data provided in the config file. Mostly checks types */
static int
validate_and_set_data (json_t *data,
                       config_data *config, GHashTable *registry, const char *config_path)
{
    json_t *query, *frequency, *destination, *max_samples, *max_size;

    query = json_object_get (data, "query");
    if (!json_is_string (query))
    {
        fprintf (stderr, "error: query is not a string\n");
        return -1;
    }

    frequency = json_object_get (data, "frequency");
    if (!json_is_integer (frequency))
    {
        fprintf (stderr, "error: frequency is not an integer\n");
        return -1;
    }
    if (json_integer_value (frequency) <= 0)
    {
        fprintf (stderr, "error: frequency must be greater than 0\n");
        return -1;
    }

    destination = json_object_get (data, "destination");
    if (!json_is_string (destination))
    {
        fprintf (stderr, "error: destination is not a string\n");
        return -1;
    }
    if (validate_destination (registry, json_string_value (destination), config_path) != 0)
    {
        return -1;
    }

    max_samples = json_object_get (data, "max_samples");
    if (!json_is_integer (max_samples))
    {
        fprintf (stderr, "error: max_samples is not an integer\n");
        return -1;
    }
    if (json_integer_value (max_samples) <= 0)
    {
        fprintf (stderr, "error: max_samples must be greater than 0\n");
        return -1;
    }

    max_size = json_object_get (data, "max_size");
    if (!json_is_integer (max_size))
    {
        fprintf (stderr, "error: max_size is not an integer\n");
        return -1;
    }
    if (json_integer_value (max_size) <= 0)
    {
        fprintf (stderr, "error: max_size must be greater than 0\n");
        return -1;
    }



    config->query = strdup (json_string_value (query));
    config->frequency = json_integer_value (frequency);
    config->destination = strdup (json_string_value (destination));
    config->max_samples = json_integer_value (max_samples);
    config->max_size = json_integer_value (max_size);

    return 0;
}

/* Tries to setup thread from config file object */
static int
initialise_config (json_t *data,
                   const char *config_path, GHashTable *registry, GPtrArray *configs)
{
    if (!json_is_object (data))
    {
        fprintf (stderr, "error: config is not a json object\n");
        return -1;
    }

    config_data *config = calloc (1, sizeof (config_data));
    g_mutex_init (&config->mutex);
    g_cond_init (&config->cond);

    int validation = validate_and_set_data (data, config, registry, config_path);
    if (validation != 0)
    {
        fprintf (stderr, "error: bad value in config \n");
        config_data_free (config);
        return -1;
    }

    validation = create_logrotate_config (config);
    if (validation != 0)
    {
        fprintf (stderr, "error: could not start logrotate. Check permissions \n");
        config_data_free (config);
        return -1;
    }

    config->initial_delay = calculate_initial_delay_at (config->frequency,
                                                        read_last_poll_timestamp
                                                        (config->destination), time (NULL));

    g_ptr_array_add (configs, config);

    return 0;
}

/* Gets all JSON files from specified directory and tries to write data to configs */
static int
load_configs_from_directory (const char *config_dir,
                             GHashTable *registry, GPtrArray *configs)
{
    DIR *dir;
    struct dirent *entry;
    char *ext;
    char *path_to_file;
    char *absolute_config_dir;
    json_t *root;
    json_error_t error;

    dir = opendir (config_dir);
    if (!dir)
    {
        fprintf (stderr, "error: failed to open config directory: %s\n", config_dir);
        return -1;
    }

    absolute_config_dir = resolve_absolute_path (config_dir);

    while ((entry = readdir (dir)) != NULL)
    {
        if (entry->d_type != DT_REG)
        {
            continue;
        }

        /* Only reads .json files */
        ext = strrchr (entry->d_name, '.');
        if ((ext == NULL) || (strcmp (ext, ".json") != 0))
        {
            continue;
        }
        path_to_file = g_strdup_printf ("%s/%s", absolute_config_dir, entry->d_name);

        root = json_load_file (path_to_file, 0, &error);
        if (!root)
        {
            fprintf (stderr,
                     "error: unable to open file: %s. May be empty or have too many objects\n",
                     path_to_file);
            free (absolute_config_dir);
            g_free (path_to_file);
            closedir (dir);
            return -1;
        }

        if (initialise_config (root, path_to_file, registry, configs) != 0)
        {
            fprintf (stderr, "error: failed to initialise config from file: %s\n",
                     path_to_file);
            free (absolute_config_dir);
            g_free (path_to_file);
            json_decref (root);
            closedir (dir);
            return -1;
        }

        json_decref (root);
        g_free (path_to_file);
    }

    free (absolute_config_dir);
    closedir (dir);
    return 0;
}

/* Fills local objects with data from config directory */
static int
load_config_set (const char *config_dir, GHashTable **registry, GPtrArray **configs)
{
    GHashTable *new_registry = g_hash_table_new_full (g_str_hash,
                                                      g_str_equal,
                                                      g_free,
                                                      g_free);
    GPtrArray *new_configs = g_ptr_array_new_with_free_func ((GDestroyNotify)
                                                             config_data_free);

    if (load_configs_from_directory (config_dir, new_registry, new_configs) != 0)
    {
        free_config_set (new_registry, new_configs);
        return -1;
    }

    *registry = new_registry;
    *configs = new_configs;
    return 0;
}

/* Resets all threads, closing old ones and adding new ones as per config directory info */
static int
replace_active_configs (const char *config_dir)
{
    GHashTable *new_registry = NULL;
    GPtrArray *new_configs = NULL;

    if (load_config_set (config_dir, &new_registry, &new_configs) != 0)
    {
        return -1;
    }

    if (new_configs && new_configs->len == 0)
    {
        /* No configuration files present, exit */
        if (main_loop)
        {
            g_main_loop_quit (main_loop);
            return 0;
        }
        else
        {
            fprintf (stderr, "error: No configuration files found in %s\n", config_dir);
            free_config_set (new_registry, new_configs);
            return -1;
        }
    }

    stop_config_set (active_configs);
    destination_registry_free_all ();

    if (start_config_set (new_configs) != 0)
    {
        free_config_set (new_registry, new_configs);
        return -1;
    }

    destination_registry = new_registry;
    active_configs = new_configs;

    return 0;
}

/* Runs on SIGHUP. Attempts to reload from current config directory */
static gboolean
reload_handler (gpointer user_data)
{
    const char *config_dir = (const char *) user_data;

    if (replace_active_configs (config_dir) != 0)
    {
        fprintf (stderr, "error: failed to reload configs from %s\n", config_dir);  // Keeps running with old configs if reload fails
    }

    return G_SOURCE_CONTINUE;
}


void
test_compare_json_deep_both_null_returns_null ()
{
    json_t *result = compare_json_deep (NULL, NULL);
    CU_ASSERT_PTR_NULL (result);
}

void
test_compare_json_deep_current_null_returns_json_null ()
{
    json_t *previous_json = json_object ();
    json_t *result = compare_json_deep (NULL, previous_json);
    json_t *expected = json_null ();

    CU_ASSERT_EQUAL (result, expected);

    json_decref (previous_json);
    json_decref (result);
    json_decref (expected);
}

void
test_compare_json_deep_previous_null_returns_current_value ()
{
    json_t *current_json = json_object ();
    json_t *result = compare_json_deep (current_json, NULL);

    CU_ASSERT_PTR_EQUAL (result, current_json);

    json_decref (current_json);
    json_decref (result);
}

void
test_compare_json_deep_type_mismatch_returns_current_value ()
{
    json_t *current_json = json_object ();
    json_t *previous_json = json_string ("previous value");
    json_t *result = compare_json_deep (current_json, previous_json);

    CU_ASSERT_PTR_EQUAL (result, current_json);

    json_decref (current_json);
    json_decref (previous_json);
    json_decref (result);
}

void
test_compare_json_deep_equal_string_returns_null ()
{
    json_t *current_json = json_string ("value");
    json_t *previous_json = json_string ("value");
    json_t *result = compare_json_deep (current_json, previous_json);

    CU_ASSERT_PTR_NULL (result);

    json_decref (current_json);
    json_decref (previous_json);
}

void
test_compare_json_deep_equal_integer_returns_null ()
{
    json_t *current_json = json_integer (42);
    json_t *previous_json = json_integer (42);
    json_t *result = compare_json_deep (current_json, previous_json);

    CU_ASSERT_PTR_NULL (result);

    json_decref (current_json);
    json_decref (previous_json);
}

void
test_compare_json_deep_different_string_returns_current_value ()
{
    json_t *current_json = json_string ("new value");
    json_t *previous_json = json_string ("old value");
    json_t *result = compare_json_deep (current_json, previous_json);

    CU_ASSERT_PTR_EQUAL (result, current_json);

    json_decref (current_json);
    json_decref (previous_json);
    json_decref (result);
}

void
test_compare_json_deep_different_integer_returns_current_value ()
{
    json_t *current_json = json_integer (42);
    json_t *previous_json = json_integer (41);
    json_t *result = compare_json_deep (current_json, previous_json);

    CU_ASSERT_PTR_EQUAL (result, current_json);

    json_decref (current_json);
    json_decref (previous_json);
    json_decref (result);
}

void
test_compare_json_deep_equal_arrays_returns_null ()
{
    json_t *current_arr = json_array ();
    json_array_append_new (current_arr, json_integer (1));
    json_array_append_new (current_arr, json_integer (2));
    json_t *previous_arr = json_array ();
    json_array_append_new (previous_arr, json_integer (1));
    json_array_append_new (previous_arr, json_integer (2));
    json_t *result = compare_json_deep (current_arr, previous_arr);

    CU_ASSERT_PTR_NULL (result);

    json_decref (current_arr);
    json_decref (previous_arr);
}

void
test_compare_json_deep_different_arrays_returns_current_array ()
{
    json_t *current_arr = json_array ();
    json_array_append_new (current_arr, json_integer (1));
    json_array_append_new (current_arr, json_integer (2));
    json_array_append_new (current_arr, json_integer (3));
    json_t *previous_arr = json_array ();
    json_array_append_new (previous_arr, json_integer (1));
    json_array_append_new (previous_arr, json_integer (2));
    json_t *result = compare_json_deep (current_arr, previous_arr);

    CU_ASSERT_PTR_EQUAL (result, current_arr);

    json_decref (current_arr);
    json_decref (previous_arr);
    json_decref (result);
}

void
test_compare_json_deep_empty_objects_returns_null ()
{
    json_t *current_obj = json_object ();
    json_t *previous_obj = json_object ();
    json_t *result = compare_json_deep (current_obj, previous_obj);

    CU_ASSERT_PTR_NULL (result);

    json_decref (current_obj);
    json_decref (previous_obj);
}

void
test_compare_json_deep_equal_object_values_returns_null ()
{
    json_t *current_obj = json_object ();
    json_t *previous_obj = json_object ();
    json_object_set_new (current_obj, "key1", json_string ("value"));
    json_object_set_new (previous_obj, "key1", json_string ("value"));
    json_t *result = compare_json_deep (current_obj, previous_obj);

    CU_ASSERT_PTR_NULL (result);

    json_decref (current_obj);
    json_decref (previous_obj);
}

void
test_compare_json_deep_changed_object_value_returns_current_value_object ()
{
    json_t *current_obj = json_object ();
    json_t *previous_obj = json_object ();
    json_object_set_new (current_obj, "key1", json_string ("new value"));
    json_object_set_new (previous_obj, "key1", json_string ("old value"));
    json_t *result = compare_json_deep (current_obj, previous_obj);

    CU_ASSERT_EQUAL (json_typeof (result), JSON_OBJECT);
    CU_ASSERT_TRUE (json_equal (result, current_obj));

    json_decref (current_obj);
    json_decref (previous_obj);
    json_decref (result);
}

void
test_compare_json_deep_deleted_key_records_null_marker ()
{
    json_t *current_obj = json_object ();
    json_t *previous_obj = json_object ();
    json_object_set_new (previous_obj, "key1", json_string ("value"));

    json_t *result = compare_json_deep (current_obj, previous_obj);
    json_t *diff = json_object_get (result, "key1");
    json_t *expected_null = json_null ();

    CU_ASSERT_EQUAL (json_typeof (result), JSON_OBJECT);
    CU_ASSERT_EQUAL (diff, expected_null);

    json_decref (expected_null);
    json_decref (current_obj);
    json_decref (previous_obj);
    json_decref (result);
}

void
test_compare_json_deep_new_key_returns_current_value ()
{
    json_t *current_obj = json_object ();
    json_t *previous_obj = json_object ();
    json_object_set_new (current_obj, "key1", json_string ("value"));
    json_object_set_new (current_obj, "key2", json_string ("new value"));
    json_object_set_new (previous_obj, "key1", json_string ("value"));

    json_t *result = compare_json_deep (current_obj, previous_obj);
    json_t *diff = json_object_get (result, "key2");
    json_t *expected = json_string ("new value");

    CU_ASSERT_EQUAL (json_typeof (result), JSON_OBJECT);
    CU_ASSERT_TRUE (json_equal (diff, expected));

    json_decref (expected);
    json_decref (current_obj);
    json_decref (previous_obj);
    json_decref (result);
}


void
test_calculate_initial_delay_at_missing_timestamp_returns_frequency ()
{
    CU_ASSERT_EQUAL (calculate_initial_delay_at (30, 0, 100), 30);
}

void
test_calculate_initial_delay_at_future_timestamp_returns_frequency ()
{
    CU_ASSERT_EQUAL (calculate_initial_delay_at (30, 200, 100), 30);
}

void
test_calculate_initial_delay_at_overdue_returns_immediate ()
{
    CU_ASSERT_EQUAL (calculate_initial_delay_at (30, 60, 100), 0);
}

void
test_calculate_initial_delay_at_partial_interval_returns_remaining ()
{
    CU_ASSERT_EQUAL (calculate_initial_delay_at (30, 80, 100), 10);
}

void
test_read_last_poll_timestamp_missing_file_returns_zero ()
{
    time_t result = read_last_poll_timestamp ("");
    CU_ASSERT_EQUAL (result, 0);
}

static int
write_test_timestamp_file (const char *path_to_diff, json_t *timestamp)
{
    json_t *root = json_object ();

    if (timestamp)
    {
        json_object_set (root, "baseline_timestamp", timestamp);
    }

    json_object_set_new (root, "baseline", json_object ());
    json_object_set_new (root, "diffs", json_array ());

    int rc = json_dump_file (root, path_to_diff, 0);
    json_decref (root);
    return rc;
}

void
test_read_last_poll_timestamp_valid_file_returns_value ()
{
    char path[] = "/tmp/recorder_timestamp_valid_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);

    json_t *timestamp = json_integer (1234);

    CU_ASSERT_EQUAL_FATAL (write_test_timestamp_file (path, timestamp), 0);

    time_t result = read_last_poll_timestamp (path);
    CU_ASSERT_EQUAL (result, 1234);

    unlink (path);
    json_decref (timestamp);
}

void
test_read_last_poll_timestamp_non_integer_returns_zero ()
{
    char path[] = "/tmp/recorder_timestamp_nonint_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);

    json_t *timestamp = json_string ("bad");

    CU_ASSERT_EQUAL_FATAL (write_test_timestamp_file (path, timestamp), 0);

    time_t result = read_last_poll_timestamp (path);
    CU_ASSERT_EQUAL (result, 0);

    unlink (path);
    json_decref (timestamp);
}


void
test_apply_forward_diff_null_changes_returns_copy ()
{
    json_t *snapshot = json_object ();
    json_object_set_new (snapshot, "key", json_string ("val"));

    json_t *result = apply_forward_diff (snapshot, NULL);

    CU_ASSERT_TRUE (json_equal (result, snapshot));
    CU_ASSERT_PTR_NOT_EQUAL (result, snapshot);

    json_decref (snapshot);
    json_decref (result);
}

void
test_apply_forward_diff_empty_changes_returns_copy ()
{
    json_t *snapshot = json_object ();
    json_object_set_new (snapshot, "key", json_string ("val"));
    json_t *changes = json_object ();

    json_t *result = apply_forward_diff (snapshot, changes);

    CU_ASSERT_TRUE (json_equal (result, snapshot));
    CU_ASSERT_PTR_NOT_EQUAL (result, snapshot);

    json_decref (snapshot);
    json_decref (changes);
    json_decref (result);
}

void
test_apply_forward_diff_updates_existing_key ()
{
    json_t *snapshot = json_object ();
    json_object_set_new (snapshot, "key", json_string ("old"));
    json_t *changes = json_object ();
    json_object_set_new (changes, "key", json_string ("new"));

    json_t *result = apply_forward_diff (snapshot, changes);
    json_t *expected = json_string ("new");

    CU_ASSERT_TRUE (json_equal (json_object_get (result, "key"), expected));

    json_decref (snapshot);
    json_decref (changes);
    json_decref (result);
    json_decref (expected);
}

void
test_apply_forward_diff_adds_new_key ()
{
    json_t *snapshot = json_object ();
    json_t *changes = json_object ();
    json_object_set_new (changes, "added", json_string ("value"));

    json_t *result = apply_forward_diff (snapshot, changes);

    CU_ASSERT_PTR_NOT_NULL (json_object_get (result, "added"));
    CU_ASSERT_TRUE (json_equal (json_object_get (result, "added"),
                                json_object_get (changes, "added")));

    json_decref (snapshot);
    json_decref (changes);
    json_decref (result);
}

void
test_apply_forward_diff_null_value_deletes_key ()
{
    json_t *snapshot = json_object ();
    json_object_set_new (snapshot, "key", json_string ("val"));
    json_t *changes = json_object ();
    json_object_set_new (changes, "key", json_null ());

    json_t *result = apply_forward_diff (snapshot, changes);

    CU_ASSERT_PTR_NULL (json_object_get (result, "key"));
    CU_ASSERT_EQUAL (json_object_size (result), 0);

    json_decref (snapshot);
    json_decref (changes);
    json_decref (result);
}

void
test_apply_forward_diff_nested_object_merges ()
{
    json_t *inner = json_object ();
    json_object_set_new (inner, "a", json_string ("1"));
    json_object_set_new (inner, "b", json_string ("2"));
    json_t *snapshot = json_object ();
    json_object_set_new (snapshot, "nested", inner);

    json_t *inner_change = json_object ();
    json_object_set_new (inner_change, "b", json_string ("changed"));
    json_t *changes = json_object ();
    json_object_set_new (changes, "nested", inner_change);

    json_t *result = apply_forward_diff (snapshot, changes);
    json_t *result_nested = json_object_get (result, "nested");

    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (result_nested, "a")), "1");
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (result_nested, "b")),
                            "changed");

    json_decref (snapshot);
    json_decref (changes);
    json_decref (result);
}


void
test_reconstruct_no_diffs_returns_baseline ()
{
    json_t *baseline = json_object ();
    json_object_set_new (baseline, "key", json_string ("val"));
    json_t *diffs = json_array ();

    json_t *result = reconstruct_latest_snapshot (baseline, diffs);

    CU_ASSERT_TRUE (json_equal (result, baseline));
    CU_ASSERT_PTR_NOT_EQUAL (result, baseline);

    json_decref (baseline);
    json_decref (diffs);
    json_decref (result);
}

void
test_reconstruct_single_diff_applies ()
{
    json_t *baseline = json_object ();
    json_object_set_new (baseline, "key", json_string ("v1"));

    json_t *diff_changes = json_object ();
    json_object_set_new (diff_changes, "key", json_string ("v2"));
    json_t *diff_entry = json_object ();
    json_object_set_new (diff_entry, "changes", diff_changes);

    json_t *diffs = json_array ();
    json_array_append_new (diffs, diff_entry);

    json_t *result = reconstruct_latest_snapshot (baseline, diffs);
    json_t *expected = json_string ("v2");

    CU_ASSERT_TRUE (json_equal (json_object_get (result, "key"), expected));

    json_decref (baseline);
    json_decref (diffs);
    json_decref (result);
    json_decref (expected);
}

void
test_reconstruct_multiple_diffs_applies_in_order ()
{
    json_t *baseline = json_object ();
    json_object_set_new (baseline, "key", json_string ("v1"));

    json_t *d1_changes = json_object ();
    json_object_set_new (d1_changes, "key", json_string ("v2"));
    json_t *d1 = json_object ();
    json_object_set_new (d1, "changes", d1_changes);

    json_t *d2_changes = json_object ();
    json_object_set_new (d2_changes, "key", json_string ("v3"));
    json_t *d2 = json_object ();
    json_object_set_new (d2, "changes", d2_changes);

    json_t *diffs = json_array ();
    json_array_append_new (diffs, d1);
    json_array_append_new (diffs, d2);

    json_t *result = reconstruct_latest_snapshot (baseline, diffs);

    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (result, "key")), "v3");

    json_decref (baseline);
    json_decref (diffs);
    json_decref (result);
}

void
test_reconstruct_diff_with_deletion ()
{
    json_t *baseline = json_object ();
    json_object_set_new (baseline, "a", json_string ("1"));
    json_object_set_new (baseline, "b", json_string ("2"));

    json_t *changes = json_object ();
    json_object_set_new (changes, "b", json_null ());
    json_t *d = json_object ();
    json_object_set_new (d, "changes", changes);

    json_t *diffs = json_array ();
    json_array_append_new (diffs, d);

    json_t *result = reconstruct_latest_snapshot (baseline, diffs);

    CU_ASSERT_PTR_NOT_NULL (json_object_get (result, "a"));
    CU_ASSERT_PTR_NULL (json_object_get (result, "b"));

    json_decref (baseline);
    json_decref (diffs);
    json_decref (result);
}


void
test_append_diff_to_empty_array ()
{
    char path[] = "/tmp/recorder_append_empty_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);

    /* Write a minimal valid file with empty diffs array */
    json_t *storage = json_object ();
    json_object_set_new (storage, "baseline_timestamp", json_integer (100));
    json_object_set_new (storage, "baseline", json_object ());
    json_object_set_new (storage, "diffs", json_array ());
    CU_ASSERT_EQUAL_FATAL (json_dump_file (storage, path, JSON_INDENT (json_indent)), 0);
    json_decref (storage);

    json_t *entry = json_object ();
    json_object_set_new (entry, "timestamp", json_integer (200));
    json_object_set_new (entry, "changes", json_object ());

    CU_ASSERT_EQUAL (append_diff_entry_to_file (path, entry), 0);
    json_decref (entry);

    /* Verify the file is still valid JSON with one diff */
    json_error_t error;
    json_t *reloaded = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (reloaded);

    json_t *diffs = json_object_get (reloaded, "diffs");
    CU_ASSERT_EQUAL (json_array_size (diffs), 1);
    CU_ASSERT_EQUAL (json_integer_value
                     (json_object_get (json_array_get (diffs, 0), "timestamp")), 200);

    json_decref (reloaded);
    unlink (path);
}

void
test_append_diff_to_nonempty_array ()
{
    char path[] = "/tmp/recorder_append_nonempty_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);

    /* Write file with one existing diff */
    json_t *existing_entry = json_object ();
    json_object_set_new (existing_entry, "timestamp", json_integer (100));
    json_object_set_new (existing_entry, "changes", json_object ());
    json_t *diffs_arr = json_array ();
    json_array_append_new (diffs_arr, existing_entry);

    json_t *storage = json_object ();
    json_object_set_new (storage, "baseline_timestamp", json_integer (50));
    json_object_set_new (storage, "baseline", json_object ());
    json_object_set_new (storage, "diffs", diffs_arr);
    CU_ASSERT_EQUAL_FATAL (json_dump_file (storage, path, JSON_INDENT (json_indent)), 0);
    json_decref (storage);

    json_t *entry = json_object ();
    json_object_set_new (entry, "timestamp", json_integer (200));
    json_object_set_new (entry, "changes", json_object ());

    CU_ASSERT_EQUAL (append_diff_entry_to_file (path, entry), 0);
    json_decref (entry);

    json_error_t error;
    json_t *reloaded = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (reloaded);

    json_t *diffs = json_object_get (reloaded, "diffs");
    CU_ASSERT_EQUAL (json_array_size (diffs), 2);
    CU_ASSERT_EQUAL (json_integer_value
                     (json_object_get (json_array_get (diffs, 0), "timestamp")), 100);
    CU_ASSERT_EQUAL (json_integer_value
                     (json_object_get (json_array_get (diffs, 1), "timestamp")), 200);

    json_decref (reloaded);
    unlink (path);
}

void
test_append_diff_nonexistent_file_fails ()
{
    json_t *entry = json_object ();
    json_object_set_new (entry, "timestamp", json_integer (100));
    json_object_set_new (entry, "changes", json_object ());

    CU_ASSERT_NOT_EQUAL (append_diff_entry_to_file
                         ("/tmp/recorder_nonexistent_file_xyz", entry), 0);

    json_decref (entry);
}


void
test_write_diff_creates_baseline_on_new_file ()
{
    char path[] = "/tmp/recorder_wd_new_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);  /* Ensure file does not exist */

    json_t *snapshot = json_object ();
    json_object_set_new (snapshot, "key", json_string ("val"));
    json_t *cache = NULL;

    CU_ASSERT_EQUAL (write_diff (snapshot, path, &cache), 0);
    CU_ASSERT_PTR_NOT_NULL (cache);

    /* Verify file structure */
    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);
    CU_ASSERT_PTR_NOT_NULL (json_object_get (storage, "baseline"));
    CU_ASSERT_PTR_NOT_NULL (json_object_get (storage, "baseline_timestamp"));
    CU_ASSERT_TRUE (json_equal (json_object_get (storage, "baseline"), snapshot));
    CU_ASSERT_EQUAL (json_array_size (json_object_get (storage, "diffs")), 0);

    json_decref (storage);
    json_decref (snapshot);
    json_decref (cache);
    unlink (path);
}

void
test_write_diff_appends_empty_diff_when_unchanged ()
{
    char path[] = "/tmp/recorder_wd_unchanged_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);

    json_t *snapshot = json_object ();
    json_object_set_new (snapshot, "key", json_string ("val"));
    json_t *cache = NULL;

    /* First call creates baseline */
    CU_ASSERT_EQUAL (write_diff (snapshot, path, &cache), 0);
    /* Second call with same data */
    CU_ASSERT_EQUAL (write_diff (snapshot, path, &cache), 0);

    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);

    json_t *diffs = json_object_get (storage, "diffs");
    CU_ASSERT_EQUAL (json_array_size (diffs), 1);

    /* Changes should be empty object */
    json_t *first_diff = json_array_get (diffs, 0);
    json_t *changes = json_object_get (first_diff, "changes");
    CU_ASSERT_EQUAL (json_object_size (changes), 0);

    json_decref (storage);
    json_decref (snapshot);
    json_decref (cache);
    unlink (path);
}

void
test_write_diff_records_changes ()
{
    char path[] = "/tmp/recorder_wd_changes_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);

    json_t *snap1 = json_object ();
    json_object_set_new (snap1, "key", json_string ("v1"));
    json_t *cache = NULL;

    CU_ASSERT_EQUAL (write_diff (snap1, path, &cache), 0);

    json_t *snap2 = json_object ();
    json_object_set_new (snap2, "key", json_string ("v2"));

    CU_ASSERT_EQUAL (write_diff (snap2, path, &cache), 0);

    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);

    /* Baseline should still be v1 */
    CU_ASSERT_STRING_EQUAL (json_string_value
                            (json_object_get
                             (json_object_get (storage, "baseline"), "key")), "v1");

    /* Diff should record the new value v2 */
    json_t *diffs = json_object_get (storage, "diffs");
    CU_ASSERT_EQUAL (json_array_size (diffs), 1);
    json_t *changes = json_object_get (json_array_get (diffs, 0), "changes");
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (changes, "key")), "v2");

    json_decref (storage);
    json_decref (snap1);
    json_decref (snap2);
    json_decref (cache);
    unlink (path);
}

void
test_write_diff_multiple_polls_accumulates_diffs ()
{
    char path[] = "/tmp/recorder_wd_multi_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);

    json_t *cache = NULL;

    json_t *s1 = json_object ();
    json_object_set_new (s1, "key", json_string ("v1"));
    CU_ASSERT_EQUAL (write_diff (s1, path, &cache), 0);

    json_t *s2 = json_object ();
    json_object_set_new (s2, "key", json_string ("v2"));
    CU_ASSERT_EQUAL (write_diff (s2, path, &cache), 0);

    json_t *s3 = json_object ();
    json_object_set_new (s3, "key", json_string ("v3"));
    CU_ASSERT_EQUAL (write_diff (s3, path, &cache), 0);

    /* Same as s3 - empty diff */
    CU_ASSERT_EQUAL (write_diff (s3, path, &cache), 0);

    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);

    json_t *diffs = json_object_get (storage, "diffs");
    CU_ASSERT_EQUAL (json_array_size (diffs), 3);

    /* Verify baseline untouched */
    CU_ASSERT_STRING_EQUAL (json_string_value
                            (json_object_get
                             (json_object_get (storage, "baseline"), "key")), "v1");

    json_decref (storage);
    json_decref (s1);
    json_decref (s2);
    json_decref (s3);
    json_decref (cache);
    unlink (path);
}

void
test_write_diff_reconstruct_from_existing_file ()
{
    char path[] = "/tmp/recorder_wd_recon_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);

    /* Simulate first session: write baseline + one diff */
    json_t *cache1 = NULL;
    json_t *s1 = json_object ();
    json_object_set_new (s1, "key", json_string ("v1"));
    CU_ASSERT_EQUAL (write_diff (s1, path, &cache1), 0);

    json_t *s2 = json_object ();
    json_object_set_new (s2, "key", json_string ("v2"));
    CU_ASSERT_EQUAL (write_diff (s2, path, &cache1), 0);
    json_decref (cache1);

    /* Simulate restart: new cache, same file */
    json_t *cache2 = NULL;
    json_t *s3 = json_object ();
    json_object_set_new (s3, "key", json_string ("v3"));
    CU_ASSERT_EQUAL (write_diff (s3, path, &cache2), 0);

    /* Verify: baseline=v1, diffs=[v2_change, v3_change] */
    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);

    CU_ASSERT_STRING_EQUAL (json_string_value
                            (json_object_get
                             (json_object_get (storage, "baseline"), "key")), "v1");

    json_t *diffs = json_object_get (storage, "diffs");
    CU_ASSERT_EQUAL (json_array_size (diffs), 2);

    /* The second diff should have v3 as the new value */
    json_t *last_changes = json_object_get (json_array_get (diffs, 1), "changes");
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (last_changes, "key")),
                            "v3");

    json_decref (storage);
    json_decref (s1);
    json_decref (s2);
    json_decref (s3);
    json_decref (cache2);
    unlink (path);
}

void
test_write_diff_replaces_existing_cache_when_file_missing ()
{
    char path[] = "/tmp/recorder_wd_replace_cache_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);

    json_t *old_cache = json_object ();
    json_object_set_new (old_cache, "key", json_string ("old"));

    /* Hold a second reference so old_cache remains valid for assertions. */
    json_incref (old_cache);
    json_t *cache = old_cache;

    json_t *current = json_object ();
    json_object_set_new (current, "key", json_string ("new"));

    CU_ASSERT_EQUAL (write_diff (current, path, &cache), 0);
    CU_ASSERT_PTR_NOT_NULL (cache);
    CU_ASSERT_PTR_NOT_EQUAL (cache, old_cache);
    CU_ASSERT_TRUE (json_equal (cache, current));

    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);
    CU_ASSERT_TRUE (json_equal (json_object_get (storage, "baseline"), current));

    json_decref (storage);
    json_decref (current);
    json_decref (cache);
    json_decref (old_cache);
    unlink (path);
}

void
test_read_last_poll_timestamp_reads_from_diffs ()
{
    char path[] = "/tmp/recorder_ts_diffs_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);

    /* Write file with a diff entry that has a known timestamp */
    json_t *diff_entry = json_object ();
    json_object_set_new (diff_entry, "timestamp", json_integer (9999));
    json_object_set_new (diff_entry, "changes", json_object ());
    json_t *diffs_arr = json_array ();
    json_array_append_new (diffs_arr, diff_entry);

    json_t *storage = json_object ();
    json_object_set_new (storage, "baseline_timestamp", json_integer (1000));
    json_object_set_new (storage, "baseline", json_object ());
    json_object_set_new (storage, "diffs", diffs_arr);
    CU_ASSERT_EQUAL_FATAL (json_dump_file (storage, path, 0), 0);
    json_decref (storage);

    time_t result = read_last_poll_timestamp (path);
    CU_ASSERT_EQUAL (result, 9999);

    unlink (path);
}


int
main (int argc, char *argv[])
{
    int opt;
    const char *config_dir = NULL;
    bool unit_test = false;
    CU_pSuite pSuite;

    while ((opt = getopt (argc, argv, "huc:l::")) != -1)
    {
        switch (opt)
        {
        case 'u':
            unit_test = true;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'l':
            logrotate_dir_override = optarg;
            break;
        case '?':
        case 'h':
        default:
            printf ("Usage: %s [-h] [-u] [-c <configdir>] [-l <logrotate_dir>]\n"
                    "  -h   show this help\n"
                    "  -u   run unit tests\n"
                    "  -c   use files from <configdir>\n"
                    "  -l   write logrotate configs to <logrotate_dir> (default: %s)\n",
                    argv[0], LOGROTATE_DIR_DEFAULT);
            return 0;
        }
    }


    if (unit_test)
    {
        CU_initialize_registry ();

        pSuite = CU_add_suite ("unit::compare_json_deep", NULL, NULL);
        CU_add_test (pSuite, "both_null_returns_null",
                     test_compare_json_deep_both_null_returns_null);
        CU_add_test (pSuite, "current_null_returns_json_null",
                     test_compare_json_deep_current_null_returns_json_null);
        CU_add_test (pSuite, "previous_null_returns_current_value",
                     test_compare_json_deep_previous_null_returns_current_value);
        CU_add_test (pSuite, "type_mismatch_returns_current_value",
                     test_compare_json_deep_type_mismatch_returns_current_value);
        CU_add_test (pSuite, "equal_string_returns_null",
                     test_compare_json_deep_equal_string_returns_null);
        CU_add_test (pSuite, "equal_integer_returns_null",
                     test_compare_json_deep_equal_integer_returns_null);
        CU_add_test (pSuite, "different_string_returns_current_value",
                     test_compare_json_deep_different_string_returns_current_value);
        CU_add_test (pSuite, "different_integer_returns_current_value",
                     test_compare_json_deep_different_integer_returns_current_value);
        CU_add_test (pSuite, "equal_arrays_returns_null",
                     test_compare_json_deep_equal_arrays_returns_null);
        CU_add_test (pSuite, "different_arrays_returns_current_array",
                     test_compare_json_deep_different_arrays_returns_current_array);

        pSuite = CU_add_suite ("integration::compare_json_deep_objects", NULL, NULL);
        CU_add_test (pSuite, "empty_objects_returns_null",
                     test_compare_json_deep_empty_objects_returns_null);
        CU_add_test (pSuite, "equal_object_values_returns_null",
                     test_compare_json_deep_equal_object_values_returns_null);
        CU_add_test (pSuite, "changed_object_value_returns_current_value_object",
                     test_compare_json_deep_changed_object_value_returns_current_value_object);
        CU_add_test (pSuite, "deleted_key_records_null_marker",
                     test_compare_json_deep_deleted_key_records_null_marker);
        CU_add_test (pSuite, "new_key_returns_current_value",
                     test_compare_json_deep_new_key_returns_current_value);

        pSuite = CU_add_suite ("unit::reload_timing", NULL, NULL);
        CU_add_test (pSuite, "missing_timestamp_returns_frequency",
                     test_calculate_initial_delay_at_missing_timestamp_returns_frequency);
        CU_add_test (pSuite, "future_timestamp_returns_frequency",
                     test_calculate_initial_delay_at_future_timestamp_returns_frequency);
        CU_add_test (pSuite, "overdue_returns_immediate",
                     test_calculate_initial_delay_at_overdue_returns_immediate);
        CU_add_test (pSuite, "partial_interval_returns_remaining",
                     test_calculate_initial_delay_at_partial_interval_returns_remaining);
        CU_add_test (pSuite, "missing_file_returns_zero",
                     test_read_last_poll_timestamp_missing_file_returns_zero);
        CU_add_test (pSuite, "valid_file_returns_value",
                     test_read_last_poll_timestamp_valid_file_returns_value);
        CU_add_test (pSuite, "non_integer_returns_zero",
                     test_read_last_poll_timestamp_non_integer_returns_zero);
        CU_add_test (pSuite, "reads_timestamp_from_last_diff",
                     test_read_last_poll_timestamp_reads_from_diffs);

        pSuite = CU_add_suite ("unit::apply_forward_diff", NULL, NULL);
        CU_add_test (pSuite, "null_changes_returns_copy",
                     test_apply_forward_diff_null_changes_returns_copy);
        CU_add_test (pSuite, "empty_changes_returns_copy",
                     test_apply_forward_diff_empty_changes_returns_copy);
        CU_add_test (pSuite, "updates_existing_key",
                     test_apply_forward_diff_updates_existing_key);
        CU_add_test (pSuite, "adds_new_key", test_apply_forward_diff_adds_new_key);
        CU_add_test (pSuite, "null_value_deletes_key",
                     test_apply_forward_diff_null_value_deletes_key);
        CU_add_test (pSuite, "nested_object_merges",
                     test_apply_forward_diff_nested_object_merges);

        pSuite = CU_add_suite ("unit::reconstruct_latest_snapshot", NULL, NULL);
        CU_add_test (pSuite, "no_diffs_returns_baseline",
                     test_reconstruct_no_diffs_returns_baseline);
        CU_add_test (pSuite, "single_diff_applies", test_reconstruct_single_diff_applies);
        CU_add_test (pSuite, "multiple_diffs_in_order",
                     test_reconstruct_multiple_diffs_applies_in_order);
        CU_add_test (pSuite, "diff_with_deletion", test_reconstruct_diff_with_deletion);

        pSuite = CU_add_suite ("unit::append_diff_entry_to_file", NULL, NULL);
        CU_add_test (pSuite, "appends_to_empty_array", test_append_diff_to_empty_array);
        CU_add_test (pSuite, "appends_to_nonempty_array",
                     test_append_diff_to_nonempty_array);
        CU_add_test (pSuite, "nonexistent_file_fails",
                     test_append_diff_nonexistent_file_fails);

        pSuite = CU_add_suite ("integration::write_diff", NULL, NULL);
        CU_add_test (pSuite, "creates_baseline_on_new_file",
                     test_write_diff_creates_baseline_on_new_file);
        CU_add_test (pSuite, "appends_empty_diff_when_unchanged",
                     test_write_diff_appends_empty_diff_when_unchanged);
        CU_add_test (pSuite, "records_changes", test_write_diff_records_changes);
        CU_add_test (pSuite, "multiple_polls_accumulates",
                     test_write_diff_multiple_polls_accumulates_diffs);
        CU_add_test (pSuite, "reconstructs_from_existing_file",
                     test_write_diff_reconstruct_from_existing_file);
        CU_add_test (pSuite, "replaces_existing_cache_when_file_missing",
                     test_write_diff_replaces_existing_cache_when_file_missing);

        CU_basic_set_mode (CU_BRM_VERBOSE);
        CU_basic_run_tests ();
        int failures = CU_get_number_of_failures ();
        CU_cleanup_registry ();

        return failures ? -1 : 0;
    }

    if (!config_dir)
    {
        fprintf (stderr,
                 "error: No configuration directory path set. Missing -c <configdir>\n");
        return -1;
    }

    apteryx_init (false);

    create_logrotate_include ();

    if (replace_active_configs (config_dir) != 0)
    {
        goto exit;
    }

    main_loop = g_main_loop_new (NULL, false);
    g_unix_signal_add (SIGINT, quit_loop_cb, main_loop);
    g_unix_signal_add (SIGTERM, quit_loop_cb, main_loop);
    g_unix_signal_add (SIGHUP, reload_handler, (gpointer) config_dir);
    g_main_loop_run (main_loop);


  exit:
    if (main_loop)
    {
        g_main_loop_unref (main_loop);
    }

    /* Stop all running config threads before freeing their data */
    stop_config_set (active_configs);

    /* Cleanup destination registry */
    destination_registry_free_all ();

    /* Cleanup client library */
    apteryx_shutdown ();

    return 0;
}
