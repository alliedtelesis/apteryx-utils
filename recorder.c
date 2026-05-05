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
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

static const int json_indent = 2;

/* Override used for testing. NULL means use default */
static const char *logrotate_dir_override = NULL;
#define LOGROTATE_DIR_DEFAULT "/etc/logrotate.d"

static json_t *compare_json_deep (json_t *old_json, json_t *new_json);

typedef struct _config_data
{
    char *query;
    long frequency;
    char *destination;
    int max_samples;
    long max_size;
    GMainLoop *loop;
} config_data;


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
compare_objects (json_t *old_obj, json_t *new_obj)
{
    json_t *changes = json_object ();
    const char *key;
    json_t *value;

    json_object_foreach (old_obj, key, value)
    {
        json_t *diff = compare_json_deep (value, json_object_get (new_obj, key));
        if (diff)
        {
            json_object_set_new (changes, key, diff);
        }
    }

    json_object_foreach (new_obj, key, value)
    {
        if (!json_object_get (old_obj, key))
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

/* Tries to compare primitively, otherwise defers to compare_objects for recursion */
static json_t *
compare_json_deep (json_t *old_json, json_t *new_json)
{
    if (!old_json && !new_json)
    {
        return NULL;
    }
    if (!old_json)
    {
        return json_null ();
    }
    if (!new_json)
    {
        return json_incref (old_json);
    }

    if (json_typeof (old_json) != json_typeof (new_json) ||
        json_typeof (old_json) != JSON_OBJECT)
    {
        return json_equal (old_json, new_json) ? NULL : json_incref (old_json);
    }

    return compare_objects (old_json, new_json);
}

/* Creates, or edits, the JSON diff file */
static int
write_diff (json_t *current_json, const char *path_to_diff)
{
    int error_code;
    json_error_t error;
    json_t *storage = json_load_file (path_to_diff, 0, &error);

    if (!storage)
    {
        json_t *new_storage = json_object ();
        json_object_set_new (new_storage, "timestamp", json_integer (time (NULL)));
        json_object_set_new (new_storage, "current", json_deep_copy (current_json));

        json_t *diffs_array = json_array ();
        json_object_set_new (new_storage, "diffs", diffs_array);

        error_code = json_dump_file (new_storage, path_to_diff, JSON_INDENT (json_indent));
        json_decref (new_storage);

        return error_code;
    }

    json_t *changes =
        compare_json_deep (json_object_get (storage, "current"), current_json);
    json_t *diff = json_object ();

    json_object_set_new (diff, "timestamp",
                         json_deep_copy (json_object_get (storage, "timestamp")));
    json_object_set_new (diff, "changes", changes ? changes : json_object ());

    json_array_insert_new (json_object_get (storage, "diffs"), 0, diff);
    json_object_set_new (storage, "timestamp", json_integer (time (NULL)));
    json_object_set_new (storage, "current", json_deep_copy (current_json));

    error_code = json_dump_file (storage, path_to_diff, JSON_INDENT (json_indent));
    json_decref (storage);

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
    if (n < 0)
    {
        fprintf (stderr, "error: failed to build logrotate config path\n");
        free (absolute_path);
        free (config_name);
        return -1;
    }

    char *config_path = malloc (n + 1);
    snprintf (config_path, n + 1, "%s/%s", out_dir, config_name);

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
             "    size %ldM\n"
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
        fprintf (stderr, "error: could not fetch JSON from query: %s\n", config->query);
        return G_SOURCE_CONTINUE;   // Continues in case it is a temporary apteryx issue
    }

    if (write_diff (json_from_tree, config->destination) != 0)
    {
        fprintf (stderr, "error: could not write diff. Check destination: %s\n",
                 config->destination);
        json_decref (json_from_tree);
        return G_SOURCE_REMOVE; // Breaks as the destination has likely been removed
    }

    json_decref (json_from_tree);

    return G_SOURCE_CONTINUE;
}

/* Setup for the GLib thread */
static gpointer
thread_func (gpointer user_data)
{
    config_data *config = (config_data *) user_data;

    GMainContext *context = g_main_context_new ();
    config->loop = g_main_loop_new (context, FALSE);

    g_main_context_push_thread_default (context);

    GSource *timeout = g_timeout_source_new_seconds (config->frequency);
    g_source_set_callback (timeout, polling_callback, config, NULL);
    g_source_attach (timeout, context);
    g_source_unref (timeout);

    g_main_loop_run (config->loop);

    g_main_context_pop_thread_default (context);
    g_main_context_unref (context);

    return NULL;
}

/* Ensures there are no configs writing to the same place. Uses destination, config-file pairs*/
static GHashTable *destination_registry = NULL;

static void
destination_registry_free_all ()
{
    if (destination_registry)
    {
        g_hash_table_destroy (destination_registry);
        destination_registry = NULL;
    }
}

/* Adds destination to table. Throws error if it is already present */
static int
destination_registry_add (const char *destination, const char *config_path)
{
    destination_registry = destination_registry ? destination_registry :
        g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

    gchar *key = resolve_absolute_path (destination);

    const char *first_seen = g_hash_table_lookup (destination_registry, key);
    if (first_seen)
    {
        fprintf (stderr,
                 "error: duplicate destination '%s' in %s "
                 "(already registered by %s)\n",
                 key, config_path ? config_path : "(unknown)", first_seen);
        g_free (key);
        return -1;
    }

    g_hash_table_insert (destination_registry, key,
                         g_strdup (config_path ? config_path : "(unknown)"));
    return 0;
}

/* Ensures destination can be created, and has not already been claimed */
static int
validate_destination (const char *destination_path, const char *config_path)
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

    if (destination_registry_add (destination_path, config_path) != 0)
    {
        return -1;
    }

    return 0;
}

/* Validates the data provided in the config file. Mostly checks types */
static int
validate_data (json_t *data, config_data *config, const char *config_path)
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

    destination = json_object_get (data, "destination");
    if (!json_is_string (destination))
    {
        fprintf (stderr, "error: destination is not a string\n");
        return -1;
    }

    if (validate_destination (json_string_value (destination), config_path) != 0)
    {
        return -1;
    }

    max_samples = json_object_get (data, "max_samples");
    if (!json_is_integer (max_samples))
    {
        fprintf (stderr, "error: max_samples is not an integer\n");
        return -1;
    }

    max_size = json_object_get (data, "max_size");
    if (!json_is_integer (max_size))
    {
        fprintf (stderr, "error: max_size is not an integer\n");
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
initialise_config (json_t *data, const char *config_path)
{
    if (!json_is_object (data))
    {
        fprintf (stderr, "error: config is not a json object\n");
        return -1;
    }

    config_data *config = malloc (sizeof (config_data));
    int validation = validate_data (data, config, config_path);
    if (validation != 0)
    {
        fprintf (stderr, "error: bad value in config \n");
        free (config);
        return -1;
    }

    validation = create_logrotate_config (config);
    if (validation != 0)
    {
        fprintf (stderr, "error: could not start logrotate \n");
        free (config);
        return -1;
    }

    g_thread_new (NULL, thread_func, config);

    return 0;
}

/* Gets all JSON files from specified directory and tries to read them */
static int
load_configs_from_directory (const char *config_dir)
{
    DIR *dir;
    struct dirent *entry;
    char *ext;
    char *path;
    json_t *root;
    json_error_t error;

    dir = opendir (config_dir);
    if (!dir)
    {
        fprintf (stderr, "error: failed to open config directory: %s\n", config_dir);
        return -1;
    }

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
        path = g_strdup_printf ("%s/%s", config_dir, entry->d_name);

        root = json_load_file (path, 0, &error);
        if (!root)
        {
            fprintf (stderr, "error: unable to open file: %s\n", path);
            g_free (path);
            closedir (dir);
            return -1;
        }

        if (initialise_config (root, path) != 0)
        {
            fprintf (stderr, "error: failed to initialise config from file: %s\n", path);
            json_decref (root);
            g_free (path);
            closedir (dir);
            return -1;
        }

        json_decref (root);
        g_free (path);
    }

    closedir (dir);
    return 0;
}


void
test_compare_json_deep_both_null_returns_null ()
{
    json_t *result = compare_json_deep (NULL, NULL);
    CU_ASSERT_PTR_NULL (result);
}

void
test_compare_json_deep_old_null_returns_json_null ()
{
    json_t *new_json = json_object ();
    json_t *result = compare_json_deep (NULL, new_json);
    json_t *expected = json_null ();

    CU_ASSERT_EQUAL (result, expected);

    json_decref (new_json);
    json_decref (result);
    json_decref (expected);
}

void
test_compare_json_deep_new_null_returns_old_value ()
{
    json_t *old_json = json_object ();
    json_t *result = compare_json_deep (old_json, NULL);

    CU_ASSERT_PTR_EQUAL (result, old_json);

    json_decref (old_json);
    json_decref (result);
}

void
test_compare_json_deep_type_mismatch_returns_old_value ()
{
    json_t *old_json = json_object ();
    json_t *new_json = json_string ("new value");
    json_t *result = compare_json_deep (old_json, new_json);

    CU_ASSERT_PTR_EQUAL (result, old_json);

    json_decref (old_json);
    json_decref (new_json);
    json_decref (result);
}

void
test_compare_json_deep_equal_string_returns_null ()
{
    json_t *old_json = json_string ("value");
    json_t *new_json = json_string ("value");
    json_t *result = compare_json_deep (old_json, new_json);

    CU_ASSERT_PTR_NULL (result);

    json_decref (old_json);
    json_decref (new_json);
}

void
test_compare_json_deep_equal_integer_returns_null ()
{
    json_t *old_json = json_integer (42);
    json_t *new_json = json_integer (42);
    json_t *result = compare_json_deep (old_json, new_json);

    CU_ASSERT_PTR_NULL (result);

    json_decref (old_json);
    json_decref (new_json);
}

void
test_compare_json_deep_different_string_returns_old_value ()
{
    json_t *old_json = json_string ("value");
    json_t *new_json = json_string ("new value");
    json_t *result = compare_json_deep (old_json, new_json);

    CU_ASSERT_PTR_EQUAL (result, old_json);

    json_decref (old_json);
    json_decref (new_json);
    json_decref (result);
}

void
test_compare_json_deep_different_integer_returns_old_value ()
{
    json_t *old_json = json_integer (42);
    json_t *new_json = json_integer (41);
    json_t *result = compare_json_deep (old_json, new_json);

    CU_ASSERT_PTR_EQUAL (result, old_json);

    json_decref (old_json);
    json_decref (new_json);
    json_decref (result);
}


void
test_compare_json_deep_equal_arrays_returns_null ()
{
    json_t *old_arr = json_array ();
    json_array_append_new (old_arr, json_integer (1));
    json_array_append_new (old_arr, json_integer (2));
    json_t *new_arr = json_array ();
    json_array_append_new (new_arr, json_integer (1));
    json_array_append_new (new_arr, json_integer (2));
    json_t *result = compare_json_deep (old_arr, new_arr);

    CU_ASSERT_PTR_NULL (result);

    json_decref (old_arr);
    json_decref (new_arr);
}

void
test_compare_json_deep_different_arrays_returns_old_array ()
{
    json_t *old_arr = json_array ();
    json_array_append_new (old_arr, json_integer (1));
    json_array_append_new (old_arr, json_integer (2));
    json_t *new_arr = json_array ();
    json_array_append_new (new_arr, json_integer (1));
    json_array_append_new (new_arr, json_integer (2));
    json_array_append_new (new_arr, json_integer (3));
    json_t *result = compare_json_deep (old_arr, new_arr);

    CU_ASSERT_PTR_EQUAL (result, old_arr);

    json_decref (old_arr);
    json_decref (new_arr);
    json_decref (result);
}


void
test_compare_json_deep_empty_objects_returns_null ()
{
    json_t *old_obj = json_object ();
    json_t *new_obj = json_object ();
    json_t *result = compare_json_deep (old_obj, new_obj);

    CU_ASSERT_PTR_NULL (result);

    json_decref (old_obj);
    json_decref (new_obj);
}

void
test_compare_json_deep_equal_object_values_returns_null ()
{
    json_t *old_obj = json_object ();
    json_t *new_obj = json_object ();
    json_object_set_new (old_obj, "key1", json_string ("value"));
    json_object_set_new (new_obj, "key1", json_string ("value"));
    json_t *result = compare_json_deep (old_obj, new_obj);

    CU_ASSERT_PTR_NULL (result);

    json_decref (old_obj);
    json_decref (new_obj);
}


void
test_compare_json_deep_changed_object_value_returns_old_value_object ()
{
    json_t *old_obj = json_object ();
    json_t *new_obj = json_object ();
    json_object_set_new (old_obj, "key1", json_string ("value"));
    json_object_set_new (new_obj, "key1", json_string ("new value"));
    json_t *result = compare_json_deep (old_obj, new_obj);

    CU_ASSERT_EQUAL (json_typeof (result), JSON_OBJECT);
    CU_ASSERT_TRUE (json_equal (result, old_obj));

    json_decref (old_obj);
    json_decref (new_obj);
    json_decref (result);
}


void
test_compare_json_deep_added_key_returns_json_null_marker ()
{
    json_t *old_obj = json_object ();
    json_t *new_obj = json_object ();
    json_object_set_new (new_obj, "key1", json_string ("value"));

    json_t *result = compare_json_deep (old_obj, new_obj);
    json_t *diff = json_object_get (result, "key1");
    json_t *expected_null = json_null ();

    CU_ASSERT_EQUAL (json_typeof (result), JSON_OBJECT);
    CU_ASSERT_EQUAL (diff, expected_null);

    json_decref (expected_null);
    json_decref (old_obj);
    json_decref (new_obj);
    json_decref (result);
}

void
test_compare_json_deep_removed_key_returns_old_value ()
{
    json_t *old_obj = json_object ();
    json_t *new_obj = json_object ();
    json_object_set_new (old_obj, "key1", json_string ("value"));
    json_object_set_new (old_obj, "key2", json_string ("new value"));
    json_object_set_new (new_obj, "key1", json_string ("value"));

    json_t *result = compare_json_deep (old_obj, new_obj);
    json_t *diff = json_object_get (result, "key2");
    json_t *expected = json_string ("new value");

    CU_ASSERT_EQUAL (json_typeof (result), JSON_OBJECT);
    CU_ASSERT_TRUE (json_equal (diff, expected));

    json_decref (expected);
    json_decref (old_obj);
    json_decref (new_obj);
    json_decref (result);
}


int
main (int argc, char *argv[])
{
    int opt;
    const char *config_dir = NULL;
    bool unit_test = false;
    CU_pSuite pSuite;
    GMainLoop *main_loop = NULL;

    while ((opt = getopt (argc, argv, "huc:")) != -1)
    {
        switch (opt)
        {
        case 'u':
            unit_test = true;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case '?':
        case 'h':
        default:
            printf ("Usage: %s [-h] [-u] [-c <configdir>]\n"
                    "  -h   show this help\n"
                    "  -u   run unit tests\n"
                    "  -c   use files from <configdir>\n", argv[0]);
            return 0;
        }
    }


    if (unit_test)
    {
        CU_initialize_registry ();

        pSuite = CU_add_suite ("unit::compare_json_deep", NULL, NULL);
        CU_add_test (pSuite, "both_null_returns_null",
                     test_compare_json_deep_both_null_returns_null);
        CU_add_test (pSuite, "old_null_returns_json_null",
                     test_compare_json_deep_old_null_returns_json_null);
        CU_add_test (pSuite, "new_null_returns_old_value",
                     test_compare_json_deep_new_null_returns_old_value);
        CU_add_test (pSuite, "type_mismatch_returns_old_value",
                     test_compare_json_deep_type_mismatch_returns_old_value);
        CU_add_test (pSuite, "equal_string_returns_null",
                     test_compare_json_deep_equal_string_returns_null);
        CU_add_test (pSuite, "equal_integer_returns_null",
                     test_compare_json_deep_equal_integer_returns_null);
        CU_add_test (pSuite, "different_string_returns_old_value",
                     test_compare_json_deep_different_string_returns_old_value);
        CU_add_test (pSuite, "different_integer_returns_old_value",
                     test_compare_json_deep_different_integer_returns_old_value);
        CU_add_test (pSuite, "equal_arrays_returns_null",
                     test_compare_json_deep_equal_arrays_returns_null);
        CU_add_test (pSuite, "different_arrays_returns_old_array",
                     test_compare_json_deep_different_arrays_returns_old_array);

        pSuite = CU_add_suite ("integration::compare_json_deep_objects", NULL, NULL);
        CU_add_test (pSuite, "empty_objects_returns_null",
                     test_compare_json_deep_empty_objects_returns_null);
        CU_add_test (pSuite, "equal_object_values_returns_null",
                     test_compare_json_deep_equal_object_values_returns_null);
        CU_add_test (pSuite, "changed_object_value_returns_old_value_object",
                     test_compare_json_deep_changed_object_value_returns_old_value_object);
        CU_add_test (pSuite, "added_key_returns_json_null_marker",
                     test_compare_json_deep_added_key_returns_json_null_marker);
        CU_add_test (pSuite, "removed_key_returns_old_value",
                     test_compare_json_deep_removed_key_returns_old_value);

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

    if (load_configs_from_directory (config_dir) != 0)
    {
        goto exit;
    }

    main_loop = g_main_loop_new (NULL, false);
    g_main_loop_run (main_loop);


  exit:
    if (main_loop)
    {
        g_main_loop_unref (main_loop);
    }

    /* Cleanup destination registry */
    destination_registry_free_all ();

    /* Cleanup client library */
    apteryx_shutdown ();

    return 0;
}
