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
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

static const int path_buffer = 256;
static const int json_indent = 2;

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

static int
write_diff (json_t *current_json, const char *path_to_diff)
{
    int error_code;
    json_error_t error;
    json_t *storage = json_load_file (path_to_diff, 0, &error);
    json_t *diff = json_object ();

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


// Creates a unique name for logrotate conf based on destination
static char *
sanitize_path_for_config (const char *path)
{
    char *result = malloc (strlen (path) + 7);
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

static char *
resolve_absolute_path (const char *path)
{
    // If full path already exists, resolve directly
    char *resolved = realpath (path, NULL);
    if (resolved)
    {
        return resolved;
    }

    // If there is no file, resolve parent directory instead (& append name)
    char *path_copy = strdup (path);
    char *resolved_dir = realpath (dirname (path_copy), NULL);
    free (path_copy);

    if (!resolved_dir)
    {
        return NULL;
    }

    path_copy = strdup (path);
    char *result = malloc (strlen (resolved_dir) + strlen (basename (path_copy)) + 2);
    sprintf (result, "%s/%s", resolved_dir, basename (path_copy));

    free (path_copy);
    free (resolved_dir);
    return result;
}

static void
create_logrotate_config (config_data *config)
{
    char *absolute_path = resolve_absolute_path (config->destination);
    if (!absolute_path)
    {
        fprintf (stderr, "error: failed to resolve path: %s\n", config->destination);
        return;
    }

    char *config_name = sanitize_path_for_config (config->destination);
    char config_path[path_buffer];
    snprintf (config_path, path_buffer, "/etc/logrotate.d/%s", config_name);

    FILE *f = fopen (config_path, "w");
    if (!f)
    {
        fprintf (stderr, "error: failed to create logrotate config: %s\n", config_path);
        free (absolute_path);
        free (config_name);
        return;
    }

    fprintf (f, "%s {\n", absolute_path);
    fprintf (f, "    size %ldM\n", config->max_size);
    fprintf (f, "    rotate %d\n", config->max_samples);
    fprintf (f, "    missingok\n");
    fprintf (f, "    notifempty\n");
    fprintf (f, "    nocreate\n");
    fprintf (f, "}\n");

    fclose (f);
    free (absolute_path);
    free (config_name);
}


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
        return G_SOURCE_CONTINUE;
    }

    if (write_diff (json_from_tree, config->destination) != 0)
    {
        fprintf (stderr, "error: could not write diff. Check destination: %s\n",
                 config->destination);
        json_decref (json_from_tree);
        return G_SOURCE_REMOVE;
    }

    json_decref (json_from_tree);

    return G_SOURCE_CONTINUE;
}

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


static int
validate_destination (json_t *destination)
{
    char *dest_str = strdup (json_string_value (destination));

    if (make_path (dest_str) != 0)
    {
        fprintf (stderr, "error: failed to create specified destination path: %s\n", dest_str);
        return -1;
    }

    return 0;
}

static int
validate_data (json_t *data, config_data *config)
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

    if (validate_destination (destination) != 0)
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

static int
initialise_config (json_t *data)
{
    if (!json_is_object (data))
    {
        fprintf (stderr, "error: config is not a json object\n");
        return -1;
    }

    config_data *config = malloc (sizeof (config_data));
    int result = validate_data (data, config);

    if (result == -1)
    {
        fprintf (stderr, "error: bad value in config \n");
        free (config);
        return -1;
    }

    create_logrotate_config (config);
    g_thread_new (NULL, thread_func, config);

    return 0;
}

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
            json_decref (root);
            g_free (path);
            return -1;
        }

        if (initialise_config (root) != 0)
        {
            fprintf (stderr, "error: failed to initialise config from file: %s\n",
                        path);
            json_decref (root);
            g_free (path);
            return -1;
        }
    }
    
    closedir (dir);
    return 0;
}


void
test_compare_json_deep_nulls ()
{
    CU_ASSERT_PTR_NULL (compare_json_deep (NULL, NULL));
    
    CU_ASSERT_EQUAL (compare_json_deep (NULL, json_object ()), json_null ());

    json_t *old = json_object ();
    CU_ASSERT_PTR_EQUAL (compare_json_deep (old, NULL), old);
    json_decref (old);
}

void
test_compare_json_deep_different_types ()
{
    json_t *old = json_object ();
    json_t *new = json_string ("new value");

    CU_ASSERT_PTR_EQUAL (compare_json_deep (old, new), old);

    json_decref (old);
    json_decref (new);
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
            break;
            case '?':
            case 'h':
            default:
                printf ("Usage: %s [-h] [-u] [-c <configdir>]\n"
                        "  -h   show this help\n"
                        "  -u   run unit tests\n"
                        "  -c   use files from <configdir>\n"
                        ,argv[0]);
                return 0;
        }
    }
 

    if (unit_test)
    {
        CU_initialize_registry ();

        pSuite = CU_add_suite("compare_json_deep units", NULL, NULL);
        CU_add_test(pSuite, "NULL values", test_compare_json_deep_nulls);
        CU_add_test(pSuite, "differing types", test_compare_json_deep_different_types);
        
        CU_basic_run_tests();
        CU_cleanup_registry();

        goto exit;
    }


    if (!config_dir)
    {
        fprintf (stderr, "error: No configuration directory path set. Missing -c <configdir>\n");
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

    /* Cleanup client library */
    apteryx_shutdown ();

    return 0;
}
