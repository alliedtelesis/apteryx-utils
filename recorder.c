#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>
#include <dirent.h>
#include <apteryx.h>
#include <glib-unix.h>
#include <apteryx-xml.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>
#include <jansson.h>
#include "common.h"
#include "apteryx_sync.h"

static const int path_buffer = 256;
static const int json_indent = 2;

static json_t *compare_json_deep(json_t *old_json, json_t *new_json);

typedef struct _config_data
{
    char *query;
    long frequency;
    char *destination;
    int max_samples;
    long max_size;
    GMainLoop *loop;
} config_data;
                       

json_t *gnode_to_json(const GNode *node)
{
    json_t *obj = json_object();
    if (!obj) return NULL;

    for (const GNode *child = node->children; child; child = child->next)
    {
        json_t *child_json = NULL;
        if (APTERYX_HAS_VALUE(child))
        {
            child_json = json_string(APTERYX_VALUE(child));
        }
        else
        {
            child_json = gnode_to_json(child);
            if (!child_json)
            {
                json_decref(obj);
                return NULL;
            }
        }

        json_object_set_new(obj, (char*)child->data, child_json);
    }

    return obj;
}

static int make_path(char *path)
{
    char *p = path + (*path == '/');  // Skip leading /
    while ((p = strchr(p, '/')))
    {
        *p = '\0';
        if (mkdir(path, 0755) && errno != EEXIST) return -1;
        *p++ = '/';
    }
    return 0;
}


static json_t *compare_objects(json_t *old_obj, json_t *new_obj)
{
    json_t *changes = json_object();
    const char *key;
    json_t *value;
    
    json_object_foreach(old_obj, key, value)
    {
        json_t *diff = compare_json_deep(value, json_object_get(new_obj, key));
        if (diff) json_object_set_new(changes, key, diff);
    }
    
    json_object_foreach(new_obj, key, value)
    {
        if (!json_object_get(old_obj, key))
        {
            json_object_set_new(changes, key, json_null());
        }
    }

    if (!json_object_size(changes))
    {
        json_decref(changes);
        return NULL;
    }
    return changes;
}

static json_t *compare_arrays(const json_t *old_arr, const json_t *new_arr)
{
    size_t old_size = json_array_size(old_arr);
    size_t new_size = json_array_size(new_arr);
    size_t max_size = old_size > new_size ? old_size : new_size;

    json_t *changes = json_array();
    gboolean has_changes = FALSE;
    
    for (size_t i = 0; i < max_size; i++)
    {       
        json_t *old_elem = i < old_size ? json_array_get(old_arr, i) : json_null();
        json_t *new_elem = i < new_size ? json_array_get(new_arr, i) : json_null();
        json_t *diff = compare_json_deep(old_elem, new_elem);

        // Always append to maintain index alignment
        json_array_append_new(changes, diff ? diff : json_null());
        if (diff) has_changes = TRUE;
    }

    if (!has_changes)
    {
        json_decref(changes);
        return NULL;
    }
    return changes;
}

// Compares objects based on their type
static json_t *compare_json_deep(json_t *old_json, json_t *new_json)
{
    if (!old_json && !new_json) return NULL;
    if (!old_json) return json_null();
    if (!new_json) return json_incref(old_json);
    
    // Cant easily compare different types
    if (json_typeof(old_json) != json_typeof(new_json))
    {
        return json_incref(old_json);
    }
    
    switch (json_typeof(old_json))
    {
        case JSON_OBJECT: return compare_objects(old_json, new_json);
        case JSON_ARRAY: return compare_arrays(old_json, new_json);
        default: return json_equal(old_json, new_json) ? NULL : json_incref(old_json);
    }
}

static int write_diff(json_t *current_json, const char* path_to_diff)
{
    int error_code;
    json_error_t error;
    json_t *storage = json_load_file(path_to_diff, 0, &error);
    json_t *diff = json_object();
   
    if (!storage)
    {
        json_t *new_storage = json_object();
        json_object_set_new(new_storage, "current", json_deep_copy(current_json));
        
        json_object_set_new(diff, "timestamp", json_integer(time(NULL)));
        json_object_set_new(diff, "changes", json_object());
        
        json_t *diffs_array = json_array();
        json_array_append_new(diffs_array, diff);
        json_object_set_new(new_storage, "diffs", diffs_array);
        
        error_code = json_dump_file(new_storage, path_to_diff, JSON_INDENT(json_indent));
        json_decref(new_storage);

        return error_code;
    }
    
    json_t *changes = compare_json_deep(json_object_get(storage, "current"), current_json);
    
    json_object_set_new(diff, "timestamp", json_integer(time(NULL)));
    json_object_set_new(diff, "changes", changes ? changes : json_object());
    
    json_array_append_new(json_object_get(storage, "diffs"), diff);
    json_object_set_new(storage, "current", json_deep_copy(current_json));
    
    error_code = json_dump_file(storage, path_to_diff, JSON_INDENT(json_indent));
    json_decref(storage);
    
    return error_code;
}


// Creates a unique name for logrotate conf based on destination
static char* sanitize_path_for_config(const char *path)
{
    char *result = malloc(strlen(path) + 7);
    strcpy(result, "config-");
    char *dst = result + 7;
    
    for (const char *src = path; *src; src++)
    {
        if (*src == '/' || *src == '.')
        {
            *dst++ = '-';
        } 
        else if (isalnum(*src) || *src == '_') 
        {
            *dst++ = *src;
        }
    }

    *dst = '\0';
    return result;
}

static char* resolve_absolute_path(const char *path)
{
    // If full path already exists, resolve directly
    char *resolved = realpath(path, NULL);
    if (resolved) return resolved;

    // If there is no file, resolve parent directory instead (& append name)
    char *path_copy = strdup(path);
    char *resolved_dir = realpath(dirname(path_copy), NULL);
    free(path_copy);

    if (!resolved_dir) return NULL;

    path_copy = strdup(path);
    char *result = malloc(strlen(resolved_dir) + strlen(basename(path_copy)) + 2);
    sprintf(result, "%s/%s", resolved_dir, basename(path_copy));

    free(path_copy);
    free(resolved_dir);
    return result;
}

static void create_logrotate_config(config_data *config)
{
    char *absolute_path = resolve_absolute_path(config->destination);
    if (!absolute_path)
    {
        fprintf(stderr, "error: failed to resolve path: %s\n", config->destination);
        return;
    }
    
    char *config_name = sanitize_path_for_config(config->destination);
    char config_path[path_buffer];
    snprintf(config_path, path_buffer, "/etc/logrotate.d/%s", config_name);
    
    FILE *f = fopen(config_path, "w");
    if (!f)
    {
        fprintf(stderr, "error: failed to create logrotate config: %s\n", config_path);
        free(absolute_path);
        free(config_name);
        return;
    }
    
    fprintf(f, "%s {\n", absolute_path);
    fprintf(f, "    size %ldM\n", config->max_size);
    fprintf(f, "    rotate %d\n", config->max_samples);
    fprintf(f, "    missingok\n");
    fprintf(f, "    notifempty\n");
    fprintf(f, "    nocreate\n");
    fprintf(f, "}\n");
    
    fclose(f);
    free(absolute_path);
    free(config_name);
}


static gboolean polling_callback(gpointer user_data)
{
    config_data *config = (config_data *)user_data;

    GNode *tree = apteryx_query (g_node_new (config->query));
        
    json_t *json_from_tree = tree ? gnode_to_json(tree) : NULL;
    apteryx_free_tree (tree);

    if (!json_from_tree)
    {
        fprintf(stderr, "error: could not fetch JSON from query: %s\n", config->query);
        return G_SOURCE_CONTINUE;
    }
    
    if (write_diff(json_from_tree, config->destination) != 0)
    {
        fprintf(stderr, "error: could not write diff. Check destination: %s\n", config->destination);
        json_decref(json_from_tree);
        return G_SOURCE_REMOVE;
    }    
    
    json_decref(json_from_tree);
    
    return G_SOURCE_CONTINUE;
}

static gpointer thread_func(gpointer user_data)
{
    config_data *config = (config_data *)user_data;
    
    GMainContext *context = g_main_context_new();
    config->loop = g_main_loop_new(context, FALSE);

    g_main_context_push_thread_default(context);
    
    GSource *timeout = g_timeout_source_new_seconds(config->frequency);
    g_source_set_callback(timeout, polling_callback, config, NULL);
    g_source_attach(timeout, context);
    g_source_unref(timeout);
    
    g_main_loop_run(config->loop);
    
    g_main_context_pop_thread_default(context);
    g_main_context_unref(context);
    
    return NULL;
}


static int initialise_configs(json_t *root)
{
    size_t i;

    for(i = 0; i < json_array_size(root); i++)
    {
        // TODO: Verify data. e.g. unique dest(?), limits on freq/max values
        // What to do if an identical query is attempted? Prefer more frequent or older?
        json_t *data, *query, *frequency, *destination, *max_samples, *max_size;
        //  "query": "/test/*/tests",
        // "frequency": "30"(s),
        // "max_samples": "10",
        // "max_size": "32000"(MB),
        // "destination": "/dest"

        data = json_array_get(root, i);
        if(!json_is_object(data))
        {
            fprintf(stderr, "error: config set %d is not an object\n", (int)(i + 1));
            json_decref(root);
            return -1;
        }

        query = json_object_get(data, "query");
        if(!json_is_string(query)) 
        {
            fprintf(stderr, "error: config set %d: query is not a string\n", (int)(i + 1));
            json_decref(root);
            return -1;
        }

        frequency = json_object_get(data, "frequency");
        if(!json_is_integer(frequency))
        {
            fprintf(stderr, "error: config set %d: frequency is not an integer\n", (int)(i + 1));
            json_decref(root);
            return -1;
        }

        destination = json_object_get(data, "destination");
        if(!json_is_string(destination))
        {
            fprintf(stderr, "error: config set %d: destination is not a string\n", (int)(i + 1));
            json_decref(root);
            return -1;
        }

        max_samples = json_object_get(data, "max_samples");
        if(!json_is_integer(max_samples))
        {
            fprintf(stderr, "error: config set %d: max_samples is not an integer\n", (int)(i + 1));
            json_decref(root);
            return -1;
        }

        max_size = json_object_get(data, "max_size");
        if(!json_is_integer(max_size))
        {
            fprintf(stderr, "error: config set %d: max_size is not an integer\n", (int)(i + 1));
            json_decref(root);
            return -1;
        }

        config_data *config = malloc(sizeof(config_data));
        config->query = strdup(json_string_value(query));
        config->frequency = json_integer_value(frequency);
        config->destination = strdup(json_string_value(destination));
        config->max_samples = json_integer_value(max_samples);
        config->max_size = json_integer_value(max_size);

        // attempt to make destination path before calling logrotate
        if(make_path(config->destination) != 0)
        {
            fprintf(stderr, "error: failed to create specified path: %s\n", config->destination);
            return -1;
        }

        create_logrotate_config(config);

        g_thread_new(NULL, thread_func, config);
    }

    return 0;
}


int main(int argc, char *argv[])
{
    apteryx_init(false);

    json_t *root;
    json_error_t error;

    if(argc != 2)
    {
        fprintf(stderr, "usage: %s [PATH/TO/CONFIG.JSON]\n", argv[0]);
        fprintf(stderr, "Reads config array from PATH/TO/CONFIG.JSON.\n");
        return -1;
    }

    root = json_load_file(argv[1], 0, &error);
    if(!root)
    {
        fprintf(stderr, "error: unable to open file: %s\n", argv[1]);
        return -1;
    }

    if(!json_is_array(root))
    {
        fprintf(stderr, "error: config is not an array\n");
        json_decref(root);
        return -1;
    }

    initialise_configs(root);
    json_decref(root);

    GMainLoop *main_loop = g_main_loop_new(NULL, false);
    g_main_loop_run(main_loop);

    return 0;
}
