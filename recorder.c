#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include <jansson.h>
#include "common.h"
#include "apteryx_sync.h"

static const int path_buffer = 256;
static const int index_buffer = 32;
static const int json_indent = 2;

static void compare_json_deep(json_t *old_json, json_t *new_json, 
                               const char *path_prefix, json_t *changes);
// FIXME: Make errors & general style consistent with other ATL/ Apteryx... e.g. error codes...

// FIXME: Replace w/ json_load_file?
static char* load_file(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    char *buffer = malloc(size + 1);
    if (buffer)
    {
        long bytes_read = fread(buffer, 1, size, f);
        if (bytes_read < size) return NULL; // File was not completely read...
        buffer[size] = '\0';
    }
    fclose(f);
    return buffer;
}

// FIXME: Function decomp
// static int read_text(char* json_text, json_t* root) {
//     json_error_t error;
//     json_t *temp_root;


//     temp_root = json_loads(json_text, 0, &error);
//     free(json_text);


//     if(!temp_root)
//     {
//         fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
//         return 0;
//     }

//     if(!json_is_array(temp_root))
//     {
//         fprintf(stderr, "error: root is not an array\n");
//         json_decref(temp_root);
//         return 0;
//     }

//     *root = *temp_root;

//     return 1;
// }


json_t *gnode_to_json(const GNode *node)
{
    json_t *obj = json_object();
    if (!obj) return NULL;

    for (const GNode *child = node->children;
         child;
         child = child->next)
    {

        json_t *child_json = NULL;
        if (APTERYX_HAS_VALUE(child))
        {
            child_json = json_string(APTERYX_VALUE(child));
        }
        else
        {
            child_json = gnode_to_json(child);
            if (!child_json) {
                json_decref(obj);
                return NULL;
            }
        }

        json_object_set_new(obj, (char*)child->data, child_json);
    }

    return obj;
}

static int make_dir(const char *path)
{
    if (mkdir(path, 0600) == -1)
    {
        if (errno == EEXIST)
        {
            printf("Directory already exists.\n");
        }
        else
        {
            perror("mkdir failed");
        }
    }
    else
    {
        printf("Directory created successfully.\n");
    }
}



// TODO: Change dot notation to be more like actual tree... 
// Uses dot notation for children/indices. e.g. parent.child.0
static void build_path(char *buffer, size_t size, const char *prefix, const char *key)
{
    if (strlen(prefix) == 0)
    {
        snprintf(buffer, size, "%s", key);
    }
    else
    {
        snprintf(buffer, size, "%s.%s", prefix, key);
    }
}

// FIXME(?): json foreach/set discards const....
    // I assume its better to keep const and suppress warnings...

// FIXME: Optimise option...
    // void *iter = json_object_iter((json_t*)new_obj);
    // while (iter) {
    //     const char *key = json_object_iter_key(iter);
    //     json_t *old_val = json_object_get(old_obj, key);
    //     json_t *new_val = json_object_iter_value(iter);
    //     // compare and mark new keys
    //     iter = json_object_iter_next((json_t*)new_obj, iter);
    // }
    // // Then iterate old_obj only for removed keys
// Compares JSON objects
static void compare_objects(json_t *old_obj, json_t *new_obj,
                           const char *path_prefix, json_t *changes)
{
    const char *key;
    json_t *value;
    
    json_object_foreach(old_obj, key, value)
    {
        char new_path[path_buffer];
        build_path(new_path, sizeof(new_path), path_prefix, key);
        
        printf("My KEY is: %s", key);
        
        json_t *new_value = json_object_get(new_obj, key);
        compare_json_deep(value, new_value, new_path, changes);
    }
    
    // This is needed to find NEW keys (thus causing NULLs in the diff)
    json_object_foreach(new_obj, key, value)
    {
        if (!json_object_get(old_obj, key))
        {
            char new_path[path_buffer];
            build_path(new_path, sizeof(new_path), path_prefix, key);
            json_object_set_new(changes, new_path, json_null());
        }
    }
}

static void compare_arrays(const json_t *old_arr, const json_t *new_arr,
                          const char *path_prefix, json_t *changes)
{
    size_t old_size = json_array_size(old_arr);
    size_t new_size = json_array_size(new_arr);
    size_t max_size = old_size > new_size ? old_size : new_size;
    
    for (size_t i = 0; i < max_size; i++)
    {
        char index_str[index_buffer];
        snprintf(index_str, sizeof(index_str), "%zu", i);
        
        char new_path[path_buffer];
        build_path(new_path, sizeof(new_path), path_prefix, index_str);
        
        json_t *old_elem = i < old_size ? json_array_get(old_arr, i) : json_null();
        json_t *new_elem = i < new_size ? json_array_get(new_arr, i) : json_null();
        
        compare_json_deep(old_elem, new_elem, new_path, changes);
    }
}

// Compares objects based on their type
static void compare_json_deep(json_t *old_json, json_t *new_json, 
                               const char *path_prefix, json_t *changes)
{
    if (!old_json && !new_json) return;
    
    if (!old_json && new_json)
    {
        json_object_set_new(changes, path_prefix, json_null());
        return;
    }
    
    if (old_json && !new_json)
    {
        json_object_set(changes, path_prefix, old_json);
        return;
    }
    
    // Cant easily compare different types
    if (json_typeof(old_json) != json_typeof(new_json))
    {
        json_object_set(changes, path_prefix, old_json);
        return;
    }
    
    switch (json_typeof(old_json))
    {
        case JSON_OBJECT:
            compare_objects(old_json, new_json, path_prefix, changes);
            break;
        case JSON_ARRAY:
            compare_arrays(old_json, new_json, path_prefix, changes);
            break;
        default: // E.g. string / num / bool
            if (!json_equal(old_json, new_json))
            {
                json_object_set(changes, path_prefix, old_json);
            }
            break;
    }
}

static int write_diff(json_t *current_json, const char* path_to_diff)
{
    int error_code;
    json_error_t error;
    json_t *storage = json_load_file(path_to_diff, 0, &error);
   
    if (!storage)
    {

        // attempt to make the path before creating the JSON
        if(!make_dir(path_to_diff)) return 0;

        json_t *new_storage = json_object();
        json_object_set_new(new_storage, "current", json_deep_copy(current_json));
        
        json_t *diffs_array = json_array();
        json_t *initial_diff = json_object();
        json_object_set_new(initial_diff, "timestamp", json_integer(time(NULL)));
        json_object_set_new(initial_diff, "changes", json_object());
        json_array_append_new(diffs_array, initial_diff);
        
        json_object_set_new(new_storage, "diffs", diffs_array);
        
        error_code = json_dump_file(new_storage, path_to_diff, JSON_INDENT(json_indent));
        json_decref(new_storage);

        if (error_code != 0) return 0;

        return 1;
    }
    
    json_t *old_current = json_object_get(storage, "current");
    json_t *changes = json_object();
    compare_json_deep(old_current, current_json, "", changes);
    
    json_t *new_diff = json_object();
    json_object_set_new(new_diff, "timestamp", json_integer(time(NULL))); // Should timestamp be earlier?
    json_object_set_new(new_diff, "changes", changes);
    
    json_t *diffs_array = json_object_get(storage, "diffs");
    json_array_append_new(diffs_array, new_diff);
    
    json_object_set_new(storage, "current", json_deep_copy(current_json));
    
    error_code = json_dump_file(storage, path_to_diff, JSON_INDENT(json_indent));
    json_decref(storage);

    if (error_code != 0) return 0;
    
    return 1;
}



int main(int argc, char *argv[])
{
    apteryx_init(false);

    size_t i;
    char *text;
    json_t *root = NULL;

    if(argc != 1)
    {
        fprintf(stderr, "usage: %s USER REPOSITORY\n\n", argv[0]);
        fprintf(stderr, "List commits at USER's REPOSITORY.\n\n");
        return -1;
    }

    text = load_file("test.json");
    if(!text) {
        fprintf(stderr, "error: unable to open file.");
        return 0;
    }


    // FIXME: Put into separate function
    json_error_t error;

    root = json_loads(text, 0, &error);
    free(text);

    if(!root)
    {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return 0;
    }

    if(!json_is_array(root))
    {
        fprintf(stderr, "error: root is not an array\n");
        json_decref(root);
        return 0;
    }

    // if (!read_text(text, root)) {
    //     fprintf(stderr, "Error: unable to read file as JSON.");
    //     return 0;
    // }

    if(!root){
        fprintf(stderr, "Erdfdfror: unable to read file as JSON.");
        return 0;
    }

    
  


    // FIXME: Put into separate functionS
    for(i = 0; i < json_array_size(root); i++)
    {
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
            return 1;
        }

        query = json_object_get(data, "query");
        if(!json_is_string(query)) 
        {
            fprintf(stderr, "error: config set %d: query is not a string\n", (int)(i + 1));
            json_decref(root);
            return 1;
        }

        frequency = json_object_get(data, "frequency");
        if(!json_is_integer(frequency))
        {
            fprintf(stderr, "error: config set %d: frequency is not an integer\n", (int)(i + 1));
            json_decref(root);
            return 1;
        }

        destination = json_object_get(data, "destination");
        if(!json_is_string(destination))
        {
            fprintf(stderr, "error: config set %d: destination is not a string\n", (int)(i + 1));
            json_decref(root);
            return 1;
        }

        max_samples = json_object_get(data, "max_samples");
        if(!json_is_integer(max_samples))
        {
            fprintf(stderr, "error: config set %d: max_samples is not an integer\n", (int)(i + 1));
            json_decref(root);
            return 1;
        }

        max_size = json_object_get(data, "max_size");
        if(!json_is_integer(max_size))
        {
            fprintf(stderr, "error: config set %d: max_size is not an integer\n", (int)(i + 1));
            json_decref(root);
            return 1;
        }

        // TODO: Make a new thread for EACH config file: give it relevant config info
        // FIXME: Put into separate function
        char *query_text;
        query_text = strdup(json_string_value(query));
        
        printf("s %s  TO %s\n",
            query_text, 
            json_string_value(destination)
            );

        GNode *gquery = g_node_new (query_text); 
        GNode *tree = apteryx_query(gquery); // FIXME: Prevent segfaults from bad queries...
        json_t *json_from_tree = gnode_to_json(tree);

        if (json_from_tree)
        {
            if (write_diff(json_from_tree, json_string_value(destination)) != 1)
            {
                printf("error: could not complete diff calculation. Check destination.\n");
                return 0;
            }

            json_decref(json_from_tree);
            apteryx_free_tree (tree);
        } else {
            printf("error: could not fetch JSON from query. Is it empty?\n");
        }
    }

    json_decref(root);
    return 0;
}
