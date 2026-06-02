#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <apteryx.h>
#include <glib-unix.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <libgen.h>
#include <jansson.h>
#include <ftw.h>
#include <unistd.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "recorder.h"

static const int json_indent = 2;


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


/* Filesystem & shared test helpers */
#define TEST_TMP_DIR "./test_tmp"

static int
test_unlink_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    (void) sb;
    (void) typeflag;
    (void) ftwbuf;
    return remove (fpath);
}

static int
test_rmrf (const char *path)
{
    struct stat st;
    if (stat (path, &st) != 0)
    {
        return 0;
    }
    return nftw (path, test_unlink_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static int
fs_suite_init (void)
{
    test_rmrf (TEST_TMP_DIR);
    if (mkdir (TEST_TMP_DIR, 0755) != 0)
    {
        return -1;
    }
    destination_registry_free_all ();
    return 0;
}

static int
fs_suite_cleanup (void)
{
    destination_registry_free_all ();
    return test_rmrf (TEST_TMP_DIR);
}

static void
write_text_file (const char *path, const char *content)
{
    FILE *f = fopen (path, "w");
    if (f)
    {
        fputs (content, f);
        fclose (f);
    }
}

static void
test_sanitize_basic (void)
{
    char *r = sanitize_path_for_config ("foo");
    CU_ASSERT_STRING_EQUAL (r, "config-foo");
    free (r);
}

static void
test_sanitize_replaces_slashes_and_dots (void)
{
    char *r = sanitize_path_for_config ("/var/log/x.json");
    CU_ASSERT_STRING_EQUAL (r, "config--var-log-x-json");
    free (r);
}

static void
test_sanitize_keeps_alnum_and_underscore (void)
{
    char *r = sanitize_path_for_config ("a_B9");
    CU_ASSERT_STRING_EQUAL (r, "config-a_B9");
    free (r);
}

static void
test_sanitize_drops_unknown_chars (void)
{
    char *r = sanitize_path_for_config ("a b!c");
    CU_ASSERT_STRING_EQUAL (r, "config-abc");
    free (r);
}

static void
test_sanitize_empty (void)
{
    char *r = sanitize_path_for_config ("");
    CU_ASSERT_STRING_EQUAL (r, "config-");
    free (r);
}

/* ===========================================================================
 * gnode_to_json (built with APTERYX_NODE / APTERYX_LEAF_STRING - no daemon)
 * =========================================================================*/

static void
test_gnode_to_json_empty (void)
{
    GNode *root = APTERYX_NODE (NULL, g_strdup ("/"));
    json_t *j = gnode_to_json (root);
    CU_ASSERT_PTR_NOT_NULL_FATAL (j);
    CU_ASSERT_EQUAL (json_typeof (j), JSON_OBJECT);
    CU_ASSERT_EQUAL (json_object_size (j), 0);
    json_decref (j);
    apteryx_free_tree (root);
}

static void
test_gnode_to_json_single_leaf (void)
{
    GNode *root = APTERYX_NODE (NULL, g_strdup ("/"));
    APTERYX_LEAF_STRING (root, "speed", "1000");

    json_t *j = gnode_to_json (root);
    CU_ASSERT_PTR_NOT_NULL_FATAL (j);
    json_t *v = json_object_get (j, "speed");
    CU_ASSERT_TRUE (json_is_string (v));
    CU_ASSERT_STRING_EQUAL (json_string_value (v), "1000");
    json_decref (j);
    apteryx_free_tree (root);
}

static void
test_gnode_to_json_nested (void)
{
    GNode *root = APTERYX_NODE (NULL, g_strdup ("/"));
    GNode *iface = APTERYX_NODE (root, g_strdup ("eth0"));
    APTERYX_LEAF_STRING (iface, "state", "up");
    APTERYX_LEAF_STRING (iface, "speed", "1000");

    json_t *j = gnode_to_json (root);
    json_t *eth0 = json_object_get (j, "eth0");
    CU_ASSERT_PTR_NOT_NULL_FATAL (eth0);
    CU_ASSERT_EQUAL (json_typeof (eth0), JSON_OBJECT);
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (eth0, "state")), "up");
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (eth0, "speed")), "1000");
    json_decref (j);
    apteryx_free_tree (root);
}

/* ===========================================================================
 * compare_objects (extra cases beyond your existing compare_json_deep tests)
 * =========================================================================*/

static void
test_compare_objects_identical_returns_null (void)
{
    json_t *a = json_pack ("{s:s, s:i}", "k", "v", "n", 1);
    json_t *b = json_pack ("{s:s, s:i}", "k", "v", "n", 1);
    CU_ASSERT_PTR_NULL (compare_objects (a, b));
    json_decref (a);
    json_decref (b);
}

/* Key present in previous but absent in current → tombstone null in forward diff */
static void
test_compare_objects_key_deleted_from_current_marked_null (void)
{
    json_t *a = json_object ();                         /* current  */
    json_t *b = json_pack ("{s:s}", "added", "x");     /* previous */
    json_t *r = compare_objects (a, b);
    CU_ASSERT_PTR_NOT_NULL_FATAL (r);
    CU_ASSERT_EQUAL (json_typeof (json_object_get (r, "added")), JSON_NULL);
    json_decref (a);
    json_decref (b);
    json_decref (r);
}

/* Key present in current but absent in previous → returns current value in forward diff */
static void
test_compare_objects_key_new_in_current_returns_current_value (void)
{
    json_t *a = json_pack ("{s:s}", "gone", "old");     /* current  */
    json_t *b = json_object ();                          /* previous */
    json_t *r = compare_objects (a, b);
    CU_ASSERT_PTR_NOT_NULL_FATAL (r);
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (r, "gone")), "old");
    json_decref (a);
    json_decref (b);
    json_decref (r);
}

static void
test_compare_objects_changed_value (void)
{
    json_t *a = json_pack ("{s:s}", "k", "old");
    json_t *b = json_pack ("{s:s}", "k", "new");
    json_t *r = compare_objects (a, b);
    CU_ASSERT_PTR_NOT_NULL_FATAL (r);
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (r, "k")), "old");
    json_decref (a);
    json_decref (b);
    json_decref (r);
}

/* ===========================================================================
 * make_path
 * =========================================================================*/

static void
test_make_path_creates_nested (void)
{
    char p[] = TEST_TMP_DIR "/a/b/c/file";
    CU_ASSERT_EQUAL (make_path (p), 0);
    struct stat st;
    CU_ASSERT_EQUAL (stat (TEST_TMP_DIR "/a/b/c", &st), 0);
    CU_ASSERT_TRUE (S_ISDIR (st.st_mode));
}

static void
test_make_path_idempotent (void)
{
    char p1[] = TEST_TMP_DIR "/dup/dir/file";
    CU_ASSERT_EQUAL (make_path (p1), 0);
    char p2[] = TEST_TMP_DIR "/dup/dir/file";
    CU_ASSERT_EQUAL (make_path (p2), 0);
}

static void
test_make_path_no_dirs_in_path (void)
{
    char p[] = "filename";
    CU_ASSERT_EQUAL (make_path (p), 0);
}

static void
test_make_path_fails_when_parent_is_file (void)
{
    write_text_file (TEST_TMP_DIR "/blocker", "x");
    char p[] = TEST_TMP_DIR "/blocker/sub/file";
    CU_ASSERT_NOT_EQUAL (make_path (p), 0);
}

/* ===========================================================================
 * resolve_absolute_path
 * =========================================================================*/

static void
test_resolve_existing_file (void)
{
    write_text_file (TEST_TMP_DIR "/exists.txt", "hi");
    char *r = resolve_absolute_path (TEST_TMP_DIR "/exists.txt");
    CU_ASSERT_PTR_NOT_NULL_FATAL (r);
    CU_ASSERT_TRUE (r[0] == '/');
    CU_ASSERT_PTR_NOT_NULL (strstr (r, "/exists.txt"));
    free (r);
}

static void
test_resolve_nonexistent_file_existing_parent (void)
{
    char *r = resolve_absolute_path (TEST_TMP_DIR "/missing.txt");
    CU_ASSERT_PTR_NOT_NULL_FATAL (r);
    CU_ASSERT_TRUE (r[0] == '/');
    CU_ASSERT_PTR_NOT_NULL (strstr (r, "/missing.txt"));
    free (r);
}

/* ===========================================================================
 * validate_destination
 * =========================================================================*/

static void
test_validate_destination_creates_dirs (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    CU_ASSERT_EQUAL (validate_destination (registry, TEST_TMP_DIR "/dst/sub/out.json", "test.json"),
                     0);
    struct stat st;
    CU_ASSERT_EQUAL (stat (TEST_TMP_DIR "/dst/sub", &st), 0);
    CU_ASSERT_TRUE (S_ISDIR (st.st_mode));
    g_hash_table_destroy (registry);
}

static void
test_validate_destination_empty_string (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_NOT_EQUAL (validate_destination (registry, "", "test.json"), 0);
    printf("END EXPECTED ERROR\n");
    g_hash_table_destroy (registry);
}

static void
test_validate_destination_null (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_NOT_EQUAL (validate_destination (registry, NULL, "test.json"), 0);
    printf("END EXPECTED ERROR\n");
    g_hash_table_destroy (registry);
}

static void
test_validate_destination_blocked_by_file (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    write_text_file (TEST_TMP_DIR "/blockfile", "x");
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_NOT_EQUAL (validate_destination (registry, TEST_TMP_DIR "/blockfile/sub/out.json",
                                               "test.json"), 0);
    printf("END EXPECTED ERROR\n");
    g_hash_table_destroy (registry);
}

static void
test_validate_destination_duplicate_rejected (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    CU_ASSERT_EQUAL (validate_destination (registry, TEST_TMP_DIR "/dup/out.json", "a.json"), 0);
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_NOT_EQUAL (validate_destination (registry, TEST_TMP_DIR "/dup/out.json", "b.json"), 0);
    printf("END EXPECTED ERROR\n");
    g_hash_table_destroy (registry);
}

/* ===========================================================================
 * validate_data
 * =========================================================================*/

static json_t *
make_valid_config_json (const char *destination)
{
    return json_pack ("{s:s, s:i, s:s, s:i, s:i}",
                      "query", "/test/*",
                      "frequency", 1,
                      "destination", destination, "max_samples", 5, "max_size", 1);
}

static void
test_validate_data_happy_path (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_ok/out.json");
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "ok.json"), 0);
    CU_ASSERT_STRING_EQUAL (cfg.query, "/test/*");
    CU_ASSERT_EQUAL (cfg.frequency, 1);
    CU_ASSERT_STRING_EQUAL (cfg.destination, TEST_TMP_DIR "/vd_ok/out.json");
    CU_ASSERT_EQUAL (cfg.max_samples, 5);
    CU_ASSERT_EQUAL (cfg.max_size, 1);
    free (cfg.query);
    free (cfg.destination);
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_query_not_string (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_q/out.json");    
    json_object_set_new (data, "query", json_integer (1));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_frequency_not_int (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_f/out.json");
    json_object_set_new (data, "frequency", json_string ("nope"));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_destination_not_string (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_d/out.json");
    json_object_set_new (data, "destination", json_integer (1));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_max_samples_not_int (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_ms/out.json");
    json_object_set_new (data, "max_samples", json_string ("x"));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_max_size_not_int (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_msz/out.json");
    json_object_set_new (data, "max_size", json_string ("x"));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_missing_field (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_mf/out.json");
    json_object_del (data, "query");
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}



/* ===========================================================================
 * load_configs_from_directory
 *
 * Note: success paths spawn worker threads via initialise_config(). To keep
 * tests fast and self-contained we only exercise the failure / no-op paths.
 * =========================================================================*/

static void
test_load_configs_missing_dir_returns_error (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    GPtrArray *configs = g_ptr_array_new_with_free_func ((GDestroyNotify) config_data_free);
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (load_configs_from_directory ("./does/not/exist", registry, configs), -1);
    printf("END EXPECTED ERROR\n");
    g_hash_table_destroy (registry);
    g_ptr_array_free (configs, TRUE);
}

static void
test_load_configs_skips_non_json_files (void)
{
    const char *dir = TEST_TMP_DIR "/empty_cfgs";
    mkdir (dir, 0755);
    write_text_file (TEST_TMP_DIR "/empty_cfgs/notes.txt", "hello");
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    GPtrArray *configs = g_ptr_array_new_with_free_func ((GDestroyNotify) config_data_free);
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (load_configs_from_directory (dir, registry, configs), -1);
    printf("END EXPECTED ERROR\n");
    g_hash_table_destroy (registry);
    g_ptr_array_free (configs, TRUE);
}

static void
test_load_configs_invalid_json_returns_error (void)
{
    const char *dir = TEST_TMP_DIR "/bad_cfgs";
    mkdir (dir, 0755);
    write_text_file (TEST_TMP_DIR "/bad_cfgs/x.json", "{ not json");
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    GPtrArray *configs = g_ptr_array_new_with_free_func ((GDestroyNotify) config_data_free);
    printf("EXPECTED ERRORS (2)\n    ");
    CU_ASSERT_EQUAL (load_configs_from_directory (dir, registry, configs), -1);
    printf("END EXPECTED ERRORS (2)\n");
    g_hash_table_destroy (registry);
    g_ptr_array_free (configs, TRUE);
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


/* ===========================================================================
 * create_logrotate_config
 * =========================================================================*/

static void
test_create_logrotate_config_writes_expected_content (void)
{
    const char *lr_dir = TEST_TMP_DIR "/logrotate_out";
    mkdir (lr_dir, 0755);
    logrotate_dir_override = lr_dir;

    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    cfg.destination = strdup (TEST_TMP_DIR "/lr_dest/data.json");
    cfg.max_size = 500;
    cfg.max_samples = 7;

    /* Ensure destination dir exists for resolve_absolute_path */
    char dest_dir[] = TEST_TMP_DIR "/lr_dest/data.json";
    make_path (dest_dir);

    CU_ASSERT_EQUAL (create_logrotate_config (&cfg), 0);

    /* Verify the config file was created in the override directory */
    char *config_name = sanitize_path_for_config (cfg.destination);
    char config_path[512];
    snprintf (config_path, sizeof (config_path), "%s/%s", lr_dir, config_name);

    FILE *f = fopen (config_path, "r");
    CU_ASSERT_PTR_NOT_NULL_FATAL (f);

    char buf[1024] = {0};
    size_t n = fread (buf, 1, sizeof (buf) - 1, f);
    (void) n;
    fclose (f);

    /* Check key content */
    CU_ASSERT_PTR_NOT_NULL (strstr (buf, "size 500k"));
    CU_ASSERT_PTR_NOT_NULL (strstr (buf, "rotate 7"));
    CU_ASSERT_PTR_NOT_NULL (strstr (buf, "missingok"));
    CU_ASSERT_PTR_NOT_NULL (strstr (buf, "notifempty"));

    free (config_name);
    free (cfg.destination);
    logrotate_dir_override = NULL;
}

/* ===========================================================================
 * polling_callback (with injected query_fn)
 * =========================================================================*/

static GNode *
mock_query_fn (GNode *root)
{
    (void) root;
    GNode *tree = APTERYX_NODE (NULL, g_strdup ("/"));
    APTERYX_LEAF_STRING (tree, "speed", "1000");
    APTERYX_LEAF_STRING (tree, "status", "up");
    return tree;
}

static void
test_polling_callback_writes_diff_with_mock (void)
{
    char path[] = "/tmp/recorder_poll_mock_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);

    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    cfg.query = strdup ("/test/*");
    cfg.destination = strdup (path);
    cfg.query_fn = mock_query_fn;
    cfg.last_snapshot = NULL;

    /* Call polling_callback directly */
    gboolean result = polling_callback (&cfg);
    CU_ASSERT_EQUAL (result, G_SOURCE_CONTINUE);

    /* Verify file was created with expected baseline */
    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);

    json_t *baseline = json_object_get (storage, "baseline");
    CU_ASSERT_PTR_NOT_NULL (baseline);
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (baseline, "speed")), "1000");
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (baseline, "status")), "up");

    json_decref (storage);
    json_decref (cfg.last_snapshot);
    free (cfg.query);
    free (cfg.destination);
    unlink (path);
}

static GNode *
mock_query_fn_updated (GNode *root)
{
    (void) root;
    GNode *tree = APTERYX_NODE (NULL, g_strdup ("/"));
    APTERYX_LEAF_STRING (tree, "speed", "2500");
    APTERYX_LEAF_STRING (tree, "status", "up");
    return tree;
}

static void
test_polling_callback_detects_changes (void)
{
    char path[] = "/tmp/recorder_poll_change_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);
    unlink (path);

    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    cfg.query = strdup ("/test/*");
    cfg.destination = strdup (path);
    cfg.query_fn = mock_query_fn;
    cfg.last_snapshot = NULL;

    /* First poll: creates baseline */
    polling_callback (&cfg);

    /* Second poll with different data: should record a diff */
    cfg.query_fn = mock_query_fn_updated;
    polling_callback (&cfg);

    json_error_t error;
    json_t *storage = json_load_file (path, 0, &error);
    CU_ASSERT_PTR_NOT_NULL_FATAL (storage);

    json_t *diffs = json_object_get (storage, "diffs");
    CU_ASSERT_EQUAL (json_array_size (diffs), 1);

    json_t *changes = json_object_get (json_array_get (diffs, 0), "changes");
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (changes, "speed")), "2500");

    json_decref (storage);
    json_decref (cfg.last_snapshot);
    free (cfg.query);
    free (cfg.destination);
    unlink (path);
}

/* ===========================================================================
 * gnode_to_json deep nesting
 * =========================================================================*/

static void
test_gnode_to_json_deep_nesting (void)
{
    GNode *root = APTERYX_NODE (NULL, g_strdup ("/"));
    GNode *l1 = APTERYX_NODE (root, g_strdup ("l1"));
    GNode *l2 = APTERYX_NODE (l1, g_strdup ("l2"));
    APTERYX_LEAF_STRING (l2, "deep_key", "deep_val");

    json_t *j = gnode_to_json (root);
    CU_ASSERT_PTR_NOT_NULL_FATAL (j);

    json_t *l1_j = json_object_get (j, "l1");
    CU_ASSERT_PTR_NOT_NULL_FATAL (l1_j);
    json_t *l2_j = json_object_get (l1_j, "l2");
    CU_ASSERT_PTR_NOT_NULL_FATAL (l2_j);
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (l2_j, "deep_key")),
                            "deep_val");

    json_decref (j);
    apteryx_free_tree (root);
}

/* ===========================================================================
 * compare_json_deep with nested objects containing changes at multiple levels
 * =========================================================================*/

static void
test_compare_json_deep_nested_partial_change (void)
{
    json_t *current = json_pack ("{s:{s:s, s:s}, s:s}",
                                 "iface", "speed", "1000", "status", "up",
                                 "name", "eth0");
    json_t *previous = json_pack ("{s:{s:s, s:s}, s:s}",
                                  "iface", "speed", "100", "status", "up",
                                  "name", "eth0");

    json_t *result = compare_json_deep (current, previous);
    CU_ASSERT_PTR_NOT_NULL_FATAL (result);

    /* Only iface should be in the diff, and within it only speed changed */
    CU_ASSERT_PTR_NULL (json_object_get (result, "name"));
    json_t *iface_diff = json_object_get (result, "iface");
    CU_ASSERT_PTR_NOT_NULL_FATAL (iface_diff);
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (iface_diff, "speed")),
                            "1000");
    CU_ASSERT_PTR_NULL (json_object_get (iface_diff, "status"));

    json_decref (current);
    json_decref (previous);
    json_decref (result);
}

/* ===========================================================================
 * append_diff_entry_to_file with corrupted file
 * =========================================================================*/

static void
test_append_diff_corrupted_file_no_bracket (void)
{
    char path[] = "/tmp/recorder_corrupted_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    CU_ASSERT_EQUAL ((int) write (fd, "{\"no_array\": true}", 18), 18);
    close (fd);

    json_t *entry = json_object ();
    json_object_set_new (entry, "timestamp", json_integer (100));
    json_object_set_new (entry, "changes", json_object ());

    CU_ASSERT_NOT_EQUAL (append_diff_entry_to_file (path, entry), 0);

    json_decref (entry);
    unlink (path);
}

/* ===========================================================================
 * validate_and_set_data — zero / negative boundary values
 * =========================================================================*/

static void
test_validate_data_frequency_zero_rejected (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_fz/out.json");
    json_object_set_new (data, "frequency", json_integer (0));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_max_samples_zero_rejected (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_msz/out.json");
    json_object_set_new (data, "max_samples", json_integer (0));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

static void
test_validate_data_max_size_zero_rejected (void)
{
    GHashTable *registry = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    json_t *data = make_valid_config_json (TEST_TMP_DIR "/vd_mssz/out.json");
    json_object_set_new (data, "max_size", json_integer (0));
    config_data cfg;
    memset (&cfg, 0, sizeof (cfg));
    printf("EXPECTED ERROR\n    ");
    CU_ASSERT_EQUAL (validate_and_set_data (data, &cfg, registry, "x.json"), -1);
    printf("END EXPECTED ERROR\n");
    json_decref (data);
    g_hash_table_destroy (registry);
}

/* ===========================================================================
 * calculate_initial_delay_at — boundary: elapsed == frequency exactly
 * =========================================================================*/

static void
test_calculate_initial_delay_at_exactly_on_time_returns_zero (void)
{
    /* elapsed == frequency → overdue by exactly 0 seconds, should poll immediately */
    CU_ASSERT_EQUAL (calculate_initial_delay_at (30, 70, 100), 0);
}

/* ===========================================================================
 * read_last_poll_timestamp — multiple diffs: must return the LAST, not first
 * =========================================================================*/

static void
test_read_last_poll_timestamp_returns_last_not_first_diff (void)
{
    char path[] = "/tmp/recorder_ts_last_XXXXXX";
    int fd = mkstemp (path);
    CU_ASSERT_NOT_EQUAL_FATAL (fd, -1);
    close (fd);

    json_t *d1 = json_object ();
    json_object_set_new (d1, "timestamp", json_integer (1000));
    json_object_set_new (d1, "changes", json_object ());
    json_t *d2 = json_object ();
    json_object_set_new (d2, "timestamp", json_integer (2000));
    json_object_set_new (d2, "changes", json_object ());
    json_t *d3 = json_object ();
    json_object_set_new (d3, "timestamp", json_integer (3000));
    json_object_set_new (d3, "changes", json_object ());

    json_t *diffs_arr = json_array ();
    json_array_append_new (diffs_arr, d1);
    json_array_append_new (diffs_arr, d2);
    json_array_append_new (diffs_arr, d3);

    json_t *storage = json_object ();
    json_object_set_new (storage, "baseline_timestamp", json_integer (500));
    json_object_set_new (storage, "baseline", json_object ());
    json_object_set_new (storage, "diffs", diffs_arr);
    CU_ASSERT_EQUAL_FATAL (json_dump_file (storage, path, 0), 0);
    json_decref (storage);

    /* Must return 3000, not 1000 or 500 */
    CU_ASSERT_EQUAL (read_last_poll_timestamp (path), 3000);
    unlink (path);
}

/* ===========================================================================
 * reconstruct_latest_snapshot — diff entry missing "changes" key
 * =========================================================================*/

static void
test_reconstruct_diff_entry_missing_changes_key (void)
{
    /* A diff entry without a "changes" key must be treated as a no-op (apply_forward_diff
     * receives NULL from json_object_get, which it handles as an empty diff). */
    json_t *baseline = json_object ();
    json_object_set_new (baseline, "key", json_string ("original"));

    json_t *bad_entry = json_object ();     /* no "changes" field */
    json_t *diffs = json_array ();
    json_array_append_new (diffs, bad_entry);

    json_t *result = reconstruct_latest_snapshot (baseline, diffs);
    CU_ASSERT_PTR_NOT_NULL_FATAL (result);

    /* Snapshot must be unchanged */
    CU_ASSERT_STRING_EQUAL (json_string_value (json_object_get (result, "key")), "original");

    json_decref (baseline);
    json_decref (diffs);
    json_decref (result);
}


int
run_tests (void)
{
    CU_pSuite pSuite;

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

    pSuite = CU_add_suite ("unit::sanitize_path_for_config", NULL, NULL);
    CU_add_test (pSuite, "basic", test_sanitize_basic);
    CU_add_test (pSuite, "slashes_dots", test_sanitize_replaces_slashes_and_dots);
    CU_add_test (pSuite, "alnum_underscore", test_sanitize_keeps_alnum_and_underscore);
    CU_add_test (pSuite, "drops_other", test_sanitize_drops_unknown_chars);
    CU_add_test (pSuite, "empty", test_sanitize_empty);

    pSuite = CU_add_suite ("unit::gnode_to_json", NULL, NULL);
    CU_add_test (pSuite, "empty", test_gnode_to_json_empty);
    CU_add_test (pSuite, "single_leaf", test_gnode_to_json_single_leaf);
    CU_add_test (pSuite, "nested", test_gnode_to_json_nested);

    pSuite = CU_add_suite ("unit::compare_objects", NULL, NULL);
    CU_add_test (pSuite, "identical_returns_null",
                 test_compare_objects_identical_returns_null);
    CU_add_test (pSuite, "key_deleted_from_current_marked_null",
                 test_compare_objects_key_deleted_from_current_marked_null);
    CU_add_test (pSuite, "key_new_in_current_returns_current_value",
                 test_compare_objects_key_new_in_current_returns_current_value);
    CU_add_test (pSuite, "changed_value_returns_old",
                 test_compare_objects_changed_value);

    pSuite = CU_add_suite ("unit::make_path", fs_suite_init, fs_suite_cleanup);
    CU_add_test (pSuite, "creates_nested", test_make_path_creates_nested);
    CU_add_test (pSuite, "idempotent", test_make_path_idempotent);
    CU_add_test (pSuite, "no_dirs_in_path", test_make_path_no_dirs_in_path);
    CU_add_test (pSuite, "parent_file_fails", test_make_path_fails_when_parent_is_file);

    pSuite =
        CU_add_suite ("unit::resolve_absolute_path", fs_suite_init, fs_suite_cleanup);
    CU_add_test (pSuite, "existing_file", test_resolve_existing_file);
    CU_add_test (pSuite, "missing_file_parent_ok",
                 test_resolve_nonexistent_file_existing_parent);

    pSuite =
        CU_add_suite ("unit::validate_destination", fs_suite_init, fs_suite_cleanup);
    CU_add_test (pSuite, "creates_dirs", test_validate_destination_creates_dirs);
    CU_add_test (pSuite, "empty_string_fails", test_validate_destination_empty_string);
    CU_add_test (pSuite, "null_fails", test_validate_destination_null);
    CU_add_test (pSuite, "blocked_by_file", test_validate_destination_blocked_by_file);
    CU_add_test (pSuite, "duplicate_rejected",
                 test_validate_destination_duplicate_rejected);

    pSuite = CU_add_suite ("unit::validate_data", fs_suite_init, fs_suite_cleanup);
    CU_add_test (pSuite, "happy_path", test_validate_data_happy_path);
    CU_add_test (pSuite, "query_not_string", test_validate_data_query_not_string);
    CU_add_test (pSuite, "frequency_not_int", test_validate_data_frequency_not_int);
    CU_add_test (pSuite, "destination_not_string",
                 test_validate_data_destination_not_string);
    CU_add_test (pSuite, "max_samples_not_int", test_validate_data_max_samples_not_int);
    CU_add_test (pSuite, "max_size_not_int", test_validate_data_max_size_not_int);
    CU_add_test (pSuite, "missing_field", test_validate_data_missing_field);
    CU_add_test (pSuite, "frequency_zero_rejected",
                 test_validate_data_frequency_zero_rejected);
    CU_add_test (pSuite, "max_samples_zero_rejected",
                 test_validate_data_max_samples_zero_rejected);
    CU_add_test (pSuite, "max_size_zero_rejected",
                 test_validate_data_max_size_zero_rejected);

    pSuite =
        CU_add_suite ("integration::load_configs_from_directory", fs_suite_init,
                      fs_suite_cleanup);
    CU_add_test (pSuite, "missing_dir_returns_error",
                 test_load_configs_missing_dir_returns_error);
    CU_add_test (pSuite, "skips_non_json_files",
                 test_load_configs_skips_non_json_files);
    CU_add_test (pSuite, "invalid_json_returns_error",
                 test_load_configs_invalid_json_returns_error);

    pSuite = CU_add_suite ("unit::reload_timing", NULL, NULL);
    CU_add_test (pSuite, "missing_timestamp_returns_frequency",
                 test_calculate_initial_delay_at_missing_timestamp_returns_frequency);
    CU_add_test (pSuite, "future_timestamp_returns_frequency",
                 test_calculate_initial_delay_at_future_timestamp_returns_frequency);
    CU_add_test (pSuite, "overdue_returns_immediate",
                 test_calculate_initial_delay_at_overdue_returns_immediate);
    CU_add_test (pSuite, "partial_interval_returns_remaining",
                 test_calculate_initial_delay_at_partial_interval_returns_remaining);
    CU_add_test (pSuite, "exactly_on_time_returns_zero",
                 test_calculate_initial_delay_at_exactly_on_time_returns_zero);
    CU_add_test (pSuite, "missing_file_returns_zero",
                 test_read_last_poll_timestamp_missing_file_returns_zero);
    CU_add_test (pSuite, "valid_file_returns_value",
                 test_read_last_poll_timestamp_valid_file_returns_value);
    CU_add_test (pSuite, "non_integer_returns_zero",
                 test_read_last_poll_timestamp_non_integer_returns_zero);
    CU_add_test (pSuite, "reads_timestamp_from_last_diff",
                 test_read_last_poll_timestamp_reads_from_diffs);
    CU_add_test (pSuite, "returns_last_not_first_diff",
                 test_read_last_poll_timestamp_returns_last_not_first_diff);

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
    CU_add_test (pSuite, "missing_changes_key_is_noop",
                 test_reconstruct_diff_entry_missing_changes_key);

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

    pSuite =
        CU_add_suite ("unit::create_logrotate_config", fs_suite_init, fs_suite_cleanup);
    CU_add_test (pSuite, "writes_expected_content",
                 test_create_logrotate_config_writes_expected_content);

    pSuite = CU_add_suite ("unit::polling_callback", NULL, NULL);
    CU_add_test (pSuite, "writes_diff_with_mock",
                 test_polling_callback_writes_diff_with_mock);
    CU_add_test (pSuite, "detects_changes",
                 test_polling_callback_detects_changes);

    pSuite = CU_add_suite ("unit::gnode_to_json_extended", NULL, NULL);
    CU_add_test (pSuite, "deep_nesting", test_gnode_to_json_deep_nesting);

    pSuite = CU_add_suite ("unit::compare_json_deep_extended", NULL, NULL);
    CU_add_test (pSuite, "nested_partial_change",
                 test_compare_json_deep_nested_partial_change);

    pSuite = CU_add_suite ("unit::append_diff_edge_cases", NULL, NULL);
    CU_add_test (pSuite, "corrupted_file_no_bracket",
                 test_append_diff_corrupted_file_no_bracket);

    CU_basic_set_mode (CU_BRM_SILENT);
    CU_basic_run_tests ();
    int failures = CU_get_number_of_failures ();
    CU_cleanup_registry ();

    return failures ? -1 : 0;
}
