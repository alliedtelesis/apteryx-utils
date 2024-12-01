#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <apteryx.h>
#include <glib-unix.h>
#include "common.h"
#include "apteryx_sync.h"

#define APTERYX_SYNC_PID "/var/run/apteryx-sync.pid"
#define APTERYX_SYNC_CONFIG_DIR "/etc/apteryx/sync/"

/* Debug */
bool apteryx_debug = false;

/* Run while true */
static GMainLoop *g_loop = NULL;

typedef struct sync_partner_s
{
    char *socket;
    char *path;
    bool new_joiner;
} sync_partner;

typedef struct _sync_entry
{
    GList *paths;
    GList *excluded_paths;
} sync_entry;

typedef struct _sync_params
{
    uint64_t ts;
    GNode *root;
    sync_entry *entry;
} sync_params;

/* keep a list of the partners we are syncing paths to */
GList *partners = NULL;
pthread_rwlock_t partners_lock = PTHREAD_RWLOCK_INITIALIZER;

/* keep pending changes (not yet pushed to clients)... */
static GNode *pending = NULL;
static guint pending_timer = 0;
static uint64_t oldest_pending = 0;
#define PENDING_HOLD_OFF 800   /* 800 ms */
#define WATCH_TREE_HOLD_OFF 200  /* 200 ms */

/* periodic sync timer */
static guint sync_timer = 0;
#define SYNC_HOLD_OFF 30 * 1000 /* 30 seconds */

/* keep a list of the paths we are syncing */
GList *paths = NULL;
pthread_rwlock_t paths_lock = PTHREAD_RWLOCK_INITIALIZER;

static uint64_t
now (void)
{
    struct timespec tms;
    uint64_t micros = 0;
    if (clock_gettime (CLOCK_MONOTONIC, &tms))
    {
        return 0;
    }

    micros = ((uint64_t) tms.tv_sec) * 1000000;
    micros += tms.tv_nsec / 1000;
    return micros;
}

static bool
flush ()
{
    pthread_rwlock_wrlock (&partners_lock);
    DEBUG ("Flushing...\n");
    for (GList * iter = partners; iter; iter = iter->next)
    {
        if (pending)
        {
            /* Dirty hack to do set tree without a deep copy */
            char *next_path = NULL;

            if (asprintf (&next_path, "%s:/", ((sync_partner *) iter->data)->socket) > 0)
            {
                free (pending->data);
                pending->data = next_path;
                apteryx_set_tree (pending);
            }
        }
    }
    apteryx_free_tree (pending);
    pending = NULL;

    oldest_pending = 0;

    if (pending_timer)
    {
        g_source_remove (pending_timer);
    }
    pending_timer = 0;
    pthread_rwlock_unlock (&partners_lock);

    return false;
}

static void
add_data_point (const char *path, const char *value)
{
    pthread_rwlock_wrlock (&partners_lock);

    if (apteryx_find_child (pending, path + 1))
    {
        DEBUG ("Flushing due to collision\n");
        pthread_rwlock_unlock (&partners_lock);
        flush ();
        pthread_rwlock_wrlock (&partners_lock);
    }

    uint64_t n = now ();

    if (pending == NULL)
    {
        pending = APTERYX_NODE (NULL, strdup ("/"));
        oldest_pending = n;
    }
    APTERYX_LEAF (pending, strlen (path) > 0 ? strdup (path + 1) : strdup (""),
                  value ? strdup (value) : NULL);

    /* Convert 5 seconds to micro seconds... */
    if (oldest_pending + (5 * 1000 * 1000) < n)
    {
        NOTICE ("Pending changes waiting in excess of 5 seconds\n");
        oldest_pending = n;
    }

    if (pending_timer)
    {
        g_source_remove (pending_timer);
    }
    pending_timer = g_timeout_add (PENDING_HOLD_OFF, (GSourceFunc) flush, NULL);

    pthread_rwlock_unlock (&partners_lock);

}

bool
syncer_add (sync_partner *sp)
{
    partners = g_list_append (partners, sp);
    return true;
}

gint
syncer_match_path (gconstpointer a, gconstpointer b)
{
    sync_partner *sp = (sync_partner *) a;
    const char *path = (const char *) b;
    return strcmp (sp->path, path);
}

sync_partner *
syncer_find_path (const char *path)
{
    GList *list_pt;

    list_pt = g_list_find_custom (partners, path, syncer_match_path);

    return list_pt ? (sync_partner *) list_pt->data : NULL;
}

bool
syncer_del (sync_partner *sp)
{
    partners = g_list_remove (partners, sp);
    free (sp->socket);
    free (sp->path);
    free (sp);
    return true;
}

static bool
new_syncer (const char *path, const char *value)
{
    pthread_rwlock_wrlock (&partners_lock);
    if (value)
    {
        sync_partner *sp = syncer_find_path (path);
        if (sp)
        {
            /* partner already exists. update it */
            DEBUG ("Updating syncer. path %s, value %s\n", path, value);
            free (sp->socket);
            free (sp->path);
        }
        else
        {
            /* new partner so get memory and add to the list now.
             * fill in the details afterwards (while we still hold the lock).
             */
            DEBUG ("Adding new syncer. path %s, value %s\n", path, value);
            sp = malloc (sizeof (sync_partner));
            syncer_add (sp);
        }
        sp->socket = strdup (value);
        sp->path = strdup (path);
        sp->new_joiner = true;
    }
    else
    {
        DEBUG ("Deleting syncer. path %s\n", path);
        sync_partner *sp = syncer_find_path (path);
        if (sp)
        {
            syncer_del (sp);
        }
    }
    pthread_rwlock_unlock (&partners_lock);
    return true;
}

bool
sync_path_check (const char *path)
{
    /* as a sanity check, make sure the path to sync isn't something crazy */
    if ((strncmp (path, "/apteryx", 8) == 0) ||
        (strcmp (path, "/") == 0))
    {
        return false;
    }
    return true;
}

bool
sync_path_excluded (sync_entry *entry, const char *path)
{
    pthread_rwlock_rdlock (&paths_lock);

    for (GList *iter = entry->excluded_paths; iter; iter = iter->next)
    {
        char *exclude_path = (char *) iter->data;
        char *star;
        size_t len = strlen (exclude_path);
        int ret;

        if (len && exclude_path[len - 1] == '*')
        {
            /* Match all paths beginning with this string */
            ret = strncmp (path, exclude_path, len - 1);
        }
        else
        {
            /* Match an exclusion path with a starred list field */
            if ((star = strchr (exclude_path, '*')))
            {
                int star_offset = star - exclude_path;
                ret = strncmp (path, exclude_path, star_offset);
                if (ret == 0)
                {
                    char *ptr = strchr (path + star_offset, '/');
                    if (!ptr || strstr (ptr, star + 1) != ptr)
                    {
                        ret = -1;
                    }
                }
            }
            else
            {
                /* Match exact path */
                ret = g_strcmp0 (path, exclude_path);
            }
        }

        if (ret == 0)
        {
            pthread_rwlock_unlock (&paths_lock);
            return true;
        }
    }
    pthread_rwlock_unlock (&paths_lock);
    return false;
}

char *
sp_path (sync_partner *sp, const char *path)
{
    char *full_path = NULL;
    if (asprintf (&full_path, "%s:%s", sp->socket, path) < 0)
    {
        return NULL;
    }
    return full_path;
}

bool
apteryx_prune_sp (sync_partner *sp, const char *path)
{
    bool res = false;
    char *full_path = sp_path (sp, path);
    if (!full_path)
    {
        return false;
    }
    res = apteryx_prune (full_path);
    free (full_path);
    return res;
}

bool
apteryx_set_sp (sync_partner *sp, const char *path, const char *value)
{
    bool res = false;
    char *full_path = sp_path (sp, path);
    if (!full_path)
    {
        return false;
    }
    res = apteryx_set (full_path, value);
    free (full_path);
    return res;
}

static gboolean
sync_tree_process (GNode *node, gpointer arg)
{
    uint64_t ts;
    sync_params *params = (sync_params *) arg;
    char *path = apteryx_node_path (node->parent);

    if (path)
    {
        if (!sync_path_excluded (params->entry, path))
        {
            /* The timestamp is stored on the parent of the value. */
            ts = apteryx_timestamp (path);
            if (ts && ts > params->ts)
            {
                apteryx_path_to_node (params->root, path, node->data ?: "");
            }
        }
        g_free (path);
    }

    return FALSE;
}

bool
sync_recursive (GNode *root, uint64_t timestamp, sync_entry *entry, const char *path)
{
    GNode *tree;
    GNode *query = g_node_new (g_strdup (path));

    if (query)
    {
        tree = apteryx_query (query);
        if (tree)
        {
            sync_params params;
            params.ts = timestamp;
            params.root = root;
            params.entry = entry;
            g_node_traverse (tree, G_IN_ORDER, G_TRAVERSE_LEAVES, -1, sync_tree_process,
                            (gpointer) &params);
            apteryx_free_tree (tree);
        }
        apteryx_free_tree (query);
    }

    return true;
}

void
sync_gather (GNode *root, uint64_t timestamp)
{
    GList *iter = NULL;
    GList *list = NULL;
    sync_entry *entry;

    pthread_rwlock_rdlock (&paths_lock);
    for (iter = paths; iter; iter = iter->next)
    {
        entry = iter->data;
        for (list = entry->paths; list; list = list->next)
        {
            sync_recursive (root, timestamp, entry, (char *) list->data);
        }
    }
    pthread_rwlock_unlock (&paths_lock);
}

void
sync_write_tree (sync_partner *sp, GNode *data)
{
    if (APTERYX_NUM_NODES (data) > 0)
    {
        char *next_path = NULL;

        if (asprintf (&next_path, "%s:/", sp->socket) > 0)
        {
            free (data->data);
            data->data = next_path;
            apteryx_set_tree (data);
        }
    }
}

bool
resync ()
{
    /* Called under a lock */
    GList *iter;
    GNode *new_data = NULL;
    GNode *sync_data = NULL;
    static uint64_t last_sync_local = 0;

    uint64_t local_ts = apteryx_timestamp ("/");

    for (iter = partners; iter; iter = iter->next)
    {
        sync_partner *sp = iter->data;
        /* Sync the entire tree to new partners */
        if (sp->new_joiner)
        {
            if (new_data == NULL)
            {
                new_data = APTERYX_NODE (NULL, strdup ("/"));
                /* Get everything */
                sync_gather (new_data, 0);
            }
            sync_write_tree (sp, new_data);
            sp->new_joiner = false;
        }
        else
        {
            /* Sync changes since the last timestamp to existing partners */
            if (sync_data == NULL)
            {
                sync_data = APTERYX_NODE (NULL, strdup ("/"));
                sync_gather (sync_data, last_sync_local);
            }
            sync_write_tree (sp, sync_data);
        }
    }

    if (new_data)
    {
        apteryx_free_tree (new_data);
    }
    if (sync_data)
    {
        apteryx_free_tree (sync_data);
    }

    last_sync_local = local_ts;
    return true;
}

static bool
periodic_syncer_thread (void *ign)
{
    pthread_rwlock_rdlock (&partners_lock);
    /* If we are already busy, wait for a quiet spell */
    if (pending_timer)
    {
        g_source_remove (sync_timer);
        sync_timer =
            g_timeout_add (PENDING_HOLD_OFF * 1.4, (GSourceFunc) periodic_syncer_thread,
                           NULL);
    }
    else
    {
        resync ();
        g_source_remove (sync_timer);
        sync_timer =
            g_timeout_add (SYNC_HOLD_OFF, (GSourceFunc) periodic_syncer_thread, NULL);
    }
    pthread_rwlock_unlock (&partners_lock);
    return false;
}

sync_entry *
sync_find_sync_entry (GNode *node)
{
    sync_entry *entry;
    char *path;
    GList *list;

    if (node->children && g_strcmp0 ((char *) node->data , "/") == 0)
    {
        node = node->children;
    }

    for (GList *iter = paths; iter; iter = iter->next)
    {
        entry = iter->data;
        list = entry->paths;
        if (list)
        {
            path = list->data;
            if (strncmp (path + 1, (char *) node->data, strlen ((char *) node->data)) == 0)
            {
                return entry;
            }
        }
    }

    return NULL;
}

static gboolean
new_change_process (GNode *node, gpointer arg)
{
    char *path = apteryx_node_path (node->parent);
    char *value = NULL;
    sync_entry *entry = (sync_entry *) arg;
    if (path)
    {
        if (!sync_path_excluded (entry, path))
        {
            if (node->data && ((char *) node->data)[0] != '\0')
            {
                value = node->data;
            }

            DEBUG ("Pushing NEW_CHANGE on path %s, value %s to cache\n", path, value);
            add_data_point (path, value);
        }
        g_free (path);
    }

    return FALSE;
}

bool
new_change (GNode *tree)
{
    if (partners)
    {
        sync_entry *entry = sync_find_sync_entry (tree);
        if (entry)
        {
            g_node_traverse (tree, G_IN_ORDER, G_TRAVERSE_LEAVES, -1, new_change_process, entry);
        }
    }
    apteryx_free_tree (tree);
    return true;
}

void
register_existing_partners (void)
{
    GList *iter = NULL;
    char *value = NULL;

    /* get all paths under the APTERYX_SYNC_DESTINATIONS_PATH node
     * note: need to add a "/" on the end for search to work
     */
    GList *existing_partners = apteryx_search (APTERYX_SYNC_DESTINATIONS_PATH "/");
    /* for each path in the search result, get the value and create a new syncer */
    iter = existing_partners;
    while (iter != NULL)
    {
        DEBUG ("Adding existing partner %s\n", (char *) iter->data);
        value = apteryx_get (iter->data);
        new_syncer (iter->data, value);
        free (value);

        /* finished with this entry. move along, nothing to see here. */
        iter = iter->next;
    }
    /* finally, clean up the list */
    g_list_free_full (existing_partners, free);
    existing_partners = NULL;
}

bool
add_path_to_sync (sync_entry *entry, const char *path)
{
    /* Note: Any path the works with apteryx -q 'path' is acceptable */
    if (sync_path_check (path))
    {
        DEBUG ("SYNC INIT: about to watch path: %s\n", path);
        apteryx_watch_tree_full (path, new_change, WATCH_F_MASK_MYSELF, WATCH_TREE_HOLD_OFF);
        char *new_path = strdup (path);
        pthread_rwlock_wrlock (&paths_lock);
        entry->paths = g_list_append (entry->paths, new_path);
        pthread_rwlock_unlock (&paths_lock);
    }
    else
    {
        ERROR ("Path %s is not valid for syncing\n", path);
    }
    return TRUE;
}

bool
add_excluded_path (sync_entry *entry, const char *path)
{
    if (sync_path_check (path))
    {
        DEBUG ("SYNC INIT: Adding exclusion for: %s\n", path);
        char *new_path = strdup (path);
        pthread_rwlock_wrlock (&paths_lock);
        entry->excluded_paths = g_list_append (entry->excluded_paths, new_path);
        pthread_rwlock_unlock (&paths_lock);
    }
    return true;
}

bool
parse_config_files (const char* config_dir)
{
    FILE *fp = NULL;
    struct dirent *config_file;
    DIR *dp = NULL;
    char *config_file_name = NULL;
    sync_entry *entry;

    /* open the sync config dir and read all the files in it to get sync paths */
    dp = opendir (config_dir);
    if (!dp)
    {
        ERROR ("Couldn't open sync config directory \"%s\"\n", config_dir);
        return FALSE;
    }
    /* Now read the config file(s) to know which paths should be synced */
    while ((config_file = readdir(dp)) != NULL)
    {
        if ((strcmp(config_file->d_name, ".") == 0) ||
            (strcmp(config_file->d_name, "..") == 0))
        {
            /* skip the directory entries */
            continue;
        }
        if (asprintf (&config_file_name, "%s%s", config_dir, config_file->d_name) == -1)
        {
            /* this shouldn't fail, but can't do anything if it does */
            continue;
        }
        fp = fopen (config_file_name, "r");
        if (!fp)
        {
            ERROR ("Couldn't open sync config file \"%s\"\n", config_file_name);
        }
        else
        {
            char *sync_path = NULL;
            char *newline = NULL;
            size_t n = 0;
            entry = g_malloc0 (sizeof (sync_entry));

            while (getline (&sync_path, &n, fp) != -1)
            {
                /* ignore empty lines or lines starting with '#' */
                if (sync_path[0] == '#' || sync_path[0] == '\n')
                {
                    free (sync_path);
                    sync_path = NULL;
                    continue;
                }
                if ((newline = strchr (sync_path, '\n')) != NULL)
                {
                    newline[0] = '\0'; // remove the trailing newline char
                }

                if (sync_path[0] == '!')
                {
                    // Add an exclusion to syncing
                    add_excluded_path (entry, sync_path + 1);
                }
                else
                {
                    add_path_to_sync (entry, sync_path);
                }

                free (sync_path);
                sync_path = NULL;
            }
            fclose (fp);
            if (!entry->paths && !entry->excluded_paths)
            {
                g_free (entry);
            }
            else
            {
                paths = g_list_append (paths, entry);
            }
        }
        free (config_file_name);
    }
    closedir (dp);
    return TRUE;
}

static gboolean
termination_handler (gpointer arg1)
{
    g_main_loop_quit (g_loop);
    return false;
}

void
help (char *app_name)
{
    printf ("Usage: %s [-h] [-b] [-d] [-p <pidfile>] [-c <configdir>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -p   use <pidfile> (defaults to "APTERYX_SYNC_PID")\n"
            "  -c   use <configdir> (defaults to "APTERYX_SYNC_CONFIG_DIR")\n",
            app_name);
}

int
main (int argc, char *argv[])
{
    const char *pid_file = APTERYX_SYNC_PID;
    const char *config_dir = APTERYX_SYNC_CONFIG_DIR;
    int i = 0;
    bool background = false;
    FILE *fp = NULL;

    apteryx_init (false);

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:c:")) != -1)
    {
        switch (i)
        {
        case 'd':
            apteryx_debug = true;
            background = false;
            break;
        case 'b':
            background = true;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case '?':
        case 'h':
        default:
            help (argv[0]);
            return 0;
        }
    }

    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    g_unix_signal_add (SIGINT, termination_handler, g_loop);
    g_unix_signal_add (SIGTERM, termination_handler, g_loop);
    signal (SIGPIPE, SIG_IGN);

    /* Daemonize */
    if (background && fork () != 0)
    {
        /* Parent */
        return 0;
    }

    /* Create pid file */
    if (background)
    {
        fp = fopen (pid_file, "w");
        if (!fp)
        {
            ERROR ("Failed to create PID file %s\n", pid_file);
            goto exit;
        }
        fprintf (fp, "%d\n", getpid ());
        fclose (fp);
    }

    /* The sync path is how applications can register the nodes to sync to */
    apteryx_watch (APTERYX_SYNC_DESTINATIONS_PATH "/*", new_syncer);

    /* next, we need to check for any existing nodes and setup syncers for them */
    register_existing_partners ();

    /* and finally, read the list of paths we should sync */
    parse_config_files (config_dir);

    /* Now we have done the setup, we can start running */
    sync_timer = g_timeout_add (SYNC_HOLD_OFF, (GSourceFunc) periodic_syncer_thread, NULL);

    g_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (g_loop);
    g_main_loop_unref (g_loop);

    exit:
    /* Remove the pid file */
    if (background)
    {
        unlink (pid_file);
    }
}
