/**
 * @file saver.c
 * API for saving persistent configuration.
 * Copyright 2017, Allied Telesis Labs New Zealand, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#include <string.h>
#include <libxml/xmlschemas.h>
#include <apteryx.h>
#include <apteryx-xml.h>
#include <glib-unix.h>
#include <syslog.h>

#define DEBUG(fmt, args...) { if (apteryx_debug) printf (fmt, ## args); }
#define INFO(fmt, args...) syslog (LOG_INFO, fmt, ## args);
#define ERROR(fmt, args...) syslog (LOG_ERR, fmt, ## args);

#define APTERYX_SCHEMA_DIR "/etc/apteryx/schema/"
#define APTERYX_CONFIG_DIR "/etc/apteryx/saver/"
#define APTERYX_SAVE_PID "/var/run/saver.pid"
#define APTERYX_SAVE_CONFIG_FILE "/etc/apteryx/saver.cfg"

bool apteryx_debug = false;
static GNode *saver_nodes = NULL;
static GNode *config_nodes = NULL;
static int write_delay = 15;
static bool automatic = false;
const char *schema_dir = APTERYX_SCHEMA_DIR;
const char *config_dir = APTERYX_CONFIG_DIR;
const char *config_file = APTERYX_SAVE_CONFIG_FILE;
static bool writing = false;

pthread_mutex_t writing_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;


/* Break a path into nodes based on "/" and add all nodes which do not exist to
 * the root tree.
 * Also set/update the value at the leaf node.
 */
static void
_path_to_node (GNode *root, const char *path, const char *value)
{
    char *key = g_strdup (path);
    char *key_start = key;
    char *new_path = g_strdup (path);
    char *new_path_start = new_path;
    GNode *old_current = root;
    GNode *current = root;
    GNode *node = NULL;
    int path_length = strlen (key);

    if (strchr (key, '/'))
    {
        *strchr (key, '/') = '\0';
    }

    while (current)
    {
        old_current = current;
        current = NULL;

        if (key + strlen (key) == key_start + path_length)
        {
            if (strcmp (key, old_current->data) == 0)
            {
                break;
            }
        }
        if (g_node_first_child (old_current) == NULL)
        {
            break;
        }
        key += strlen (key) + 1;
        if (strchr (key, '/'))
        {
            *strchr (key, '/') = '\0';
        }

        for (node = g_node_first_child (old_current); node;
             node = g_node_next_sibling (node))
        {
            if (strcmp (node->data, key) == 0)
            {
                current = node;
                break;
            }
        }
        if (current)
        {
            new_path += 1;
            if (strchr (new_path, '/'))
            {
                new_path = strchr (new_path, '/');
            }
            else
            {
                new_path = "";
            }
        }
    }
    if (strlen (new_path) > 0)
    {
        /* add the path */
        apteryx_path_to_node (old_current, new_path, value);
    }
    else
    {
        if (g_node_first_child (old_current))
        {
            /* update the value */
            char *tmp = g_node_first_child (old_current)->data;
            g_free (tmp);
            g_node_first_child (old_current)->data = value ? strdup (value) : NULL;
        }
    }
    g_free (key_start);
    g_free (new_path_start);
    return;
}

static bool
process_node (xmlNode *node, char *parent)
{
    xmlChar *name = NULL;
    char *path = NULL;
    bool res = true;

    /* Ignore fluff */
    if (!node || node->type != XML_ELEMENT_NODE)
    {
        return true;
    }

    /* Process this node */
    if (strcmp ((const char *) node->name, "NODE") == 0)
    {
        /* Find node name and path */
        name = xmlGetProp (node, (xmlChar *) "name");
        if (parent)
        {
            path = g_strdup_printf ("%s/%s", parent, name);
        }
        else
        {
            path = g_strdup_printf ("/%s", name);
        }
        if (sch_is_config (node))
        {
            DEBUG ("Schema: %s\n", path);
            _path_to_node (saver_nodes, path, NULL);
        }
    }
    /* Process children */
    for (xmlNode *n = node->children; n; n = n->next)
    {
        if (!process_node (n, path))
        {
            res = false;
            goto exit;
        }
    }

  exit:
    g_free (path);
    g_free (name);
    return res;
}

bool
parse_config_files (const char* config_dir)
{
    FILE *fp = NULL;
    struct dirent *config_file;
    DIR *dp = NULL;
    char *config_file_name = NULL;

    /* open the sync config dir and read all the files in it to get sync paths */
    dp = opendir (config_dir);
    if (!dp)
    {
        ERROR ("Couldn't open saver config directory \"%s\"\n", config_dir);
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
        if (asprintf (&config_file_name, "%s/%s", config_dir, config_file->d_name) == -1)
        {
            /* this shouldn't fail, but can't do anything if it does */
            continue;
        }
        fp = fopen (config_file_name, "r");
        if (!fp)
        {
            ERROR ("Couldn't open saver config file \"%s\"\n", config_file_name);
        }
        else
        {
            char *path = NULL;
            char *newline = NULL;
            size_t n = 0;

            DEBUG ("Parsing %s\n", config_file_name);

            while (getline (&path, &n, fp) != -1)
            {
                /* ignore empty lines or lines starting with '#' */
                if (path[0] == '#' || path[0] == '\n')
                {
                    free (path);
                    path = NULL;
                    continue;
                }
                if ((newline = strchr (path, '\n')) != NULL)
                {
                    newline[0] = '\0'; // remove the trailing newline char
                }
                DEBUG ("Config: %s\n", path);
                _path_to_node (saver_nodes, path, NULL);
                free (path);
                path = NULL;
            }
            fclose (fp);
        }
        free (config_file_name);
    }
    closedir (dp);
    return TRUE;
}

static gboolean
write_line (GNode *node, gpointer data)
{
    if (APTERYX_HAS_VALUE (node))
    {
        char *path = apteryx_node_path (node);
        fprintf ((FILE *)data, "%s\t%s\n", path, APTERYX_VALUE (node) ? : "");
        free (path);
    }
    return FALSE;
}

static void
_write_config ()
{
    FILE *data = NULL;
    char *old_root_name = NULL;

    INFO ("Writing %s\n", config_file);

    /* Create file */
    data = fopen (config_file, "w");
    if (!data)
    {
        return;
    }
    old_root_name = APTERYX_NAME (config_nodes);
    config_nodes->data = "";
    g_node_traverse (config_nodes, G_PRE_ORDER, G_TRAVERSE_NON_LEAVES, -1, write_line,
                     data);
    config_nodes->data = old_root_name;

    fclose (data);
    data = NULL;
}

static gboolean
write_config_process (gpointer arg1)
{
    pthread_mutex_lock (&writing_lock);
    writing = false;
    pthread_mutex_unlock (&writing_lock);
    pthread_mutex_lock (&config_lock);
    _write_config ();
    pthread_mutex_unlock (&config_lock);
    return false;
}

void
write_config (int delay)
{
    pthread_mutex_lock (&writing_lock);
    if (!writing)
    {
        writing = true;
        g_timeout_add_seconds (delay, write_config_process, NULL);
    }
    pthread_mutex_unlock (&writing_lock);
}

static bool
watch_cb (const char *path, const char *value)
{
    _path_to_node (config_nodes, path, value);
    write_config (write_delay);
    return false;
}

static gboolean
node_watch (GNode *node, gpointer data)
{
    char *path = apteryx_node_path (node);
    apteryx_watch (path, watch_cb);
    g_free (path);
    return FALSE;
}

void
load_config ()
{
    GNode *root = NULL;
    FILE *data = NULL;
    char *line = NULL;
    size_t len = 0;
    size_t count = 0;

    data = fopen (config_file, "r");
    if (!data)
    {
        return;
    }
    root = g_node_new (strdup("/"));

    while ((count = getline (&line, &len, data)) != -1)
    {
        /* Remove trailing newline */
        line[count-1] = '\0';
        char *path = g_strdup (line);
        if (strncmp (path, "/", 1) != 0)
        {
            g_free (path);
            continue;
        }
        char *value = NULL;

        if (strchr (path, '\t'))
        {
            *strchr (path, '\t') = '\0';
            value = strchr (line, '\t') + 1;
        }
        _path_to_node (root, path, value);
        g_free (path);
    }
    apteryx_set_tree (root);

    fclose (data);
    data = NULL;
    apteryx_free_tree (root);
    g_free (line);
}

/* Glib unit test */
void
test_xml_to_nodes_basic ()
{
    FILE *data = NULL;
    char *test_str = NULL;

    saver_nodes = g_node_new (g_strdup("/"));
    /* Create XML */
    data = fopen ("saver_test.xml", "w");
    g_assert (data != NULL);

    fprintf (data, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                   "<MODULE xmlns=\"https://github.com/alliedtelesis/apteryx\"\n"
                   "  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
                   "  xsi:schemaLocation=\"https://github.com/alliedtelesis/apteryx\n"
                   "  https://github.com/alliedtelesis/apteryx/releases/download/v2.10/apteryx.xsd\">\n"
                   "  <NODE name=\"test\">\n"
                   "    <NODE name=\"set_node\" mode=\"c\"  help=\"Set this node for fun\">\n"
                   "    </NODE>\n"
                   "  </NODE>\n"
                   "</MODULE>\n");
    fclose (data);
    data = NULL;

    /* Trigger Action */
    sch_instance *test_schemas = sch_load ("./");
    process_node (test_schemas, NULL);

    const char *nodes[2] = {"test", "set_node"};
    int i = 0;
    for (GNode *node = g_node_first_child (saver_nodes); node;
         node = g_node_first_child (node))
    {
        g_assert (strcmp(nodes[i], (char *) node->data) == 0);
        i++;
    }

    sleep(1);
    /* Clean up */
    if (data)
    {
        fclose (data);
        unlink ("saver_test.xml");
        data = NULL;
    }
    if (test_str)
    {
        free (test_str);
    }
    sch_free (test_schemas);
    apteryx_free_tree (saver_nodes);
    saver_nodes = NULL;
}

/* Glib unit test */
void
test_xml_to_nodes_no_mode ()
{
    FILE *data = NULL;
    char *test_str = NULL;

    saver_nodes = g_node_new (g_strdup("/"));
    /* Create XML */
    data = fopen ("saver_test.xml", "w");
    g_assert (data != NULL);

    fprintf (data, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                   "<MODULE xmlns=\"https://github.com/alliedtelesis/apteryx\"\n"
                   "  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
                   "  xsi:schemaLocation=\"https://github.com/alliedtelesis/apteryx\n"
                   "  https://github.com/alliedtelesis/apteryx/releases/download/v2.10/apteryx.xsd\">\n"
                   "  <NODE name=\"test\">\n"
                   "    <NODE name=\"set_node\" mode=\"\"  help=\"Set this node for fun\">\n"
                   "    </NODE>\n"
                   "    <NODE name=\"set_node1\" mode=\"a\"  help=\"Set this node for fun\">\n"
                   "    </NODE>\n"
                   "    <NODE name=\"set_node2\" mode=\"c\"  help=\"Set this node for fun\">\n"
                   "    </NODE>\n"
                   "  </NODE>\n"
                   "</MODULE>\n");
    fclose (data);
    data = NULL;

    /* Trigger Action */
    sch_instance *test_schemas = sch_load ("./");
    process_node (test_schemas, NULL);

    const char *nodes[2] = {"test", "set_node2"};
    int i = 0;
    for (GNode *node = g_node_first_child (saver_nodes); node;
         node = g_node_first_child (node))
    {
        g_assert (strcmp(nodes[i], (char *) node->data) == 0);
        i++;
    }

    sleep(1);
    /* Clean up */
    if (data)
    {
        fclose (data);
        unlink ("saver_test.xml");
        data = NULL;
    }
    if (test_str)
    {
        free (test_str);
    }
    sch_free (test_schemas);
    apteryx_free_tree (saver_nodes);
    saver_nodes = NULL;
}

/* Glib unit test */
void
test_write_config ()
{
    GNode *iroot = NULL;
    FILE *data = NULL;
    char *line = NULL;
    size_t len = 0;
    size_t count = 0;
    int i = 0;

    config_nodes = g_node_new (g_strdup("/"));
    iroot = apteryx_path_to_node (config_nodes, "/test/junk/hello/5", NULL);
    APTERYX_LEAF (iroot, strdup ("prefix"), strdup ("10.0.0.0/8"));
    APTERYX_LEAF (iroot, strdup ("ifname"),strdup ( "eth0"));
    APTERYX_LEAF (iroot, strdup ("proto"), strdup ("static"));

    write_config (i);

    sleep (1);
    const char *paths[3] = {"/test/junk/hello/5/proto", "/test/junk/hello/5/ifname", "/test/junk/hello/5/prefix"};
    const char *values[3] = {"static", "eth0", "10.0.0.0/8"};
    data = fopen (config_file, "r");
    g_assert (data != NULL);

    while ((count = getline (&line, &len, data)) != -1)
    {
        /* Remove trailing whitespace */
        line[count-1] = '\0';
        char *path = g_strdup (line);
        g_assert (strncmp (path, "/", 1) == 0);
        char *value = NULL;
        if (strchr (path, '\t'))
        {
            *strchr (path, '\t') = '\0';
            value = strchr (line, '\t') + 1;
        }
        g_assert (strcmp (paths[i], path) == 0);
        g_assert (strcmp (values[i], value) == 0);
        g_free (path);
        i++;
    }
    fclose (data);
    data = NULL;
    g_free (line);

    apteryx_free_tree (config_nodes);
    config_nodes = NULL;
}

/* Glib unit test */
void
test_load_config ()
{
    FILE *data = NULL;
    char *val = NULL;

    apteryx_init (false);
    /* Create XML */
    data = fopen (config_file, "w");
    g_assert (data != NULL);

    fprintf (data, "/test/junk/hello/6/proto\tstatic\n"
                   "/test/junk/hello/6/ifname\teth1\n"
                   "/test/junk/hello/6/prefix\t11.0.0.0/8\n");
    fclose (data);
    data = NULL;

    load_config ();

    val = apteryx_get ("/test/junk/hello/6/proto");
    g_assert (val && strcmp (val, "static") == 0);
    g_free (val);
    val = apteryx_get ("/test/junk/hello/6/ifname");
    g_assert (val && strcmp (val, "eth1") == 0);
    g_free (val);
    val = apteryx_get ("/test/junk/hello/6/prefix");
    g_assert (val && strcmp (val, "11.0.0.0/8") == 0);
    g_free (val);

    apteryx_free_tree (config_nodes);
    config_nodes = NULL;
}

static gboolean
termination_handler (gpointer arg1)
{
    GMainLoop *loop = (GMainLoop *) arg1;
    g_main_loop_quit (loop);
    pthread_mutex_lock (&config_lock);
    pthread_mutex_lock (&writing_lock);
    if (automatic && writing)
    {
        _write_config ();
    }
    pthread_mutex_unlock (&writing_lock);
    pthread_mutex_unlock (&config_lock);
    return false;
}

void
help (char *app_name)
{
    printf ("Usage: %s [-h] [-b] [-d] [-p <pidfile>] [-s <schemadir>] [-c <configdir>] [-u <filter>] [-w <writedelay>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -p   use <pidfile> (defaults to " APTERYX_SAVE_PID ")\n"
            "  -s   use <schemadir> to search for schemas (defaults to " APTERYX_SCHEMA_DIR ")\n"
            "  -c   use <configdir> to search for config files (defaults to " APTERYX_CONFIG_DIR ")\n"
            "  -f   use <configfile> for saving configuration (defaults to " APTERYX_SAVE_CONFIG_FILE ")\n"
            "  -w   set write delay (defaults to 15 seconds)\n"
            "  -l   load in configuration at startup\n"
            "  -u   Run unit tests\n"
            , app_name);
}

int
main (int argc, char *argv[])
{
    GMainLoop *g_loop = NULL;
    const char *pid_file = APTERYX_SAVE_PID;
    char *old_root_name = NULL;
    FILE *fp = NULL;
    sch_instance *schemas = NULL;
    bool unit_test = false;
    bool background = false;
    bool load_startup_config = false;
    int w = 0;
    int i = 0;

    apteryx_init (false);

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:s:c:uaw:f:l")) != -1)
    {
        switch (i)
        {
        case 'd':
            apteryx_debug = true;
            background = false;
            setvbuf (stdout, NULL, _IONBF, 0);
            break;
        case 'b':
            background = true;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case 's':
            schema_dir = optarg;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'u':
            unit_test = true;
            break;
        case 'a':
            automatic = true;
            break;
        case 'w':
            w = strtol (optarg, NULL, 10);
            if ((w >= 1) && w < 61)
            {
                write_delay = w;
            }
            else
            {
                syslog (LOG_ERR, "Write dalay must be between 1 and 60 seconds.\n");
                return 0;
            }
            break;
        case 'f':
            config_file = optarg;
            break;
        case 'l':
          load_startup_config = true;
            break;
        case '?':
        case 'h':
        default:
            help (argv[0]);
            return 0;
        }
    }

    /* Daemonize */
    if (background && fork () != 0)
    {
        /* Parent */
        return 0;
    }

    if (unit_test)
    {
        pthread_t main_thread;
        pthread_attr_t attr;

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        g_test_init (&argc, &argv, NULL);
        g_test_add_func ("/test_xml_to_nodes_basic", test_xml_to_nodes_basic);
        g_test_add_func ("/test_xml_to_nodes_no_mode", test_xml_to_nodes_no_mode);
        g_test_add_func ("/test_write_config", test_write_config);
        g_test_add_func ("/test_load_config", test_load_config);

        g_loop = g_main_loop_new (NULL, true);
        g_unix_signal_add (SIGINT, termination_handler, g_loop);
        g_unix_signal_add (SIGTERM, termination_handler, g_loop);
        pthread_create (&main_thread, &attr, (void *) g_main_loop_run, g_loop);
        pthread_join (main_thread, NULL);
        g_test_run();
        pthread_cancel (main_thread);
        pthread_attr_destroy (&attr);
        goto exit;
    }

    /* Create pid file */
    if (background)
    {
        fp = fopen (pid_file, "w");
        if (!fp)
        {
            syslog (LOG_ERR, "Failed to create PID file %s\n", pid_file);
            goto exit;
        }
        fprintf (fp, "%d\n", getpid ());
        fclose (fp);
    }

    saver_nodes = g_node_new (g_strdup("/"));
    schemas = sch_load (schema_dir);
    process_node (schemas, NULL);
    parse_config_files (config_dir);
    if (load_startup_config)
    {
        load_config ();
    }
    config_nodes = apteryx_query (saver_nodes);
    if (!config_nodes)
    {
        config_nodes = g_node_new (g_strdup("/"));
    }
    if (automatic)
    {
        old_root_name = APTERYX_NAME (saver_nodes);
        saver_nodes->data = "";
        g_node_traverse (saver_nodes, G_PRE_ORDER, G_TRAVERSE_LEAVES, -1, node_watch, NULL);
        saver_nodes->data = old_root_name;
    }

    /* Now we have done the setup, we can start running and doing more stuff */
    g_loop = g_main_loop_new (NULL, false);
    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    g_unix_signal_add (SIGINT, termination_handler, g_loop);
    g_unix_signal_add (SIGTERM, termination_handler, g_loop);
    g_unix_signal_add (SIGUSR1, write_config_process, NULL);
    signal (SIGPIPE, SIG_IGN);
    g_main_loop_run (g_loop);

  exit:
    if (schemas)
    {
        sch_free (schemas);
    }
    apteryx_free_tree (config_nodes);
    apteryx_free_tree (saver_nodes);
    /* Free the glib main loop */
    if (g_loop)
    {
        g_main_loop_unref (g_loop);
    }

    apteryx_shutdown ();

    /* Remove the pid file */
    if (background)
    {
        unlink (pid_file);
    }
}
