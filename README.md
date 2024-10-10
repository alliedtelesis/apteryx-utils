Utility applications to be used with the Apteryx Centralized configuration database.

## ALFRED
**A**pteryx **L**ightweight **F**eatu**re** **D**aemon

Generic daemon that implements Apteryx Watch, Provide and Index actions.

This allows apteryx_sets to a particular Apteryx XML node to be actioned and state/status information to be provided when apteryx_get is called

Definition of the feature API and implementation in a single XML file. Actions to be taken or responses to be given are defined as inline or imported lua scripts.

* Actions  are specified in the tree structure using the tags `<WATCH>`, `<PROVIDE>` and `<INDEX>`.
* Additional Lua functions are provided using the `<SCRIPT>` tag.
* Actions are implemented using Lua scripting.
* All XML files in /etc/apteryx/schema are parsed at daemon startup.

Use alfred -h for options:
```
# alfred -h
Usage: alfred [-h] [-b] [-d] [-p <pidfile>] [-c <configdir>] [-u <filter>]
  -h   show this help
  -b   background mode
  -d   enable verbose debug
  -m   memory profiling
  -p   use <pidfile> (defaults to /var/run/apteryx-alfred.pid)
  -c   use <configdir> (defaults to /etc/apteryx/schema/)
  -u   Run unit tests
```

Simple example:
```
<MODULE xmlns="https://github.com/alliedtelesis/apteryx" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://github.com/alliedtelesis/apteryx https://github.com/alliedtelesis/apteryx/releases/download/v3.50/apteryx.xsd">
    <SCRIPT>
        function system_get_meminfo(type)
            local f = io.popen("cat /proc/meminfo | grep "..type.." | awk '{print $2}'", 'r')
            local value = f:read()
            f:close()
            return value
        end
        function system_ram_total(ram)
            return system_get_meminfo('MemTotal')
        end
        function system_ram_free(ram)
            return system_get_meminfo('MemFree')
        end
    </SCRIPT>
    <NODE name="system">
        <NODE name="reboot" mode="w" help="Command to halt and perform a cold restart" pattern="^1$">
            <VALUE name="now" value="1" help="The device is told to halt and perform a cold restart"/>
            <WATCH>
                os.execute("/sbin/pre_shutdown")
                os.execute("fastboot \"Rebooting at user request\"")
            </WATCH>
        </NODE>
        <NODE name="ram" help="Ram memory information">
            <NODE name="total" mode="r" help="Total RAM (kB)">
                <PROVIDE>return system_ram_total()</PROVIDE>
            </NODE>
            <NODE name="free" mode="r" help="Total free RAM (kB)">
                <PROVIDE>return system_ram_free()</PROVIDE>
            </NODE>
        </NODE>
    </NODE>
</MODULE>
```

Depends on apteryx-xml

## Saver
Utility daemon to save Apteryx database contents to persistent storage. Uses Apteryx XML schema
files to determine which database entries should be saved. Only entries marked with mode 'c' (config)
are saved.

The entries stored in persistent storage can be loaded into the database when saver starts up, using
the -l option.

Use saver -h for options:
```
# saver -h
Usage: saver [-h] [-b] [-d] [-p <pidfile>] [-c <configdir>] [-u <filter>] [-w <writedelay>]
  -h   show this help
  -b   background mode
  -d   enable verbose debug
  -p   use <pidfile> (defaults to /var/run/saver.pid)
  -c   use <configdir> to search for schemas (defaults to /etc/apteryx/schema/)
  -f   use <configfile> for saving configuration (defaults to /etc/apteryx/saver.cfg)
  -w   set write delay (defaults to 15 seconds)
  -l   load in configuration at startup
  -u   Run unit tests
```

Depends on apteryx-xml

## Syncer
Syncs selected data from the local Apteryx database to other remote Apteryx databases

Use apteryx-sync -h for options:

```
# apteryx-sync -h
Usage: apteryx-sync [-h] [-b] [-d] [-p <pidfile>] [-c <configdir>]
  -h   show this help
  -b   background mode
  -d   enable verbose debug
  -p   use <pidfile> (defaults to /var/run/apteryx-sync.pid)
  -c   use <configdir> (defaults to /etc/apteryx/sync/)
```

To register a remote Apteryx to sync to, add it to Apteryx at /apteryx-sync/destinations
before or after starting apteryx-sync. e.g.

```
apteryx -s /apteryx-sync/destinations/remote-1 tcp://192.168.1.2:9999
```

In c, this can be done by including apteryx_sync.h and using the following apteryx call:
```
apteryx_set_string (APTERYX_SYNC_DESTINATIONS_PATH, dest_name, dest_url);
apteryx_set_string (APTERYX_SYNC_DESTINATIONS_PATH, "remote-1", "tcp://192.168.1.2:9999");
```

Paths to sync are stored in config files in a configurable directory (/etc/apteryx/sync/ by default).
All files in this directory are read in.

* To sync a particular path and all sub-paths, add the path on a new line with a trailing /*. e.g.
```
/path/to/sync/*
```
* Any path that will work with the CLI "apterxy -q path" can be used. e.g.
```
/path/to/sync/*/specific/information
```
* To exclude a particular node in a synced path, add it as a new line preceded by an '!'. e.g.
```
!/path/to/sync/excluded_node
```
* To exclude all paths that begin with a certain string, end the exclude path with a '*'. e.g.
```
!/path/to/sync/exclude_tree*
```
* Lines starting with a # are treated as comments
