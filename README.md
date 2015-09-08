Canaryfy
=============
by Thinkst Applied Research

Overview
--------
Canaryfy is an example Linux file read monitor. It watches individual files or files in directories, and triggers a [Canarytoken](http://canarytokens.org/) when a read occurs. It relies on the inotify(7) API for firing on file reads.

Building
------------
Run `make` which will compile to a `canaryfy` binary.

To get the version which searches for a low PID, uncomment the DEFINES line with `-DLOWPID` in the Makefile.


Installation
------------
Move the binary to an unexpected location (e.g. `/var/lib/mailmain/bin/bouncer`).

Execution
---------
```canaryfy <process_name> <dns_canarytoken> <path> [ <path> ,]```
where 
* `process_name` is what will appear in the `ps` listing. e.g. '[kswapd1]'
* `dns_canarytoken` is a new token from [Canarytoken](http://canarytokens.org).
* `path` is a full path to a file or directory

