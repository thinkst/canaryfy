/* Canaryfy inotifier

   Thinksts Applied Research


   SOooooooo hacky. GNU libc specific. Could blow up.

   Compile with:
   gcc  -o canaryfy canaryfy.c base32.c -lm -g

   Run with:

   ./canaryfy <new_psname> <dns_canarytoken> <path1> <path2> ... <pathN>

    <pathX> -- either a file or a directory. If a directory, it triggers on any file read in that dir (but not subdirs).

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <math.h>
#include <netdb.h>
#include <assert.h>
#include <time.h>

#include "base32.h"

#define MAX_DNS_LEN 254
#define MAX_LABEL_LEN 62
#define PORT "80"

#define BASE32_SIZE(x) ((int)(ceil(ceil(8.0 * (x) / 5) / 8) * 8))
#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

#ifdef DEBUG
#define dprintf(...) printf (__VA_ARGS__)
#else
#define dprintf(...) {}
#endif

char *files[256];

static void request_hostname(char *hostname) {
    struct addrinfo hints, *resp;
    memset(&hints, 0, sizeof(hints));
    int r = getaddrinfo(hostname, PORT, &hints, &resp);
    if (r != 0) 
        dprintf("%s\n", gai_strerror(r));
        
    dprintf("Lookup done\n");
}

static void build_base32_hostname(char *buf, size_t buf_size, char *file_name) {
    unsigned int plain_size, label_count;
    char *local_buf = malloc(buf_size); char *tmp = local_buf;

    assert(local_buf);

    dprintf("Buf_size = %d\n", (int) buf_size);

    //buffer can take buf_size hostname. how much filename fits in there after base32 conversion?
    plain_size = ceil( ((double)buf_size - 1) / 8) * 5 ;
    dprintf("base32 should take %d bytes\n", plain_size);

    //include space for DNS label separators '.'
    plain_size -= plain_size / MAX_LABEL_LEN; 
    dprintf("Number of dots: %d\n", plain_size / MAX_LABEL_LEN);

    //shrink the filename until it fits into the free space
    while (strlen(file_name) > plain_size)
        file_name++;

    base32_encode(local_buf, &buf_size, file_name, strlen(file_name));
    dprintf("Expected %d bytes from base32 and dot insertion. Filename length is %d back\n", plain_size, (int) strlen(file_name));

    label_count = 0;
    while (tmp < local_buf + strlen(local_buf) && buf < buf+buf_size){
        *buf = *tmp;
        if (++label_count > MAX_LABEL_LEN) {
           buf++;
           *buf = '.';
           label_count = 0;
        }
        buf++;
        tmp++;
    }

    free(local_buf);
}

static void process_event(struct inotify_event *i, char *token, unsigned int token_size)
{
    char *fn, *fn_shrink;
    unsigned int size;
    size_t free_space = MAX_DNS_LEN - (token_size + 1 + 3 + 1); // + 1 + 3 + 1 is for the '.L??.' in front
    char hostname[MAX_DNS_LEN+1];
    memset(hostname, 0, sizeof(hostname));

    srand(time(NULL));

    if (i->len > 0) {
        dprintf("file read on dir = %s/%s\n", files[i->wd-1], i->name);

        size = asprintf(&fn, "%s/%s", files[i->wd-1], i->name);
        if (size == -1)
             return;
    } else {
        dprintf("file read = %s\n", files[i->wd-1]);
        size = asprintf(&fn, "%s", files[i->wd-1]);
        if (size == -1)
             return;
    }
    
    dprintf("Free space is %d\n", (unsigned int) free_space);

    dprintf("filename is %s\n", fn);

    build_base32_hostname(hostname, free_space, fn);

    dprintf("base32 filename: %s (%d bytes)\n", hostname, (unsigned int) strlen(hostname));

    snprintf(hostname+strlen(hostname), sizeof(hostname)-(strlen(hostname)+1),".L%02.f.%s", ((float)rand())/RAND_MAX*99, token);
    dprintf("Requesting: %s (%d bytes)\n", hostname, (unsigned int) strlen(hostname));

    request_hostname(hostname);

    free(fn);
}


int main(int argc, char *argv[])
{
    int inotify_fd, path, res, i;
    char buf[BUF_LEN] __attribute__ ((aligned(8)));
    ssize_t read_count;
    char *p, ps_name[256], token[256];
    struct inotify_event *event;
    pid_t parent;

    if (argc < 4 || argc > 258) {
        dprintf("simple_inotify name token path [ path, ... ] \n");
        exit(1);
    }

    strncpy(ps_name, argv[1], sizeof(ps_name) - 1);
    strncpy(token,   argv[2], sizeof(token) - 1);


    inotify_fd = inotify_init();
    if (inotify_fd == -1){
        dprintf("inotify_init\n");
        exit(2);
    }

    for (path = 3; path < argc; path++) {
        int name_length = strlen(argv[path])+1;
        res = inotify_add_watch(inotify_fd, argv[path], IN_ACCESS);
        files[path-3] = malloc(name_length);
        strncpy(files[path-3], argv[path], name_length);
        memset(argv[path], '\0', name_length);
        if (res == -1) {
            dprintf("inotify_add_watch\n");
        exit(3);
        }
    }

    //clear out ps listing info
    for (i = 2; i >= 0; i--) 
        memset(argv[i], '\0', strlen(argv[i])+1);
    //wut!?!?
    strcpy(argv[0], ps_name);

#ifndef DEBUG
    //daemonize and search for the lowest open PID
    parent = getpid();
    while (1) {
        if (fork())
           exit(5);
    setsid();

#ifdef LOWPID
    if (getpid() < parent)
#endif
    break;
    }
#endif

    //launch inotify watches 
    while (1){
        read_count = read(inotify_fd, buf, BUF_LEN);
        if (read_count == 0) {
            dprintf("read() from inotify fd returned 0!\n");
            exit(4);
        }

        if (read_count == -1) {
            dprintf("read()\n");
            exit(4);
        }

        for (p = buf; p < buf + read_count; ) {
            event = (struct inotify_event *) p;
            process_event(event, token, strlen(token));
            p += sizeof(struct inotify_event) + event->len;
        }
    }

    exit(0);
}
