#ifndef DFLOG_H
#define DFLOG_H

/* On-device diagnostic log shared by exp.c, bootstrap.c and dftty.c.
 *
 * Every line is appended (with a wall-clock timestamp and pid) to a single
 * file so a physical-device test can be read back with one command:
 *
 *   adb pull /sdcard/Android/data/com.worldmargin.dfroot/files/dfroot.log
 *
 * The public app dir is preferred because `adb pull` can read it without root.
 * If it cannot be opened - notably the root daemon launched by the LKM may be
 * blocked by SELinux from reaching /sdcard - we fall back to the app's
 * device-protected dir, which dftty.out already proves is writable there:
 *
 *   adb exec-out run-as com.worldmargin.dfroot cat files/dfroot.log   (debug build)
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DFLOG_PUBLIC  "/sdcard/Android/data/com.worldmargin.dfroot/files/dfroot.log"
#define DFLOG_PRIVATE "/data/user_de/0/com.worldmargin.dfroot/files/dfroot.log"

static FILE *dflog_open(void)
{
    static FILE *fp = NULL;
    static int tried = 0;
    if (tried) return fp;
    tried = 1;

    mkdir("/sdcard/Android/data/com.worldmargin.dfroot/files", 0771);
    mkdir("/data/user_de/0/com.worldmargin.dfroot/files", 0771);

    const char *paths[] = { DFLOG_PUBLIC, DFLOG_PRIVATE };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        fp = fopen(paths[i], "a");
        if (fp) {
            setvbuf(fp, NULL, _IOLBF, 0);
            break;
        }
    }
    return fp;
}

static void dflog(const char *tag, const char *fmt, ...)
{
    FILE *fp = dflog_open();
    if (!fp) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    flockfile(fp);
    fprintf(fp, "[%ld.%03ld] %d %s: ",
            (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000), getpid(), tag);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    fflush(fp);
    funlockfile(fp);
}

#endif /* DFLOG_H */
