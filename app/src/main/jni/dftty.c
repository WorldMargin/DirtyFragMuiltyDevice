#include "dftty.h"
#include "dflog.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef TIOCSCTTY
#define TIOCSCTTY 0x540E
#endif

/* Paths and shell. Guards let the unit test point them at a writable dir;
 * production uses the app's device-protected files dir. */
#ifndef DFTTY_CMD
#define DFTTY_CMD "/data/user_de/0/com.worldmargin.dfroot/files/dftty.cmd"
#endif
#ifndef DFTTY_OUT
#define DFTTY_OUT "/data/user_de/0/com.worldmargin.dfroot/files/dftty.out"
#endif
#ifndef DFTTY_SH
#define DFTTY_SH  "/system/bin/sh"
#endif
#ifndef DFTTY_HB
#define DFTTY_HB  "/data/user_de/0/com.worldmargin.dfroot/files/dftty.alive"
#endif

/* Bound the transcript so a chatty command cannot grow it forever. */
#define DFTTY_OUT_MAX 262144

void dftty_run(const char *cmd, long seq)
{
    dflog("dftty", "run seq=%ld cmd=%.160s", seq, cmd);

    struct stat st;
    if (stat(DFTTY_OUT, &st) == 0 && st.st_size > DFTTY_OUT_MAX) {
        int t = open(DFTTY_OUT, O_WRONLY | O_TRUNC);
        if (t >= 0) close(t);
    }

    int fd = open(DFTTY_OUT, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) { dflog("dftty", "run seq=%ld open %s failed", seq, DFTTY_OUT); return; }
    fchmod(fd, 0666);

    char hdr[48];
    int len = snprintf(hdr, sizeof(hdr), "<<<begin:%ld>>>\n", seq);
    if (len > 0) write(fd, hdr, (size_t)len);

    /* The command's stdout/stderr go straight to the transcript and the
     * direct child exiting (waitpid) is the completion signal. An earlier
     * version piped the output and looped on read() until EOF, but any
     * command that leaves a background process holding the write end - e.g.
     * "ksud late-load", which spawns the resident KSU daemon - never hits
     * EOF. That blocked the daemon forever: no "<<<done>>>" footer was
     * written and the serve loop stopped reading, so every later command of
     * the session produced no output at all. */
    int rc = -1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        char *argv[] = { "sh", "-c", (char *)cmd, NULL };
        execv(DFTTY_SH, argv);
        _exit(127);
    } else if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    char ftr[64];
    len = snprintf(ftr, sizeof(ftr), "\n<<<done:%ld>>> rc=%d\n", seq, rc);
    if (len > 0) write(fd, ftr, (size_t)len);
    close(fd);
    dflog("dftty", "run seq=%ld done rc=%d", seq, rc);
}

/* Fork a root interactive shell whose stdio is the given pty slave. The app
 * holds the master and renders it, so this is a real interactive terminal
 * (prompt, cd, job control, full-screen programs) running as root - the shell
 * is a child of this daemon, which the LKM launched with root creds and a
 * privileged SELinux context. Root cannot be "transferred" to the app's own
 * process (setuid(0) from untrusted_app fails), so exec'ing inside the daemon
 * tree is the only way to get a genuine root shell. */
void dftty_spawn_on_pts(const char *pts)
{
    if (pts == NULL || pts[0] == '\0') return;
    dflog("dftty", "spawn: interactive shell on %s", pts);

    pid_t pid = fork();
    if (pid != 0) return; /* daemon keeps looping; the loop reaps this child */

    setsid();

    int slave = open(pts, O_RDWR);
    if (slave < 0) _exit(1);
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, STDIN_FILENO);
    dup2(slave, STDOUT_FILENO);
    dup2(slave, STDERR_FILENO);
    if (slave > 2) close(slave);

    /* Drop every other fd inherited from the daemon (cmd/out files, etc.). */
    DIR *self = opendir("/proc/self/fd");
    if (self != NULL) {
        int self_fd = dirfd(self);
        struct dirent *e;
        while ((e = readdir(self)) != NULL) {
            int fd = atoi(e->d_name);
            if (fd > 2 && fd != self_fd) close(fd);
        }
        closedir(self);
    }

    /* The daemon is forked at the very start of bootstrap, before the zygote
     * env is adopted, so build a sane interactive environment explicitly. */
    setenv("TERM", "xterm-256color", 1);
    setenv("HOME", "/", 1);
    setenv("LANG", "en_US.UTF-8", 1);
    setenv("PATH",
           "/data/adb/ksu/bin:/data/adb/magisk:/debug_ramdisk:/sbin"
           ":/system/sbin:/system/bin:/system/xbin:/odm/bin:/vendor/bin"
           ":/product/bin:/data/local/tmp", 1);

    char *argv[] = { "sh", "-i", NULL };
    execv(DFTTY_SH, argv);
    _exit(127);
}

void dftty_serve_once(long *last_seq)
{
    int fd = open(DFTTY_CMD, O_RDONLY);
    if (fd < 0) return;
    char buf[8192];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    if (strncmp(buf, "<<<pty:", 7) == 0) {
        char *endp = NULL;
        long seq = strtol(buf + 7, &endp, 10);
        if (!endp || strncmp(endp, ">>> ", 4) != 0) return;
        if (seq == *last_seq) return;
        *last_seq = seq;
        char *pts = endp + 4;
        char *nl = strchr(pts, '\n');
        if (nl) *nl = '\0';
        dflog("dftty", "serve: pty seq=%ld pts=%s", seq, pts);
        dftty_spawn_on_pts(pts);
        return;
    }

    if (strncmp(buf, "<<<cmd:", 7) != 0) return;
    char *endp = NULL;
    long seq = strtol(buf + 7, &endp, 10);
    if (!endp || strncmp(endp, ">>>\n", 4) != 0) return;
    if (seq == *last_seq) return;
    *last_seq = seq;
    dflog("dftty", "serve: accepted seq=%ld", seq);
    if (endp[4] != '\0')
        dftty_run(endp + 4, seq);
}

/* The app's uid, read off its device-protected data dir. */
static int app_uid(void)
{
    struct stat st;
    if (stat("/data/user_de/0/com.worldmargin.dfroot", &st) != 0) return -1;
    return (int) st.st_uid;
}

/* True while any process runs under the app's uid. The daemon polls this so it
 * exits when the app is closed - no root context should outlive the app.
 * Conservative: if the uid can't be determined, report alive rather than risk
 * killing the daemon while the app is still running. */
static int app_alive(void)
{
    int uid = app_uid();
    if (uid < 0) return 1;

    DIR *d = opendir("/proc");
    if (!d) return 1;

    struct dirent *e;
    int alive = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%s/status", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                if (atoi(line + 4) == uid) alive = 1;
                break;
            }
        }
        fclose(f);
        if (alive) break;
    }
    closedir(d);
    return alive;
}

/* Refresh the heartbeat file the app stats to tell whether this daemon is still
 * alive. /dev/df survives daemon exit (it is just a tmpfs node), so the app
 * cannot rely on it alone. */
static void heartbeat(void)
{
    int fd = open(DFTTY_HB, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { fchmod(fd, 0666); write(fd, "1", 1); close(fd); }
}

static void dftty_loop(void)
{
    dflog("dftty", "daemon: session start pid=%d", (int)getpid());

    /* Fresh session: truncate both files so a reboot can never re-run the last
     * command the user typed, and the app starts from an empty transcript. */
    int fd = open(DFTTY_CMD, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { fchmod(fd, 0666); close(fd); }
    fd = open(DFTTY_OUT, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { fchmod(fd, 0666); close(fd); }

    heartbeat();
    long last_seq = -1;
    int ticks = 0;
    for (;;) {
        dftty_serve_once(&last_seq);

        /* Reap any pty shell that has exited (the app closed its master, so the
         * slave got SIGHUP) so we don't accumulate zombies. */
        while (waitpid(-1, NULL, WNOHANG) > 0) { }

        /* Exit once the app is gone, checked about once a second. */
        if (++ticks >= 7) {
            ticks = 0;
            heartbeat();
            if (!app_alive()) {
                dflog("dftty", "daemon: app gone, exiting");
                unlink(DFTTY_HB);
                break;
            }
        }
        usleep(150000);
    }
}

/* True if /proc/<pid>/comm equals name ("bootstrap" for our binary, since the
 * kernel launches the staged file at .../com.worldmargin.dfroot/bootstrap). */
static int comm_is(const char *pid, const char *name)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    char buf[64];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    for (int i = 0; i < n; i++) if (buf[i] == '\n') { buf[i] = '\0'; break; }
    return strcmp(buf, name) == 0;
}

/* Kill any console daemon left over from an earlier run. The daemon is
 * detached and loops forever, so it outlives app updates and even later
 * exploit runs; installing a new APK never kills it. Without this, a stale
 * daemon - in particular one built before the pipe/EOF fix, which would wedge
 * on the first command - keeps watching the same files and breaks the new
 * session (no output, send appears dead). Every daemon is a "bootstrap"
 * process, so we clear all of them except ourselves. */
static void kill_stale_daemons(void)
{
    pid_t self = getpid();
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *e;
    int killed = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid_t p = (pid_t)atoi(e->d_name);
        if (p <= 1 || p == self) continue;
        if (comm_is(e->d_name, "bootstrap")) { kill(p, SIGKILL); killed++; }
    }
    closedir(d);
    dflog("dftty", "killed %d stale daemon(s)", killed);
}

/* Detach the console daemon so bootstrap can still run ksud and return (which
 * lets the LKM's UMH_WAIT_PROC finish and unload the module) while the
 * console keeps running as root. */
void dftty_start(void)
{
    dflog("dftty", "start: bootstrap pid=%d, spawning console daemon", (int)getpid());
    kill_stale_daemons();

    pid_t pid = fork();
    if (pid != 0) return;

    setsid();
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > 2) close(devnull);
    }
    dftty_loop();
    _exit(0);
}
