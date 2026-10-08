#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLKROSET   0x125d
#define KSUD       "/data/user_de/0/df.root/ksud"
#define PREFS_PATH "/data/user_de/0/df.root/shared_prefs/dfroot.xml"
#define MODULES_DIR "/data/adb/modules"
#define DFTTY_CMD  "/data/user_de/0/df.root/files/dftty.cmd"
#define DFTTY_OUT  "/data/user_de/0/df.root/files/dftty.out" 

static int pref_true(const char *buf, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "name=\"%s\"", key);
    char *p = strstr(buf, needle);
    if (!p) return 0;
    char *tag_end = strchr(p, '>');
    char *v = strstr(p, "value=\"true\"");
    return v && tag_end && v < tag_end;
}

static int read_prefs(char *su_manager, size_t su_manager_size, int *soft_reboot,
                      int *disable_modules)
{
    int fd = open(PREFS_PATH, O_RDONLY);
    if (fd < 0) return -1;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *p = strstr(buf, "name=\"su_manager\">");
    if (!p) return -1;
    p += strlen("name=\"su_manager\">");
    char *end = strchr(p, '<');
    if (!end) return -1;
    size_t len = end - p;
    if (len == 0 || len >= su_manager_size) return -1;
    memcpy(su_manager, p, len);
    su_manager[len] = '\0';

    *soft_reboot = pref_true(buf, "soft_reboot");
    *disable_modules = pref_true(buf, "disable_modules");

    return 0;
}

static int adopt_zygote_env(void)
{
    FILE *f = popen("pidof zygote64 zygote", "r");
    if (!f) return -1;
    int pid = 0;
    fscanf(f, "%d", &pid);
    pclose(f);
    if (!pid) return -1;

    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    static char buf[16384];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    for (char *p = buf, *end = buf + n; p < end; p += strlen(p) + 1)
        putenv(p);
    return 0;
}

static int should_ro(const char *name)
{
    size_t len = strlen(name);
    if (!strcmp(name, "super"))  return 1;
    if (!strcmp(name, "misc"))   return 1;
    if (!strcmp(name, "steady")) return 1;
    if (len >= 2 && name[len - 2] == '_' &&
        (name[len - 1] == 'a' || name[len - 1] == 'b'))
        return 1;
    return 0;
}

static int set_partitions_ro(void)
{
    DIR *dir = opendir("/dev/block/by-name");
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!should_ro(ent->d_name))
            continue;

        char path[128];
        snprintf(path, sizeof(path), "/dev/block/by-name/%s", ent->d_name);

        int fd = open(path, O_RDONLY);
        if (fd < 0)
            continue;

        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)) {
            int on = 1;
            ioctl(fd, BLKROSET, &on);
        }
        close(fd);
    }

    closedir(dir);
    return 0;
}

static int run(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void touch(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY, 0666);
    if (fd >= 0)
        close(fd);
}

/* Mark every installed module disabled before ksud runs. A broken module
 * otherwise loads on the next boot and bootloops the device. */
static int disable_modules(void)
{
    DIR *dir = opendir(MODULES_DIR);
    if (!dir)
        return -1;

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.')
            continue;
        char path[256];
        snprintf(path, sizeof(path), MODULES_DIR "/%s/disable", ent->d_name);
        touch(path);
    }
    closedir(dir);
    return 0;
}

/* ── root debug console ───────────────────────────────────────────────────
 * bootstrap runs as root because the LKM launches it via call_usermodehelper,
 * but it is the only root context this flow ever gets: once it hands off to
 * ksud and exits there is nothing left running as root. If the automatic
 * `ksud late-load` fails that leaves the user with no root and no way to
 * retry short of a full reroot.
 *
 * Fork a detached root daemon that watches a command file the app writes and
 * runs each command through /system/bin/sh, appending the transcript to a
 * result file the app reads back. That gives the in-app debug console a root
 * shell even when ksud failed, so a manual `ksud late-load` is possible.
 *
 * Wire format (sequence-tagged so a reply maps to its request):
 *   dftty.cmd : "<<<cmd:N>>>\n<command>\n"
 *   dftty.out : "<<<begin:N>>>\n<output>\n<<<done:N>>> rc=R\n"
 */
static void dftty_exec_to_fd(const char *cmd, int out_fd, int *rc)
{
    int pfd[2];
    if (pipe(pfd) < 0) { *rc = -1; return; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        *rc = -1;
        return;
    }
    if (pid == 0) {
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        char *argv[] = { "sh", "-c", (char *)cmd, NULL };
        execv("/system/bin/sh", argv);
        _exit(127);
    }
    close(pfd[1]);

    char buf[1024];
    ssize_t n;
    while ((n = read(pfd[0], buf, sizeof(buf))) > 0)
        write(out_fd, buf, (size_t)n);
    close(pfd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    *rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void dftty_run(const char *cmd, long seq)
{
    /* Bound the transcript so a chatty command cannot grow it forever. */
    struct stat st;
    if (stat(DFTTY_OUT, &st) == 0 && st.st_size > 262144) {
        int t = open(DFTTY_OUT, O_WRONLY | O_TRUNC);
        if (t >= 0) close(t);
    }

    int fd = open(DFTTY_OUT, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0) return;
    fchmod(fd, 0666);

    char hdr[48];
    int len = snprintf(hdr, sizeof(hdr), "<<<begin:%ld>>>\n", seq);
    if (len > 0) write(fd, hdr, (size_t)len);

    int rc;
    dftty_exec_to_fd(cmd, fd, &rc);

    char ftr[64];
    len = snprintf(ftr, sizeof(ftr), "\n<<<done:%ld>>> rc=%d\n", seq, rc);
    if (len > 0) write(fd, ftr, (size_t)len);
    close(fd);
}

static void dftty_serve_once(long *last_seq)
{
    int fd = open(DFTTY_CMD, O_RDONLY);
    if (fd < 0) return;
    char buf[8192];
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    if (strncmp(buf, "<<<cmd:", 7) != 0) return;
    char *endp = NULL;
    long seq = strtol(buf + 7, &endp, 10);
    if (!endp || strncmp(endp, ">>>\n", 4) != 0) return;
    if (seq == *last_seq) return;
    *last_seq = seq;
    if (endp[4] != '\0')
        dftty_run(endp + 4, seq);
}

static void dftty_loop(void)
{
    /* Fresh session: truncate both files so a reboot can never re-run the last
     * command the user typed, and the app starts from an empty transcript. */
    int fd = open(DFTTY_CMD, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { fchmod(fd, 0666); close(fd); }
    fd = open(DFTTY_OUT, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) { fchmod(fd, 0666); close(fd); }

    long last_seq = -1;
    for (;;) {
        dftty_serve_once(&last_seq);
        usleep(150000);
    }
}

/* Detach the console daemon so bootstrap can still run ksud and return (which
 * lets the LKM's UMH_WAIT_PROC finish and unload the module) while the
 * console keeps running as root. */
static void dftty_start(void)
{
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

int main(void)
{
    /* Start the root debug console first so it is available even if a later
     * step (including ksud late-load) fails - that is the whole point. */
    dftty_start();

    char su_manager[256];
    int soft_reboot, disable_mods;
    if (read_prefs(su_manager, sizeof(su_manager), &soft_reboot, &disable_mods) != 0) {
        touch("/dev/dfme0");
        return 1;
    }
    touch("/dev/dfm1");

    touch("/dev/dfm7");
    if (adopt_zygote_env() == 0)
        touch("/dev/dfm2");
    else
        touch("/dev/dfmw0");

    touch("/dev/dfm8");
    if (set_partitions_ro() == 0)
        touch("/dev/dfm3");
    else
        touch("/dev/dfmw1");

    if (disable_mods && disable_modules() != 0)
        touch("/dev/dfmw2");

    touch("/dev/dfm4");
    char **late_load;
    if (soft_reboot)
        late_load = (char *[]){ KSUD, "late-load", "--package-name", su_manager, "--soft-reboot", NULL };
    else
        late_load = (char *[]){ KSUD, "late-load", "--package-name", su_manager, NULL };
    if (run(late_load) == 0)
        touch("/dev/dfm5");
    else
        touch("/dev/dfme1");

    return 0;
}
