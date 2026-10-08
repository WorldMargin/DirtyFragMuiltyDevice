#include "dftty.h"
#include "dflog.h"

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
/* The manager's own ksud is used in place; its path (the manager app's
 * libksud.so) is resolved by the Java side and handed over through prefs. This
 * is only a fallback for when that pref is missing. */
#define KSUD_FALLBACK "/data/adb/ksud"
#define PREFS_PATH "/data/user_de/0/com.worldmargin.dfroot/shared_prefs/dfroot.xml"
#define MODULES_DIR "/data/adb/modules"

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

/* Extracts <string name="key">VALUE</string> from a decoded prefs XML blob.
 * Returns 0 on success, -1 when the key is absent. */
static int pref_str(const char *buf, const char *key, char *out, size_t out_size)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "name=\"%s\">", key);
    char *p = strstr(buf, needle);
    if (!p) return -1;
    p += strlen(needle);
    char *end = strchr(p, '<');
    if (!end) return -1;
    size_t len = end - p;
    if (len == 0 || len >= out_size) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

static int read_prefs(char *su_manager, size_t su_manager_size, char *ksud_path,
                      size_t ksud_path_size, int *soft_reboot, int *disable_modules)
{
    int fd = open(PREFS_PATH, O_RDONLY);
    if (fd < 0) return -1;

    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    if (pref_str(buf, "su_manager", su_manager, su_manager_size) != 0)
        return -1;
    if (pref_str(buf, "ksud_path", ksud_path, ksud_path_size) != 0)
        ksud_path[0] = '\0';

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
 * See dftty.c for the daemon that gives the in-app debug console a root shell
 * even when ksud failed, so a manual `ksud late-load` is possible.
 */

int main(void)
{
    dflog("boot", "bootstrap start pid=%d", (int)getpid());

    /* Start the root debug console first so it is available even if a later
     * step (including ksud late-load) fails - that is the whole point. */
    dftty_start();
    touch("/dev/dfmc");
    dflog("boot", "root console daemon requested");

    char su_manager[256];
    char ksud_path[512];
    int soft_reboot, disable_mods;
    if (read_prefs(su_manager, sizeof(su_manager), ksud_path, sizeof(ksud_path),
                   &soft_reboot, &disable_mods) != 0) {
        dflog("boot", "read prefs failed (%s)", PREFS_PATH);
        touch("/dev/dfme0");
        return 1;
    }
    touch("/dev/dfm1");
    dflog("boot", "prefs: su_manager=%s soft_reboot=%d disable_modules=%d",
          su_manager, soft_reboot, disable_mods);

    const char *ksud = ksud_path[0] ? ksud_path : KSUD_FALLBACK;
    dflog("boot", "ksud = %s", ksud);

    touch("/dev/dfm7");
    if (adopt_zygote_env() == 0) {
        touch("/dev/dfm2");
        dflog("boot", "adopted zygote env");
    } else {
        touch("/dev/dfmw0");
        dflog("boot", "WARNING: adopt zygote env failed");
    }

    touch("/dev/dfm8");
    if (set_partitions_ro() == 0) {
        touch("/dev/dfm3");
        dflog("boot", "partitions set ro");
    } else {
        touch("/dev/dfmw1");
        dflog("boot", "WARNING: set partitions ro failed");
    }

    if (disable_mods && disable_modules() != 0) {
        touch("/dev/dfmw2");
        dflog("boot", "WARNING: disable modules failed");
    }

    touch("/dev/dfm4");
    char **late_load;
    if (soft_reboot)
        late_load = (char *[]){ (char *)ksud, "late-load", "--package-name", su_manager, "--soft-reboot", NULL };
    else
        late_load = (char *[]){ (char *)ksud, "late-load", "--package-name", su_manager, NULL };
    dflog("boot", "running ksud late-load (soft_reboot=%d)", soft_reboot);
    int rc = run(late_load);
    if (rc == 0) {
        touch("/dev/dfm5");
        dflog("boot", "ksud late-load OK");
    } else {
        touch("/dev/dfme1");
        dflog("boot", "ksud late-load failed rc=%d", rc);
    }

    return 0;
}
