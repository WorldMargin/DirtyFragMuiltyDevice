/* Unit test for the dftty console-daemon protocol (dftty.c).
 *
 * The bug this pins down: a command that leaves a background process holding
 * the transcript's write end ("ksud late-load" spawns the resident KSU
 * daemon) used to block the daemon forever, so no "<<<done>>>" was written
 * and every later command of the session produced no output at all.
 *
 * Runs on Android (any device or emulator, no root needed): the daemon is
 * plain fork/exec/pipe code, and bionic is the same libc the real device
 * uses. Build + run with tests/run_dftty_test.ps1.
 */
#define DFTTY_CMD "/data/local/tmp/dftty_test.cmd"
#define DFTTY_OUT "/data/local/tmp/dftty_test.out"

#include "../dftty.c"

#include <time.h>

static int failures;
static int checks;

static void check(const char *name, int ok)
{
    checks++;
    if (!ok) failures++;
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
}

static void truncate_out(void)
{
    int fd = open(DFTTY_OUT, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) close(fd);
}

static const char *read_out(void)
{
    static char buf[65536];
    int fd = open(DFTTY_OUT, O_RDONLY);
    if (fd < 0) { buf[0] = '\0'; return buf; }
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) n = 0;
    buf[n] = '\0';
    return buf;
}

static int contains(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

static int count_of(const char *hay, const char *needle)
{
    int c = 0;
    size_t l = strlen(needle);
    for (const char *p = hay; (p = strstr(p, needle)); p += l) c++;
    return c;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* A plain command produces begin, body and a rc=0 footer. */
static void t_echo(void)
{
    truncate_out();
    dftty_run("echo hello", 11);
    const char *o = read_out();
    check("echo: begin marker", contains(o, "<<<begin:11>>>"));
    check("echo: body captured", contains(o, "hello"));
    check("echo: done rc=0", contains(o, "<<<done:11>>> rc=0"));
}

/* THE regression: a command whose child keeps the pipe write end open must
 * still complete promptly (the fix waits on the direct child, not on EOF). */
static void t_background(void)
{
    truncate_out();
    double t0 = now_ms();
    dftty_run("sleep 30 & echo ok", 12);
    double dt = now_ms() - t0;
    const char *o = read_out();
    printf("     background case took %.0f ms (was ~30000 ms before the fix)\n", dt);
    check("background: returns promptly (<8000 ms)", dt < 8000.0);
    check("background: body captured", contains(o, "ok"));
    check("background: done rc=0", contains(o, "<<<done:12>>> rc=0"));
}

/* stderr is folded into the transcript. */
static void t_stderr(void)
{
    truncate_out();
    dftty_run("echo to_err 1>&2", 13);
    check("stderr: captured", contains(read_out(), "to_err"));
}

/* A non-zero exit is reported in the footer. */
static void t_exitcode(void)
{
    truncate_out();
    dftty_run("exit 7", 14);
    check("exitcode: rc=7", contains(read_out(), "<<<done:14>>> rc=7"));
}

/* serve_once parses the wire header, runs the command and records the seq. */
static void t_serve(void)
{
    truncate_out();
    int fd = open(DFTTY_CMD, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    const char *wire = "<<<cmd:22>>>\necho served\n";
    if (fd >= 0) { write(fd, wire, strlen(wire)); close(fd); }
    long last = -1;
    dftty_serve_once(&last);
    const char *o = read_out();
    check("serve: seq remembered", last == 22);
    check("serve: command ran", contains(o, "served"));
    check("serve: done footer", contains(o, "<<<done:22>>> rc=0"));
}

/* The same seq must not run twice (the app rewrites the file with a fresh
 * seq per command; a duplicate seq is a re-read, not a re-run). */
static void t_serve_dedup(void)
{
    truncate_out();
    int fd = open(DFTTY_CMD, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    const char *wire = "<<<cmd:33>>>\necho once\n";
    if (fd >= 0) { write(fd, wire, strlen(wire)); close(fd); }
    long last = -1;
    dftty_serve_once(&last);
    dftty_serve_once(&last);
    check("dedup: ran exactly once", count_of(read_out(), "<<<begin:33>>>") == 1);
}

/* Two commands back to back - the actual user-visible symptom was that the
 * second one produced nothing. */
static void t_sequential(void)
{
    truncate_out();
    dftty_run("echo first", 41);
    dftty_run("echo second", 42);
    const char *o = read_out();
    check("sequential: first present", contains(o, "first"));
    check("sequential: second present", contains(o, "second"));
    check("sequential: both footers",
          contains(o, "<<<done:41>>>") && contains(o, "<<<done:42>>>"));
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("dftty protocol tests (cmd=%s out=%s)\n\n", DFTTY_CMD, DFTTY_OUT);
    t_echo();
    t_background();
    t_stderr();
    t_exitcode();
    t_serve();
    t_serve_dedup();
    t_sequential();

    printf("\n%d checks, %d failed -> %s\n",
           checks, failures, failures ? "FAIL" : "OK");
    return failures ? 1 : 0;
}
