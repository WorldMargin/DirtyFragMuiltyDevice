#ifndef DFTTY_H
#define DFTTY_H

/* Root debug console daemon.
 *
 * bootstrap runs as root because the LKM launches it via call_usermodehelper,
 * but it is the only root context this flow ever gets: once it hands off to
 * ksud and exits there is nothing left running as root. If the automatic
 * `ksud late-load` fails that leaves the user with no root and no way to
 * retry short of a full reroot.
 *
 * So bootstrap forks this detached daemon, which watches a command file the
 * app writes and runs each command through the shell, appending a transcript
 * the app reads back. That gives the in-app debug console a root shell even
 * when ksud failed, so a manual `ksud late-load` is possible.
 *
 * Wire format (sequence-tagged so a reply maps to its request):
 *   dftty.cmd : "<<<cmd:N>>>\n<command>\n"
 *   dftty.out : "<<<begin:N>>>\n<output>\n<<<done:N>>> rc=R\n"
 *
 * It also serves a second request type that gives the app a genuine interactive
 * root terminal: the app allocates a pty (JNI.createPty), hands us the slave
 * path, and we fork a shell onto it. The command's stdout/stderr then flow
 * through that pty instead of a transcript file:
 *   dftty.cmd : "<<<pty:N>>> /dev/pts/K\n"
 *
 * The daemon exits once the app process is gone, so no root context survives
 * closing the app.
 *
 * Kept in its own translation unit (rather than inline in bootstrap.c) so the
 * protocol can be unit-tested without a device - see tests/dftty_test.c.
 */

/* Fork the detached daemon, killing any stale one from an earlier run first. */
void dftty_start(void);

/* Run one command and append the begin/output/done record to the transcript. */
void dftty_run(const char *cmd, long seq);

/* Fork a root interactive shell onto the given pty slave (e.g. "/dev/pts/3").
 * The shell I/O is that pty, so the app holding the master renders it. */
void dftty_spawn_on_pts(const char *pts);

/* Poll the command file once; run a new command if one is present. */
void dftty_serve_once(long *last_seq);

#endif
