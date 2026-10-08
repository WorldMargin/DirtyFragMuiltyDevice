#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);

/* Force an exec-time security/DEFEX decision function to return ALLOW (0)
 * without running its body.
 *
 * Every target is "int f(...)" whose 0 means allow and which is entered with a
 * plain `bl`, so setting x0 = 0 and jumping back to the link register makes the
 * caller observe "allowed". */
static int allow_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    regs->regs[0] = 0;         /* x0 = 0 == allow */
    regs->pc = regs->regs[30]; /* return to caller, skip the body */
    return 1;
}

/* Every entry point that can carry a denial for executing an untrusted file:
 * Samsung DEFEX's own core/exec hooks on the devices that have them, plus the
 * generic LSM dispatchers that carry DEFEX (and any OEM equivalent) when the
 * core symbols are inlined or renamed. Hooking by name and tolerating failures
 * is the point - the previous code gave up silently when the one name it wanted
 * (task_defex_user_exec) was absent, which is the common case off Samsung. */
static const char *hook_names[] = {
    "task_defex_enforce",              /* DEFEX core dispatcher                  */
    "task_defex_user_exec",            /* DEFEX exec hook                        */
    "security_inode_permission",       /* MAY_EXEC denial at open_exec           */
    "security_bprm_check",             /* LSM exec check (all LSMs)              */
    "security_bprm_creds_for_exec",    /* LSM creds hook                         */
    "security_bprm_committing_creds",  /* LSM creds hook                         */
    "security_mmap_file",              /* PROT_EXEC mmap of the staged ELF       */
};
#define NHOOKS (sizeof(hook_names) / sizeof(hook_names[0]))

/* The log the app already reads back, so a captured bootstrap failure shows up
 * in the in-app diagnostic log with no adb/dmesg needed. */
#define DF_LOG "/data/user_de/0/com.worldmargin.dfroot/files/dfroot.log"

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    void *selinux_state;
    struct kprobe kln_kp;
    static struct kprobe hooks[NHOOKS];
    int hooked[NHOOKS];
    char marks[192];
    size_t mo;
    void *info;
    int ret, sl_cleared;
    size_t i;

    static const char sh[]        = "/system/bin/sh";
    static const char bootstrap[] = "/data/user_de/0/com.worldmargin.dfroot/bootstrap";
    static char cmd[512];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };

    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    /* selinux_state starts with a run of bools. Whether `enforcing` is the
     * first byte depends on CONFIG_SECURITY_SELINUX_DISABLE (which prepends a
     * `disabled` field); the old code always wrote byte 0 and so silently did
     * nothing - leaving SELinux enforcing - on kernels built with that option.
     * `disabled` is always 0, so the first byte that is set is `enforcing`. */
    selinux_state = (void *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    sl_cleared = 0;
    for (i = 0; i < 8; i++) {
        u8 *st = (u8 *)selinux_state + i;
        if (READ_ONCE(*st) == 1) {
            WRITE_ONCE(*st, 0);
            sl_cleared = 1;
            break;
        }
    }
    pr_info("dfroot: selinux_state permissive (cleared=%d)\n", sl_cleared);

    /* Clear the exec-time barriers. Best-effort per name: which of these exist
     * varies between kernels, and every one that lands is reported through a
     * /dev/dfh<i> marker so a failed run stays diagnosable without dmesg. */
    mo = 0;
    marks[0] = '\0';
    if (sl_cleared)
        mo += (size_t)snprintf(marks + mo, sizeof(marks) - mo, "touch /dev/dfms; ");

    for (i = 0; i < NHOOKS; i++) {
        struct kprobe *kp = &hooks[i];

        hooked[i] = 0;
        memset(kp, 0, sizeof(*kp));
        kp->symbol_name = hook_names[i];
        kp->pre_handler = allow_pre_handler;
        if (register_kprobe(kp) == 0) {
            hooked[i] = 1;
            pr_info("dfroot: hooked %s\n", hook_names[i]);
            if (mo < sizeof(marks))
                mo += (size_t)snprintf(marks + mo, sizeof(marks) - mo,
                                       "touch /dev/dfh%d; ", (int)i);
        } else {
            pr_warn("dfroot: %s unavailable\n", hook_names[i]);
        }
    }

    /* Run bootstrap as a child (not `exec`) so the shell survives an exec
     * denial, and tee its stdout/stderr plus exit status into the app-visible
     * log. This turns a silent hang into a captured reason: if the kernel (or
     * SELinux / an OEM LSM) refuses the exec, the log gets sh's "Permission
     * denied"; if the loader or bootstrap itself fails, the log gets that. */
    snprintf(cmd, sizeof(cmd),
             "touch /dev/dfm0; %s"
             "{ %s >> %s 2>&1; rc=$?; echo df-bootstrap-exit=$rc >> %s; "
             "if [ $rc -eq 0 ]; then touch /dev/dfmrok; else touch /dev/dfmre; fi; }",
             marks, bootstrap, DF_LOG, DF_LOG);

    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        goto done;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        goto done;
    }
    /* bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to "" */
    ((struct subprocess_info *)info)->path = sh;

    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("dfroot: usermodehelper_exec(%s) returned %d\n", bootstrap, ret);

done:
    for (i = 0; i < NHOOKS; i++)
        if (hooked[i]) unregister_kprobe(&hooks[i]);
    return -E2BIG; /* return any error to unload module */
}

/* no module_exit: we never unload; saves .exit sections */
module_init(dfroot_init);
