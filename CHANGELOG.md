# Changelog

## 1.11

### Device support
- Launch-time support banner now folds in a kernel-module (KMI) check: it probes the page-cache
  primitive, and on a vulnerable device verifies that a bundled dfroot.ko matches the kernel KMI
  (parsed from `/proc/version`). The banner reports supported / missing KMI / unsupported
- `exp.c` picks the KO staging file dynamically: the known paths are tried first, then a scan of the
  vendor library directories

### Localisation
- English and Simplified Chinese, with an in-app language switcher (System default / English / 简体中文)

### Misc
- In-app links point at the WorldMargin/DirtyFragMuiltyDevice fork
- Root debug console
- GPL-3.0 LICENSE and a NOTICE crediting the upstream forks

## 1.10

Based on upstream DFRoot 3.3 (upstream 3.0 - 3.3 merged into this fork).

### Engine
- The exploit is no longer a JNI library: it runs as a staged executable and hands off to a
  bootstrap binary. The bootstrap reads the app's device-protected settings, adopts the zygote
  environment, sets partitions read-only, optionally disables all modules, and only then starts the
  SU daemon
- Runtime kallsyms resolution of `kern_path`, `invalidate_inode_pages2` and `path_put`, which fixes
  namespace violations on some Android 13 kernels
- `__nocfi` annotations on the kernel module - the upstream issue #68 class of crashes on kernels
  with control-flow integrity
- libc++ restore-ordering fix
- `ksud` is staged from the selected SU manager instead of being bundled with the app. The APK is
  2.9 MB instead of 6.5 MB

### DirtyFrag
- Pick your SU manager inside the app; Run stays disabled until one is selected
- KernelSU Modules and soft reboot now work without root
- Autorun keeps its Expert-mode gate and its failed-run interlock
- SU-manager launcher button: a circle while a run is in flight, opening into a "Manager" pill once
  root is verified
- Save the log to Downloads from the circle beside the run pill, available after any finished run
- Neutral grey press highlights throughout, and the Material purple tints are gone - including the
  purple flash for a moment on cold start
- The eight prebuilt kernel modules are committed so that a clone of this repository can build

## 1.08
- KernelSU Modules toggle
- Clearer status text and a refresh when returning to the app

## Earlier
See the release notes on the releases page.
