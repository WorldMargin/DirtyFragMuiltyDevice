package com.worldmargin.dfroot;

import android.content.Context;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.text.SpannableString;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.util.Log;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.content.res.ResourcesCompat;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.os.LocaleListCompat;

import com.worldmargin.dfroot.databinding.ActivityMainBinding;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity implements IReporter {

    private static final String TAG = "dfroot";

    /** Home of this project (the WorldMargin fork). The original upstream fork,
     *  mitschud/DirtyFrag, is credited in the README. */
    private static final String REPO_NEW =
            "https://github.com/WorldMargin/DirtyFragMuiltyDevice";
    /** GitHub API slug used for the release check. */
    private static final String API_REPO = "WorldMargin/DirtyFragMuiltyDevice";

    /** Kernel-module matrix bundled in the APK, one row per dfroot-<kmi>.ko:
     *  {androidRelease, kverMajor, kverMinor}. Mirrors exp.c select_ko_image()
     *  and jni/ko/*.ko; P3.1 will data-ise this into a build-time manifest, so
     *  keep both in sync until then. */
    private static final int[][] BUNDLED_KO_KMIS = {
            {12, 5, 10}, {13, 5, 10}, {13, 5, 15}, {14, 5, 15},
            {14, 6, 1},  {15, 6, 6},  {16, 6, 12}, {17, 6, 18},
    };

    private ActivityMainBinding binding;
    private final Handler mMain = new Handler(Looper.getMainLooper());
    private final Executor mExec = Executors.newSingleThreadExecutor();
    private final StringBuilder logBuffer = new StringBuilder();
    private File lastLogFile;
    private boolean running;
    private boolean runArmed;
    private boolean advancedLog;
    private boolean expertMode;
    private String exploitPhase = "";
    private int cleanupSteps;
    private float seg1;
    private float pillPercent = 0.48f;
    /** SU-manager launcher geometry: a 54dp circle with a 12dp gap to the Run
     *  pill while a run is in flight; once root is verified the circle morphs
     *  into a pill as wide as the shrunken Run pill (setCompactButton +
     *  morphKsuToPill). Matches the share circle's 54dp on the left. */
    private static final float KSU_CIRCLE_DP = 54f;
    private static final float KSU_GAP_DP = 12f;
    private android.animation.ValueAnimator ksuMorph;
    private VersionPillSpan pillSpan;
    private TextView titleView;
    private boolean updateAvailable;
    private boolean moduleRefresh;

    /** SAF "Save as" launcher for the log export; text is staged in
     *  pendingExportText, written once the user picks a destination. */
    private androidx.activity.result.ActivityResultLauncher<String> exportLauncher;
    private String pendingExportText;

    /** The embedded terminal's view, so the session client can ask it to redraw
     *  when new output arrives (TerminalView only repaints on invalidate()). */
    private com.termux.view.TerminalView mTermView;

    /** Terminal session client (clipboard + logs) shared by the embedded
     *  terminal's pty sessions. */
    private final TermClient mTermClient = new TermClient();

    /** Terminal font size in dp. On a phone the Termux default (14) renders too
     *  small, so start much larger; pinch-to-zoom adjusts it at runtime. */
    private int mTermTextSize = 44;

    /** Device-protected storage context: bootstrap.c reads its prefs from
     *  /data/user_de/0/com.worldmargin.dfroot/, so every pref the exploit depends on must live
     *  there, not in credential-protected storage. */
    private Context mDeCtx;
    /** Package name of the SU manager whose ksud (libksud.so) is used, or null. */
    private String suManagerPkg;
    private CharSequence suManagerLabel;
    /** A failed run locks the Run button until reboot (page-cache patch). */
    private boolean failedRun;
    /** Raw "***FAILED***: ..." text from the exploit, used for the failure log. */
    private String lastFailReason;

    @Override
    public void report(String msg) {
        Log.i(TAG, msg.trim());
        DiagLog.d("native", msg.trim());
        mMain.post(() -> {
            // Drive the two-step progress bar from the raw (unfiltered) lines.
            for (String line : msg.split("\n", -1)) {
                driveProgress(line.trim());
            }
            for (String line : msg.split("\n", -1)) {
                String t = line.trim();
                // Skip empty lines to keep the log compact.
                if (t.isEmpty()) {
                    continue;
                }
                // Drop byte-progress counters ("0 ?", "512 ?", ...).
                if (t.matches("\\d+\\s*(\\u2026|\\.{3})?")) {
                    continue;
                }
                // Drop internal patch/hook details and raw result markers: the
                // app renders its own SETUP/EXPLOIT/INIT/CLEANUP headers and
                // synthesizes a single failure line instead of the raw one.
                if (t.contains("hook=") || t.matches("\\*+SUCCESS\\*+")
                        || t.startsWith("***FAILED***")) {
                    continue;
                }
                // Strip hex file offsets: ".../libc.so+0x6e8b0" -> ".../libc.so"
                t = t.replaceAll("\\+0x[0-9a-fA-F]+$", "");
                t = stripHeader(t);
                appendLog(t);
            }
            binding.outputScroll.post(() -> binding.outputScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void appendLog(String line) {
        binding.outputView.append(styleLogLine(line));
        binding.outputView.append("\n");
        logBuffer.append(line).append('\n');
        saveLog();
    }

    /** Translates raw native log lines into two-step progress-bar states.
     *  Seg 1 tracks the file patching, seg 2 the init phase: since upstream 3.2
     *  the LKM hands off to "bootstrap", which reports progress by touching
     *  /dev/dfm* nodes that exp.c polls for 70 seconds and prints. */
    private void driveProgress(String t) {
        if (t.isEmpty()) return;
        if (t.startsWith("***FAILED***")) {
            lastFailReason = t.substring("***FAILED***:".length()).trim();
        }
        switch (t) {
            case "=== setup ===":
                exploitPhase = "setup";
                setSeg1(0.05f);
                break;
            case "=== exploit (patching files) ===":
                exploitPhase = "exploit";
                setSeg1(0.15f);
                break;
            case "=== init  ===":
                exploitPhase = "init";
                setSeg2(0.05f, getString(R.string.verification), 0xFFFFFFFF);
                break;
            case "=== cleanup ===":
                exploitPhase = "cleanup";
                cleanupSteps = 0;
                break;
            default:
                break;
        }
        if (exploitPhase.equals("setup") && t.startsWith("found ko_target:")) {
            setSeg1(0.10f);
        }
        if (exploitPhase.equals("exploit")) {
            if (t.startsWith("patch: crash_dump64")) {
                setSeg1(0.30f);
            } else if (t.contains("<- dfroot.ko")) {
                setSeg1(0.50f);
            } else if (t.startsWith("Finding symbol offsets")) {
                setSeg1(0.60f);
            } else if (t.contains("<- shellcode")) {
                setSeg1(0.75f);
            } else if (t.contains("<- trampoline")) {
                setSeg1(0.90f);
            } else if (t.startsWith("Triggering hook")) {
                setSeg1(0.95f);
            }
        }
        // Init phase: one step per bootstrap marker (see exp.c markers[]).
        if (t.startsWith("libc++: mutex acquired")) {
            setSeg1(1f);
            setSeg2(0.12f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("dfroot: launching bootstrap")) {
            setSeg2(0.24f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: prefs loaded")) {
            setSeg2(0.36f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: adopting zygote env")) {
            setSeg2(0.48f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: env adopted")
                || t.startsWith("bootstrap: WARNING: adopt zygote env failed")) {
            setSeg2(0.56f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: setting partitions ro")) {
            setSeg2(0.64f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: partitions set ro")
                || t.startsWith("bootstrap: WARNING: set partitions ro failed")) {
            setSeg2(0.72f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: WARNING: disable modules failed")) {
            setSeg2(0.76f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.startsWith("bootstrap: starting SU daemon")) {
            setSeg2(0.85f, getString(R.string.verification), 0xFFFFFFFF);
        }
        if (t.matches("\\*+SUCCESS\\*+")) {
            setSeg1(1f);
            setSeg2(1f, getString(R.string.verified), 0xFFFFFFFF);
        }
        if (exploitPhase.equals("cleanup") && t.startsWith("restoring")) {
            cleanupSteps++;
        }
    }

    private void setSeg1(float p) {
        seg1 = p;
        binding.twoStep.setSeg1(p, Math.round(p * 100) + "%");
    }

    private void setSeg2(float p, String label, int color) {
        binding.twoStep.setSeg2(p, label, color);
    }

    /** Visibility of log / share button / progress bar, composed from the
     *  advanced-log setting and whether any run data exists. The log block
     *  needs the switch; the share circle does not - a finished run can always
     *  be saved. */
    private void updateLogVisibility() {
        boolean hasRun = logBuffer.length() > 0
                || (lastLogFile != null && lastLogFile.exists());
        boolean showLog = advancedLog && hasRun;
        binding.outputScroll.setVisibility(showLog ? View.VISIBLE : View.GONE);
        // Share circle: any FINISHED run, advanced log on or off. Still hidden
        // while a run is in flight (the log is being written) and shown for a
        // saved log from a previous boot, which is finished by definition.
        setShareButtonVisible(hasRun && !running);
        // Progress bar is the simple status: always visible.
    }

    /** Pop the share circle in/out with the same animation the KernelSU
     *  launcher circle uses (fade + 0.6x -> 1x scale, 150ms delay). */
    private void setShareButtonVisible(boolean show) {
        android.widget.ImageButton b = binding.btnShareLog;
        boolean wasVisible = b.getVisibility() == View.VISIBLE
                && b.getAlpha() > 0.99f;
        if (show && !wasVisible) {
            b.setVisibility(View.VISIBLE);
            b.setAlpha(0f);
            b.setScaleX(0.6f);
            b.setScaleY(0.6f);
            b.postDelayed(() -> b.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180).start(), 150);
        } else if (show) {
            b.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(120).start();
        } else if (wasVisible) {
            b.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f).setDuration(200)
                    .withEndAction(() -> b.setVisibility(View.GONE)).start();
        }
    }

    /** "=== setup ===" -> "SETUP"; "=== exploit (patching files) ===" ->
     *  "PATCHING"; "=== exploit failed: x ===" -> "EXPLOIT FAILED: X". */
    private static String stripHeader(String t) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^===\\s*(.*?)\\s*===$").matcher(t);
        if (!m.matches()) return t;
        String h = m.group(1).toUpperCase();
        // The native binary still prints "=== exploit (patching files) ===";
        // the UI shows the short form.
        if (h.equals("EXPLOIT (PATCHING FILES)")) return "PATCHING";
        return h;
    }

    /** Short firmware token from the build display string, e.g. "S931BXXU1AYB2"
     *  - everything that is not the model-prefixed version is dropped. */
    private static String fwToken() {
        String d = android.os.Build.DISPLAY;
        String model = android.os.Build.MODEL == null
                ? "" : android.os.Build.MODEL.replace("SM-", "").trim();
        if (d == null || d.trim().isEmpty()) return "UNKNOWN";
        if (model.isEmpty()) return d.trim();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("[A-Z0-9]*" + java.util.regex.Pattern.quote(model) + "[A-Z0-9]*")
                .matcher(d);
        return m.find() ? m.group() : d.trim();
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private boolean isHeader(String line) {
        return line.equals("SETUP") || line.equals("PATCHING")
                || line.equals("EXPLOIT (PATCHING FILES)")
                || line.equals("INIT") || line.equals("CLEANUP")
                || line.startsWith("EXPLOIT FAILED")
                || line.equals(fwToken());
    }

    /** Header lines render big, white and bold; the rest is dimmed. */
    private CharSequence styleLogLine(String line) {
        SpannableString ss = new SpannableString(line);
        if (isHeader(line)) {
            ss.setSpan(new StyleSpan(Typeface.BOLD), 0, line.length(), 0);
            ss.setSpan(new RelativeSizeSpan(1.3f), 0, line.length(), 0);
            ss.setSpan(new ForegroundColorSpan(0xFFFFFFFF), 0, line.length(), 0);
        } else {
            ss.setSpan(new ForegroundColorSpan(0xFFB3B3B3), 0, line.length(), 0);
        }
        return ss;
    }

    private void saveLog() {
        try (FileOutputStream out = new FileOutputStream(lastLogFile)) {
            out.write(logBuffer.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (IOException ignored) {
        }
        // Remember which boot this log came from - it is invalidated on reboot.
        createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putInt("log_boot_count", bootCount()).apply();
    }

    private int bootCount() {
        try {
            return android.provider.Settings.Global.getInt(getContentResolver(),
                    android.provider.Settings.Global.BOOT_COUNT, -1);
        } catch (Exception e) {
            return -1;
        }
    }

    private String readLastLog() {
        if (lastLogFile == null || !lastLogFile.exists()) return "";
        try (java.io.FileInputStream in = new java.io.FileInputStream(lastLogFile);
             java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) != -1; ) bos.write(buf, 0, n);
            String log = bos.toString(java.nio.charset.StandardCharsets.UTF_8.name()).trim();
            // Normalize exploit-result headers to lowercase (older runs saved
            // them uppercase); the file gets rewritten on next save.
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("(===\\s*exploit\\s+(?:success|failed[^=]*)\\s*===)",
                            java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(log);
            StringBuilder sb = new StringBuilder();
            while (m.find()) m.appendReplacement(sb, java.util.regex.Matcher
                    .quoteReplacement(m.group().toLowerCase()));
            m.appendTail(sb);
            return sb.toString();
        } catch (IOException e) {
            return "";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mDeCtx = createDeviceProtectedStorageContext();
        DiagLog.init(this);
        DiagLog.d("app", "onCreate");
        // Register before the activity is started; the export row triggers it.
        exportLauncher = registerForActivityResult(
                new androidx.activity.result.contract.ActivityResultContracts
                        .CreateDocument("text/plain"),
                uri -> {
                    if (uri != null && pendingExportText != null)
                        writeTextToUri(uri, pendingExportText);
                    pendingExportText = null;
                });
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Version tag flowing right after the header title.
        SpannableString title = new SpannableString("DirtyFrag 1.10");
        pillSpan = new VersionPillSpan(0.45f);
        title.setSpan(pillSpan, 10, title.length(),
                SpannableString.SPAN_EXCLUSIVE_EXCLUSIVE);
        binding.toolbar.setTitle(title);
        // NOTE: no setSupportActionBar() - it makes the ActionBar delegate draw
        // the title and ignore the toolbar's titleTextAppearance (breaks bold).
        // The toolbar renders its own title via app:titleTextAppearance.

        // Update check (SamSU-style): the pill around the version turns green
        // when GitHub has a newer release; tapping the title opens the releases
        // page (only while an update is flagged, so it stays a no-op otherwise).
        mExec.execute(this::checkForAppUpdate);

        // D2 vault status (Samsung VaultKeeper): Odin flashing allowed or
        // locked. Read-only; non-Samsung devices show "not available".

        // SU Manager card: upstream 3.2 deleted the bundled assets/ksud, and this
        // fork goes further - it no longer stages its own ksud at all. The chosen
        // manager's libksud.so is used in place (bootstrap is told its path), so
        // only apps that ship that library are offered.
        loadSuManagerPref();
        binding.rowSuManager.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            showSuManagerPopup();
        });

        // KSU modules toggle: since 3.2 this is a plain preference, not a root
        // operation. bootstrap.c reads disable_modules and touches a `disable`
        // flag file in every installed module before ksud runs, so the toggle
        // works before the device is rooted and applies on the next root.
        moduleRefresh = true;
        binding.switchModules.setChecked(!mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("disable_modules", false));
        moduleRefresh = false;
        binding.modulesSubtitle.setText(binding.switchModules.isChecked()
                ? getString(R.string.modules_enabled)
                : getString(R.string.modules_disabled));
        binding.switchModules.setOnCheckedChangeListener((btn, on) -> {
            if (moduleRefresh) return;
            btn.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            applyModuleState(on);
        });

        // Force real bold (wght 700) One UI Sans on the toolbar title TextView.
        binding.toolbar.post(() -> {
            Typeface base = ResourcesCompat.getFont(this, R.font.inter_vf);
            if (base == null) return;
            Typeface bold = Typeface.create(base, 700, false);
            for (int i = 0; i < binding.toolbar.getChildCount(); i++) {
                View child = binding.toolbar.getChildAt(i);
                if (child instanceof TextView) {
                    titleView = (TextView) child;
                    titleView.setTypeface(bold);
                    titleView.setOnClickListener(v -> {
                        if (updateAvailable) openUrl(REPO_NEW + "/releases");
                    });
                }
            }
        });

        // Show the log from the last run, if any. No run yet -> log hidden.
        // A log saved before the current boot is stale: delete it so a reboot
        // always starts with a clean screen (log + share icon hidden).
        lastLogFile = new File(createDeviceProtectedStorageContext().getFilesDir(), "last_run.log");
        int savedBoot = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE).getInt("log_boot_count", -1);
        if (lastLogFile.exists() && savedBoot != bootCount()) {
            lastLogFile.delete();
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
        }
        String last = readLastLog();
        boolean hasLastLog = !last.isEmpty();
        if (hasLastLog) {
            appendLog(fwToken());
            for (String l : last.split("\n")) {
                String t = stripHeader(l.trim());
                // Skip stale headers, old result lines and duplicate fw lines.
                if (t.isEmpty()
                        || t.equals("LAST RUN")
                        || t.equals("EXPLOIT SUCCESS")
                        || t.equals(fwToken())) {
                    continue;
                }
                appendLog(t);
            }
        }

        // Advanced log toggle: full log vs. simple status (progress bar only).
        advancedLog = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("advanced_log", false);
        binding.switchAdvancedLog.setChecked(advancedLog);
        binding.switchAdvancedLog.setOnCheckedChangeListener((btn, checked) -> {
            advancedLog = checked;
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("advanced_log", checked).apply();
            updateLogVisibility();
        });
        updateLogVisibility();

        // Restore the simple status for the current state: a successful last
        // run -> 100% + Verified; failed run -> Failed.
        boolean rootedNow = false;
        boolean lastSuccess = hasLastLog
                && createDeviceProtectedStorageContext()
                        .getSharedPreferences("dfroot", MODE_PRIVATE)
                        .getBoolean("last_run_success", false);
        boolean lastFailed = hasLastLog
                && last.toLowerCase().contains("=== exploit failed");
        if (rootedNow || lastSuccess) {
            binding.twoStep.setSeg1(1f, "100%");
            binding.twoStep.setSeg2(1f, getString(R.string.verified), 0xFFFFFFFF);
        } else if (lastFailed) {
            setFailedState();
        }

        binding.btnRun.setOnClickListener(v -> {
            if (running) return;
            // Two-tap confirmation: first tap arms ("Are you sure"), second runs.
            if (!runArmed) {
                runArmed = true;
                v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                binding.btnRun.setText(getString(R.string.are_you_sure));
                return;
            }
            runArmed = false;
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            running = true;
            binding.btnRun.setEnabled(false);
            binding.btnRun.setText(getString(R.string.running));
            // Same dark greyed-out styling as the Rooted state.
            binding.btnRun.setTextColor(0xFF6E6E6E);
            binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
            ((com.google.android.material.button.MaterialButton) binding.btnRun)
                    .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
            binding.outputView.setText("");
            logBuffer.setLength(0);
            if (lastLogFile.exists()) lastLogFile.delete();
            createDeviceProtectedStorageContext()
                    .getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", false).apply();
            appendLog(fwToken());
            binding.twoStep.reset();
            setCompactButton(true, false);
            updateLogVisibility();
            mExec.execute(this::runExploit);
        });

        binding.btnKsu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            openKsu();
        });

        // Subtle push-in + keyboard-tap haptic on the run button.
        binding.btnRun.setOnTouchListener((v, ev) -> {
            switch (ev.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                    v.animate().scaleX(0.96f).scaleY(0.96f).setDuration(80).start();
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    v.animate().scaleX(1f).scaleY(1f).setDuration(120).start();
                    break;
                default:
                    break;
            }
            return false;
        });

        binding.btnShareLog.setOnClickListener(v -> shareLog());

        // Overflow menu on the custom grey-circle button: the popup closes
        // ONLY on outside taps, so multi-tap actions are possible.
        binding.btnMenu.setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            float md = getResources().getDisplayMetrics().density;
            final android.widget.PopupWindow[] pwRef = {null};

            android.widget.LinearLayout box = new android.widget.LinearLayout(this);
            box.setOrientation(android.widget.LinearLayout.VERTICAL);
            box.setBackgroundResource(R.drawable.popup_bg);
            box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

            // -- Github Page row: opens this build's home (the WorldMargin fork). --
            TextView ghRow = new TextView(this);
            ghRow.setBackgroundResource(R.drawable.menu_row_highlight);
            ghRow.setText(R.string.menu_github);
            ghRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            ghRow.setPadding((int) (20 * md), 0, 0, 0);
            ghRow.setTextColor(0xFFE8E8E8);
            ghRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            ghRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                openUrl(REPO_NEW);
            });
            box.addView(ghRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Expert Mode row: white dot appears when enabled --
            android.widget.LinearLayout exRow = new android.widget.LinearLayout(this);
            exRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            exRow.setPadding((int) (20 * md), 0, 0, 0);
            TextView exText = new TextView(this);
            exRow.setBackgroundResource(R.drawable.menu_row_highlight);
            exText.setText(R.string.menu_expert_mode);
            exText.setTextColor(0xFFE8E8E8);
            exText.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            exRow.addView(exText);
            final android.view.View[] dotRef = {null};
            android.view.View dot = new android.view.View(this);
            dot.setBackgroundResource(R.drawable.dot_white);
            android.widget.LinearLayout.LayoutParams dotLp =
                    new android.widget.LinearLayout.LayoutParams(
                            (int) (7 * md), (int) (7 * md));
            dotLp.setMargins((int) (7 * md), 0, 0, 0);
            dot.setVisibility(expertMode ? View.VISIBLE : View.GONE);
            exRow.addView(dot, dotLp);
            dotRef[0] = dot;
            exRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                expertMode = !expertMode;
                createDeviceProtectedStorageContext()
                        .getSharedPreferences("dfroot", MODE_PRIVATE)
                        .edit().putBoolean("expert_mode", expertMode).apply();
                applyExpertMode();
                if (dotRef[0] != null)
                    dotRef[0].setVisibility(expertMode ? View.VISIBLE : View.GONE);
            });
            box.addView(exRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Terminal row: opens a real pty-backed terminal (vendored Termux
            //    terminal-emulator/view) running su or sh. Unlike a line-based
            //    prompt this keeps cwd/env/history and runs interactive tools. --
            TextView dbgRow = new TextView(this);
            dbgRow.setBackgroundResource(R.drawable.menu_row_highlight);
            dbgRow.setText(R.string.menu_debug_console);
            dbgRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            dbgRow.setPadding((int) (20 * md), 0, 0, 0);
            dbgRow.setTextColor(0xFFE8E8E8);
            dbgRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            dbgRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                if (pwRef[0] != null) pwRef[0].dismiss();
                showTerminal();
            });
            box.addView(dbgRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Test primitive row: minimal runtime probe of the page-cache
            //    write primitive. Needs no SU manager and doesn't run the full
            //    exploit; tells you whether this device is usable at all. --
            TextView probeRow = new TextView(this);
            probeRow.setBackgroundResource(R.drawable.menu_row_highlight);
            probeRow.setText(R.string.menu_test_primitive);
            probeRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            probeRow.setPadding((int) (20 * md), 0, 0, 0);
            probeRow.setTextColor(0xFFE8E8E8);
            probeRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            probeRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                if (pwRef[0] != null) pwRef[0].dismiss();
                runProbe();
            });
            box.addView(probeRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Language row: in-app locale switch (AppCompat persists it). --
            TextView langRow = new TextView(this);
            langRow.setBackgroundResource(R.drawable.menu_row_highlight);
            langRow.setText(R.string.menu_language);
            langRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            langRow.setPadding((int) (20 * md), 0, 0, 0);
            langRow.setTextColor(0xFFE8E8E8);
            langRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            langRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                if (pwRef[0] != null) pwRef[0].dismiss();
                showLanguageDialog();
            });
            box.addView(langRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Export log row: saves the diagnostic log (dfroot.log, Java +
            //    native) to Downloads so a tester can send it back. Pull it by
            //    adb instead with:
            //    adb pull /sdcard/Android/data/com.worldmargin.dfroot/files/dfroot.log --
            TextView expRow = new TextView(this);
            expRow.setBackgroundResource(R.drawable.menu_row_highlight);
            expRow.setText(R.string.menu_export_log);
            expRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            expRow.setPadding((int) (20 * md), 0, 0, 0);
            expRow.setTextColor(0xFFE8E8E8);
            expRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            expRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                if (pwRef[0] != null) pwRef[0].dismiss();
                exportDiagLog();
            });
            box.addView(expRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Clear log row: wipes the on-screen log, the saved run log and
            //    the diagnostic log (dfroot.log) from the device. --
            TextView clrRow = new TextView(this);
            clrRow.setBackgroundResource(R.drawable.menu_row_highlight);
            clrRow.setText(R.string.menu_clear_log);
            clrRow.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            clrRow.setPadding((int) (20 * md), 0, 0, 0);
            clrRow.setTextColor(0xFFE8E8E8);
            clrRow.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            clrRow.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                if (pwRef[0] != null) pwRef[0].dismiss();
                clearLogs();
            });
            box.addView(clrRow, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (46 * md)));

            // -- Remove KSU/KSUD row: 3-tap confirm, greyed out until a manager
            //    is picked. Pre-3.2 this hardcoded me.weishu.kernelsu; it now
            //    targets whichever manager is actually selected. --
            final boolean haveManager = suManagerPkg != null;
            android.widget.LinearLayout rmCol = new android.widget.LinearLayout(this);
            rmCol.setOrientation(android.widget.LinearLayout.VERTICAL);
            rmCol.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            rmCol.setPadding((int) (20 * md), 0, (int) (20 * md), 0);
            TextView rmTitle = new TextView(this);
            rmCol.setBackgroundResource(R.drawable.menu_row_highlight);
            rmTitle.setText(R.string.menu_remove_ksu);
            rmTitle.setGravity(android.view.Gravity.START);
            rmTitle.setTextColor(haveManager ? 0xFFE8E8E8 : 0xFF6E6E6E);
            rmTitle.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            rmCol.addView(rmTitle);
            TextView rmSub = new TextView(this);
            rmSub.setText(haveManager ? getString(R.string.menu_click_3)
                    : getString(R.string.no_su_selected));
            rmSub.setGravity(android.view.Gravity.START);
            rmSub.setTextColor(haveManager ? 0xFF8E8E8E : 0xFF5A5A5A);
            rmSub.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
            rmCol.addView(rmSub);
            final int[] taps = {0};
            rmCol.setOnClickListener(v2 -> {
                if (!haveManager) return;
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                taps[0]++;
                if (taps[0] == 1) {
                    rmTitle.setText(R.string.are_you_sure);
                    rmSub.setText(R.string.menu_click_2);
                    return;
                }
                if (taps[0] == 2) {
                    rmTitle.setText(R.string.menu_one_more);
                    rmSub.setText(R.string.menu_click_1);
                    return;
                }
                if (pwRef[0] != null) pwRef[0].dismiss();
                // Deliberately NOT calling `ksud uninstall`: its upstream
                // implementation force-flashes a stored boot image when a backup
                // exists and reboots the device after 5 seconds - surprises we
                // don't want. DirtyFrag's kernel side is a page-cache patch that
                // a plain reboot clears, so removing the manager app is the job.
                try {
                    Intent un = new Intent(Intent.ACTION_DELETE,
                            Uri.fromParts("package", suManagerPkg, null));
                    un.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(un);
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this,
                            "Uninstall prompt unavailable", Toast.LENGTH_SHORT).show();
                }
            });
            box.addView(rmCol, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (58 * md)));

            // Width: content, but at least 210dp so the popup reads properly.
            box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
            int pw_w = Math.max(box.getMeasuredWidth(), (int) (190 * md));

            final android.widget.PopupWindow pw = new android.widget.PopupWindow(box,
                    pw_w, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, true);
            pw.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(
                    android.graphics.Color.TRANSPARENT));
            pw.setOutsideTouchable(true);
            pwRef[0] = pw;
            pw.setOnDismissListener(() ->
                    binding.dimOverlay.animate().alpha(0f).setDuration(150)
                            .withEndAction(() -> binding.dimOverlay
                                    .setVisibility(View.GONE)).start());

            // Centered separators between the rows.
            android.widget.LinearLayout.LayoutParams sepLp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sepLp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            android.view.View sep1 = new android.view.View(this);
            sep1.setBackgroundColor(0xFF3F3F3F);
            box.addView(sep1, 1, sepLp);
            android.view.View sep2 = new android.view.View(this);
            sep2.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep2Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep2Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep2, 3, sep2Lp);
            android.view.View sep3 = new android.view.View(this);
            sep3.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep3Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep3Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep3, 5, sep3Lp);
            android.view.View sep4 = new android.view.View(this);
            sep4.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep4Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep4Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep4, 7, sep4Lp);
            android.view.View sep5 = new android.view.View(this);
            sep5.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep5Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep5Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep5, 9, sep5Lp);
            android.view.View sep6 = new android.view.View(this);
            sep6.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep6Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep6Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep6, 11, sep6Lp);
            android.view.View sep7 = new android.view.View(this);
            sep7.setBackgroundColor(0xFF3F3F3F);
            android.widget.LinearLayout.LayoutParams sep7Lp =
                    new android.widget.LinearLayout.LayoutParams(
                            android.view.ViewGroup.LayoutParams.MATCH_PARENT, Math.max(1, (int) md));
            sep7Lp.setMargins((int) (20 * md), 0, (int) (20 * md), 0);
            box.addView(sep7, 13, sep7Lp);

            box.setOutlineProvider(new android.view.ViewOutlineProvider() {
                @Override
                public void getOutline(View view, android.graphics.Outline outline) {
                    outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
                }
            });
            box.setClipToOutline(true);
            box.setElevation(48 * md);

            int[] loc = new int[2];
            binding.menuAnchor.getLocationOnScreen(loc);
            int x = loc[0] + binding.menuAnchor.getWidth() - pw_w;
            int y = loc[1] + (int) (2 * md);
            binding.dimOverlay.setVisibility(View.VISIBLE);
            binding.dimOverlay.setAlpha(0f);
            binding.dimOverlay.animate().alpha(0.5f).setDuration(150).start();
            box.setPivotX(pw_w);
            box.setPivotY(0f);
            box.setScaleX(0.85f);
            box.setScaleY(0.9f);
            box.setAlpha(0f);
            pw.showAtLocation(binding.menuAnchor,
                    android.view.Gravity.TOP | android.view.Gravity.START, x, y);
            box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator())
                    .start();
        });
        ComponentName bootReceiver = new ComponentName(this, BootReceiver.class);
        int state = getPackageManager().getComponentEnabledSetting(bootReceiver);
        boolean bootEnabled = state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
        binding.switchBootStart.setChecked(bootEnabled);
        binding.switchBootStart.setOnCheckedChangeListener((btn, checked) -> {
            getPackageManager().setComponentEnabledSetting(bootReceiver,
                checked ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP);
            binding.switchAutoSoftReboot.setEnabled(checked);
        });

        boolean autoSoftReboot = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("auto_soft_reboot", false);
        binding.switchAutoSoftReboot.setChecked(autoSoftReboot);
        binding.switchAutoSoftReboot.setEnabled(bootEnabled);
        binding.switchAutoSoftReboot.setOnCheckedChangeListener((btn, checked) ->
            createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("auto_soft_reboot", checked).apply());

        // Expert mode gates the autorun card: locked until toggled in the menu.
        expertMode = createDeviceProtectedStorageContext()
                .getSharedPreferences("dfroot", MODE_PRIVATE)
                .getBoolean("expert_mode", false);
        applyExpertMode();

        // Run stays locked until an SU manager is selected (and, after a failed
        // run, until the device has been rebooted).
        updateRunButton();

        // Launch-time device support check: run the primitive probe once and
        // report the verdict in the inline status banner (no dialog).
        runSupportCheck();
    }

    /** Automatically probes the page-cache primitive on launch and writes the
     *  verdict into the inline support banner. Independent of the SU manager,
     *  so it works before the user has picked one. The verdict also folds in
     *  the kernel-module (KMI) check: a vulnerable device still can't be rooted
     *  if no bundled dfroot.ko matches its kernel. */
    private void runSupportCheck() {
        if (running) return;
        setSupportBanner(R.string.support_checking, 0xFFB0B0B0);
        final String release = kernelRelease();
        final int[] kmi = parseKmi(release);
        DiagLog.d("support", "kernel=" + release
                + " kmi=" + (kmi == null ? "unparsed" : kmiLabel(kmi)));
        mExec.execute(() -> {
            int rc;
            try {
                rc = ExploitRunner.probe(mDeCtx, s -> { });
            } catch (Exception e) {
                Log.e(TAG, "support check failed", e);
                DiagLog.e("support", "probe exception", e);
                mMain.post(() -> setSupportBanner(R.string.support_unknown, 0xFFE5A663));
                return;
            }
            final int r = rc;
            DiagLog.d("support", "probe rc=" + r);
            mMain.post(() -> {
                if (r != 0) {
                    setSupportBanner(R.string.support_unsupported, 0xFFE57373);
                } else if (kmi != null && !kmiCovered(kmi)) {
                    setSupportBanner(getString(R.string.support_no_ko, kmiLabel(kmi)), 0xFFE5A663);
                } else {
                    setSupportBanner(R.string.support_supported, 0xFF7BD88F);
                }
            });
        });
    }

    /** Kernel release string, e.g. "6.1.145-android14-11-maybe-dirty". Reads
     *  /proc/version as the native side does; falls back to os.version. */
    private static String kernelRelease() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/version"))) {
            String line = r.readLine();
            if (line != null) {
                String marker = "Linux version ";
                int i = line.indexOf(marker);
                if (i >= 0) {
                    String rest = line.substring(i + marker.length()).trim();
                    int sp = rest.indexOf(' ');
                    if (sp > 0) rest = rest.substring(0, sp);
                    if (!rest.isEmpty()) return rest;
                }
            }
        } catch (Exception ignored) {
        }
        return System.getProperty("os.version");
    }

    /** Parses a kernel release into {androidRelease, major, minor}, or null when
     *  it is not a GKI-style "<w>.<x>.<y>-android<rel>-..." release. */
    private static int[] parseKmi(String release) {
        if (release == null) return null;
        Matcher rel = Pattern.compile("^(\\d+)\\.(\\d+)").matcher(release);
        Matcher and = Pattern.compile("android(\\d+)").matcher(release);
        if (!rel.find() || !and.find()) return null;
        return new int[]{ Integer.parseInt(and.group(1)),
                          Integer.parseInt(rel.group(1)),
                          Integer.parseInt(rel.group(2)) };
    }

    private static String kmiLabel(int[] kmi) {
        return "android" + kmi[0] + "-" + kmi[1] + "." + kmi[2];
    }

    /** Mirrors exp.c select_ko_image(): covered when a bundled module matches
     *  the device's major.minor (android release preferred); any module with
     *  the same major.minor is accepted as the fallback the exploit would use. */
    private static boolean kmiCovered(int[] kmi) {
        boolean sameMajorMinor = false;
        for (int[] ko : BUNDLED_KO_KMIS) {
            if (ko[1] != kmi[1] || ko[2] != kmi[2]) continue;
            if (ko[0] == kmi[0]) return true;
            sameMajorMinor = true;
        }
        return sameMajorMinor;
    }

    private void setSupportBanner(int textRes, int color) {
        setSupportBanner(getString(textRes), color);
    }

    private void setSupportBanner(CharSequence text, int color) {
        binding.supportBanner.setText(text);
        binding.supportBanner.setTextColor(color);
    }

    /** In-app language picker: System default / English / 简体中文. AppCompat
     *  persists the choice and recreates the activity on change. */
    private void showLanguageDialog() {
        final String[] tags = { "", "en", "zh-CN" };
        final String[] labels = {
                getString(R.string.language_system),
                getString(R.string.language_en),
                getString(R.string.language_zh)
        };
        LocaleListCompat current = AppCompatDelegate.getApplicationLocales();
        String currentTag = current.isEmpty() ? "" : current.toLanguageTags();
        int checked = 0;
        for (int i = 0; i < tags.length; i++) {
            if (tags[i].equalsIgnoreCase(currentTag)) { checked = i; break; }
        }
        new androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle(R.string.menu_language)
                .setSingleChoiceItems(labels, checked, (d, which) -> {
                    String tag = tags[which];
                    AppCompatDelegate.setApplicationLocales(tag.isEmpty()
                            ? LocaleListCompat.getEmptyLocaleList()
                            : LocaleListCompat.forLanguageTags(tag));
                    d.dismiss();
                })
                .show();
    }

    /** Expert mode off: the autorun card is inaccessible - greyed text and
     *  disabled toggles, titles suffixed with (Expert). */
    private void applyExpertMode() {
        boolean ok = expertMode;
        binding.tvAutorunTitle.setText(ok ? getString(R.string.autorun_title)
                : getString(R.string.autorun_title_expert));
        binding.tvRebootTitle.setText(ok ? getString(R.string.auto_reboot_title)
                : getString(R.string.auto_reboot_title_expert));
        binding.tvAutorunTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvAutorunDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.tvRebootTitle.setTextColor(ok ? 0xFFFFFFFF : 0xFF6E6E6E);
        binding.tvRebootDesc.setTextColor(ok ? 0xFF9E9E9E : 0xFF5A5A5A);
        binding.switchBootStart.setEnabled(ok);
        binding.switchAutoSoftReboot.setEnabled(ok
                && binding.switchBootStart.isChecked());
    }

    /** Re-read the SU manager selection when returning to the app: the user may
     *  have installed or uninstalled a manager while we were in the background,
     *  and the Run button has to reflect that immediately. */
    @Override
    protected void onResume() {
        super.onResume();
        loadSuManagerPref();
        updateRunButton();
    }

    private void setRootedState() {
        setRootedState(true);
    }

    /** Applies the Modules card. Since 3.2 this is a preference write, not a
     *  root operation: bootstrap.c reads disable_modules and touches a
     *  `disable` flag file in every installed module before it starts ksud
     *  (a broken module otherwise bootloops the device). OFF = modules stay
     *  disabled on the next root, ON = modules load. No su required. */
    private void applyModuleState(boolean on) {
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        SharedPreferences.Editor ed = sp.edit();
        if (on) ed.remove("disable_modules");
        else ed.putBoolean("disable_modules", true);
        ed.apply();
        binding.modulesSubtitle.setText(on
                ? getString(R.string.modules_enabled)
                : getString(R.string.modules_disabled));
        Toast.makeText(this,
                on ? getString(R.string.modules_enabled_toast)
                        : getString(R.string.modules_disabled_toast),
                Toast.LENGTH_SHORT).show();
    }

    // ---- SU manager picker --------------------------------------------------

    /** One candidate: an app that actually ships libksud.so. */
    private static final class SuManagerEntry {
        final String packageName;
        final CharSequence label;

        SuManagerEntry(String pkg, CharSequence label) {
            this.packageName = pkg;
            this.label = label;
        }
    }

    /** Every installed app carrying libksud.so in its native lib dir - exactly
     *  the set whose ksud (libksud.so) ExploitRunner can point bootstrap at, so
     *  anything listed here is a usable manager. */
    private List<SuManagerEntry> scanSuManagers() {
        List<SuManagerEntry> out = new ArrayList<>();
        PackageManager pm = getPackageManager();
        for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
            if (ai.packageName.equals(getPackageName())) continue;
            if (ai.nativeLibraryDir == null) continue;
            if (!new File(ai.nativeLibraryDir, "libksud.so").exists()) continue;
            out.add(new SuManagerEntry(ai.packageName, pm.getApplicationLabel(ai)));
        }
        out.sort((a, b) -> a.label.toString().compareToIgnoreCase(b.label.toString()));
        return out;
    }

    /** Restores the saved selection, dropping it if that app is gone or no
     *  longer ships libksud.so. */
    private void loadSuManagerPref() {
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        String saved = sp.getString("su_manager", null);
        suManagerPkg = null;
        suManagerLabel = null;
        if (saved != null) {
            for (SuManagerEntry e : scanSuManagers()) {
                if (e.packageName.equals(saved)) {
                    suManagerPkg = e.packageName;
                    suManagerLabel = e.label;
                    break;
                }
            }
            if (suManagerPkg == null) sp.edit().remove("su_manager").apply();
        }
        binding.suManagerSubtitle.setText(suManagerPkg == null
                ? "Not selected - required"
                : suManagerLabel + "  (" + suManagerPkg + ")");
        binding.suManagerSubtitle.setTextColor(suManagerPkg == null
                ? 0xFFE57373 : 0xFF9E9E9E);
    }

    /** OneUI-style rounded popup list over the dim overlay - same look and feel
     *  as the overflow menu, so the picker does not look like a stock spinner. */
    private void showSuManagerPopup() {
        float md = getResources().getDisplayMetrics().density;
        List<SuManagerEntry> apps = scanSuManagers();
        final android.widget.PopupWindow[] pwRef = {null};

        android.widget.LinearLayout box = new android.widget.LinearLayout(this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.setBackgroundResource(R.drawable.popup_bg);
        box.setPadding(0, (int) (6 * md), 0, (int) (6 * md));

        if (apps.isEmpty()) {
            TextView none = new TextView(this);
            none.setText(R.string.no_libksud_app);
            none.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            none.setPadding((int) (20 * md), (int) (12 * md), (int) (20 * md), (int) (12 * md));
            none.setTextColor(0xFF6E6E6E);
            none.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            box.addView(none);
        }

        for (SuManagerEntry e : apps) {
            android.widget.LinearLayout col = new android.widget.LinearLayout(this);
            col.setOrientation(android.widget.LinearLayout.VERTICAL);
            col.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            col.setBackgroundResource(R.drawable.menu_row_highlight);
            col.setPadding((int) (20 * md), 0, (int) (20 * md), 0);

            android.widget.LinearLayout line = new android.widget.LinearLayout(this);
            line.setOrientation(android.widget.LinearLayout.HORIZONTAL);
            line.setGravity(android.view.Gravity.CENTER_VERTICAL | android.view.Gravity.START);
            TextView t = new TextView(this);
            t.setText(e.label);
            t.setTextColor(0xFFE8E8E8);
            t.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 15);
            line.addView(t, new android.widget.LinearLayout.LayoutParams(
                    0, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            if (e.packageName.equals(suManagerPkg)) {
                android.view.View dot = new android.view.View(this);
                dot.setBackgroundResource(R.drawable.dot_white);
                android.widget.LinearLayout.LayoutParams dotLp =
                        new android.widget.LinearLayout.LayoutParams(
                                (int) (7 * md), (int) (7 * md));
                dotLp.setMargins((int) (7 * md), 0, 0, 0);
                line.addView(dot, dotLp);
            }
            col.addView(line, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (26 * md)));

            TextView sub = new TextView(this);
            sub.setText(e.packageName);
            sub.setTextColor(0xFF8E8E8E);
            sub.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
            col.addView(sub);

            col.setOnClickListener(v2 -> {
                v2.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
                selectSuManager(e);
                if (pwRef[0] != null) pwRef[0].dismiss();
            });
            box.addView(col, new android.widget.LinearLayout.LayoutParams(
                    android.view.ViewGroup.LayoutParams.MATCH_PARENT, (int) (56 * md)));
        }

        box.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
        int cardW = binding.cardSuManager.getWidth();
        int pw_w = cardW > 0 ? cardW : Math.max(box.getMeasuredWidth(), (int) (240 * md));

        final android.widget.PopupWindow pw = new android.widget.PopupWindow(box,
                pw_w, android.view.ViewGroup.LayoutParams.WRAP_CONTENT, true);
        pw.setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(
                android.graphics.Color.TRANSPARENT));
        pw.setOutsideTouchable(true);
        pwRef[0] = pw;
        pw.setOnDismissListener(() ->
                binding.dimOverlay.animate().alpha(0f).setDuration(150)
                        .withEndAction(() -> binding.dimOverlay
                                .setVisibility(View.GONE)).start());

        box.setOutlineProvider(new android.view.ViewOutlineProvider() {
            @Override
            public void getOutline(View view, android.graphics.Outline outline) {
                outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), 26 * md);
            }
        });
        box.setClipToOutline(true);
        box.setElevation(48 * md);

        int[] loc = new int[2];
        binding.cardSuManager.getLocationOnScreen(loc);
        // Centered, NOT card-anchored: the popup is exactly card-wide and the
        // card sits 16dp from each edge, so half the leftover IS the card's own
        // margin. Anchoring to the card's left + 16dp pushed the popup 16dp
        // right, which read as off-centre and clipped its right edge.
        int x = (getResources().getDisplayMetrics().widthPixels - pw_w) / 2;
        int y = loc[1] + binding.cardSuManager.getHeight() + (int) (4 * md);
        binding.dimOverlay.setVisibility(View.VISIBLE);
        binding.dimOverlay.setAlpha(0f);
        binding.dimOverlay.animate().alpha(0.5f).setDuration(150).start();
        box.setPivotX(0f);
        box.setPivotY(0f);
        box.setScaleX(0.9f);
        box.setScaleY(0.9f);
        box.setAlpha(0f);
        pw.showAtLocation(binding.cardSuManager,
                android.view.Gravity.TOP | android.view.Gravity.START, x, y);
        box.animate().scaleX(1f).scaleY(1f).alpha(1f).setDuration(150)
                .setInterpolator(new android.view.animation.DecelerateInterpolator())
                .start();
    }

    /** Writes the DE pref that bootstrap.c reads as su_manager, then unlocks Run. */
    private void selectSuManager(SuManagerEntry e) {
        mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putString("su_manager", e.packageName).apply();
        suManagerPkg = e.packageName;
        suManagerLabel = e.label;
        binding.suManagerSubtitle.setText(e.label + "  (" + e.packageName + ")");
        binding.suManagerSubtitle.setTextColor(0xFF9E9E9E);
        updateRunButton();
    }

    /** Run needs a manager selected and no failed-run lock. */
    private boolean canRun() {
        return suManagerPkg != null && !failedRun;
    }

    /** Single place that decides the Run pill's look and enabled state. */
    private void updateRunButton() {
        if (running) return;
        if (failedRun) {
            setFailedState();
            return;
        }
        boolean ok = suManagerPkg != null;
        binding.btnRun.setEnabled(ok);
        binding.btnRun.setText(R.string.run_exploit);
        binding.btnRun.setTextColor(ok ? 0xFFE0E0E0 : 0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(ok ? 0xFF7A7A7A : 0xFF1F1F1F));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(ok ? 0xFFA6A6A6 : 0xFF1F1F1F));
    }

    /** SamSU-style GitHub release check: the pill around the version turns
     *  green when the latest published release tag differs from this build's
     *  versionName. Silent on offline / rate-limit / API hiccups. */
    private void checkForAppUpdate() {
        try {
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection)
                    new java.net.URL("https://api.github.com/repos/" + API_REPO + "/releases/latest")
                            .openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setRequestProperty("Accept", "application/vnd.github+json");
            conn.setRequestProperty("User-Agent", "DirtyFrag");
            if (conn.getResponseCode() != 200) return;
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream()));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) body.append(line);
            reader.close();
            String tag = new org.json.JSONObject(body.toString()).optString("tag_name", "");
            if (tag.isEmpty()) {
                Log.i(TAG, "update check: empty tag_name");
                return;
            }
            String latest = tag.replaceFirst("^[vV]", "").trim();
            String mine;
            try {
                mine = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            } catch (Exception e) {
                return;
            }
            if (latest.equalsIgnoreCase(mine)) return;
            Log.i(TAG, "update check: update available (latest=" + latest + ")");
            mMain.post(() -> {
                updateAvailable = true;
                // Grow the pill from its left edge into the lime update state,
                // same 250ms feel as the Run pill's shrink.
                if (titleView != null) {
                    android.animation.ValueAnimator a =
                            android.animation.ValueAnimator.ofFloat(0f, 1f);
                    a.setDuration(250);
                    a.addUpdateListener(anim -> {
                        pillSpan.setProgress((float) anim.getAnimatedValue());
                        titleView.invalidate();
                    });
                    a.start();
                } else {
                    pillSpan.setProgress(1f);
                }
            });
        } catch (Exception e) {
            Log.i(TAG, "update check failed: " + e);
        }
    }

    /** Failure presentation: left bar label "Failure", right label "Reboot",
     *  bars + labels red, run pill greyed out like the Running/Rooted state.
     *  The pill stays disabled because the vendor patch is page-cache only:
     *  retrying without rebooting would fail the same way. */
    private void setFailedState() {
        failedRun = true;
        binding.twoStep.setFailed(true);
        binding.twoStep.setSeg1(seg1, getString(R.string.failure));
        binding.twoStep.setSeg2(1f, getString(R.string.reboot), 0xFFE57373);
        binding.btnRun.setEnabled(false);
        binding.btnRun.setText(R.string.run_exploit);
        binding.btnRun.setTextColor(0xFF6E6E6E);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(0xFF1F1F1F));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(0xFF1F1F1F));
        setCompactButton(false, false);
    }

    private void setRootedState(boolean rooted) {
        runArmed = false;
        // Not rooted does not mean runnable: the manager still has to be picked
        // and a failed run locks the pill until reboot.
        boolean ok = !rooted && canRun();
        int fg = (rooted || !ok) ? 0xFF6E6E6E : 0xFFE0E0E0;
        int bg = (rooted || !ok) ? 0xFF1F1F1F : 0xFF7A7A7A;
        int stroke = (rooted || !ok) ? 0xFF1F1F1F : 0xFFA6A6A6;
        binding.btnRun.setEnabled(ok);
        binding.btnRun.setText(rooted ? getString(R.string.rooted)
                : getString(R.string.run_exploit));
        binding.btnRun.setTextColor(fg);
        binding.btnRun.setBackgroundTintList(ColorStateList.valueOf(bg));
        ((com.google.android.material.button.MaterialButton) binding.btnRun)
                .setStrokeColor(ColorStateList.valueOf(stroke));
        // Rooted/running: shrink the pill left and pop the KSU circle next to
        // it (lit when rooted); fresh run state: full-width pill, no circle.
        setCompactButton(rooted, rooted);
    }

    /** Shrinks the main pill to the left and pops the KSU launcher circle
     *  next to it (compact=true, ksuLit=lit after successful root), or
     *  restores the full-width pill. */
    private void setCompactButton(boolean compact, boolean ksuLit) {
        // Fresh pill: 48% wide starting at the 26% guideline → right edge at
        // 74%. Compact: pill + 12dp gap + 54dp circle must occupy the same
        // 48% total (left edge pinned), so pill = 48% - extras.
        float parentW = ((View) binding.btnRun.getParent()).getWidth();
        if (parentW <= 0) parentW = getResources().getDisplayMetrics().widthPixels;
        float density = getResources().getDisplayMetrics().density;
        float target = 0.48f;
        if (compact) {
            float extrasPx = (KSU_GAP_DP + KSU_CIRCLE_DP) * density;
            target = Math.max(0.20f, 0.48f - extrasPx / parentW);
        }
        android.animation.ValueAnimator a =
                android.animation.ValueAnimator.ofFloat(pillPercent, target);
        a.setDuration(250);
        a.addUpdateListener(anim -> {
            pillPercent = (float) anim.getAnimatedValue();
            androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                    (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                            binding.btnRun.getLayoutParams();
            lp.matchConstraintPercentWidth = pillPercent;
            binding.btnRun.setLayoutParams(lp);
        });
        a.start();
        // The launcher pill ends up exactly as wide as the shrunken Run pill
        // (measured off the user's mockups: 331 vs 332 px on the S25), which is
        // what fills the old 100dp right-hand deadzone and mirrors the share
        // circle on the left.
        int ksuPillPx = (int) (target * parentW);
        int ksuCirclePx = (int) (KSU_CIRCLE_DP * density);
        binding.btnKsu.setEnabled(ksuLit);
        boolean wasVisible = binding.btnKsu.getVisibility() == View.VISIBLE
                && binding.btnKsu.getAlpha() > 0.99f;
        binding.btnKsu.setBackgroundTintList(ColorStateList.valueOf(
                ksuLit ? 0xFFB0B0B0 : 0xFF1F1F1F));
        // Dark ink on the lit pill, mid-grey on the unlit one - same grey as
        // the share glyph.
        binding.ksuChevron.setImageTintList(ColorStateList.valueOf(
                ksuLit ? 0xFF1F1F1F : 0xFF6E6E6E));
        if (compact && !wasVisible) {
            // First appearance: pop in as a circle. The morph is chained to the
            // pop-in's end so the Run pill has already finished shrinking - its
            // right edge is the launcher's start anchor, so the launcher's left
            // edge must be stable before we animate the width.
            setKsuWidth(ksuCirclePx);
            binding.ksuLabel.setAlpha(0f);
            binding.btnKsu.setVisibility(View.VISIBLE);
            binding.btnKsu.setAlpha(0f);
            binding.btnKsu.setScaleX(0.6f);
            binding.btnKsu.setScaleY(0.6f);
            binding.btnKsu.postDelayed(() -> binding.btnKsu.animate()
                    .alpha(1f).scaleX(1f).scaleY(1f).setDuration(180)
                    .withEndAction(() -> {
                        settleKsuTint(ksuLit);
                        morphKsuToPill(ksuLit, ksuPillPx, ksuCirclePx);
                    }).start(), 150);
        } else if (compact) {
            // Already visible (state change): stay in place, recolor + grow.
            settleKsuTint(ksuLit);
            morphKsuToPill(ksuLit, ksuPillPx, ksuCirclePx);
        } else {
            binding.ksuLabel.animate().alpha(0f).setDuration(150).start();
            binding.btnKsu.animate().alpha(0f).scaleX(0.6f).scaleY(0.6f)
                    .setDuration(200)
                    .withEndAction(() -> {
                        binding.btnKsu.setVisibility(View.GONE);
                        setKsuWidth(ksuCirclePx);
                    })
                    .start();
        }
    }

    /** After the lit circle settles, ease it slightly towards grey. */
    private void settleKsuTint(boolean ksuLit) {
        if (!ksuLit) return;
        android.animation.ValueAnimator g =
                android.animation.ValueAnimator.ofFloat(0f, 1f);
        g.setStartDelay(250);
        g.setDuration(300);
        g.addUpdateListener(anim -> binding.btnKsu
                .setBackgroundTintList(ColorStateList.valueOf(
                        mixColor(0xFFB0B0B0, 0xFF9A9A9E,
                                (float) anim.getAnimatedValue()))));
        g.start();
    }

    /** Circle -> pill (or back): width only, left edge pinned, 250ms
     *  Decelerate - the same one-axis / one-side feel as the Run pill's
     *  shrink. The label fades in as the pill opens up. */
    private void morphKsuToPill(boolean lit, int pillPx, int circlePx) {
        int from = binding.btnKsu.getWidth();
        int to = lit ? pillPx : circlePx;
        if (from <= 0 || from == to) return;
        if (ksuMorph != null && ksuMorph.isRunning()) ksuMorph.cancel();
        ksuMorph = android.animation.ValueAnimator.ofInt(from, to);
        ksuMorph.setDuration(250);
        ksuMorph.setInterpolator(
                new android.view.animation.DecelerateInterpolator());
        ksuMorph.addUpdateListener(
                anim -> setKsuWidth((int) anim.getAnimatedValue()));
        // One final re-layout after the last width frame: the label and the
        // chevron are positioned by the FrameLayout, and a mid-morph width can
        // leave them stale (seen on device: the label stayed at the circle's
        // left edge instead of moving into the pill). ValueAnimator has no
        // withEndAction - that is ViewPropertyAnimator's API.
        ksuMorph.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                binding.btnKsu.requestLayout();
            }
        });
        ksuMorph.start();
        binding.ksuLabel.animate().alpha(lit ? 1f : 0f)
                .setStartDelay(lit ? 120 : 0).setDuration(220).start();
    }

    /** The launcher's animated width. layout_constraintHorizontal_bias="0"
     *  welds its left edge to the Run pill while the right edge travels. */
    private void setKsuWidth(int px) {
        androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                        binding.btnKsu.getLayoutParams();
        lp.width = px;
        binding.btnKsu.setLayoutParams(lp);
    }

    /** Opens the SU manager that is actually selected - pre-3.2 this walked a
     *  hardcoded package list that no longer matches reality. */
    private void openKsu() {
        if (suManagerPkg == null) {
            Toast.makeText(this, R.string.no_su_selected, Toast.LENGTH_SHORT).show();
            return;
        }
        Intent launch = getPackageManager().getLaunchIntentForPackage(suManagerPkg);
        if (launch == null) {
            Toast.makeText(this, getString(R.string.cannot_launch, suManagerPkg),
                    Toast.LENGTH_SHORT).show();
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(launch);
    }

    private static int mixColor(int a, int b, float t) {
        int ar = (a >> 16) & 0xFF, ag = (a >> 8) & 0xFF, ab = a & 0xFF;
        int br = (b >> 16) & 0xFF, bg = (b >> 8) & 0xFF, bb = b & 0xFF;
        return 0xFF000000
                | (Math.round(ar + (br - ar) * t) << 16)
                | (Math.round(ag + (bg - ag) * t) << 8)
                | Math.round(ab + (bb - ab) * t);
    }

    /** The full log a tester needs: the on-device diagnostic log (dfroot.log,
     *  Java + native, written by DiagLog.java / dflog.h) plus the run log shown
     *  in the UI. The root console daemon may have been forced onto the
     *  device-protected copy of dfroot.log, so both copies are merged. */
    private String collectLog() {
        StringBuilder sb = new StringBuilder();
        sb.append(DiagLog.readAll());

        File deLog = new File(createDeviceProtectedStorageContext().getFilesDir(), "dfroot.log");
        if (deLog.exists()) {
            try (java.io.FileInputStream in = new java.io.FileInputStream(deLog)) {
                byte[] buf = new byte[8192];
                for (int n; (n = in.read(buf)) != -1; ) sb.append(
                        new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8));
            } catch (IOException e) {
                Log.e(TAG, "read diag log failed", e);
            }
        }
        String runLog = logBuffer.length() > 0 ? logBuffer.toString() : readLastLog();
        if (!runLog.trim().isEmpty()) {
            sb.append("\n=== run log ===\n").append(runLog);
        }
        return sb.toString();
    }

    /** Bottom share circle: hands the log to the system share sheet as a text
     *  file attachment (ACTION_SEND), so it can go to mail / chat / cloud. */
    private void shareLog() {
        String log = collectLog();
        if (log.trim().isEmpty()) {
            Toast.makeText(this, R.string.log_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        DiagLog.d("app", "share log (" + log.length() + " chars)");
        try {
            File cache = new File(getCacheDir(), "dirtyfrag_log.txt");
            try (FileOutputStream out = new FileOutputStream(cache)) {
                out.write(log.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            Uri uri = androidx.core.content.FileProvider.getUriForFile(
                    this, getPackageName() + ".fileprovider", cache);

            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            send.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_log_subject));
            send.putExtra(Intent.EXTRA_STREAM, uri);
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(send, getString(R.string.share_log)));
        } catch (Exception e) {
            Log.e(TAG, "share log failed", e);
            Toast.makeText(this, e.toString(), Toast.LENGTH_SHORT).show();
        }
    }

    /** Menu "Export log": opens the system "Save to…" dialog (SAF) so the user
     *  picks the destination and file name. */
    private void exportDiagLog() {
        String log = collectLog();
        if (log.trim().isEmpty()) {
            Toast.makeText(this, R.string.log_empty, Toast.LENGTH_SHORT).show();
            return;
        }
        pendingExportText = log;
        exportLauncher.launch("dirtyfrag_diag_log.txt");
    }

    /** Writes text to a user-picked SAF uri. "wt" truncates any existing file. */
    private void writeTextToUri(Uri uri, String text) {
        try (java.io.OutputStream out = getContentResolver().openOutputStream(uri, "wt")) {
            if (out != null) {
                out.write(text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                DiagLog.d("app", "exported log to " + uri);
            }
        } catch (Exception e) {
            Log.e(TAG, "write export failed", e);
            Toast.makeText(this, e.toString(), Toast.LENGTH_SHORT).show();
        }
    }

    /** Menu "Clear log": wipes the on-screen log, the saved run log and both
     *  copies of the diagnostic log (external + device-protected). */
    private void clearLogs() {
        logBuffer.setLength(0);
        binding.outputView.setText("");
        if (lastLogFile != null && lastLogFile.exists()) lastLogFile.delete();
        DiagLog.clear();
        File deLog = new File(createDeviceProtectedStorageContext().getFilesDir(), "dfroot.log");
        if (deLog.exists()) deLog.delete();
        createDeviceProtectedStorageContext().getSharedPreferences("dfroot", MODE_PRIVATE)
                .edit().putBoolean("last_run_success", false).apply();
        updateLogVisibility();
        DiagLog.d("app", "logs cleared");
        Toast.makeText(this, R.string.log_cleared, Toast.LENGTH_SHORT).show();
    }

    private void runExploit() {
        // bootstrap.c reads soft_reboot straight out of the DE prefs, so mirror
        // the Autorun card's choice into the key it reads right before launch.
        SharedPreferences sp = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE);
        boolean autoSoftReboot = sp.getBoolean("auto_soft_reboot", false);
        sp.edit().putBoolean("soft_reboot", autoSoftReboot).apply();
        lastFailReason = null;
        DiagLog.d("run", "exploit start, su_manager=" + suManagerPkg);
        try {
            int rc = ExploitRunner.run(mDeCtx, this);
            DiagLog.d("run", "exploit returned rc=" + rc);
            if (rc != 0) {
                // 0 ok, 1 ksud/bootstrap error, 2 poll timeout or bad setup,
                // 3 failed to patch files (see exp.c markers[]).
                String why = lastFailReason != null ? lastFailReason
                        : rc == 1 ? getString(R.string.fail_ksud)
                        : rc == 2 ? getString(R.string.fail_check_logs)
                        : getString(R.string.fail_patch);
                report("\n=== exploit failed: " + why + " ===\n");
            }
            mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                    .edit().putBoolean("last_run_success", rc == 0).apply();
        } catch (Exception e) {
            Log.e(TAG, "exploit exception", e);
            report("\nexception: " + e + "\n");
        } finally {
            mMain.post(() -> {
                running = false;
                boolean rooted = new File("/dev/df").exists();
                if (rooted) {
                    setRootedState(true);
                    binding.twoStep.setSeg2(1f, getString(R.string.verified), 0xFFFFFFFF);
                } else {
                    setFailedState();
                    setRootedState(false);
                }
                updateLogVisibility();
            });
        }
    }

    /** Expert aid: minimal runtime probe of the page-cache write primitive.
     *  Runs the same write + read-back the exploit uses to decide
     *  "DEVICE NOT VULNERABLE", but standalone and non-destructive, so you can
     *  tell whether the device is usable before committing to a full run. */
    private void runProbe() {
        if (running) return;
        running = true;
        mExec.execute(() -> {
            StringBuilder out = new StringBuilder();
            try {
                int rc = ExploitRunner.probe(mDeCtx, out::append);
                DiagLog.d("probe", "probe rc=" + rc + " out=" + out);
                mMain.post(() -> {
                    String verdict = rc == 0
                            ? getString(R.string.probe_ok)
                            : getString(R.string.probe_failed);
                    new androidx.appcompat.app.AlertDialog.Builder(this)
                            .setTitle(R.string.probe_title)
                            .setMessage(verdict + "\n\n" + out)
                            .setPositiveButton(R.string.ok, null)
                            .show();
                });
            } catch (Exception e) {
                Log.e(TAG, "probe exception", e);
                mMain.post(() -> new androidx.appcompat.app.AlertDialog.Builder(this)
                        .setTitle(R.string.probe_title)
                        .setMessage(getString(R.string.probe_error, String.valueOf(e)))
                        .setPositiveButton(R.string.ok, null)
                        .show());
            } finally {
                mMain.post(() -> running = false);
            }
        });
    }

    /** The embedded terminal: a real pty-backed session (vendored Termux
     *  terminal-emulator / terminal-view), not a line-based prompt. It runs an
     *  interactive shell, so cwd/env/history and full-screen programs behave
     *  normally. Opens as su when a root manager is present, else the app's sh;
     *  the header lets the user switch shells and close. */
    private void showTerminal() {
        final android.app.Dialog dlg = new android.app.Dialog(this,
                android.R.style.Theme_Black_NoTitleBar_Fullscreen);
        View content = getLayoutInflater().inflate(R.layout.dialog_terminal, null);
        dlg.setContentView(content);
        dlg.setCanceledOnTouchOutside(false);
        DiagLog.d("term", "terminal opened");

        final com.termux.view.TerminalView tv = content.findViewById(R.id.terminalView);
        mTermView = tv;
        tv.setTerminalViewClient(new TerminalViewClientImpl(tv));
        tv.setTextSize(mTermTextSize);

        content.findViewById(R.id.terminalClose).setOnClickListener(v -> dlg.dismiss());
        content.findViewById(R.id.terminalRunRoot).setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            startTerminalSession(tv, "su");
        });
        content.findViewById(R.id.terminalRunSh).setOnClickListener(v -> {
            v.performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
            startTerminalSession(tv, "sh");
        });

        // Never leave the pty shell running behind the app.
        dlg.setOnDismissListener(d -> {
            com.termux.terminal.TerminalSession s = tv.getCurrentSession();
            if (s != null) s.finishIfRunning();
            mTermView = null;
        });
        dlg.show();

        android.view.Window w = dlg.getWindow();
        if (w != null) w.setSoftInputMode(
                android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);

        // The view has no size before its first layout and a session only spawns
        // its pty once updateSize() runs, so start the shell after layout.
        tv.post(() -> {
            if (daemonAvailable()) startRootPtySession(tv);
            else startTerminalSession(tv, suCmdAvailable() ? "su" : "sh");
        });
    }

    /** True when a root daemon from a successful exploit is actually running, so
     *  a genuine root shell can be opened without su. /dev/df is created by a
     *  successful run, but it is a tmpfs node that outlives the daemon, so the
     *  daemon's heartbeat (refreshed about once a second) is what we trust. */
    private boolean daemonAvailable() {
        if (!new File("/dev/df").exists()) return false;
        File hb = new File(mDeCtx.getFilesDir(), "dftty.alive");
        return hb.exists() && System.currentTimeMillis() - hb.lastModified() < 5000;
    }

    /** Open the terminal as root by handing the exploit's root daemon a pty whose
     *  slave it execs the shell on. termux.c only allocates the pty here, so the
     *  shell - and thus uid 0 - comes from the daemon's process tree; root cannot
     *  be setuid'd into our own process. Falls back to su/sh if the pty or daemon
     *  is unavailable. */
    private void startRootPtySession(com.termux.view.TerminalView tv) {
        com.termux.terminal.TerminalSession old = tv.getCurrentSession();
        if (old != null) old.finishIfRunning();

        String[] ptsOut = new String[1];
        int fd = com.termux.terminal.JNI.createPty(24, 80, ptsOut);
        if (fd < 0 || ptsOut[0] == null) {
            DiagLog.d("term", "createPty failed, falling back to su/sh");
            startTerminalSession(tv, suCmdAvailable() ? "su" : "sh");
            return;
        }
        DiagLog.d("term", "root pty pts=" + ptsOut[0] + " fd=" + fd);
        requestDaemonShell(ptsOut[0]);

        com.termux.terminal.TerminalSession session =
                new com.termux.terminal.TerminalSession(fd, 2000, mTermClient);
        tv.attachSession(session);
        tv.requestFocus();
        android.view.inputmethod.InputMethodManager imm =
                (android.view.inputmethod.InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        if (imm != null)
            imm.showSoftInput(tv, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);
    }

    /** Hand the pty slave path to the root daemon through its command file; the
     *  daemon forks an interactive root shell onto it. Sequence-tagged like the
     *  other dftty commands so the daemon runs it exactly once. */
    private void requestDaemonShell(String pts) {
        File cmd = new File(mDeCtx.getFilesDir(), "dftty.cmd");
        long seq = System.currentTimeMillis() & 0x7fffffff;
        String line = "<<<pty:" + seq + ">>> " + pts + "\n";
        try (FileOutputStream out = new FileOutputStream(cmd, false)) {
            out.write(line.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            DiagLog.d("term", "requestDaemonShell failed: " + e);
        }
    }

    /** (Re)starts the terminal on the given shell ("su" or "sh"), tearing down
     *  the previous session first. cwd is "/" and a fuller PATH is exported so
     *  interactive tools resolve like in a normal root shell. */
    private void startTerminalSession(com.termux.view.TerminalView tv, String shell) {
        com.termux.terminal.TerminalSession old = tv.getCurrentSession();
        if (old != null) old.finishIfRunning();
        com.termux.terminal.TerminalSession session = new com.termux.terminal.TerminalSession(
                shell, "/", new String[] { shell }, terminalEnv(), 2000, mTermClient);
        tv.attachSession(session);
        tv.requestFocus();
        android.view.inputmethod.InputMethodManager imm =
                (android.view.inputmethod.InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        if (imm != null)
            imm.showSoftInput(tv, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);
    }

    /** Environment for the pty shell. termux.c clears the environment and sets
     *  only what we pass, so PATH must list every place a su/sh binary lives. */
    private static String[] terminalEnv() {
        return new String[] {
                "TERM=xterm-256color",
                "LANG=en_US.UTF-8",
                "HOME=/",
                "TMPDIR=/data/local/tmp",
                "ANDROID_ROOT=/system",
                "ANDROID_DATA=/data",
                "PATH=/data/adb/ksu/bin:/data/adb/magisk:/debug_ramdisk:/sbin"
                        + ":/system/sbin:/system/bin:/system/xbin:/odm/bin:/vendor/bin"
                        + ":/product/bin:/data/local/tmp",
        };
    }

    /** True when the device exposes a su binary (a root manager is installed and
     *  this app may be granted); decides whether the terminal opens as su. */
    private boolean suCmdAvailable() {
        String mgr = mDeCtx.getSharedPreferences("dfroot", MODE_PRIVATE)
                .getString("su_manager", "");
        if (mgr != null && !mgr.isEmpty()) return true;
        for (String c : new String[] { "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/data/adb/ksu/bin/su", "/data/adb/magisk/su" }) {
            if (new File(c).exists()) return true;
        }
        return false;
    }

    /** TerminalSessionClient for the embedded terminal: clipboard + diag logs. */
    private final class TermClient implements com.termux.terminal.TerminalSessionClient {
        @Override public void onTextChanged(com.termux.terminal.TerminalSession s) {
            // TerminalView.draw() only runs on invalidate(); without this the
            // screen stays stale until a touch/scroll forces a repaint.
            if (mTermView != null) mTermView.onScreenUpdated();
        }

        @Override public void onTitleChanged(com.termux.terminal.TerminalSession s) { }

        @Override public void onSessionFinished(com.termux.terminal.TerminalSession s) {
            if (mTermView != null) mTermView.onScreenUpdated();
            DiagLog.d("term", "session finished rc=" + s.getExitStatus());
        }

        @Override public void onCopyTextToClipboard(com.termux.terminal.TerminalSession s, String text) {
            android.content.ClipboardManager cm =
                    (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm != null)
                cm.setPrimaryClip(android.content.ClipData.newPlainText("terminal", text));
        }

        @Override public void onPasteTextFromClipboard(com.termux.terminal.TerminalSession s) {
            android.content.ClipboardManager cm =
                    (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm == null || !cm.hasPrimaryClip()) return;
            CharSequence text = cm.getPrimaryClip().getItemAt(0).coerceToText(MainActivity.this);
            if (text != null && s != null) s.write(text.toString());
        }

        @Override public void onBell(com.termux.terminal.TerminalSession s) { }

        @Override public void onColorsChanged(com.termux.terminal.TerminalSession s) { }

        @Override public void onTerminalCursorStateChange(boolean state) { }

        @Override public Integer getTerminalCursorStyle() { return null; }

        @Override public void logError(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logWarn(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logInfo(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logDebug(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logVerbose(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logStackTraceWithMessage(String tag, String msg, Exception e) {
            DiagLog.d("term", tag + ": " + msg + " " + e);
        }
        @Override public void logStackTrace(String tag, Exception e) { DiagLog.d("term", tag + ": " + e); }
    }

    /** TerminalViewClient for the embedded terminal: keyboard/gesture policy.
     *  Minimal - back maps to ESC, taps raise the soft keyboard. */
    private final class TerminalViewClientImpl implements com.termux.view.TerminalViewClient {
        private final com.termux.view.TerminalView view;

        TerminalViewClientImpl(com.termux.view.TerminalView view) { this.view = view; }

        @Override public float onScale(float scale) {
            // Pinch-to-zoom: rescale the font, clamped so the terminal stays usable.
            int next = Math.round(mTermTextSize * scale);
            next = Math.max(10, Math.min(40, next));
            if (next != mTermTextSize) {
                mTermTextSize = next;
                final int size = next;
                view.post(() -> view.setTextSize(size));
            }
            return 1.0f;
        }

        @Override public void onSingleTapUp(android.view.MotionEvent e) {
            android.view.inputmethod.InputMethodManager imm =
                    (android.view.inputmethod.InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
            if (imm != null)
                imm.showSoftInput(view, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT);
        }

        @Override public boolean shouldBackButtonBeMappedToEscape() { return true; }

        @Override public boolean shouldEnforceCharBasedInput() { return true; }

        @Override public boolean shouldUseCtrlSpaceWorkaround() { return false; }

        @Override public boolean isTerminalViewSelected() { return true; }

        @Override public void copyModeChanged(boolean copyMode) { }

        @Override public boolean onKeyDown(int keyCode, android.view.KeyEvent e,
                com.termux.terminal.TerminalSession session) { return false; }

        @Override public boolean onKeyUp(int keyCode, android.view.KeyEvent e) { return false; }

        @Override public boolean onLongPress(android.view.MotionEvent event) { return false; }

        @Override public boolean readControlKey() { return false; }

        @Override public boolean readAltKey() { return false; }

        @Override public boolean readShiftKey() { return false; }

        @Override public boolean readFnKey() { return false; }

        @Override public boolean onCodePoint(int codePoint, boolean ctrlDown,
                com.termux.terminal.TerminalSession session) { return false; }

        @Override public void onEmulatorSet() { }

        @Override public void logError(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logWarn(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logInfo(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logDebug(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logVerbose(String tag, String msg) { DiagLog.d("term", tag + ": " + msg); }
        @Override public void logStackTraceWithMessage(String tag, String msg, Exception e) {
            DiagLog.d("term", tag + ": " + msg + " " + e);
        }
        @Override public void logStackTrace(String tag, Exception e) { DiagLog.d("term", tag + ": " + e); }
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Toast.makeText(this, R.string.no_browser, Toast.LENGTH_SHORT).show();
        }
    }

}
