package com.worldmargin.dfroot;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Java side of the on-device diagnostic log. Writes the same file the native
 * code (dflog.h) appends to, so a single pull captures the whole flow:
 *
 *   adb pull /sdcard/Android/data/com.worldmargin.dfroot/files/dfroot.log
 *
 * Falls back to the app's internal files dir when external storage is
 * unavailable (mirrors dflog.h's fallback path).
 */
public final class DiagLog {

    private static final String TAG = "dfroot";
    private static final String NAME = "dfroot.log";
    private static final Object LOCK = new Object();

    private static File file;

    /** Call once per process before logging (app startup / boot receiver). */
    public static void init(Context ctx) {
        File dir = ctx.getExternalFilesDir(null);
        if (dir == null) dir = ctx.getFilesDir();
        file = new File(dir, NAME);
    }

    /** The backing log file, or null if init() has not run yet. */
    public static File getFile() {
        return file;
    }

    /** Full contents of the log file, or "" when it does not exist yet. */
    public static String readAll() {
        File f = file;
        if (f == null || !f.exists()) return "";
        try (FileInputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            return new String(bos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    /** Truncates the log file, keeping the same path for future appends. */
    public static void clear() {
        synchronized (LOCK) {
            if (file == null) return;
            try (FileWriter w = new FileWriter(file, false)) {
                // Opening in non-append mode is enough to truncate.
            } catch (IOException ignored) {
            }
        }
    }

    public static void d(String tag, String msg) {
        Log.d(TAG, tag + ": " + msg);
        write(tag, msg);
    }

    public static void e(String tag, String msg, Throwable t) {
        Log.e(TAG, tag + ": " + msg, t);
        write(tag, msg + (t != null ? ": " + t : ""));
    }

    private static void write(String tag, String msg) {
        synchronized (LOCK) {
            if (file == null) return;
            try (FileWriter w = new FileWriter(file, true)) {
                w.write(new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date())
                        + " " + tag + ": " + msg + "\n");
            } catch (IOException ignored) {
            }
        }
    }
}
