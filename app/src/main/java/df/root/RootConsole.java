package df.root;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Client for the root debug console daemon forked by bootstrap.c.
 *
 * The daemon is the only process that ever runs as root in this flow, so it is
 * what makes a manual `ksud late-load` possible when the automatic one fails.
 * It watches a command file in the app's device-protected files dir and
 * appends the output of every command it runs to a transcript file. Requests
 * and replies carry a sequence number so a reply can be matched to its
 * request:
 *
 *   dftty.cmd : "&lt;&lt;&lt;cmd:N&gt;&gt;&gt;\n&lt;command&gt;\n"
 *   dftty.out : "&lt;&lt;&lt;begin:N&gt;&gt;&gt;\n&lt;output&gt;\n&lt;&lt;&lt;done:N&gt;&gt;&gt; rc=R\n"
 */
public final class RootConsole {

    private static final String CMD_NAME = "dftty.cmd";
    private static final String OUT_NAME = "dftty.out";

    private final File cmdFile;
    private final File outFile;
    private long seq;

    public RootConsole(File filesDir) {
        this.cmdFile = new File(filesDir, CMD_NAME);
        this.outFile = new File(filesDir, OUT_NAME);
        // Seed from the wall clock so a fresh client never collides with the
        // daemon's own last-seen sequence after it restarts.
        this.seq = System.currentTimeMillis() / 1000;
    }

    /** Empties the transcript so a new console session starts clean. */
    public void reset() {
        try (FileOutputStream out = new FileOutputStream(outFile)) {
            out.write(new byte[0]);
        } catch (IOException ignored) {
        }
    }

    /**
     * Runs one command as root and returns its captured output, or a hint if
     * the daemon never answered (e.g. the app was updated since the last root,
     * so no console daemon is running until a reroot).
     */
    public String run(String command, long timeoutMs) {
        long mySeq = ++seq;
        try (FileOutputStream out = new FileOutputStream(cmdFile)) {
            out.write(("<<<cmd:" + mySeq + ">>>\n" + command + "\n")
                    .getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return "send failed: " + e.getMessage();
        }

        String begin = "<<<begin:" + mySeq + ">>>";
        String done = "<<<done:" + mySeq + ">>>";
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            String all = readAll(outFile);
            int b = all.indexOf(begin);
            if (b >= 0) {
                int d = all.indexOf(done, b + begin.length());
                if (d >= 0) {
                    String body = all.substring(b + begin.length(), d).trim();
                    int eol = all.indexOf('\n', d);
                    String tail = eol >= 0
                            ? all.substring(d, eol).trim()
                            : all.substring(d).trim();
                    return body.isEmpty() ? "[" + tail + "]" : body + "\n[" + tail + "]";
                }
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                return "(interrupted)";
            }
        }
        return "(no response - root console not running? reroot to start it)";
    }

    private static String readAll(File f) {
        try (FileInputStream in = new FileInputStream(f)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}
