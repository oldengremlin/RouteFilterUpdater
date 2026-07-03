/*
 * Copyright 2025 olden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ukrcom.routefilterupdater;

import com.jcraft.jsch.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Low-level SSH client wrapping JSch.
 * Provides exec-channel commands and an interactive shell channel with prompt detection.
 */
public class SshClient implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SshClient.class);
    private static final int CONNECT_TIMEOUT_MS = 10_000;

    // Strips ANSI escape sequences and non-printable control characters from terminal output
    private static final String ANSI_STRIP
            = "[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]|[\\x1B]\\[[0-9;]*[a-zA-Z]";

    private Session session;
    private String username;

    // Shell channel state
    private ChannelShell shellChannel;
    private InputStream shellIn;
    private BufferedReader shellReader;
    private OutputStream shellRawOut;
    private BufferedWriter shellWriter;

    // -------------------------------------------------------------------------
    // Session management
    // -------------------------------------------------------------------------
    public void connect(String host, String username, String password) throws JSchException {
        this.username = username;
        JSch jsch = new JSch();
        session = jsch.getSession(username, host, 22);
        session.setPassword(password);
        // TODO: replace with known_hosts validation before production use
        session.setConfig("StrictHostKeyChecking", "no");
        session.setConfig("PreferredAuthentications", "password");
        session.setTimeout(CONNECT_TIMEOUT_MS);
        session.connect(CONNECT_TIMEOUT_MS);
        log.debug("SSH connected to {}@{}", username, host);
    }

    // -------------------------------------------------------------------------
    // Exec channel (single command, returns stdout)
    // -------------------------------------------------------------------------
    public String executeCommand(String command, int timeoutSeconds) throws JSchException, IOException {
        ChannelExec ch = (ChannelExec) session.openChannel("exec");
        ch.setCommand(command);
        ch.setErrStream(System.err);
        InputStream in = ch.getInputStream();
        ch.connect(3_000);
        try {
            long deadline = System.currentTimeMillis() + (long) timeoutSeconds * 1_000;
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[8192];
            while (System.currentTimeMillis() < deadline) {
                if (in.available() > 0) {
                    int n = in.read(buf);
                    if (n > 0) {
                        sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                    }
                } else if (ch.isClosed()) {
                    break;
                } else {
                    sleep(100);
                }
            }
            // drain
            while (in.available() > 0) {
                int n = in.read(buf);
                if (n > 0) {
                    sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                }
            }
            return sb.toString();
        } finally {
            ch.disconnect();
        }
    }

    // -------------------------------------------------------------------------
    // Shell channel (PTY / interactive)
    // -------------------------------------------------------------------------
    public void openShell() throws JSchException, IOException {
        shellChannel = (ChannelShell) session.openChannel("shell");
        shellChannel.setPty(true);
        shellChannel.setPtyType("vt100");
        shellChannel.setPtySize(200, 50, 0, 0);

        shellIn = shellChannel.getInputStream();
        shellReader = new BufferedReader(new InputStreamReader(shellIn, StandardCharsets.UTF_8));
        shellRawOut = shellChannel.getOutputStream();
        shellWriter = new BufferedWriter(new OutputStreamWriter(shellRawOut, StandardCharsets.UTF_8));

        shellChannel.connect(3_000);
        log.debug("Shell channel opened (PTY vt100 200x50)");
    }

    /** Send a line terminated with CR+LF (Junos expects \r\n).
     * @param command
     * @throws java.io.IOException */
    public void sendLine(String command) throws IOException {
        log.debug("→ {}", command.trim());
        shellWriter.write(command + "\r\n");
        shellWriter.flush();
    }

    /** Send raw bytes (e.g. Ctrl+D = 0x04, or large binary content).
     * @param data
     * @throws java.io.IOException */
    public void sendRaw(byte[] data) throws IOException {
        shellRawOut.write(data);
        shellRawOut.flush();
    }

    /**
     * Wait for a Junos mode prompt using the configured username:
     *   "operational" → user@host>
     *   "config"      → user@host#
     * @param mode
     * @param timeoutMs
     * @return 
     * @throws java.io.IOException
     */
    public String waitForPrompt(String mode, int timeoutMs) throws IOException {
        String promptRe = "config".equals(mode)
                          ? Pattern.quote(username) + "@[^#]+#\\s*"
                          : Pattern.quote(username) + "@[^>]+>\\s*";
        Pattern target = Pattern.compile("(?s)" + promptRe + "$", Pattern.DOTALL);
        // Skip intermediate prompts that appear mid-output (e.g. inside paged output)
        Pattern skipper = Pattern.compile(
                "(?s)^.*?" + Pattern.quote(username) + "@[^>#]+[>#](?![\\s\\r\\n]*$)",
                Pattern.DOTALL);
        return doWait(target, skipper, timeoutMs, "prompt(" + mode + ")");
    }

    /**
     * Wait until the accumulated output matches an arbitrary regex.
     * Useful for non-prompt markers like "[Type ^D".
     * @param regex
     * @param timeoutMs
     * @return 
     * @throws java.io.IOException
     */
    public String waitForString(String regex, int timeoutMs) throws IOException {
        Pattern target = Pattern.compile(regex, Pattern.DOTALL);
        return doWait(target, null, timeoutMs, regex);
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------
    private String doWait(Pattern target, Pattern skipper, int timeoutMs, String label)
            throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        StringBuilder acc = new StringBuilder();

        while (System.currentTimeMillis() < deadline) {
            String chunk = readAvailable();
            if (!chunk.isEmpty()) {
                chunk = chunk.replaceAll(ANSI_STRIP, "");
                if (skipper != null) {
                    Matcher m = skipper.matcher(chunk);
                    if (m.find()) {
                        chunk = m.replaceAll("");
                    }
                }
                acc.append(chunk);
                if (log.isDebugEnabled() && chunk.length() > 1) {
                    String tail = chunk.length() > 120 ? "…" + chunk.substring(chunk.length() - 120) : chunk;
                    log.debug("← [{}]", tail.replace("\n", "↵").replace("\r", ""));
                }
                if (target.matcher(acc.toString()).find()) {
                    log.debug("Pattern matched: {}", label);
                    return acc.toString().trim();
                }
            } else {
                sleep(10);
            }
        }

        String tail = acc.length() > 300 ? "…" + acc.substring(acc.length() - 300) : acc.toString();
        log.warn("Timeout ({} ms) waiting for: {}\nLast output: [{}]", timeoutMs, label, tail);
        throw new IOException("Timeout waiting for: " + label);
    }

    private String readAvailable() throws IOException {
        if (shellReader.ready()) {
            char[] buf = new char[16384];
            int n = shellReader.read(buf);
            return n > 0 ? new String(buf, 0, n) : "";
        }
        if (shellIn.available() > 0) {
            byte[] raw = new byte[shellIn.available()];
            int n = shellIn.read(raw);
            return n > 0 ? new String(raw, 0, n, StandardCharsets.UTF_8) : "";
        }
        return "";
    }

    public void closeShell() {
        if (shellChannel != null && !shellChannel.isClosed()) {
            shellChannel.disconnect();
            shellChannel = null;
        }
    }

    @Override
    public void close() {
        closeShell();
        if (session != null && session.isConnected()) {
            sleep(500);
            session.disconnect();
            log.debug("SSH disconnected");
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
