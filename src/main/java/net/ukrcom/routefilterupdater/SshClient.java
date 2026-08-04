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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Низькорівневий SSH-клієнт поверх JSch.
 * Надає exec-канал для одиничних команд і інтерактивний shell-канал з розпізнаванням промптів.
 */
public class SshClient implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SshClient.class);
    private static final int CONNECT_TIMEOUT_MS = 10_000;

    private Session session;
    private String username;

    // Патерни промптів залежать лише від username, тож компілюються один раз при connect()
    private Pattern opPromptAtEnd;
    private Pattern cfgPromptAtEnd;
    private Pattern intermediatePrompt;
    private Pattern promptLine;

    // Стан shell-каналу
    private ChannelShell shellChannel;
    private InputStream shellIn;
    private OutputStream shellOut;

    // Декодер UTF-8 із власним станом: вивід читається довільними шматками,
    // і межа шматка може розрізати багатобайтову послідовність навпіл.
    // Незавершений «хвіст» переноситься у наступне читання через leftover.
    private CharsetDecoder decoder;
    private byte[] leftover = new byte[0];

    // -------------------------------------------------------------------------
    // Керування сесією
    // -------------------------------------------------------------------------
    public void connect(String host, String username, String password) throws JSchException {
        this.username = username;
        this.opPromptAtEnd = JunosOutput.operationalPromptAtEnd(username);
        this.cfgPromptAtEnd = JunosOutput.configPromptAtEnd(username);
        this.intermediatePrompt = JunosOutput.intermediatePrompt(username);
        this.promptLine = JunosOutput.promptLine(username);

        JSch jsch = new JSch();
        session = jsch.getSession(username, host, 22);
        session.setPassword(password);
        // TODO: замінити на перевірку known_hosts перед використанням поза довіреним сегментом
        session.setConfig("StrictHostKeyChecking", "no");
        session.setConfig("PreferredAuthentications", "password");
        session.setTimeout(CONNECT_TIMEOUT_MS);
        session.connect(CONNECT_TIMEOUT_MS);
        log.debug("SSH connected to {}@{}", username, host);
    }

    // -------------------------------------------------------------------------
    // Exec-канал (одна команда, повертає stdout)
    // -------------------------------------------------------------------------
    /**
     * Виконує команду й повертає її вивід.
     *
     * @throws IOException якщо команда не завершилася за {@code timeoutSeconds}.
     *         Раніше в цьому випадку мовчки повертався частковий вивід — обрізаний
     *         список сусідів виглядав як успішний результат.
     */
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
            boolean completed = false;

            while (System.currentTimeMillis() < deadline) {
                if (in.available() > 0) {
                    int n = in.read(buf);
                    if (n > 0) {
                        sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                    }
                } else if (ch.isClosed()) {
                    completed = true;
                    break;
                } else {
                    sleep(50);
                }
            }
            // Дочитуємо залишок, що встиг накопичитись у буфері
            while (in.available() > 0) {
                int n = in.read(buf);
                if (n > 0) {
                    sb.append(new String(buf, 0, n, StandardCharsets.UTF_8));
                }
            }

            if (!completed && !ch.isClosed()) {
                throw new IOException("Timeout (" + timeoutSeconds + "s) executing command: " + command);
            }
            int exit = ch.getExitStatus();
            if (exit > 0) {
                log.warn("Command exited with status {}: {}", exit, command);
            }
            return sb.toString();
        } finally {
            ch.disconnect();
        }
    }

    // -------------------------------------------------------------------------
    // Shell-канал (PTY / інтерактивний)
    // -------------------------------------------------------------------------
    public void openShell() throws JSchException, IOException {
        shellChannel = (ChannelShell) session.openChannel("shell");
        shellChannel.setPty(true);
        shellChannel.setPtyType("vt100");
        shellChannel.setPtySize(200, 50, 0, 0);

        shellIn = shellChannel.getInputStream();
        shellOut = shellChannel.getOutputStream();
        decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        leftover = new byte[0];

        shellChannel.connect(3_000);
        log.debug("Shell channel opened (PTY vt100 200x50)");
    }

    /** Надсилає рядок із завершенням CR+LF (Junos очікує саме \r\n).
     * @param command
     * @throws java.io.IOException */
    public void sendLine(String command) throws IOException {
        log.debug("→ {}", command.trim());
        sendRaw((command + "\r\n").getBytes(StandardCharsets.UTF_8));
    }

    /** Надсилає сирі байти (напр. Ctrl+D = 0x04 або великий блок конфігурації).
     * @param data
     * @throws java.io.IOException */
    public void sendRaw(byte[] data) throws IOException {
        shellOut.write(data);
        shellOut.flush();
    }

    /**
     * Чекає на промпт відповідного режиму Junos:
     *   "operational" → user@host&gt;
     *   "config"      → user@host#
     * @param mode
     * @param timeoutMs
     * @return
     * @throws java.io.IOException
     */
    public String waitForPrompt(String mode, int timeoutMs) throws IOException {
        Pattern target = "config".equals(mode) ? cfgPromptAtEnd : opPromptAtEnd;
        // Проміжні промпти всередині виводу пропускаємо, щоб не сплутати з фінальним
        return doWait(target, intermediatePrompt, timeoutMs, "prompt(" + mode + ")");
    }

    /**
     * Чекає, доки накопичений вивід не збігатиметься із заданим регексом.
     * Потрібно для не-промптових маркерів на кшталт "[Type ^D".
     * @param regex
     * @param timeoutMs
     * @return
     * @throws java.io.IOException
     */
    public String waitForString(String regex, int timeoutMs) throws IOException {
        Pattern target = Pattern.compile(regex, Pattern.DOTALL);
        return doWait(target, null, timeoutMs, regex);
    }

    /**
     * Після "commit and-quit" очікує на один із двох результатів:
     *   - промпт операційного режиму (&gt;) → коміт успішний, повертає накопичений вивід
     *   - промпт режиму конфігурації (#) разом з "error:" → коміт провалено, кидає IOException
     *   - таймаут → кидає IOException
     *
     * На відміну від waitForPrompt, тут не застосовується skipper: потрібно побачити
     * саме фінальний промпт, щоб визначити, в якому режимі лишився роутер.
     * @param timeoutMs
     * @return накопичений вивід у разі успіху
     * @throws java.io.IOException при провалі коміту або таймауті
     */
    public String waitForCommit(int timeoutMs) throws IOException {
        Pattern errMarker = Pattern.compile("(?m)^error:");

        long deadline = System.currentTimeMillis() + timeoutMs;
        StringBuilder acc = new StringBuilder();

        while (System.currentTimeMillis() < deadline) {
            String chunk = readAvailable();
            if (!chunk.isEmpty()) {
                chunk = JunosOutput.stripAnsi(chunk);
                acc.append(chunk);
                logChunk(chunk);
                String s = acc.toString();
                if (opPromptAtEnd.matcher(s).find()) {
                    log.debug("Commit: operational prompt detected (success)");
                    return s.trim();
                }
                if (cfgPromptAtEnd.matcher(s).find() && errMarker.matcher(s).find()) {
                    throw new IOException("Commit failed:\n" + extractCommitErrors(s));
                }
            } else {
                sleep(10);
            }
        }

        String tail = acc.length() > 500 ? "…" + acc.substring(acc.length() - 500) : acc.toString();
        log.warn("Timeout ({} ms) waiting for commit result\nLast output: [{}]", timeoutMs, tail);
        throw new IOException("Timeout waiting for commit result");
    }

    private String extractCommitErrors(String output) {
        StringBuilder sb = new StringBuilder();
        for (String line : output.split("\n")) {
            String clean = JunosOutput.stripAnsi(line).trim();
            if (clean.isBlank()) continue;
            if (promptLine.matcher(clean).matches()) continue;      // user@host> / user@host#
            if (JunosOutput.isModeIndicator(clean)) continue;       // {master}[edit]
            sb.append(clean).append("\n");
        }
        return sb.toString().trim();
    }

    // -------------------------------------------------------------------------
    // Внутрішнє
    // -------------------------------------------------------------------------
    private String doWait(Pattern target, Pattern skipper, int timeoutMs, String label)
            throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        StringBuilder acc = new StringBuilder();

        while (System.currentTimeMillis() < deadline) {
            String chunk = readAvailable();
            if (!chunk.isEmpty()) {
                chunk = JunosOutput.stripAnsi(chunk);
                if (skipper != null) {
                    Matcher m = skipper.matcher(chunk);
                    if (m.find()) {
                        chunk = m.replaceAll("");
                    }
                }
                acc.append(chunk);
                logChunk(chunk);
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

    private static void logChunk(String chunk) {
        if (log.isDebugEnabled() && chunk.length() > 1) {
            String tail = chunk.length() > 120 ? "…" + chunk.substring(chunk.length() - 120) : chunk;
            log.debug("← [{}]", tail.replace("\n", "↵").replace("\r", ""));
        }
    }

    /**
     * Читає доступні байти й декодує їх як UTF-8, зберігаючи незавершений
     * багатобайтовий «хвіст» до наступного виклику.
     */
    private String readAvailable() throws IOException {
        int avail = shellIn.available();
        if (avail <= 0) {
            return "";
        }
        byte[] buf = new byte[avail];
        int n = shellIn.read(buf);
        if (n <= 0) {
            return "";
        }

        ByteBuffer bb = ByteBuffer.allocate(leftover.length + n);
        bb.put(leftover).put(buf, 0, n).flip();
        CharBuffer cb = CharBuffer.allocate(leftover.length + n);
        decoder.decode(bb, cb, false);

        leftover = new byte[bb.remaining()];
        bb.get(leftover);
        cb.flip();
        return cb.toString();
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
