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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Запускає bgpq4 для генерації маршрутних фільтрів у форматі Junos.
 *
 * Шаблон команди:
 *   bgpq4 -A -J -E [-6] [-S &lt;sources&gt;] -l &lt;policyName&gt;/&lt;termName&gt; &lt;asSet&gt;...
 *
 * Прапорці:
 *   -A  агрегація префіксів
 *   -J  формат JunOS
 *   -E  маркер replace: (для load merge terminal)
 *   -6  режим IPv6
 *   -S  список IRR-баз через кому (опційно)
 *   -l  &lt;policy-statement&gt;/&lt;term&gt; — назви policy-statement і терму
 */
public class Bgpq4Client {

    private static final Logger log = LoggerFactory.getLogger(Bgpq4Client.class);
    private static final int TIMEOUT_SECONDS = 60;

    private final String bgpq4Path;
    private final String sources;

    public Bgpq4Client(String bgpq4Path, String sources) {
        this.bgpq4Path = bgpq4Path;
        this.sources = sources;
    }

    /** true, якщо бінарник bgpq4 існує і виконуваний. */
    public static boolean isAvailable(String bgpq4Path) {
        File f = new File(bgpq4Path);
        return f.exists() && f.canExecute();
    }

    /**
     * Генерує Junos policy-statement для заданих наборів.
     *
     * Ненульовий код завершення трактується як помилка, а не попередження: bgpq4
     * може вивести частину префіксів і зірватись на IRR, а блок із {@code replace:}
     * замінив би повний список префіксів урізаним — це чорна діра для трафіку клієнта.
     *
     * @param policyName назва Junos policy-statement (напр. "Client_plf_SINHRON")
     * @param af         сімейство адрес (визначає прапорець -6 і назву терму)
     * @param asSets     номери AS / AS-SET (напр. ["AS-SYNCHRON"] або ["AS-A", "AS-B"])
     * @return Junos-блок, готовий до "load merge terminal"; порожній рядок — префіксів немає
     * @throws java.io.IOException якщо bgpq4 завершився з помилкою або не вклався в таймаут
     * @throws java.lang.InterruptedException
     */
    public String generateFilter(String policyName, AddressFamily af, List<String> asSets)
            throws IOException, InterruptedException {

        List<String> cmd = buildCommand(policyName, af, asSets);
        log.debug("bgpq4: {}", String.join(" ", cmd));

        // stderr читається окремо від stdout: раніше redirectErrorStream(true) зливав
        // діагностику bgpq4 у той самий потік, що потім ставав конфігурацією роутера.
        Process proc = new ProcessBuilder(cmd).start();

        StringBuilder out = new StringBuilder();
        StringBuilder err = new StringBuilder();
        Thread tOut = drainAsync(proc.getInputStream(), out);
        Thread tErr = drainAsync(proc.getErrorStream(), err);

        boolean finished = proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            // Примусове завершення закриває потоки й розблоковує читачів,
            // тому таймаут спрацьовує навіть якщо bgpq4 завис на IRR-запиті.
            proc.destroyForcibly();
            proc.waitFor();
        }
        tOut.join(5_000);
        tErr.join(5_000);

        String stderr = err.toString().trim();
        if (!finished) {
            throw new IOException("bgpq4 timed out after " + TIMEOUT_SECONDS + "s for "
                    + String.join(" ", asSets));
        }
        if (proc.exitValue() != 0) {
            throw new IOException("bgpq4 exited with code " + proc.exitValue()
                    + " for " + String.join(" ", asSets)
                    + (stderr.isEmpty() ? "" : ": " + stderr));
        }
        if (!stderr.isEmpty()) {
            log.warn("bgpq4 stderr for {}: {}", String.join(" ", asSets), stderr);
        }

        String result = out.toString().trim();
        if (result.isEmpty()) {
            log.warn("bgpq4 returned empty result for {} ({})",
                    String.join(" ", asSets), af.label());
        }
        return result;
    }

    /** Читає потік у фоні (віртуальний потік), щоб stdout і stderr не блокували один одного. */
    private static Thread drainAsync(InputStream stream, StringBuilder sink) {
        return Thread.ofVirtual().start(() -> {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    sink.append(line).append('\n');
                }
            } catch (IOException e) {
                // Потік закрито через destroyForcibly — очікувано при таймауті
                log.debug("Stream drain ended: {}", e.getMessage());
            }
        });
    }

    private List<String> buildCommand(String policyName, AddressFamily af, List<String> asSets) {
        List<String> cmd = new ArrayList<>();
        cmd.add(bgpq4Path);
        cmd.add("-A");  // агрегація
        cmd.add("-J");  // формат JunOS
        cmd.add("-E");  // маркер replace:
        if (af.isV6()) {
            cmd.add("-6");
        }
        if (sources != null && !sources.isBlank()) {
            cmd.add("-S");
            cmd.add(sources);
        }
        cmd.add("-l");
        cmd.add(policyName + "/" + af.termName());
        cmd.addAll(asSets);
        return cmd;
    }
}
