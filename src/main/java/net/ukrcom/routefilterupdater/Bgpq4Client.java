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
 * Invokes the bgpq4 binary to generate Junos-format route filters.
 *
 * Command template:
 *   bgpq4 -A -J -E [-6] [-S <sources>] -l <policyName>/<termName> <asSet>
 *
 * Flags used:
 *   -A  aggregate prefixes
 *   -J  JunOS output format
 *   -E  add replace: keyword (for load merge terminal)
 *   -6  IPv6 mode
 *   -S  comma-separated list of IRR databases (optional)
 *   -l  <policy-statement>/<term>  sets the JunOS policy-statement and term names
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

    /** Returns true if the bgpq4 binary exists and is executable. */
    public boolean isAvailable() {
        File f = new File(bgpq4Path);
        return f.exists() && f.canExecute();
    }

    /**
     * Generates a Junos policy-statement block for {@code asSet}.
     *
     * @param policyName  Junos policy-statement name (e.g. "Client_plf_SINHRON")
     * @param termName    Junos term name         (e.g. "accept")
     * @param asSet       AS number or AS-SET    (e.g. "AS-SYNCHRON" or "AS42545")
     * @param ipv6        true for IPv6 (-6 flag)
     * @return Junos config block ready for "load merge terminal", or empty string if no prefixes
     * @throws java.io.IOException
     * @throws java.lang.InterruptedException
     */
    public String generateFilter(String policyName, String termName,
                                 String asSet, boolean ipv6)
            throws IOException, InterruptedException {

        List<String> cmd = buildCommand(policyName, termName, asSet, ipv6);
        log.debug("bgpq4: {}", String.join(" ", cmd));

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line).append("\n");
            }
        }

        boolean finished = proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            throw new IOException("bgpq4 timed out for " + asSet);
        }

        if (proc.exitValue() != 0) {
            log.warn("bgpq4 exited with code {} for {}", proc.exitValue(), asSet);
        }

        String result = out.toString().trim();
        if (result.isEmpty()) {
            log.warn("bgpq4 returned empty result for {} ({})", asSet, ipv6 ? "IPv6" : "IPv4");
        }
        return result;
    }

    private List<String> buildCommand(String policyName, String termName,
                                      String asSet, boolean ipv6) {
        List<String> cmd = new ArrayList<>();
        cmd.add(bgpq4Path);
        cmd.add("-A");  // aggregate
        cmd.add("-J");  // JunOS format
        cmd.add("-E");  // replace: marker
        if (ipv6) {
            cmd.add("-6");
        }
        if (sources != null && !sources.isBlank()) {
            cmd.add("-S");
            cmd.add(sources);
        }
        cmd.add("-l");
        cmd.add(policyName + "/" + termName);
        cmd.add(asSet);
        return cmd;
    }
}
