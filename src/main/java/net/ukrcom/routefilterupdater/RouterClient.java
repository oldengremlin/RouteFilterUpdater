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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/**
 * Junos-specific SSH operations: reading BGP neighbor config and applying filters.
 */
public class RouterClient implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(RouterClient.class);

    private final SshClient ssh;
    private final String host;
    private final String username;
    private final String password;

    public RouterClient(String host, String username, String password) {
        this.ssh = new SshClient();
        this.host = host;
        this.username = username;
        this.password = password;
    }

    public void connect() throws Exception {
        ssh.connect(host, username, password);
    }

    // -------------------------------------------------------------------------
    // Read neighbors
    // -------------------------------------------------------------------------
    /**
     * Fetches BGP neighbor list from the router with a single SSH exec command:
     *   show configuration protocols bgp group <GROUP>
     *     | display set | match "(import|peer-as)" | except "<EXCEPT_REGEX>"
     *
     * Returns deduplicated BgpNeighbor list (one entry per neighbor IP).
     * @param bgpGroup
     * @param exceptRegex
     * @return 
     * @throws java.lang.Exception
     */
    public List<BgpNeighbor> getNeighbors(String bgpGroup, String exceptRegex) throws Exception {
        String cmd = buildNeighborCommand(bgpGroup, exceptRegex);
        log.info("Fetching neighbors: group='{}'", bgpGroup);
        log.debug("Command: {}", cmd);
        String output = ssh.executeCommand(cmd, 30);
        return parseNeighbors(output, bgpGroup);
    }

    private String buildNeighborCommand(String bgpGroup, String exceptRegex) {
        String cmd = "show configuration protocols bgp group " + bgpGroup
                + " | display set | match \"(import|peer-as)\"";
        if (exceptRegex != null && !exceptRegex.isBlank()) {
            cmd += " | except \"" + exceptRegex + "\"";
        }
        return cmd;
    }

    private List<BgpNeighbor> parseNeighbors(String output, String bgpGroup) {
        Pattern importPat = Pattern.compile(
                "set protocols bgp group \\S+ neighbor (\\S+) import (\\S+)");
        Pattern peerAsPat = Pattern.compile(
                "set protocols bgp group \\S+ neighbor (\\S+) peer-as (\\d+)");

        Map<String, String> importMap = new LinkedHashMap<>();
        Map<String, Long> peerAsMap = new LinkedHashMap<>();

        for (String line : output.split("\n")) {
            line = line.trim();
            Matcher m = importPat.matcher(line);
            if (m.find()) {
                importMap.putIfAbsent(m.group(1), m.group(2));
                continue;
            }
            m = peerAsPat.matcher(line);
            if (m.find()) {
                peerAsMap.putIfAbsent(m.group(1), Long.valueOf(m.group(2)));
            }
        }

        List<BgpNeighbor> neighbors = new ArrayList<>();
        for (var entry : importMap.entrySet()) {
            String ip = entry.getKey();
            String policy = entry.getValue();
            Long peerAs = peerAsMap.get(ip);
            if (peerAs == null) {
                log.warn("No peer-as for {} (import {}), skipping", ip, policy);
                continue;
            }
            neighbors.add(new BgpNeighbor(ip, peerAs, policy));
        }

        log.info("Parsed {} neighbors from group '{}'", neighbors.size(), bgpGroup);
        return neighbors;
    }

    // -------------------------------------------------------------------------
    // Apply configuration
    // -------------------------------------------------------------------------
    /**
     * Applies Junos-format filter configuration (bgpq4 -J output) to the router using:
     *   configure private → load merge terminal → [paste] → show | compare → commit and-quit
     *
     * Returns the cleaned "show | compare" output.
     * @param filtersContent
     * @return 
     * @throws java.lang.Exception
     */
    public String applyFilters(String filtersContent) throws Exception {
        log.info("Opening shell to apply configuration on {}", host);
        ssh.openShell();
        try {
            ssh.waitForPrompt("operational", 30_000);

            ssh.sendLine("configure private");
            ssh.waitForPrompt("config", 30_000);
            log.info("Entered configure private mode");

            ssh.sendLine("load merge terminal");
            ssh.waitForString("\\[Type \\^D", 10_000);
            log.info("Sending filter configuration ({} bytes)", filtersContent.length());

            ssh.sendRaw(filtersContent.getBytes(StandardCharsets.UTF_8));
            if (!filtersContent.endsWith("\n")) {
                ssh.sendRaw("\n".getBytes(StandardCharsets.UTF_8));
            }
            ssh.sendRaw(new byte[]{0x04}); // Ctrl+D — end of input
            ssh.waitForPrompt("config", 30_000);
            log.info("Configuration loaded");

            ssh.sendLine("show | compare | no-more");
            String compareOutput = ssh.waitForPrompt("config", 60_000);

            ssh.sendLine("commit and-quit");
            try {
                ssh.waitForCommit(120_000);
                log.info("Committed successfully");
            } catch (IOException commitEx) {
                log.error("Commit failed: {}", commitEx.getMessage());
                // Router stayed in configure mode — roll back and exit cleanly
                try {
                    ssh.sendLine("rollback 0");
                    ssh.waitForPrompt("config", 15_000);
                    ssh.sendLine("exit");
                    ssh.waitForPrompt("operational", 15_000);
                    log.info("Rolled back and exited configure mode");
                } catch (IOException recoveryEx) {
                    log.warn("Recovery (rollback/exit) also failed: {}", recoveryEx.getMessage());
                }
                throw commitEx;
            }

            return cleanOutput(compareOutput, username);
        } finally {
            ssh.closeShell();
        }
    }

    private static String cleanOutput(String raw, String username) {
        StringBuilder sb = new StringBuilder();
        for (String line : raw.split("\n")) {
            line = line.replaceAll(
                    "[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]|[\\x1B]\\[[0-9;]*[a-zA-Z]", ""
            ).trim();
            if (!line.isBlank() && !line.matches(Pattern.quote(username) + "@[^>#]+[>#].*")) {
                sb.append(line).append("\n");
            }
        }
        String result = sb.toString().trim();
        return result.isEmpty() ? "No configuration changes detected." : result;
    }

    @Override
    public void close() {
        ssh.close();
    }
}
