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

import java.util.*;
import java.util.ArrayList;

/**
 * Orchestrates filter generation:
 *
 * 1. Query WHOIS for SELF_AS → build peerAs → WhoisPolicy map (in-memory cache)
 * 2. SSH to router → parse BGP group neighbors (ip, peerAs, importPolicy)
 * 3. For each unique importPolicy:
 *    a. Look up peer's accepted AS/AS-SET in WHOIS map
 *    b. Skip if: no entry, family not configured, accept is ANY
 *    c. Call bgpq4 -AJEl <importPolicy>/accept <acceptSet>
 *    d. Append output to result
 *
 * Multiple neighbors sharing the same (peerAs, importPolicy) produce a single filter.
 */
public class FilterGenerator {

    private static final Logger log = LoggerFactory.getLogger(FilterGenerator.class);

    private final Config config;
    private final WhoisFetcher whoisFetcher;
    private final Bgpq4Client bgpq4;

    public FilterGenerator(Config config, String sqlitePath) {
        this.config = config;
        this.whoisFetcher = new WhoisFetcher(config.whoisServer, sqlitePath);
        this.bgpq4 = new Bgpq4Client(config.bgpq4Path, config.bgpq4Sources);
    }

    public GenerateResult generate(boolean ipv6, boolean strictRpsl, boolean strictRpslReverse)
            throws Exception {
        List<String> warnings = new ArrayList<>();

        // Step 1: WHOIS lookup for SELF_AS
        Map<Long, WhoisPolicy> policies = whoisFetcher.fetchSelfAsPolicies(config.selfAs);

        // Step 2: get neighbors from router
        String routerHost = config.routerIp(ipv6);
        String bgpGroup = config.bgpGroup(ipv6);

        // routerHost is always non-blank: routerIp(true) falls back to ROUTER_IP if ROUTER_IP_IPV6 is absent
        if (bgpGroup.isBlank()) {
            throw new IllegalArgumentException("BGP_GROUP_IP" + (ipv6 ? "V6" : "V4") + " not configured");
        }
        if (ipv6 && config.routerIpV6.isBlank()) {
            log.warn("ROUTER_IP_IPV6 not set — falling back to ROUTER_IP ({}) for IPv6 filter generation", routerHost);
        }

        List<BgpNeighbor> neighbors;
        try (RouterClient router = new RouterClient(routerHost, config.username, config.password)) {
            router.connect();
            neighbors = router.getNeighbors(bgpGroup, config.exceptRegex());
        }

        // Step 3: deduplicate by importPolicy; each unique policy gets one filter
        // (multiple IPs may share the same peerAs + importPolicy)
        Map<String, Long> policyToAs = new LinkedHashMap<>();
        for (BgpNeighbor n : neighbors) {
            policyToAs.putIfAbsent(n.getImportPolicy(), n.getPeerAs());
        }

        log.info("Generating {} unique filters ({})...", policyToAs.size(), ipv6 ? "IPv6" : "IPv4");
        StringBuilder output = new StringBuilder();
        int generated = 0, skipped = 0;

        for (var entry : policyToAs.entrySet()) {
            String importPolicy = entry.getKey();
            long peerAs = entry.getValue();

            WhoisPolicy wp = policies.get(peerAs);
            if (wp == null) {
                log.warn("  SKIP  {} — AS{} has no WHOIS import entry", importPolicy, peerAs);
                skipped++;
                continue;
            }

            String acceptSet = wp.getAcceptSet(ipv6);
            if (acceptSet == null) {
                log.warn("  SKIP  {} — AS{} has no {} accept set in WHOIS",
                        importPolicy, peerAs, ipv6 ? "IPv6" : "IPv4");
                skipped++;
                continue;
            }
            if (acceptSet.equalsIgnoreCase("ANY")) {
                log.info("  SKIP  {} — AS{} accepts ANY (permit-all, no prefix filter needed)",
                        importPolicy, peerAs);
                if (strictRpsl) {
                    warnings.add(String.format(
                            "WARNING: AS%d is described in your import policy as \"accept ANY\".%n"
                            + "No prefix filter generated for %s.%n"
                            + "Verify whether this is intentional or an incomplete RPSL description.",
                            peerAs, importPolicy));
                }
                skipped++;
                continue;
            }

            if (strictRpslReverse) {
                String peerExport = whoisFetcher.fetchPeerExportToSelf(peerAs, config.selfAs, ipv6);
                log.debug("  RPSL-REVERSE AS{}: peer export to AS{} = {}",
                        peerAs, config.selfAs, peerExport);
                if (peerExport == null) {
                    warnings.add(String.format(
                            "RPSL-REVERSE WARNING: AS%d has no export to AS%d in WHOIS.%n"
                            + "Your import policy expects \"%s\" — the peer's RPSL may be incomplete.",
                            peerAs, config.selfAs, acceptSet));
                } else if (!peerExport.equalsIgnoreCase(acceptSet)) {
                    warnings.add(String.format(
                            "RPSL-REVERSE WARNING: AS%d export to AS%d declares \"%s\""
                            + " but your import policy expects \"%s\".%n"
                            + "Verify that the RPSL records in both AS objects are consistent.",
                            peerAs, config.selfAs, peerExport, acceptSet));
                }
            }

            log.info("  GEN   {} ← AS{} ← {}", importPolicy, peerAs, acceptSet);
            String termName = ipv6 ? "accept_v6" : "accept";
            String filter = bgpq4.generateFilter(importPolicy, termName, acceptSet, ipv6);
            if (!filter.isBlank()) {
                output.append(filter).append("\n");
                generated++;
            } else {
                log.warn("  EMPTY {} ← {} — bgpq4 returned no prefixes", importPolicy, acceptSet);
                skipped++;
            }
        }

        log.info("Done: {} filters generated, {} skipped", generated, skipped);
        return new GenerateResult(output.toString(), List.copyOf(warnings));
    }
}
