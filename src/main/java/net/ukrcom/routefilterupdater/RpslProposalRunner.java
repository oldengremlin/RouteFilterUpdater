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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Standalone RPSL consistency checker (--rpsl-proposal).
 *
 * For each active BGP neighbor in the configured group:
 *   1. Look up what we accept from that peer (our SELF_AS import policy in WHOIS)
 *   2. Look up what the peer declares it exports to us (peer's WHOIS)
 *   3. If they match  → silent (no output)
 *   4. If mismatch    → print current accept set + proposed updated mp-import line
 *   5. If peer ANY    → print warning
 *   6. If no export   → print notice (peer has no export declaration for us)
 *
 * Output goes to stdout only; use shell redirection to capture to a file.
 * Deduplication is by peerAs (not importPolicy) to avoid redundant WHOIS queries.
 */
public class RpslProposalRunner {

    private static final Logger log = LoggerFactory.getLogger(RpslProposalRunner.class);

    private final Config config;
    private final WhoisFetcher whoisFetcher;

    public RpslProposalRunner(Config config, String sqlitePath) {
        this.config = config;
        this.whoisFetcher = new WhoisFetcher(config.whoisServer, sqlitePath);
    }

    public void run(boolean ipv6) throws Exception {
        String proto = ipv6 ? "IPv6" : "IPv4";
        String afi   = ipv6 ? "ipv6.unicast" : "ipv4.unicast";

        // Step 1: our own import policies from SELF_AS WHOIS
        Map<Long, WhoisPolicy> selfPolicies = whoisFetcher.fetchSelfAsPolicies(config.selfAs);

        // Step 2: active neighbors from router
        String routerHost = config.routerIp(ipv6);
        String bgpGroup   = config.bgpGroup(ipv6);
        if (bgpGroup.isBlank()) {
            throw new IllegalArgumentException("BGP_GROUP_IP" + (ipv6 ? "V6" : "V4") + " not configured");
        }

        List<BgpNeighbor> neighbors;
        try (RouterClient router = new RouterClient(routerHost, config.username, config.password)) {
            router.connect();
            neighbors = router.getNeighbors(bgpGroup, config.exceptRegex());
        }

        // Deduplicate by peerAs — one WHOIS query per peer AS, not per import policy
        Map<Long, BgpNeighbor> asnToNeighbor = new LinkedHashMap<>();
        for (BgpNeighbor n : neighbors) {
            asnToNeighbor.putIfAbsent(n.getPeerAs(), n);
        }

        log.info("Checking RPSL consistency for {} peers ({})...", asnToNeighbor.size(), proto);

        int matched = 0, mismatched = 0, warnings = 0, noExport = 0;

        for (var entry : asnToNeighbor.entrySet()) {
            long peerAs = entry.getKey();
            BgpNeighbor neighbor = entry.getValue();
            String asName = whoisFetcher.fetchAsName(peerAs);

            String privatePrefix = isPrivateAsn(peerAs) ? "[PRIVATE]" : "";
            String header = "AS" + peerAs + " [" + neighbor.getIp() + "]"
                    + (asName != null ? " " + asName : "");

            // Our accept set for this peer
            WhoisPolicy wp = selfPolicies.get(peerAs);
            String ourAccept = (wp != null) ? wp.getAcceptSet(ipv6) : null;

            // Peer's export declaration to us
            String peerExport = whoisFetcher.fetchPeerExportToSelf(peerAs, config.selfAs, ipv6);

            if (peerExport == null) {
                System.out.printf("%s[NO-EXPORT] %s%n", privatePrefix, header);
                System.out.printf("  peer has no %s export to AS%d in WHOIS%n%n", proto, config.selfAs);
                log.debug("  {} — no export declaration found", header);
                noExport++;
                continue;
            }

            if (peerExport.equalsIgnoreCase("ANY")) {
                System.out.printf("%s[WARNING]   %s%n", privatePrefix, header);
                System.out.printf("  peer exports ANY to AS%d — no specific prefix set declared%n%n",
                        config.selfAs);
                log.debug("  {} — peer exports ANY", header);
                warnings++;
                continue;
            }

            if (ourAccept == null) {
                // We have no import entry for this peer in our own WHOIS
                System.out.printf("%s[MISSING]   %s%n", privatePrefix, header);
                System.out.printf("  we have no %s import for this peer in AS%d WHOIS%n", proto, config.selfAs);
                System.out.printf("  peer exports: %s%n", peerExport);
                System.out.printf("  proposed: mp-import: afi %s from AS%d accept %s%n%n",
                        afi, peerAs, peerExport);
                log.debug("  {} — no import entry in our WHOIS", header);
                mismatched++;
                continue;
            }

            if (ourAccept.equalsIgnoreCase(peerExport)) {
                log.debug("  {} — OK ({})", header, ourAccept);
                matched++;
                continue;
            }

            // Mismatch: our import ≠ peer's export
            System.out.printf("%s[MISMATCH]  %s%n", privatePrefix, header);
            System.out.printf("  our import:   %s%n", ourAccept);
            System.out.printf("  peer exports: %s%n", peerExport);
            System.out.printf("  proposed: mp-import: afi %s from AS%d accept %s%n%n",
                    afi, peerAs, peerExport);
            log.debug("  {} — mismatch: us={} peer={}", header, ourAccept, peerExport);
            mismatched++;
        }

        System.out.printf("--- %s: %d checked, %d matched, %d mismatched/missing, %d ANY warnings, %d no-export%n",
                proto, asnToNeighbor.size(), matched, mismatched, warnings, noExport);
    }

    // RFC 6996: 64512–65534 (16-bit) and 4200000000–4294967294 (32-bit)
    private static boolean isPrivateAsn(long asn) {
        return (asn >= 64512 && asn <= 65534) || (asn >= 4_200_000_000L && asn <= 4_294_967_294L);
    }
}
