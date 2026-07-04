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

import org.apache.commons.net.whois.WhoisClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.*;
import java.util.*;
import java.util.regex.*;

/**
 * Queries a WHOIS server for the SELF_AS record and parses mp-import / import lines
 * to build a map of (peerAs → WhoisPolicy) indicating what each peer announces.
 *
 * Supported line formats:
 *   mp-import: afi ipv4.unicast from AS12345 accept AS-SOMETHING AND NOT fltr-martian
 *   mp-import: afi ipv6.unicast from AS12345 accept AS-SOMETHING-V6 AND NOT fltr-martian-v6
 *   import:    from AS12345 action pref=100; accept AS12345
 *
 * The accept-set token is the first token after "accept" that matches AS[...] or is "ANY".
 * Handles "accept NOT fltr-martian AND AS51475" by scanning all tokens, not just the first.
 */
public class WhoisFetcher {

    private static final Logger log = LoggerFactory.getLogger(WhoisFetcher.class);
    private static final int TIMEOUT_MS = 10_000;
    private static final int MAX_RETRIES = 3;

    private static final Pattern MP_IMPORT = Pattern.compile(
            "^mp-import:\\s+afi\\s+(ipv4|ipv6)\\.unicast\\s+from\\s+AS(\\d+)\\s+accept\\s+(.+)$",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PLAIN_IMPORT = Pattern.compile(
            "^import:\\s+from\\s+AS(\\d+)(?:\\s+action[^;]+;)?\\s+accept\\s+(.+)$",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern MP_EXPORT = Pattern.compile(
            "^mp-export:\\s+afi\\s+(ipv4|ipv6)\\.unicast\\s+to\\s+AS(\\d+)(?:\\s+action[^;]+;)?\\s+announce\\s+(.+)$",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PLAIN_EXPORT = Pattern.compile(
            "^export:\\s+to\\s+AS(\\d+)(?:\\s+action[^;]+;)?\\s+announce\\s+(.+)$",
            Pattern.CASE_INSENSITIVE);

    private final String server;
    private final String sqlitePath; // null → live WHOIS only

    public WhoisFetcher(String server, String sqlitePath) {
        this.server = server;
        this.sqlitePath = sqlitePath;
    }

    /**
     * Queries WHOIS for {@code selfAs} and returns a map of peerAs → WhoisPolicy.
     * The result is cached in-memory for the lifetime of this run.
     * @param selfAs
     * @return 
     * @throws java.io.IOException
     */
    public Map<Long, WhoisPolicy> fetchSelfAsPolicies(long selfAs) throws IOException {
        log.info("Querying {} for AS{}",
                sqlitePath != null ? "SQLite (" + sqlitePath + ")" : "WHOIS (" + server + ")",
                selfAs);
        String data = getAsBlock(selfAs);
        Map<Long, WhoisPolicy> result = parsePolicies(data);
        log.info("WHOIS: found import policies for {} peer ASes", result.size());
        if (log.isDebugEnabled()) {
            result.forEach((as, pol) -> log.debug("  AS{}: {}", as, pol));
        }
        return result;
    }

    // package-private for unit testing
    Map<Long, WhoisPolicy> parsePolicies(String whoisData) {
        Map<Long, WhoisPolicy> result = new LinkedHashMap<>();
        for (String line : whoisData.split("\n")) {
            parseImportLine(line.trim(), result);
        }
        return result;
    }

    private void parseImportLine(String line, Map<Long, WhoisPolicy> out) {
        Matcher m = MP_IMPORT.matcher(line);
        if (m.find()) {
            boolean v6 = "ipv6".equalsIgnoreCase(m.group(1));
            long peerAs = Long.parseLong(m.group(2));
            String accept = extractAcceptSet(m.group(3));
            if (accept != null) {
                applyToPolicy(out, peerAs, accept, v6);
            }
            return;
        }
        m = PLAIN_IMPORT.matcher(line);
        if (m.find()) {
            long peerAs = Long.parseLong(m.group(1));
            String accept = extractAcceptSet(m.group(2));
            if (accept != null) {
                applyToPolicy(out, peerAs, accept, false);
            }
        }
    }

    private static void applyToPolicy(Map<Long, WhoisPolicy> map,
                                      long peerAs, String acceptSet, boolean v6) {
        WhoisPolicy pol = map.computeIfAbsent(peerAs, WhoisPolicy::new);
        if (v6) {
            if (pol.getIpv6Set() == null) {
                pol.setIpv6Set(acceptSet);
            }
        } else {
            if (pol.getIpv4Set() == null) {
                pol.setIpv4Set(acceptSet);
            }
        }
    }

    /**
     * Extracts the AS / AS-SET identifier from the accept clause.
     * Returns "ANY" if the clause is a catch-all, or null if no AS identifier found.
     *
     * Examples:
     *   "AS-SYNCHRON AND NOT fltr-martian"       → "AS-SYNCHRON"
     *   "AS42545 AND NOT fltr-martian"            → "AS42545"
     *   "NOT fltr-martian AND AS51475"            → "AS51475"
     *   "AS43180:AS-TRUNKNETWORKS AND NOT …"      → "AS43180:AS-TRUNKNETWORKS"
     *   "ANY"                                     → "ANY"
     *   "fltr-unallocated"                        → null
     */
    static String extractAcceptSet(String clause) {
        for (String token : clause.trim().split("\\s+")) {
            if (token.equalsIgnoreCase("ANY")) {
                return "ANY";
            }
            if (token.matches("(?i)AS[\\w:-]+")) {
                return token;
            }
        }
        return null;
    }

    /**
     * Queries WHOIS for {@code peerAs} and finds what it announces to {@code selfAs}.
     *
     * Matches lines of the form:
     *   export:    to AS&lt;selfAs&gt; [action ...;] announce &lt;set&gt;           (IPv4)
     *   mp-export: afi ipv4.unicast to AS&lt;selfAs&gt; [action ...;] announce &lt;set&gt;
     *   mp-export: afi ipv6.unicast to AS&lt;selfAs&gt; [action ...;] announce &lt;set&gt;
     *
     * Returns the extracted announce set ("ANY", "AS-SOMETHING", …) or null if
     * no matching export line is found for the given address family.
     *
     * @param peerAs  AS number of the peer to query
     * @param selfAs  our own AS number (the "to" target in the peer's RPSL)
     * @param ipv6    true → look for IPv6 export, false → IPv4
     * @return announced set string, or null if not found
     * @throws java.io.IOException on WHOIS connectivity failure
     */
    public String fetchPeerExportToSelf(long peerAs, long selfAs, boolean ipv6) throws IOException {
        log.debug("Querying {} for AS{} export to AS{}",
                sqlitePath != null ? "SQLite" : "WHOIS", peerAs, selfAs);
        String data = getAsBlock(peerAs);
        for (String line : data.split("\n")) {
            line = line.trim();
            Matcher m = MP_EXPORT.matcher(line);
            if (m.find()) {
                boolean isV6 = "ipv6".equalsIgnoreCase(m.group(1));
                if (isV6 != ipv6) continue;
                if (Long.parseLong(m.group(2)) != selfAs) continue;
                return extractAcceptSet(m.group(3));
            }
            m = PLAIN_EXPORT.matcher(line);
            if (m.find()) {
                if (ipv6) continue; // plain export: is IPv4 only
                if (Long.parseLong(m.group(1)) != selfAs) continue;
                return extractAcceptSet(m.group(2));
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // SQLite + fallback logic
    // -------------------------------------------------------------------------

    /**
     * Returns the raw RPSL block for the given AS number.
     * If a SQLite DB path is configured: tries the local DB first;
     * falls back to live WHOIS when the record is absent or the DB is unreadable.
     * Without SQLite configured: goes directly to live WHOIS.
     */
    private String getAsBlock(long asn) throws IOException {
        if (sqlitePath != null) {
            String local = queryLocalDb(asn);
            if (local != null) {
                log.debug("AS{} found in SQLite", asn);
                return local;
            }
            log.info("AS{} not found in SQLite — falling back to WHOIS ({})", asn, server);
        }
        return queryWithRetry("-r AS" + asn);
    }

    /**
     * Queries the local SQLite DB for the aut-num block of the given AS.
     * Returns the block text, or null if not found or on any DB error.
     */
    private String queryLocalDb(long asn) {
        String url = "jdbc:sqlite:" + sqlitePath;
        try (Connection conn = DriverManager.getConnection(url);
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT block FROM rpsl WHERE key = 'aut-num' AND UPPER(value) = UPPER(?)")) {
            ps.setString(1, "AS" + asn);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("block");
                }
            }
        } catch (SQLException e) {
            log.warn("SQLite query failed for AS{}: {} — falling back to WHOIS", asn, e.getMessage());
        }
        return null;
    }

    // -------------------------------------------------------------------------
    private String queryWithRetry(String query) throws IOException {
        IOException last = null;
        for (int i = 1; i <= MAX_RETRIES; i++) {
            try {
                return doQuery(query);
            } catch (IOException e) {
                last = e;
                log.warn("WHOIS attempt {}/{} failed: {}", i, MAX_RETRIES, e.getMessage());
                if (i < MAX_RETRIES) {
                    sleep(1_000L * i);
                }
            }
        }
        throw last;
    }

    private String doQuery(String query) throws IOException {
        WhoisClient client = new WhoisClient();
        client.setDefaultTimeout(TIMEOUT_MS);
        client.connect(server);
        try {
            return client.query(query);
        } finally {
            try {
                client.disconnect();
            } catch (IOException ignored) {
            }
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
