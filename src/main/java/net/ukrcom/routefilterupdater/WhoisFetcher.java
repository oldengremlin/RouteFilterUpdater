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
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.*;

/**
 * Запитує WHOIS (або локальну SQLite БД) і розбирає RPSL-політики.
 *
 * Підтримувані форми атрибутів (RFC 2622):
 * <pre>
 *   import:    from AS12345 accept AS-SOMETHING
 *   import:    from AS12345 at 1.2.3.4 action pref=100; accept AS12345
 *   mp-import: afi ipv4.unicast from AS12345 accept AS-X AND NOT fltr-martian
 *   mp-import: afi ipv4.unicast, ipv6.unicast from AS1 accept AS-X OR AS-Y
 *   export:    to AS12345 announce AS-OURS
 *   mp-export: afi ipv6.unicast to AS12345 announce AS-OURS-V6
 * </pre>
 *
 * Розбір навмисно не є одним монолітним регексом: рядок ділиться за ключовим
 * словом accept/announce, ліва частина дає afi та перелік peer-ів, права —
 * вираз-фільтр. Це дозволяє коректно обробляти список afi через кому,
 * клаузу {@code at} і кілька {@code from} в одному рядку.
 */
public class WhoisFetcher implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(WhoisFetcher.class);
    private static final int TIMEOUT_MS = 10_000;
    private static final int MAX_RETRIES = 3;

    /** Атрибут import / mp-import разом із тілом. */
    private static final Pattern IMPORT_ATTR = Pattern.compile(
            "^(mp-)?import:\\s*(.+)$", Pattern.CASE_INSENSITIVE);

    /** Атрибут export / mp-export разом із тілом. */
    private static final Pattern EXPORT_ATTR = Pattern.compile(
            "^(mp-)?export:\\s*(.+)$", Pattern.CASE_INSENSITIVE);

    /** Клауза afi перед from/to; значення може бути списком через кому. */
    private static final Pattern AFI_CLAUSE = Pattern.compile(
            "\\bafi\\s+(.+?)\\s+(?=\\b(?:from|to)\\b)", Pattern.CASE_INSENSITIVE);

    /** Кожен peer у лівій частині: from AS123 / to AS123. */
    private static final Pattern PEER_AS = Pattern.compile(
            "\\b(?:from|to)\\s+AS(\\d+)", Pattern.CASE_INSENSITIVE);

    /** Ідентифікатор AS/AS-SET, можливо з суфіксом діапазону довжин (AS-FOO^24-24). */
    private static final Pattern AS_TOKEN = Pattern.compile(
            "^(AS[\\w:-]+?)(?:\\^[\\d-]+)?$", Pattern.CASE_INSENSITIVE);

    private final String server;
    private final String sqlitePath; // null → лише живий WHOIS

    /** Кеш сирих RPSL-блоків за номером AS — один AS запитується не більше разу за запуск. */
    private final Map<Long, String> blockCache = new ConcurrentHashMap<>();

    /** Спільне з'єднання з SQLite; відкривається лениво, доступ серіалізовано. */
    private final Object dbLock = new Object();
    private Connection dbConnection;

    public WhoisFetcher(String server, String sqlitePath) {
        this.server = server;
        this.sqlitePath = sqlitePath;
    }

    /**
     * Скільки запитів має сенс виконувати паралельно.
     * Локальна БД витримує багато, живий WHOIS ріже за rate limit.
     */
    public int recommendedConcurrency() {
        return sqlitePath != null ? 8 : 3;
    }

    // -------------------------------------------------------------------------
    // Публічний API
    // -------------------------------------------------------------------------
    /**
     * Запитує запис SELF_AS і повертає мапу peerAs → WhoisPolicy.
     * @param selfAs
     * @return
     * @throws java.io.IOException
     */
    public Map<Long, WhoisPolicy> fetchSelfAsPolicies(long selfAs) throws IOException {
        log.info("Querying {} for AS{}",
                sqlitePath != null ? "SQLite (" + sqlitePath + ")" : "WHOIS (" + server + ")",
                selfAs);
        Map<Long, WhoisPolicy> result = parsePolicies(getAsBlock(selfAs));
        log.info("WHOIS: found import policies for {} peer ASes", result.size());
        if (log.isDebugEnabled()) {
            result.forEach((as, pol) -> log.debug("  AS{}: {}", as, pol));
        }
        return result;
    }

    /**
     * Запитує WHOIS peer-а і повертає те, що він оголошує в наш бік.
     *
     * @param peerAs номер AS peer-а
     * @param selfAs наш номер AS (ціль "to" в RPSL peer-а)
     * @param af     сімейство адрес
     * @return список оголошених наборів; порожній — запису немає
     * @throws java.io.IOException при недоступності WHOIS
     */
    public List<String> fetchPeerExportToSelf(long peerAs, long selfAs, AddressFamily af)
            throws IOException {
        log.debug("Querying {} for AS{} export to AS{}",
                sqlitePath != null ? "SQLite" : "WHOIS", peerAs, selfAs);
        return parseExport(getAsBlock(peerAs), selfAs, af);
    }

    /**
     * Назва AS або null, якщо недоступна.
     * Читається лише з локальної SQLite (колонка asn.name) — без --sqlite завжди null,
     * щоб не робити зайвий мережевий запит на кожного peer-а.
     * @param asn
     * @return
     */
    public String fetchAsName(long asn) {
        if (sqlitePath == null) {
            return null;
        }
        try {
            synchronized (dbLock) {
                Connection conn = db();
                if (conn == null) {
                    return null;
                }
                try (PreparedStatement ps = conn.prepareStatement(
                        "SELECT name FROM asn WHERE asn = ? LIMIT 1")) {
                    ps.setLong(1, asn);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            String name = rs.getString("name");
                            return (name != null && !name.isBlank()) ? name.trim() : null;
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.debug("SQLite asn.name query failed for AS{}: {}", asn, e.getMessage());
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Розбір RPSL (package-private — покрито юніт-тестами)
    // -------------------------------------------------------------------------
    Map<Long, WhoisPolicy> parsePolicies(String whoisData) {
        Map<Long, WhoisPolicy> result = new LinkedHashMap<>();
        for (String line : joinContinuationLines(whoisData)) {
            Matcher attr = IMPORT_ATTR.matcher(line.trim());
            if (!attr.matches()) {
                continue;
            }
            boolean multiProtocol = attr.group(1) != null;
            PolicyClause pc = parseClause(attr.group(2), "accept", multiProtocol);
            if (pc == null) {
                continue;
            }
            for (long peerAs : pc.peers()) {
                WhoisPolicy pol = result.computeIfAbsent(peerAs, WhoisPolicy::new);
                for (AddressFamily af : pc.families()) {
                    pol.merge(af, pc.sets());
                }
            }
        }
        return result;
    }

    List<String> parseExport(String block, long selfAs, AddressFamily af) {
        List<String> result = new ArrayList<>();
        for (String line : joinContinuationLines(block)) {
            Matcher attr = EXPORT_ATTR.matcher(line.trim());
            if (!attr.matches()) {
                continue;
            }
            boolean multiProtocol = attr.group(1) != null;
            PolicyClause pc = parseClause(attr.group(2), "announce", multiProtocol);
            if (pc == null || !pc.families().contains(af) || !pc.peers().contains(selfAs)) {
                continue;
            }
            if (WhoisPolicy.isAny(pc.sets())) {
                return WhoisPolicy.ANY;
            }
            for (String s : pc.sets()) {
                if (result.stream().noneMatch(x -> x.equalsIgnoreCase(s))) {
                    result.add(s);
                }
            }
        }
        return List.copyOf(result);
    }

    /** Розібрана клауза політики: сімейства адрес, перелік peer-ів і набори маршрутів. */
    private record PolicyClause(Set<AddressFamily> families, List<Long> peers, List<String> sets) {
    }

    /**
     * Ділить тіло атрибута за ключовим словом (accept / announce) і розбирає обидві частини.
     * Повертає null, якщо ключового слова немає, peer-ів не знайдено або набір порожній.
     */
    private static PolicyClause parseClause(String body, String keyword, boolean multiProtocol) {
        Matcher kw = Pattern.compile("\\b" + keyword + "\\b", Pattern.CASE_INSENSITIVE).matcher(body);
        if (!kw.find()) {
            return null;
        }
        String left = body.substring(0, kw.start());
        String right = body.substring(kw.end());

        List<Long> peers = new ArrayList<>();
        Matcher pm = PEER_AS.matcher(left);
        while (pm.find()) {
            long as = Long.parseLong(pm.group(1));
            if (!peers.contains(as)) {
                peers.add(as);
            }
        }
        if (peers.isEmpty()) {
            return null;
        }

        List<String> sets = extractAcceptSets(right);
        if (sets.isEmpty()) {
            return null;
        }
        return new PolicyClause(parseAfi(left, multiProtocol), peers, sets);
    }

    /**
     * Визначає сімейства адрес із клаузи afi.
     * Без afi: {@code import:} — лише IPv4; {@code mp-import:} — обидва (RPSL default).
     */
    private static Set<AddressFamily> parseAfi(String left, boolean multiProtocol) {
        Matcher m = AFI_CLAUSE.matcher(left);
        if (!m.find()) {
            return multiProtocol
                    ? EnumSet.allOf(AddressFamily.class)
                    : EnumSet.of(AddressFamily.V4);
        }
        Set<AddressFamily> families = EnumSet.noneOf(AddressFamily.class);
        for (String entry : m.group(1).split("\\s*,\\s*")) {
            String e = entry.trim().toLowerCase(Locale.ROOT);
            if (e.startsWith("ipv4")) {
                families.add(AddressFamily.V4);
            } else if (e.startsWith("ipv6")) {
                families.add(AddressFamily.V6);
            } else if (e.startsWith("any")) {
                families.addAll(EnumSet.allOf(AddressFamily.class));
            }
        }
        return families.isEmpty() ? EnumSet.of(AddressFamily.V4) : families;
    }

    /**
     * Витягує набори AS/AS-SET із виразу-фільтра RPSL.
     *
     * Враховує заперечення: терм під {@code NOT} до результату не потрапляє.
     * Раніше сканувався перший AS-подібний токен, тож
     * {@code accept NOT AS-BAD AND AS-GOOD} повертало саме {@code AS-BAD} —
     * тобто фільтр будувався з того, що RPSL забороняє.
     *
     * <pre>
     *   "AS-SYNCHRON AND NOT fltr-martian"  → [AS-SYNCHRON]
     *   "NOT fltr-martian AND AS51475"      → [AS51475]
     *   "NOT AS-BAD AND AS-GOOD"            → [AS-GOOD]
     *   "AS-A OR AS-B"                      → [AS-A, AS-B]
     *   "NOT (AS-A OR AS-B) AND AS-C"       → [AS-C]
     *   "ANY"                               → [ANY]
     *   "fltr-unallocated"                  → []
     * </pre>
     */
    static List<String> extractAcceptSets(String clause) {
        List<String> out = new ArrayList<>();
        String[] tokens = clause.replace("(", " ( ").replace(")", " ) ").trim().split("\\s+");

        boolean negateNext = false;
        int depth = 0;
        int negatedGroupDepth = -1;

        for (String raw : tokens) {
            String t = raw.replaceAll("[,;]+$", "");
            if (t.isEmpty()) {
                continue;
            }
            if ("(".equals(t)) {
                depth++;
                if (negateNext && negatedGroupDepth < 0) {
                    negatedGroupDepth = depth;   // уся група під запереченням
                    negateNext = false;
                }
                continue;
            }
            if (")".equals(t)) {
                if (negatedGroupDepth == depth) {
                    negatedGroupDepth = -1;
                }
                depth--;
                continue;
            }
            if (negatedGroupDepth >= 0) {
                continue;                        // всередині NOT (...)
            }
            // EXCEPT — це віднімання (RFC 2622 §5.6: "A EXCEPT B" = A без B),
            // тож наступний терм виключається так само, як після NOT.
            if (t.equalsIgnoreCase("NOT") || t.equalsIgnoreCase("EXCEPT")) {
                negateNext = true;
                continue;
            }
            if (t.equalsIgnoreCase("AND") || t.equalsIgnoreCase("OR")) {
                continue;
            }
            // Далі — терм фільтра
            if (negateNext) {
                negateNext = false;              // заперечений терм пропускаємо
                continue;
            }
            if (t.equalsIgnoreCase("ANY")) {
                return WhoisPolicy.ANY;
            }
            Matcher m = AS_TOKEN.matcher(t);
            if (m.matches()) {
                String set = m.group(1);
                if (out.stream().noneMatch(x -> x.equalsIgnoreCase(set))) {
                    out.add(set);
                }
            }
        }
        return List.copyOf(out);
    }

    /**
     * RFC 2622 §2: рядок-продовження починається з пробілу, табуляції або '+'.
     * Об'єднує такі рядки в один логічний перед регекс-розбором.
     */
    static List<String> joinContinuationLines(String data) {
        List<String> logical = new ArrayList<>();
        StringBuilder current = null;
        for (String raw : data.split("\n")) {
            if (raw.isEmpty()) {
                if (current != null) {
                    logical.add(current.toString());
                    current = null;
                }
                continue;
            }
            char first = raw.charAt(0);
            if ((first == ' ' || first == '\t') && current != null) {
                current.append(' ').append(raw.trim());
            } else if (first == '+' && current != null) {
                String rest = raw.substring(1).trim();
                if (!rest.isEmpty()) {
                    current.append(' ').append(rest);
                }
            } else {
                if (current != null) {
                    logical.add(current.toString());
                }
                current = new StringBuilder(raw);
            }
        }
        if (current != null) {
            logical.add(current.toString());
        }
        return logical;
    }

    // -------------------------------------------------------------------------
    // Отримання даних: SQLite + fallback на живий WHOIS
    // -------------------------------------------------------------------------
    /**
     * Сирий RPSL-блок для заданого AS.
     * Спершу кеш, далі локальна БД (якщо задано --sqlite), далі живий WHOIS.
     */
    private String getAsBlock(long asn) throws IOException {
        String cached = blockCache.get(asn);
        if (cached != null) {
            log.debug("AS{} taken from in-memory cache", asn);
            return cached;
        }

        String block = null;
        if (sqlitePath != null) {
            block = queryLocalDb(asn);
            if (block != null) {
                log.debug("AS{} found in SQLite", asn);
            } else {
                log.info("AS{} not found in SQLite — falling back to WHOIS ({})", asn, server);
            }
        }
        if (block == null) {
            block = queryWithRetry("-r AS" + asn);
        }
        blockCache.putIfAbsent(asn, block);
        return block;
    }

    /** Блок aut-num з локальної БД або null, якщо запису немає чи БД недоступна. */
    private String queryLocalDb(long asn) {
        try {
            synchronized (dbLock) {
                Connection conn = db();
                if (conn == null) {
                    return null;
                }
                try (PreparedStatement ps = conn.prepareStatement(
                        "SELECT block FROM rpsl WHERE key = 'aut-num' AND UPPER(value) = UPPER(?)")) {
                    ps.setString(1, "AS" + asn);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            return rs.getString("block");
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.warn("SQLite query failed for AS{}: {} — falling back to WHOIS", asn, e.getMessage());
        }
        return null;
    }

    /**
     * Спільне з'єднання з SQLite (відкривається при першому зверненні).
     * Викликати лише під {@link #dbLock}.
     */
    private Connection db() {
        if (dbConnection == null) {
            try {
                dbConnection = DriverManager.getConnection("jdbc:sqlite:" + sqlitePath);
                dbConnection.setReadOnly(true);
            } catch (SQLException e) {
                log.warn("Cannot open SQLite DB {}: {} — using live WHOIS", sqlitePath, e.getMessage());
                dbConnection = null;
            }
        }
        return dbConnection;
    }

    @Override
    public void close() {
        synchronized (dbLock) {
            if (dbConnection != null) {
                try {
                    dbConnection.close();
                } catch (SQLException e) {
                    log.debug("Error closing SQLite connection: {}", e.getMessage());
                }
                dbConnection = null;
            }
        }
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
