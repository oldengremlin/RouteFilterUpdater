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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

/**
 * Головна логіка генерації фільтрів:
 *
 * 1. Запит WHOIS для SELF_AS → мапа peerAs → WhoisPolicy
 * 2. SSH до роутера → список BGP-сусідів (ip, peerAs, importPolicy)
 * 3. Для кожної унікальної importPolicy паралельно:
 *    a. знайти набори peer-а в мапі WHOIS
 *    b. пропустити, якщо запису немає, сімейство не описане або accept ANY
 *    c. викликати bgpq4 і зібрати Junos-блок
 *
 * Кілька сусідів з однаковою importPolicy дають один фільтр.
 * Збій bgpq4 на одній політиці не зриває весь запуск: така політика лишається
 * без змін на роутері, а запуск завершується ненульовим кодом.
 */
public class FilterGenerator {

    private static final Logger log = LoggerFactory.getLogger(FilterGenerator.class);

    /**
     * Скільки процесів bgpq4 запускати одночасно. Робота суто I/O-bound (запити до IRR),
     * тож віртуальні потоки дешеві, але обмеження потрібне, щоб не отримати
     * rate limit від RADB і не плодити десятки процесів.
     */
    private static final int BGPQ4_CONCURRENCY = 6;

    private final Config config;
    private final WhoisFetcher whoisFetcher;
    private final Bgpq4Client bgpq4;

    public FilterGenerator(Config config, WhoisFetcher whoisFetcher) {
        this.config = config;
        this.whoisFetcher = whoisFetcher;
        this.bgpq4 = new Bgpq4Client(config.bgpq4Path, config.bgpq4Sources);
    }

    public GenerateResult generate(AddressFamily af, boolean strictRpsl, boolean strictRpslReverse)
            throws Exception {

        Map<Long, WhoisPolicy> policies = whoisFetcher.fetchSelfAsPolicies(config.selfAs);
        List<BgpNeighbor> neighbors = NeighborLoader.load(config, af);

        // Дедуплікація за importPolicy; перший сусід зберігається заради IP у заголовку
        Map<String, BgpNeighbor> policyToNeighbor = new LinkedHashMap<>();
        for (BgpNeighbor n : neighbors) {
            BgpNeighbor prev = policyToNeighbor.putIfAbsent(n.importPolicy(), n);
            if (prev != null && prev.peerAs() != n.peerAs()) {
                log.warn("Import policy '{}' is shared by AS{} and AS{} — using AS{}",
                        n.importPolicy(), prev.peerAs(), n.peerAs(), prev.peerAs());
            }
        }

        // Зі --strict-rpsl-reverse кожна політика тягне ще й WHOIS-запит. Якщо він піде
        // в живий WHOIS, шість паралельних з'єднань RADB рве — тому беремо менше з двох меж.
        int concurrency = strictRpslReverse
                ? Math.min(BGPQ4_CONCURRENCY, whoisFetcher.recommendedConcurrency())
                : BGPQ4_CONCURRENCY;

        log.info("Generating {} unique filters ({}), up to {} in parallel...",
                policyToNeighbor.size(), af.label(), concurrency);

        List<PolicyOutcome> outcomes = runInParallel(
                policyToNeighbor, policies, af, strictRpsl, strictRpslReverse, concurrency);

        // Збірка результату в порядку сусідів — щоб файл і диф читались передбачувано
        StringBuilder output = new StringBuilder();
        StringBuilder annotatedOutput = new StringBuilder();
        List<String> warnings = new ArrayList<>();
        int generated = 0, skipped = 0, failed = 0;

        for (PolicyOutcome o : outcomes) {
            warnings.addAll(o.warnings());
            switch (o.status()) {
                case GENERATED -> {
                    log.info("  GEN   {} ← AS{}{} ← {}",
                            o.importPolicy(), o.neighbor().peerAs(),
                            o.asName() != null ? " (" + o.asName() + ")" : "", o.detail());
                    output.append(o.filter()).append("\n");
                    annotatedOutput.append(header(o)).append("\n")
                            .append(o.filter()).append("\n");
                    generated++;
                }
                case SKIPPED -> {
                    log.info("  SKIP  {} — {}", o.importPolicy(), o.detail());
                    skipped++;
                }
                case FAILED -> {
                    log.error("  FAIL  {} — {}", o.importPolicy(), o.detail());
                    warnings.add(String.format(
                            "ERROR: filter generation failed for %s (AS%d).%n"
                            + "%s%nThe existing filter on the router was left unchanged.",
                            o.importPolicy(), o.neighbor().peerAs(), o.detail()));
                    failed++;
                }
            }
        }

        log.info("Done: {} generated, {} skipped, {} failed", generated, skipped, failed);
        return new GenerateResult(output.toString(), annotatedOutput.toString(),
                List.copyOf(warnings), generated, skipped, failed);
    }

    private static String header(PolicyOutcome o) {
        return "## AS" + o.neighbor().peerAs()
                + " [" + o.neighbor().ip() + "]"
                + (o.asName() != null ? " " + o.asName() : "");
    }

    /**
     * Виконує обробку політик паралельно, але повертає результати строго в порядку подачі.
     * Логування винесено назовні саме заради збереження порядку.
     */
    private List<PolicyOutcome> runInParallel(Map<String, BgpNeighbor> policyToNeighbor,
                                              Map<Long, WhoisPolicy> policies,
                                              AddressFamily af,
                                              boolean strictRpsl,
                                              boolean strictRpslReverse,
                                              int concurrency) throws Exception {
        Semaphore permits = new Semaphore(concurrency);
        List<PolicyOutcome> outcomes = new ArrayList<>(policyToNeighbor.size());

        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<PolicyOutcome>> futures = new ArrayList<>(policyToNeighbor.size());
            for (var entry : policyToNeighbor.entrySet()) {
                String importPolicy = entry.getKey();
                BgpNeighbor neighbor = entry.getValue();
                futures.add(exec.submit(() -> {
                    permits.acquire();
                    try {
                        return process(importPolicy, neighbor, policies, af,
                                strictRpsl, strictRpslReverse);
                    } finally {
                        permits.release();
                    }
                }));
            }
            for (Future<PolicyOutcome> f : futures) {
                outcomes.add(f.get());
            }
        }
        return outcomes;
    }

    /** Обробка однієї import-політики. Винятки не випускає — повертає статус FAILED. */
    private PolicyOutcome process(String importPolicy, BgpNeighbor neighbor,
                                  Map<Long, WhoisPolicy> policies, AddressFamily af,
                                  boolean strictRpsl, boolean strictRpslReverse) {
        long peerAs = neighbor.peerAs();
        List<String> warnings = new ArrayList<>();

        WhoisPolicy wp = policies.get(peerAs);
        if (wp == null) {
            return PolicyOutcome.skipped(importPolicy, neighbor,
                    "AS" + peerAs + " has no WHOIS import entry", warnings);
        }

        String unsupportedFilter = wp.getUnsupportedFilter(af);
        if (unsupportedFilter != null) {
            warnings.add(String.format(
                    "WARNING: AS%d %s import policy uses constructs bgpq4 cannot express: %s%n"
                    + "No filter generated for %s — the existing filter on the router"
                    + " was left unchanged.",
                    peerAs, af.label(), unsupportedFilter, importPolicy));
            return PolicyOutcome.skipped(importPolicy, neighbor,
                    "AS" + peerAs + " filter not expressible for bgpq4: " + unsupportedFilter,
                    warnings);
        }

        List<String> acceptSets = wp.getAcceptSets(af);
        if (acceptSets.isEmpty()) {
            return PolicyOutcome.skipped(importPolicy, neighbor,
                    "AS" + peerAs + " has no " + af.label() + " accept set in WHOIS", warnings);
        }

        if (WhoisPolicy.isAny(acceptSets)) {
            if (strictRpsl) {
                warnings.add(String.format(
                        "WARNING: AS%d is described in your import policy as \"accept ANY\".%n"
                        + "No prefix filter generated for %s.%n"
                        + "Verify whether this is intentional or an incomplete RPSL description.",
                        peerAs, importPolicy));
            }
            return PolicyOutcome.skipped(importPolicy, neighbor,
                    "AS" + peerAs + " accepts ANY (permit-all, no prefix filter needed)", warnings);
        }

        if (strictRpslReverse) {
            checkReverse(peerAs, af, acceptSets, warnings);
        }

        String asName = whoisFetcher.fetchAsName(peerAs);
        try {
            String filter = bgpq4.generateFilter(importPolicy, af, acceptSets);
            if (filter.isBlank()) {
                return PolicyOutcome.skipped(importPolicy, neighbor,
                        "bgpq4 returned no prefixes for " + WhoisPolicy.format(acceptSets), warnings);
            }
            return new PolicyOutcome(importPolicy, neighbor, asName, Status.GENERATED,
                    WhoisPolicy.format(acceptSets), filter, warnings);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return PolicyOutcome.failed(importPolicy, neighbor, "interrupted", warnings);
        } catch (Exception e) {
            return PolicyOutcome.failed(importPolicy, neighbor, e.getMessage(), warnings);
        }
    }

    /** Зворотна RPSL-перевірка: чи збігається export peer-а в наш бік з тим, що ми приймаємо. */
    private void checkReverse(long peerAs, AddressFamily af,
                              List<String> acceptSets, List<String> warnings) {
        List<String> peerExport;
        try {
            peerExport = whoisFetcher.fetchPeerExportToSelf(peerAs, config.selfAs, af);
        } catch (Exception e) {
            warnings.add(String.format(
                    "RPSL-REVERSE WARNING: could not query WHOIS for AS%d: %s",
                    peerAs, e.getMessage()));
            return;
        }
        log.debug("  RPSL-REVERSE AS{}: peer export to AS{} = {}",
                peerAs, config.selfAs, WhoisPolicy.format(peerExport));

        if (peerExport.isEmpty()) {
            warnings.add(String.format(
                    "RPSL-REVERSE WARNING: AS%d has no export to AS%d in WHOIS.%n"
                    + "Your import policy expects \"%s\" — the peer's RPSL may be incomplete.",
                    peerAs, config.selfAs, WhoisPolicy.format(acceptSets)));
        } else if (!sameSets(peerExport, acceptSets)) {
            warnings.add(String.format(
                    "RPSL-REVERSE WARNING: AS%d export to AS%d declares \"%s\""
                    + " but your import policy expects \"%s\".%n"
                    + "Verify that the RPSL records in both AS objects are consistent.",
                    peerAs, config.selfAs,
                    WhoisPolicy.format(peerExport), WhoisPolicy.format(acceptSets)));
        }
    }

    /** Порівняння наборів без урахування регістру та порядку. */
    static boolean sameSets(List<String> a, List<String> b) {
        if (a.size() != b.size()) {
            return false;
        }
        return a.stream().allMatch(x -> b.stream().anyMatch(y -> y.equalsIgnoreCase(x)));
    }

    private enum Status { GENERATED, SKIPPED, FAILED }

    /** Результат обробки однієї import-політики. */
    private record PolicyOutcome(String importPolicy, BgpNeighbor neighbor, String asName,
                                 Status status, String detail, String filter,
                                 List<String> warnings) {

        static PolicyOutcome skipped(String policy, BgpNeighbor n, String detail, List<String> w) {
            return new PolicyOutcome(policy, n, null, Status.SKIPPED, detail, null, w);
        }

        static PolicyOutcome failed(String policy, BgpNeighbor n, String detail, List<String> w) {
            return new PolicyOutcome(policy, n, null, Status.FAILED, detail, null, w);
        }
    }
}
