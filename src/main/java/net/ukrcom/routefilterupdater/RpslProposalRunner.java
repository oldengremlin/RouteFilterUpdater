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
 * Автономна перевірка узгодженості RPSL (--rpsl-proposal).
 *
 * Для кожного активного BGP-сусіда в налаштованій групі:
 *   1. що ми приймаємо від цього peer-а (наша import-політика в WHOIS SELF_AS)
 *   2. що peer оголошує в наш бік (WHOIS peer-а)
 *   3. збіг       → тиша
 *   4. розбіжність → поточний набір + пропозиція оновленого mp-import
 *   5. peer ANY    → попередження
 *   6. немає export → повідомлення
 *
 * Вивід іде лише в stdout; для збереження у файл користуйтесь перенаправленням оболонки.
 * Дедуплікація за peerAs (а не за importPolicy) — щоб не робити зайвих запитів.
 */
public class RpslProposalRunner {

    private static final Logger log = LoggerFactory.getLogger(RpslProposalRunner.class);

    private final Config config;
    private final WhoisFetcher whoisFetcher;

    public RpslProposalRunner(Config config, WhoisFetcher whoisFetcher) {
        this.config = config;
        this.whoisFetcher = whoisFetcher;
    }

    /**
     * @return true, якщо виявлено розбіжності або помилки (для коду виходу)
     */
    public boolean run(AddressFamily af) throws Exception {
        Map<Long, WhoisPolicy> selfPolicies = whoisFetcher.fetchSelfAsPolicies(config.selfAs);
        List<BgpNeighbor> neighbors = NeighborLoader.load(config, af);

        // Один запит на peer AS, а не на кожну import-політику
        Map<Long, BgpNeighbor> asnToNeighbor = new LinkedHashMap<>();
        for (BgpNeighbor n : neighbors) {
            asnToNeighbor.putIfAbsent(n.peerAs(), n);
        }

        int concurrency = whoisFetcher.recommendedConcurrency();
        log.info("Checking RPSL consistency for {} peers ({}), up to {} in parallel...",
                asnToNeighbor.size(), af.label(), concurrency);

        List<PeerOutcome> outcomes = check(asnToNeighbor, selfPolicies, af, concurrency);

        int matched = 0, mismatched = 0, warnings = 0, noExport = 0, errors = 0;
        for (PeerOutcome o : outcomes) {
            switch (o.kind()) {
                case MATCH -> {
                    log.debug("  {} — OK ({})", o.header(), WhoisPolicy.format(o.ourAccept()));
                    matched++;
                }
                case MISMATCH -> {
                    System.out.printf("%s[MISMATCH]  %s%n", o.privateTag(), o.header());
                    System.out.printf("  our import:   %s%n", WhoisPolicy.format(o.ourAccept()));
                    System.out.printf("  peer exports: %s%n", WhoisPolicy.format(o.peerExport()));
                    System.out.printf("  proposed: %s%n%n", proposal(af, o));
                    mismatched++;
                }
                case MISSING -> {
                    System.out.printf("%s[MISSING]   %s%n", o.privateTag(), o.header());
                    System.out.printf("  we have no %s import for this peer in AS%d WHOIS%n",
                            af.label(), config.selfAs);
                    System.out.printf("  peer exports: %s%n", WhoisPolicy.format(o.peerExport()));
                    System.out.printf("  proposed: %s%n%n", proposal(af, o));
                    mismatched++;
                }
                case ANY_WARNING -> {
                    System.out.printf("%s[WARNING]   %s%n", o.privateTag(), o.header());
                    System.out.printf("  peer exports ANY to AS%d — no specific prefix set declared%n%n",
                            config.selfAs);
                    warnings++;
                }
                case NO_EXPORT -> {
                    System.out.printf("%s[NO-EXPORT] %s%n", o.privateTag(), o.header());
                    System.out.printf("  peer has no %s export to AS%d in WHOIS%n%n",
                            af.label(), config.selfAs);
                    noExport++;
                }
                case UNSUPPORTED -> {
                    System.out.printf("%s[UNSUPPORTED] %s%n", o.privateTag(), o.header());
                    System.out.printf("  our %s import is not expressible for bgpq4: %s%n",
                            af.label(), o.error());
                    System.out.printf("  peer exports: %s%n", WhoisPolicy.format(o.peerExport()));
                    System.out.printf("  proposed: %s%n%n", proposal(af, o));
                    mismatched++;
                }
                case ERROR -> {
                    System.out.printf("%s[ERROR]     %s%n", o.privateTag(), o.header());
                    System.out.printf("  WHOIS lookup failed: %s%n%n", o.error());
                    errors++;
                }
            }
        }

        System.out.printf(
                "--- %s: %d checked, %d matched, %d mismatched/missing, %d ANY warnings, "
                + "%d no-export, %d errors%n",
                af.label(), asnToNeighbor.size(), matched, mismatched, warnings, noExport, errors);

        return mismatched > 0 || errors > 0;
    }

    private static String proposal(AddressFamily af, PeerOutcome o) {
        return String.format("mp-import: afi %s from AS%d accept %s",
                af.afi(), o.peerAs(), String.join(" OR ", o.peerExport()));
    }

    /** Паралельні запити з обмеженням; результати повертаються в порядку сусідів. */
    private List<PeerOutcome> check(Map<Long, BgpNeighbor> asnToNeighbor,
                                    Map<Long, WhoisPolicy> selfPolicies,
                                    AddressFamily af,
                                    int concurrency) throws Exception {
        Semaphore permits = new Semaphore(concurrency);
        List<PeerOutcome> outcomes = new ArrayList<>(asnToNeighbor.size());

        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<PeerOutcome>> futures = new ArrayList<>(asnToNeighbor.size());
            for (BgpNeighbor neighbor : asnToNeighbor.values()) {
                futures.add(exec.submit(() -> {
                    permits.acquire();
                    try {
                        return checkPeer(neighbor, selfPolicies, af);
                    } finally {
                        permits.release();
                    }
                }));
            }
            for (Future<PeerOutcome> f : futures) {
                outcomes.add(f.get());
            }
        }
        return outcomes;
    }

    private PeerOutcome checkPeer(BgpNeighbor neighbor, Map<Long, WhoisPolicy> selfPolicies,
                                  AddressFamily af) {
        long peerAs = neighbor.peerAs();
        String asName = whoisFetcher.fetchAsName(peerAs);

        WhoisPolicy wp = selfPolicies.get(peerAs);
        List<String> ourAccept = (wp != null) ? wp.getAcceptSets(af) : List.of();

        List<String> peerExport;
        try {
            peerExport = whoisFetcher.fetchPeerExportToSelf(peerAs, config.selfAs, af);
        } catch (Exception e) {
            return new PeerOutcome(peerAs, neighbor, asName, Kind.ERROR,
                    ourAccept, List.of(), e.getMessage());
        }

        Kind kind;
        if (peerExport.isEmpty()) {
            kind = Kind.NO_EXPORT;
        } else if (WhoisPolicy.isAny(peerExport)) {
            kind = Kind.ANY_WARNING;
        } else if (wp != null && wp.getUnsupportedFilter(af) != null) {
            // Import у нас є, просто bgpq4 його не виражає — це не «немає запису»
            return new PeerOutcome(peerAs, neighbor, asName, Kind.UNSUPPORTED,
                    ourAccept, peerExport, wp.getUnsupportedFilter(af));
        } else if (ourAccept.isEmpty()) {
            kind = Kind.MISSING;
        } else if (FilterGenerator.sameSets(ourAccept, peerExport)) {
            kind = Kind.MATCH;
        } else {
            kind = Kind.MISMATCH;
        }
        return new PeerOutcome(peerAs, neighbor, asName, kind, ourAccept, peerExport, null);
    }

    /** RFC 6996: приватні діапазони 64512–65534 (16 біт) і 4200000000–4294967294 (32 біти). */
    private static boolean isPrivateAsn(long asn) {
        return (asn >= 64512 && asn <= 65534) || (asn >= 4_200_000_000L && asn <= 4_294_967_294L);
    }

    private enum Kind { MATCH, MISMATCH, MISSING, UNSUPPORTED, ANY_WARNING, NO_EXPORT, ERROR }

    private record PeerOutcome(long peerAs, BgpNeighbor neighbor, String asName, Kind kind,
                               List<String> ourAccept, List<String> peerExport, String error) {

        String header() {
            return "AS" + peerAs + " [" + neighbor.ip() + "]"
                    + (asName != null ? " " + asName : "");
        }

        String privateTag() {
            return isPrivateAsn(peerAs) ? "[PRIVATE]" : "";
        }
    }
}
