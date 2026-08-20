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
 * Повертає повний текстовий звіт (для stdout і для email при -r), а не друкує його сам —
 * так само, як FilterGenerator повертає текст замість запису у файл.
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
     * Результат перевірки.
     *
     * @param report      повний текстовий звіт у форматі [MISMATCH]/[MISSING]/... з підсумком
     * @param hasProblems true, якщо виявлено розбіжності або помилки (для коду виходу й теми листа)
     */
    public record RpslProposalResult(String report, boolean hasProblems) {
    }

    public RpslProposalResult run(AddressFamily af) throws Exception {
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

        StringBuilder sb = new StringBuilder();
        int matched = 0, mismatched = 0, warnings = 0, noExport = 0, errors = 0;
        for (PeerOutcome o : outcomes) {
            switch (o.kind()) {
                case MATCH -> {
                    log.debug("  {} — OK ({})", o.header(), WhoisPolicy.format(o.ourAccept()));
                    matched++;
                }
                case MISMATCH -> {
                    sb.append(o.privateTag()).append("[MISMATCH]  ").append(o.header()).append('\n');
                    sb.append("  our import:   ").append(WhoisPolicy.format(o.ourAccept())).append('\n');
                    sb.append("  peer exports: ").append(WhoisPolicy.format(o.peerExport())).append('\n');
                    sb.append("  proposed: ").append(proposal(af, o)).append("\n\n");
                    mismatched++;
                }
                case MISSING -> {
                    sb.append(o.privateTag()).append("[MISSING]   ").append(o.header()).append('\n');
                    sb.append("  we have no ").append(af.label())
                            .append(" import for this peer in AS").append(config.selfAs)
                            .append(" WHOIS\n");
                    sb.append("  peer exports: ").append(WhoisPolicy.format(o.peerExport())).append('\n');
                    sb.append("  proposed: ").append(proposal(af, o)).append("\n\n");
                    mismatched++;
                }
                case ANY_WARNING -> {
                    sb.append(o.privateTag()).append("[WARNING]   ").append(o.header()).append('\n');
                    sb.append("  peer exports ANY to AS").append(config.selfAs)
                            .append(" — no specific prefix set declared\n\n");
                    warnings++;
                }
                case NO_EXPORT -> {
                    sb.append(o.privateTag()).append("[NO-EXPORT] ").append(o.header()).append('\n');
                    sb.append("  peer has no ").append(af.label()).append(" export to AS")
                            .append(config.selfAs).append(" in WHOIS\n\n");
                    noExport++;
                }
                case UNSUPPORTED -> {
                    sb.append(o.privateTag()).append("[UNSUPPORTED] ").append(o.header()).append('\n');
                    sb.append("  our ").append(af.label())
                            .append(" import is not expressible for bgpq4: ")
                            .append(o.error()).append('\n');
                    sb.append("  peer exports: ").append(WhoisPolicy.format(o.peerExport())).append('\n');
                    sb.append("  proposed: ").append(proposal(af, o)).append("\n\n");
                    mismatched++;
                }
                case ERROR -> {
                    sb.append(o.privateTag()).append("[ERROR]     ").append(o.header()).append('\n');
                    sb.append("  WHOIS lookup failed: ").append(o.error()).append("\n\n");
                    errors++;
                }
            }
        }

        sb.append(String.format(
                "--- %s: %d checked, %d matched, %d mismatched/missing, %d ANY warnings, "
                + "%d no-export, %d errors%n",
                af.label(), asnToNeighbor.size(), matched, mismatched, warnings, noExport, errors));

        return new RpslProposalResult(sb.toString(), mismatched > 0 || errors > 0);
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
