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

import java.util.ArrayList;
import java.util.List;

/**
 * Набори маршрутів (з import-політик WHOIS), які ми приймаємо від одного peer-а.
 * Будується з рядків mp-import / import запису SELF_AS.
 *
 * Зберігається саме список наборів, а не один рядок: RPSL дозволяє
 * {@code accept AS-A OR AS-B}, і раніше другий набір мовчки губився.
 */
public class WhoisPolicy {

    /** Позначка «приймаємо все» — RPSL {@code accept ANY}. */
    public static final List<String> ANY = List.of("ANY");

    private final long peerAs;
    private List<String> ipv4Sets = List.of();
    private List<String> ipv6Sets = List.of();

    public WhoisPolicy(long peerAs) {
        this.peerAs = peerAs;
    }

    public long getPeerAs() {
        return peerAs;
    }

    /** Набори для заданого сімейства адрес; порожній список — запису немає. */
    public List<String> getAcceptSets(AddressFamily af) {
        return af.isV6() ? ipv6Sets : ipv4Sets;
    }

    /**
     * Об'єднує нові набори з уже наявними для цього сімейства адрес.
     *
     * Кілька рядків import від одного peer-а (напр. для різних точок стику)
     * дають об'єднання: приймаємо все, що дозволяє будь-який із них.
     * Раніше спрацьовувало «перший виграв», і решта мовчки відкидалась.
     */
    void merge(AddressFamily af, List<String> sets) {
        if (sets.isEmpty()) {
            return;
        }
        List<String> current = getAcceptSets(af);
        List<String> merged;
        if (isAny(sets) || isAny(current)) {
            merged = ANY;
        } else {
            merged = new ArrayList<>(current);
            for (String s : sets) {
                if (merged.stream().noneMatch(x -> x.equalsIgnoreCase(s))) {
                    merged.add(s);
                }
            }
            merged = List.copyOf(merged);
        }
        if (af.isV6()) {
            ipv6Sets = merged;
        } else {
            ipv4Sets = merged;
        }
    }

    /** true, якщо набір означає {@code accept ANY} (фільтр не потрібен). */
    public static boolean isAny(List<String> sets) {
        return sets.size() == 1 && "ANY".equalsIgnoreCase(sets.get(0));
    }

    /** Людиночитне подання набору: {@code "AS-A OR AS-B"}. */
    public static String format(List<String> sets) {
        return sets.isEmpty() ? "(none)" : String.join(" OR ", sets);
    }

    @Override
    public String toString() {
        return "AS" + peerAs + " [v4=" + format(ipv4Sets) + ", v6=" + format(ipv6Sets) + "]";
    }
}
