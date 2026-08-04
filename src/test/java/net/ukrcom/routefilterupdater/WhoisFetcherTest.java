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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тести розбору RPSL. Мережа не потрібна: всі методи розбору чисті.
 */
class WhoisFetcherTest {

    /** Парсер працює без мережі — сервер і шлях до БД тут не використовуються. */
    private final WhoisFetcher fetcher = new WhoisFetcher("whois.example.net", null);

    @Nested
    @DisplayName("extractAcceptSets")
    class ExtractAcceptSets {

        @Test
        @DisplayName("простий набір із виключенням martian")
        void simpleWithMartian() {
            assertEquals(List.of("AS-SYNCHRON"),
                    WhoisFetcher.extractAcceptSets("AS-SYNCHRON AND NOT fltr-martian"));
        }

        @Test
        @DisplayName("заперечення перед набором — набір іде першим у рядку")
        void negationFirst() {
            assertEquals(List.of("AS51475"),
                    WhoisFetcher.extractAcceptSets("NOT fltr-martian AND AS51475"));
        }

        @Test
        @DisplayName("заперечений AS-SET не потрапляє в результат")
        void negatedAsSetIsExcluded() {
            // Раніше повертало AS-BAD — тобто саме те, що RPSL забороняє
            assertEquals(List.of("AS-GOOD"),
                    WhoisFetcher.extractAcceptSets("NOT AS-BAD AND AS-GOOD"));
        }

        @Test
        @DisplayName("кілька наборів через OR зберігаються всі")
        void multipleSetsViaOr() {
            assertEquals(List.of("AS-A", "AS-B"),
                    WhoisFetcher.extractAcceptSets("AS-A OR AS-B"));
        }

        @Test
        @DisplayName("заперечена група в дужках пропускається цілком")
        void negatedParenthesizedGroup() {
            assertEquals(List.of("AS-C"),
                    WhoisFetcher.extractAcceptSets("NOT (AS-A OR AS-B) AND AS-C"));
        }

        @Test
        @DisplayName("ANY розпізнається як дозвіл усього")
        void any() {
            assertEquals(WhoisPolicy.ANY, WhoisFetcher.extractAcceptSets("ANY"));
            assertTrue(WhoisPolicy.isAny(WhoisFetcher.extractAcceptSets("ANY AND NOT fltr-martian")));
        }

        @Test
        @DisplayName("заперечений ANY не вважається дозволом усього")
        void negatedAny() {
            assertFalse(WhoisPolicy.isAny(WhoisFetcher.extractAcceptSets("NOT ANY")));
        }

        @Test
        @DisplayName("ієрархічна назва набору")
        void hierarchicalSet() {
            assertEquals(List.of("AS43180:AS-TRUNKNETWORKS"),
                    WhoisFetcher.extractAcceptSets("AS43180:AS-TRUNKNETWORKS AND NOT fltr-martian"));
        }

        @Test
        @DisplayName("суфікс діапазону довжин відкидається")
        void prefixLengthRangeSuffix() {
            assertEquals(List.of("AS-FOO"), WhoisFetcher.extractAcceptSets("AS-FOO^24-24"));
        }

        @Test
        @DisplayName("EXCEPT виключає наступний набір")
        void exceptSubtracts() {
            assertEquals(List.of("AS-A"), WhoisFetcher.extractAcceptSets("AS-A EXCEPT AS-B"));
        }

        @Test
        @DisplayName("вираз без жодного AS дає порожній результат")
        void noAsIdentifier() {
            assertTrue(WhoisFetcher.extractAcceptSets("fltr-unallocated").isEmpty());
            // Явний список префіксів не виражається аргументом bgpq4 — фільтр не генерується
            assertTrue(WhoisFetcher.extractAcceptSets("{ 192.0.2.0/24^24-32 }").isEmpty());
        }

        @Test
        @DisplayName("дублікати згортаються")
        void duplicatesCollapse() {
            assertEquals(List.of("AS-A"), WhoisFetcher.extractAcceptSets("AS-A OR as-a"));
        }
    }

    @Nested
    @DisplayName("parsePolicies")
    class ParsePolicies {

        @Test
        @DisplayName("mp-import розділяє IPv4 та IPv6")
        void separateFamilies() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies("""
                    aut-num:        AS12593
                    mp-import:      afi ipv4.unicast from AS59613 accept AS-UBNIX AND NOT fltr-martian
                    mp-import:      afi ipv6.unicast from AS59613 accept AS-UBNIX-V6 AND NOT fltr-martian-v6
                    """);
            assertEquals(List.of("AS-UBNIX"), p.get(59613L).getAcceptSets(AddressFamily.V4));
            assertEquals(List.of("AS-UBNIX-V6"), p.get(59613L).getAcceptSets(AddressFamily.V6));
        }

        @Test
        @DisplayName("список afi через кому застосовується до обох сімейств")
        void commaSeparatedAfiList() {
            // Раніше такий рядок не матчився взагалі й peer мовчки зникав
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies(
                    "mp-import: afi ipv4.unicast, ipv6.unicast from AS1 accept AS-X\n");
            assertEquals(List.of("AS-X"), p.get(1L).getAcceptSets(AddressFamily.V4));
            assertEquals(List.of("AS-X"), p.get(1L).getAcceptSets(AddressFamily.V6));
        }

        @Test
        @DisplayName("простий import: діє лише для IPv4")
        void plainImportIsV4Only() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies(
                    "import: from AS12345 action pref=100; accept AS12345\n");
            assertEquals(List.of("AS12345"), p.get(12345L).getAcceptSets(AddressFamily.V4));
            assertTrue(p.get(12345L).getAcceptSets(AddressFamily.V6).isEmpty());
        }

        @Test
        @DisplayName("клауза at не заважає розбору")
        void atClause() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies(
                    "import: from AS1 at 1.2.3.4 action pref=100; accept AS-X\n");
            assertEquals(List.of("AS-X"), p.get(1L).getAcceptSets(AddressFamily.V4));
        }

        @Test
        @DisplayName("кілька from в одному рядку дають кілька peer-ів")
        void multiplePeersInOneLine() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies(
                    "import: from AS1 from AS2 accept AS-X\n");
            assertEquals(List.of("AS-X"), p.get(1L).getAcceptSets(AddressFamily.V4));
            assertEquals(List.of("AS-X"), p.get(2L).getAcceptSets(AddressFamily.V4));
        }

        @Test
        @DisplayName("mp-import без afi застосовується до обох сімейств")
        void mpImportWithoutAfi() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies(
                    "mp-import: from AS1 accept AS-X\n");
            assertEquals(List.of("AS-X"), p.get(1L).getAcceptSets(AddressFamily.V4));
            assertEquals(List.of("AS-X"), p.get(1L).getAcceptSets(AddressFamily.V6));
        }

        @Test
        @DisplayName("рядок-продовження з пробілом приєднується до значення")
        void whitespaceContinuation() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies("""
                    mp-import:      afi ipv4.unicast from AS1
                                    accept AS-LONG-SET AND NOT fltr-martian
                    """);
            assertEquals(List.of("AS-LONG-SET"), p.get(1L).getAcceptSets(AddressFamily.V4));
        }

        @Test
        @DisplayName("рядок-продовження з '+' приєднується до значення")
        void plusContinuation() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies("""
                    mp-import:      afi ipv4.unicast from AS1 accept AS-A
                    +               OR AS-B
                    """);
            assertEquals(List.of("AS-A", "AS-B"), p.get(1L).getAcceptSets(AddressFamily.V4));
        }

        @Test
        @DisplayName("кілька import від одного peer-а об'єднуються, а не затираються")
        void multipleImportLinesMerge() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies("""
                    import: from AS1 at 10.0.0.1 accept AS-A
                    import: from AS1 at 10.0.0.2 accept AS-B
                    """);
            assertEquals(List.of("AS-A", "AS-B"), p.get(1L).getAcceptSets(AddressFamily.V4));
        }

        @Test
        @DisplayName("export не потрапляє в import-політики")
        void exportIsIgnored() {
            Map<Long, WhoisPolicy> p = fetcher.parsePolicies(
                    "mp-export: afi ipv4.unicast to AS1 announce AS-OURS\n");
            assertTrue(p.isEmpty());
        }
    }

    @Nested
    @DisplayName("parseExport")
    class ParseExport {

        private static final String BLOCK = """
                aut-num:        AS59613
                mp-export:      afi ipv4.unicast to AS12593 announce AS-UKRHUB
                mp-export:      afi ipv6.unicast to AS12593 announce AS-UKRHUB-v6
                mp-export:      afi ipv4.unicast to AS99999 announce AS-OTHER
                """;

        @Test
        @DisplayName("вибирає export для потрібного сімейства адрес")
        void picksCorrectFamily() {
            assertEquals(List.of("AS-UKRHUB"),
                    fetcher.parseExport(BLOCK, 12593L, AddressFamily.V4));
            assertEquals(List.of("AS-UKRHUB-v6"),
                    fetcher.parseExport(BLOCK, 12593L, AddressFamily.V6));
        }

        @Test
        @DisplayName("не плутає export до іншої AS")
        void ignoresOtherPeer() {
            assertEquals(List.of("AS-OTHER"),
                    fetcher.parseExport(BLOCK, 99999L, AddressFamily.V4));
            assertTrue(fetcher.parseExport(BLOCK, 99999L, AddressFamily.V6).isEmpty());
        }

        @Test
        @DisplayName("простий export діє лише для IPv4")
        void plainExportIsV4Only() {
            String block = "export: to AS12593 announce AS-OURS\n";
            assertEquals(List.of("AS-OURS"), fetcher.parseExport(block, 12593L, AddressFamily.V4));
            assertTrue(fetcher.parseExport(block, 12593L, AddressFamily.V6).isEmpty());
        }

        @Test
        @DisplayName("announce ANY розпізнається")
        void announceAny() {
            String block = "export: to AS12593 announce ANY\n";
            assertTrue(WhoisPolicy.isAny(fetcher.parseExport(block, 12593L, AddressFamily.V4)));
        }

        @Test
        @DisplayName("відсутній запис дає порожній список")
        void noRecord() {
            assertTrue(fetcher.parseExport(BLOCK, 55555L, AddressFamily.V4).isEmpty());
        }
    }

    @Nested
    @DisplayName("joinContinuationLines")
    class JoinContinuationLines {

        @Test
        @DisplayName("порожній рядок завершує логічний рядок")
        void blankLineSeparatesObjects() {
            List<String> lines = WhoisFetcher.joinContinuationLines("""
                    import: from AS1 accept AS-A

                    import: from AS2 accept AS-B
                    """);
            assertEquals(2, lines.size());
            assertEquals("import: from AS1 accept AS-A", lines.get(0));
        }

        @Test
        @DisplayName("продовження без попереднього рядка не приєднується до наступного")
        void orphanContinuation() {
            List<String> lines = WhoisFetcher.joinContinuationLines(
                    "   orphan tail\nimport: from AS1 accept AS-A\n");
            assertEquals(2, lines.size());
            assertEquals("import: from AS1 accept AS-A", lines.get(1));
        }
    }
}
