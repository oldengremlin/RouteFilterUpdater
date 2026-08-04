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

import net.ukrcom.routefilterupdater.RpslFilterParser.FilterValue;
import net.ukrcom.routefilterupdater.RpslFilterParser.Kind;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тести рекурсивного спуску по виразу-фільтру RPSL (RFC 2622 §5.4, §5.6).
 */
class RpslFilterParserTest {

    private static FilterValue parse(String clause) {
        return RpslFilterParser.parse(clause);
    }

    private static List<String> sets(String clause) {
        return parse(clause).sets();
    }

    @Nested
    @DisplayName("пріоритет операторів")
    class Precedence {

        @Test
        @DisplayName("AND зв'язує сильніше за OR")
        void andBindsTighterThanOr() {
            // AS-A OR (AS-B AND NOT AS-C) → обидва набори
            assertEquals(List.of("AS-A", "AS-B"), sets("AS-A OR AS-B AND NOT AS-C"));
        }

        @Test
        @DisplayName("дужки змінюють групування: перетин двох наборів невиразний")
        void parenthesesChangeGrouping() {
            // (AS-A OR AS-B) AND AS-C — перетин, bgpq4 його не виражає.
            // Плаский сканер повертав би [AS-A, AS-B, AS-C], тобто ширше за політику.
            assertEquals(Kind.UNSUPPORTED, parse("(AS-A OR AS-B) AND AS-C").kind());
        }

        @Test
        @DisplayName("вкладені дужки розбираються рекурсивно")
        void nestedGroups() {
            assertEquals(List.of("AS-A", "AS-B", "AS-C"),
                    sets("((AS-A OR AS-B) OR (AS-C))"));
        }
    }

    @Nested
    @DisplayName("заперечення")
    class Negation {

        @Test
        @DisplayName("NOT нейтралізує свій операнд, не даючи внеску")
        void notIsNeutral() {
            assertEquals(List.of("AS-X"), sets("AS-X AND NOT fltr-martian"));
            assertEquals(List.of("AS-X"), sets("NOT fltr-martian AND AS-X"));
        }

        @Test
        @DisplayName("заперечений AS-SET не потрапляє в результат")
        void negatedSetExcluded() {
            assertEquals(List.of("AS-GOOD"), sets("NOT AS-BAD AND AS-GOOD"));
        }

        @Test
        @DisplayName("NOT над групою прибирає всю групу")
        void notOverGroup() {
            assertEquals(List.of("AS-C"), sets("NOT (AS-A OR AS-B) AND AS-C"));
        }

        @Test
        @DisplayName("подвійне заперечення теж нейтральне")
        void doubleNegation() {
            assertEquals(List.of("AS-X"), sets("NOT NOT AS-Y AND AS-X"));
        }

        @Test
        @DisplayName("NOT над невиразною конструкцією не псує решту")
        void notOverUnsupported() {
            assertEquals(List.of("AS-X"), sets("AS-X AND NOT { 192.0.2.0/24^24-32 }"));
        }
    }

    @Nested
    @DisplayName("ANY")
    class Any {

        @Test
        @DisplayName("ANY розпізнається")
        void plainAny() {
            assertEquals(Kind.ANY, parse("ANY").kind());
        }

        @Test
        @DisplayName("ANY із виключенням martian лишається ANY")
        void anyWithMartianExclusion() {
            assertEquals(Kind.ANY, parse("ANY AND NOT fltr-martian").kind());
        }

        @Test
        @DisplayName("ANY у диз'юнкції поглинає інші набори")
        void anyAbsorbsInOr() {
            assertEquals(Kind.ANY, parse("AS-A OR ANY").kind());
        }

        @Test
        @DisplayName("ANY у кон'юнкції звужується до конкретного набору")
        void anyNarrowedByAnd() {
            assertEquals(List.of("AS-A"), sets("ANY AND AS-A"));
        }

        @Test
        @DisplayName("заперечений ANY не є дозволом усього")
        void negatedAny() {
            assertNotEquals(Kind.ANY, parse("NOT ANY").kind());
        }
    }

    @Nested
    @DisplayName("EXCEPT")
    class Except {

        @Test
        @DisplayName("права частина віднімається")
        void rightSideSubtracted() {
            assertEquals(List.of("AS-A"), sets("AS-A EXCEPT AS-B"));
        }

        @Test
        @DisplayName("ланцюжок EXCEPT")
        void chained() {
            assertEquals(List.of("AS-A"), sets("AS-A EXCEPT AS-B EXCEPT AS-C"));
        }
    }

    @Nested
    @DisplayName("конструкції, невиразні для bgpq4")
    class Unsupported {

        @Test
        @DisplayName("список префіксів")
        void prefixList() {
            assertEquals(Kind.UNSUPPORTED, parse("{ 192.0.2.0/24^24-32 }").kind());
            assertEquals(Kind.UNSUPPORTED, parse("{}").kind());
        }

        @Test
        @DisplayName("regexp AS-path")
        void asPathRegexp() {
            assertEquals(Kind.UNSUPPORTED, parse("<^AS1 AS2+ AS3*$>").kind());
        }

        @Test
        @DisplayName("фільтр за community")
        void community() {
            assertEquals(Kind.UNSUPPORTED, parse("community(65000:1)").kind());
        }

        @Test
        @DisplayName("невиразність поширюється через OR — фільтр не генерується взагалі")
        void propagatesThroughOr() {
            assertEquals(Kind.UNSUPPORTED, parse("AS-A OR { 192.0.2.0/24 }").kind());
        }

        @Test
        @DisplayName("невиразність поширюється через AND")
        void propagatesThroughAnd() {
            assertEquals(Kind.UNSUPPORTED, parse("AS-A AND community(65000:1)").kind());
        }
    }

    @Nested
    @DisplayName("терми")
    class Terms {

        @Test
        @DisplayName("номер AS, as-set та ієрархічна назва")
        void names() {
            assertEquals(List.of("AS12345"), sets("AS12345"));
            assertEquals(List.of("AS-FOO"), sets("AS-FOO"));
            assertEquals(List.of("AS43180:AS-TRUNKNETWORKS"), sets("AS43180:AS-TRUNKNETWORKS"));
        }

        @Test
        @DisplayName("route-set передається в bgpq4 нарівні з as-set")
        void routeSet() {
            assertEquals(List.of("RS-CUSTOMERS"), sets("RS-CUSTOMERS"));
            assertEquals(List.of("AS12593:RS-CUSTOMERS"), sets("AS12593:RS-CUSTOMERS"));
        }

        @Test
        @DisplayName("суфікс діапазону довжин відкидається")
        void lengthRangeSuffix() {
            assertEquals(List.of("AS-FOO"), sets("AS-FOO^24-24"));
        }

        @Test
        @DisplayName("назва filter-set нейтральна")
        void filterSetName() {
            assertTrue(sets("fltr-unallocated").isEmpty());
        }

        @Test
        @DisplayName("дублікати згортаються без урахування регістру")
        void duplicates() {
            assertEquals(List.of("AS-A"), sets("AS-A OR as-a"));
        }

        @Test
        @DisplayName("порожній вираз")
        void empty() {
            assertTrue(sets("").isEmpty());
            assertTrue(sets("   ").isEmpty());
        }
    }

    @Nested
    @DisplayName("лексер")
    class Tokenizer {

        @Test
        @DisplayName("дужки груп — окремі токени")
        void groupParentheses() {
            assertEquals(List.of("(", "AS-A", "OR", "AS-B", ")"),
                    RpslFilterParser.tokenize("(AS-A OR AS-B)"));
        }

        @Test
        @DisplayName("список префіксів лишається цілим токеном")
        void prefixListStaysWhole() {
            assertEquals(List.of("{ 192.0.2.0/24, 198.51.100.0/24 }"),
                    RpslFilterParser.tokenize("{ 192.0.2.0/24, 198.51.100.0/24 }"));
        }

        @Test
        @DisplayName("виклик з аргументами лишається цілим токеном")
        void functionCallStaysWhole() {
            assertEquals(List.of("AS-A", "AND", "community(65000:1)"),
                    RpslFilterParser.tokenize("AS-A AND community(65000:1)"));
        }

        @Test
        @DisplayName("незакрита конструкція не зациклює лексер")
        void unbalancedDoesNotHang() {
            assertFalse(RpslFilterParser.tokenize("{ 192.0.2.0/24").isEmpty());
            assertFalse(RpslFilterParser.tokenize("<^AS1").isEmpty());
            assertEquals(List.of("AS-A"), sets("(AS-A"));
        }
    }
}
