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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Рекурсивний спуск для виразу-фільтра RPSL (RFC 2622 §5.4, §5.6).
 *
 * <pre>
 *   filter  := andExpr (OR andExpr)*
 *   andExpr := unary ((AND | EXCEPT) unary)*      // AND зв'язує сильніше за OR
 *   unary   := NOT unary | primary
 *   primary := '(' filter ')' | term
 * </pre>
 *
 * Мета розбору вузька: визначити, які AS-SET / route-set передати в bgpq4.
 * Тому результат — не дерево, а згорнуте значення {@link FilterValue} з трьох станів:
 *
 * <ul>
 *   <li>{@code ANY} — приймаємо все, фільтр не потрібен</li>
 *   <li>{@code SETS} — перелік наборів для bgpq4 (порожній = нічого не витягнуто)</li>
 *   <li>{@code UNSUPPORTED} — вираз містить позитивне обмеження, яке bgpq4 не виражає
 *       (список префіксів, regexp AS-path, community). Фільтр не генерується взагалі —
 *       краще лишити наявний на роутері, ніж згенерувати ширший за політику.</li>
 * </ul>
 *
 * Заперечені підвирази ({@code NOT ...}, права частина {@code EXCEPT}) не дають
 * позитивного внеску й вважаються нейтральними: {@code AS-X AND NOT fltr-martian}
 * дає {@code [AS-X]}. Це свідоме спрощення — martian-фільтри на роутері
 * застосовуються окремо.
 */
final class RpslFilterParser {

    /** Стан згорнутого значення фільтра. */
    enum Kind { ANY, SETS, UNSUPPORTED }

    /** Результат розбору: стан і перелік наборів (непорожній лише для SETS). */
    record FilterValue(Kind kind, List<String> sets) {

        static final FilterValue ANY = new FilterValue(Kind.ANY, WhoisPolicy.ANY);
        static final FilterValue EMPTY = new FilterValue(Kind.SETS, List.of());
        static final FilterValue UNSUPPORTED = new FilterValue(Kind.UNSUPPORTED, List.of());

        boolean isEmpty() {
            return kind == Kind.SETS && sets.isEmpty();
        }
    }

    /** Номер AS, as-set або route-set; необов'язковий суфікс діапазону довжин (AS-FOO^24-24). */
    private static final Pattern SET_NAME = Pattern.compile(
            "^((?:AS|RS)[\\w:-]+?)(?:\\^[\\d-]+)?$", Pattern.CASE_INSENSITIVE);

    private final List<String> tokens;
    private int pos;

    private RpslFilterParser(List<String> tokens) {
        this.tokens = tokens;
    }

    static FilterValue parse(String clause) {
        return new RpslFilterParser(tokenize(clause)).parseTop();
    }

    // -------------------------------------------------------------------------
    // Граматика
    // -------------------------------------------------------------------------
    private FilterValue parseTop() {
        FilterValue value = parseOr();
        // Толерантність до залишку: зайві токени приєднуються через OR,
        // щоб частина виразу не зникла мовчки при нестандартному записі.
        while (pos < tokens.size()) {
            if (")".equals(peek())) {
                pos++;
                continue;
            }
            value = or(value, parseOr());
        }
        return value;
    }

    private FilterValue parseOr() {
        FilterValue left = parseAnd();
        while (matches("OR")) {
            left = or(left, parseAnd());
        }
        return left;
    }

    private FilterValue parseAnd() {
        FilterValue left = parseUnary();
        while (true) {
            if (matches("AND")) {
                left = and(left, parseUnary());
            } else if (matches("EXCEPT")) {
                parseUnary();   // права частина віднімається — позитивного внеску не дає
            } else {
                return left;
            }
        }
    }

    private FilterValue parseUnary() {
        if (matches("NOT")) {
            parseUnary();       // операнд заперечення споживається й відкидається
            return FilterValue.EMPTY;
        }
        return parsePrimary();
    }

    private FilterValue parsePrimary() {
        if (pos >= tokens.size()) {
            return FilterValue.EMPTY;
        }
        String t = tokens.get(pos++);
        if ("(".equals(t)) {
            FilterValue inner = parseOr();
            if (pos < tokens.size() && ")".equals(peek())) {
                pos++;
            }
            return inner;
        }
        if (")".equals(t)) {
            return FilterValue.EMPTY;   // незбалансована дужка
        }
        return term(t);
    }

    /** Одиничний терм фільтра. */
    private static FilterValue term(String token) {
        String s = token.replaceAll("[,;]+$", "");
        if (s.isEmpty()) {
            return FilterValue.EMPTY;
        }
        if (s.equalsIgnoreCase("ANY")) {
            return FilterValue.ANY;
        }
        // Конструкції, які bgpq4 не виражає аргументом
        if (s.startsWith("{")            // список префіксів { 192.0.2.0/24^24-32 }
                || s.startsWith("<")     // regexp AS-path <^AS1 AS2+$>
                || s.contains("(")) {    // community(...), origin(...)
            return FilterValue.UNSUPPORTED;
        }
        Matcher m = SET_NAME.matcher(s);
        if (m.matches()) {
            return new FilterValue(Kind.SETS, List.of(m.group(1)));
        }
        // Назви filter-set (fltr-*) та інші нерозпізнані — нейтральні
        return FilterValue.EMPTY;
    }

    // -------------------------------------------------------------------------
    // Операції над згорнутими значеннями
    // -------------------------------------------------------------------------
    private static FilterValue or(FilterValue a, FilterValue b) {
        if (a.kind() == Kind.UNSUPPORTED || b.kind() == Kind.UNSUPPORTED) {
            return FilterValue.UNSUPPORTED;
        }
        if (a.kind() == Kind.ANY || b.kind() == Kind.ANY) {
            return FilterValue.ANY;
        }
        return new FilterValue(Kind.SETS, union(a.sets(), b.sets()));
    }

    private static FilterValue and(FilterValue a, FilterValue b) {
        if (a.kind() == Kind.UNSUPPORTED || b.kind() == Kind.UNSUPPORTED) {
            return FilterValue.UNSUPPORTED;
        }
        // Нейтральний бік перевіряється раніше за ANY:
        // "ANY AND NOT fltr-martian" має лишитись ANY
        if (a.isEmpty()) {
            return b;
        }
        if (b.isEmpty()) {
            return a;
        }
        if (a.kind() == Kind.ANY) {
            return b;           // ANY ∩ X = X
        }
        if (b.kind() == Kind.ANY) {
            return a;
        }
        // Перетин двох непорожніх наборів bgpq4 не виражає — об'єднання було б ширшим за політику
        return FilterValue.UNSUPPORTED;
    }

    private static List<String> union(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        for (String s : b) {
            if (out.stream().noneMatch(x -> x.equalsIgnoreCase(s))) {
                out.add(s);
            }
        }
        return List.copyOf(out);
    }

    // -------------------------------------------------------------------------
    // Лексер
    // -------------------------------------------------------------------------
    /**
     * Ділить вираз на токени. Дужки груп — окремі токени; списки префіксів
     * {@code {...}}, regexp {@code <...>} і виклики {@code name(...)} лишаються цілими.
     */
    static List<String> tokenize(String input) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        int n = input.length();
        while (i < n) {
            char c = input.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '(' || c == ')') {
                tokens.add(String.valueOf(c));
                i++;
            } else if (c == '{') {
                int end = matchBalanced(input, i, '{', '}');
                tokens.add(input.substring(i, end));
                i = end;
            } else if (c == '<') {
                int end = input.indexOf('>', i);
                end = (end < 0) ? n : end + 1;
                tokens.add(input.substring(i, end));
                i = end;
            } else {
                int end = i;
                while (end < n && !Character.isWhitespace(input.charAt(end))
                        && input.charAt(end) != '(' && input.charAt(end) != ')') {
                    end++;
                }
                if (end < n && input.charAt(end) == '(') {
                    // виклик на кшталт community(65000:1) — один токен разом з аргументами
                    end = matchBalanced(input, end, '(', ')');
                }
                tokens.add(input.substring(i, end));
                i = end;
            }
        }
        return tokens;
    }

    /** Індекс одразу після парної закривної дужки. */
    private static int matchBalanced(String s, int start, char open, char close) {
        int depth = 0;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == open) {
                depth++;
            } else if (c == close) {
                depth--;
                if (depth == 0) {
                    return i + 1;
                }
            }
        }
        return s.length();
    }

    // -------------------------------------------------------------------------
    private String peek() {
        return tokens.get(pos);
    }

    /** Споживає наступний токен, якщо це вказане ключове слово. */
    private boolean matches(String keyword) {
        if (pos < tokens.size() && tokens.get(pos).equalsIgnoreCase(keyword)) {
            pos++;
            return true;
        }
        return false;
    }
}
