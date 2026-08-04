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

import java.util.regex.Pattern;

/**
 * Спільні патерни для очищення виводу термінала Junos.
 *
 * Раніше цей самий регекс був продубльований літералом у {@code RouterClient}
 * і перекомпілювався на кожному виклику {@code String.replaceAll}. Тут він
 * скомпільований один раз.
 */
final class JunosOutput {

    /** ANSI-послідовності та недруковані керуючі символи. */
    private static final Pattern ANSI = Pattern.compile(
            "[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]|\\x1B\\[[0-9;]*[a-zA-Z]");

    /** Індикатор режиму Junos, напр. {@code {master}[edit]}. */
    private static final Pattern MODE_INDICATOR = Pattern.compile("\\{[^}]*\\}.*");

    private JunosOutput() {
    }

    /** Прибирає ANSI-послідовності й керуючі символи. */
    static String stripAnsi(String s) {
        return ANSI.matcher(s).replaceAll("");
    }

    static boolean isModeIndicator(String line) {
        return MODE_INDICATOR.matcher(line).matches();
    }

    /** Рядок-промпт Junos: {@code user@host>} або {@code user@host#}. */
    static Pattern promptLine(String username) {
        return Pattern.compile(Pattern.quote(username) + "@[^>#]+[>#].*");
    }

    /** Промпт операційного режиму в кінці накопиченого виводу. */
    static Pattern operationalPromptAtEnd(String username) {
        return Pattern.compile(Pattern.quote(username) + "@[^>]+>\\s*$", Pattern.DOTALL);
    }

    /** Промпт режиму конфігурації в кінці накопиченого виводу. */
    static Pattern configPromptAtEnd(String username) {
        return Pattern.compile(Pattern.quote(username) + "@[^#]+#\\s*$", Pattern.DOTALL);
    }

    /**
     * Проміжний промпт усередині виводу (не в самому кінці) — такий пропускаємо,
     * щоб не сплутати його з фінальним.
     */
    static Pattern intermediatePrompt(String username) {
        return Pattern.compile(
                "(?s)^.*?" + Pattern.quote(username) + "@[^>#]+[>#](?![\\s\\r\\n]*$)",
                Pattern.DOTALL);
    }
}
