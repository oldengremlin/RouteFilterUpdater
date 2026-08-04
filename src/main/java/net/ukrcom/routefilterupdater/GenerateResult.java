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

import java.util.List;

/**
 * Результат {@link FilterGenerator#generate}.
 *
 * @param filters          чистий Junos-конфіг, придатний для "load merge terminal"
 * @param annotatedFilters ті самі блоки із заголовками "## AS&lt;n&gt; [&lt;ip&gt;] &lt;name&gt;"
 *                         для файлу (-o) і звіту (-r)
 * @param warnings         діагностика RPSL і помилки генерації
 * @param generated        скільки фільтрів згенеровано
 * @param skipped          скільки пропущено (accept ANY, немає запису в WHOIS тощо)
 * @param failed           скільки не вдалося згенерувати через помилку bgpq4
 */
public record GenerateResult(String filters, String annotatedFilters, List<String> warnings,
                             int generated, int skipped, int failed) {

    /** true, якщо хоча б один фільтр не вдалося згенерувати. */
    public boolean hasFailures() {
        return failed > 0;
    }
}
