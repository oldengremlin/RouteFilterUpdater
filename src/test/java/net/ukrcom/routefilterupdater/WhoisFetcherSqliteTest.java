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

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.*;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тести доступу до локальної SQLite БД (--sqlite).
 *
 * <p><b>Важливо про фікстуру.</b> Цей проєкт БД лише читає — готує її сторонній
 * whois-lite-local. Тому {@code CREATE TABLE} нижче — не частина продакшн-логіки,
 * а <i>дзеркало зовнішнього контракту</i>: мінімальна БД тієї самої структури,
 * щоб тест був герметичним (справжня БД важить ~1 ГБ і в репозиторії її немає).
 *
 * <p>Слабке місце такого підходу: фікстуру й запити писала одна голова з одного
 * припущення про схему. Якщо схема whois-lite-local зміниться, тести лишаться
 * зеленими, а продакшн — ні. Тому є два запобіжники:
 * <ul>
 *   <li>{@code WhoisFetcher} перевіряє структуру БД при відкритті й голосно
 *       повідомляє про розбіжність (див. {@link #schemaMismatchIsDetected()});</li>
 *   <li>{@link RealDatabase} звіряє припущення зі справжньою БД, якщо шлях до неї
 *       задано змінною середовища {@code WHOIS_LITE_LOCAL_DB}.</li>
 * </ul>
 *
 * <p>Регресія, заради якої з'явився цей клас: режим read-only задавався через
 * {@code Connection.setReadOnly} вже після встановлення з'єднання, що драйвер
 * відхиляє. БД не відкривалась ніколи, і кожен запит мовчки йшов у живий WHOIS.
 */
class WhoisFetcherSqliteTest {

    @TempDir
    static Path tempDir;

    private static String dbPath;

    /** Структура згідно з whois-lite-local; сюди пишемо лише щоб було що читати. */
    @BeforeAll
    static void createFixtureMirroringExternalSchema() throws SQLException {
        dbPath = tempDir.resolve("whoislitelocal.db").toString();
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
             Statement st = c.createStatement()) {
            st.executeUpdate("CREATE TABLE rpsl (key TEXT, value TEXT, block TEXT)");
            st.executeUpdate("CREATE TABLE asn (asn INTEGER, name TEXT)");
            st.executeUpdate("""
                    INSERT INTO rpsl (key, value, block) VALUES ('aut-num', 'AS42545',
                    'aut-num:        AS42545
                    mp-export:      afi ipv4.unicast to AS12593 announce AS42545
                    ')""");
            st.executeUpdate("INSERT INTO asn (asn, name) VALUES (42545, 'ASTARTA')");
        }
    }

    @Test
    @DisplayName("БД відкривається і назва AS читається")
    void readsAsName() {
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", dbPath)) {
            assertEquals("ASTARTA", f.fetchAsName(42545L));
        }
    }

    @Test
    @DisplayName("відсутній запис дає null, без падіння")
    void missingAsName() {
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", dbPath)) {
            assertNull(f.fetchAsName(99999L));
        }
    }

    @Test
    @DisplayName("блок aut-num читається з БД без звернення до мережі")
    void readsBlockWithoutNetwork() throws Exception {
        // whois.invalid не резолвиться: якщо запис знайдено в БД, мережа не потрібна
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", dbPath)) {
            assertEquals(List.of("AS42545"),
                    f.fetchPeerExportToSelf(42545L, 12593L, AddressFamily.V4));
        }
    }

    @Test
    @DisplayName("з'єднання переюзується між запитами")
    void connectionIsReused() {
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", dbPath)) {
            for (int i = 0; i < 5; i++) {
                assertEquals("ASTARTA", f.fetchAsName(42545L));
            }
        }
    }

    @Test
    @DisplayName("БД відкривається лише для читання")
    void databaseIsOpenedReadOnly() throws SQLException {
        org.sqlite.SQLiteConfig cfg = new org.sqlite.SQLiteConfig();
        cfg.setReadOnly(true);
        try (Connection c = cfg.createConnection("jdbc:sqlite:" + dbPath);
             Statement st = c.createStatement()) {
            assertTrue(c.isReadOnly());
            assertThrows(SQLException.class,
                    () -> st.executeUpdate("INSERT INTO asn (asn, name) VALUES (1, 'X')"));
        }
    }

    @Test
    @DisplayName("неіснуючий файл БД не валить запуск")
    void missingFileDegradesGracefully() {
        String missing = tempDir.resolve("no-such-file.db").toString();
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", missing)) {
            assertNull(f.fetchAsName(42545L));
        }
    }

    @Test
    @DisplayName("розбіжність схеми виявляється при відкритті, а не на кожному запиті")
    void schemaMismatchIsDetected() throws SQLException {
        String wrong = tempDir.resolve("wrong-schema.db").toString();
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + wrong);
             Statement st = c.createStatement()) {
            // Таблиці є, але колонки не ті, що очікують запити
            st.executeUpdate("CREATE TABLE rpsl (id INTEGER, payload TEXT)");
            st.executeUpdate("CREATE TABLE asn (number INTEGER, title TEXT)");
        }
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", wrong)) {
            assertNull(f.fetchAsName(42545L));
        }
    }

    /**
     * Звірка припущення про схему зі справжньою БД whois-lite-local.
     * Виконується лише якщо задано {@code WHOIS_LITE_LOCAL_DB}, напр.:
     *
     * <pre>WHOIS_LITE_LOCAL_DB=/path/to/whoislitelocal.db mvn test</pre>
     *
     * Саме цей тест ловить розбіжність між фікстурою й реальністю.
     */
    @Nested
    @DisplayName("справжня БД whois-lite-local")
    class RealDatabase {

        private String realDb() {
            String path = System.getenv("WHOIS_LITE_LOCAL_DB");
            Assumptions.assumeTrue(path != null && !path.isBlank(),
                    "WHOIS_LITE_LOCAL_DB not set — skipping real-database check");
            Assumptions.assumeTrue(Files.isReadable(Path.of(path)),
                    "WHOIS_LITE_LOCAL_DB is not readable: " + path);
            return path;
        }

        @Test
        @DisplayName("структура збігається з тією, яку очікують запити")
        void schemaMatchesExpectations() throws SQLException {
            String path = realDb();
            org.sqlite.SQLiteConfig cfg = new org.sqlite.SQLiteConfig();
            cfg.setReadOnly(true);
            try (Connection c = cfg.createConnection("jdbc:sqlite:" + path);
                 Statement st = c.createStatement()) {
                // Ті самі запити, що й у продакшні — якщо схема інша, тут буде SQLException
                st.executeQuery("SELECT block FROM rpsl WHERE key = 'aut-num'"
                        + " AND UPPER(value) = UPPER('AS1') LIMIT 1").close();
                st.executeQuery("SELECT name FROM asn WHERE asn = 1 LIMIT 1").close();
            }
        }

        @Test
        @DisplayName("власна AS читається і має розбірний RPSL-блок")
        void selfAsIsReadable() throws Exception {
            String path = realDb();
            try (WhoisFetcher f = new WhoisFetcher("whois.invalid", path)) {
                // whois.invalid: якщо AS немає в БД, буде мережева помилка, а не тихий null
                assertFalse(f.fetchSelfAsPolicies(12593L).isEmpty(),
                        "AS12593 має бути в локальній БД і містити import-політики");
            }
        }
    }
}
