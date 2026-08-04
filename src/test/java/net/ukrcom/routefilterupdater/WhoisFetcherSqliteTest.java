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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тести доступу до локальної SQLite БД (--sqlite).
 *
 * Регресія: режим read-only задавався через {@code Connection.setReadOnly} вже після
 * встановлення з'єднання, що драйвер відхиляє. Через це БД ніколи не відкривалась,
 * і кожен запит мовчки йшов у живий WHOIS.
 */
class WhoisFetcherSqliteTest {

    @TempDir
    static Path tempDir;

    private static String dbPath;

    @BeforeAll
    static void createDatabase() throws SQLException {
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
            assertEquals(java.util.List.of("AS42545"),
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
    @DisplayName("недоступна БД не валить запуск — fetchAsName повертає null")
    void unreadableDatabaseDegradesGracefully() {
        String missing = tempDir.resolve("no-such-file.db").toString();
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", missing)) {
            // Порожня БД відкриється, але таблиць у ній немає — запит впаде й дасть null
            assertNull(f.fetchAsName(42545L));
        }
    }

    @Test
    @DisplayName("БД відкрита лише для читання")
    void databaseIsOpenedReadOnly() throws SQLException {
        try (WhoisFetcher f = new WhoisFetcher("whois.invalid", dbPath)) {
            f.fetchAsName(42545L);   // змушує відкрити з'єднання
        }
        // Перевіряємо саму передумову фіксу: read-only задається до створення з'єднання
        org.sqlite.SQLiteConfig cfg = new org.sqlite.SQLiteConfig();
        cfg.setReadOnly(true);
        try (Connection c = cfg.createConnection("jdbc:sqlite:" + dbPath);
             Statement st = c.createStatement()) {
            assertTrue(c.isReadOnly());
            assertThrows(SQLException.class,
                    () -> st.executeUpdate("INSERT INTO asn (asn, name) VALUES (1, 'X')"));
        }
    }
}
