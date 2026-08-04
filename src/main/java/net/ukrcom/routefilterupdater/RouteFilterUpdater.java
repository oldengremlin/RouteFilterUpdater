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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.filter.ThresholdFilter;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * RouteFilterUpdater — генератор і застосовувач BGP-маршрутних фільтрів для Juniper.
 *
 * Хід роботи:
 *   1. Запит WHOIS для SELF_AS → розбір import-політик (в пам'яті, без файлу кешу)
 *   2. SSH до роутера → зчитування BGP-сусідів (peer-as + назва import-політики)
 *   3. Для кожної унікальної import-політики → bgpq4 → Junos-блок
 *   4. Запис у файл / stdout, опційно застосування через "load merge terminal"
 *   5. Опційно надсилання звіту поштою
 *
 * Конфігурація: RouteFilterUpdater.properties (перелік властивостей — у Config.java)
 *
 * Коди виходу: 0 — успіх, 1 — фатальна помилка, 2 — завершено з проблемами.
 */
public class RouteFilterUpdater {

    private static final Logger log = LoggerFactory.getLogger(RouteFilterUpdater.class);

    private static final String PROPERTIES_FILE = "RouteFilterUpdater.properties";
    private static final String LOCK_FILE
            = System.getProperty("java.io.tmpdir") + File.separator + "RouteFilterUpdater.lock";

    private static final int EXIT_OK = 0;
    private static final int EXIT_FATAL = 1;
    private static final int EXIT_PROBLEMS = 2;

    public static void main(String[] argv) {
        Args args = new Args(argv);
        if (args.help) {
            Args.printHelp();
            return;
        }
        if (!args.errors.isEmpty()) {
            args.errors.forEach(e -> System.err.println("Error: " + e));
            System.err.println();
            Args.printHelp();
            System.exit(EXIT_FATAL);
        }

        // Блокування через FileLock, а не через наявність файлу: ОС звільняє його
        // навіть при kill -9, тож «застряглий» lock більше не блокує наступні запуски.
        try (RandomAccessFile lockFile = new RandomAccessFile(LOCK_FILE, "rw");
             FileLock lock = tryLock(lockFile)) {

            if (lock == null) {
                System.err.println("Another instance is already running (lock: " + LOCK_FILE + ")");
                System.exit(EXIT_FATAL);
            }
            System.exit(run(args));

        } catch (IOException e) {
            System.err.println("Cannot access lock file " + LOCK_FILE + ": " + e.getMessage());
            System.exit(EXIT_FATAL);
        }
    }

    private static FileLock tryLock(RandomAccessFile f) throws IOException {
        try {
            return f.getChannel().tryLock();
        } catch (OverlappingFileLockException e) {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    private static int run(Args args) {
        Config config;
        try {
            config = new Config(PROPERTIES_FILE);
        } catch (Exception e) {
            System.err.println("Configuration error: " + e.getMessage());
            return EXIT_FATAL;
        }
        configureLogging(args, config);

        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        log.info("=== RouteFilterUpdater  {}  {} ===", args.family.label(), ts);

        try (WhoisFetcher whois = new WhoisFetcher(config.whoisServer, args.sqlitePath)) {
            if (args.rpslProposal) {
                // Автономний режим: фільтри не генеруються, конфігурація не застосовується
                boolean problems = new RpslProposalRunner(config, whois).run(args.family);
                log.info("=== RouteFilterUpdater completed ===");
                return problems ? EXIT_PROBLEMS : EXIT_OK;
            }
            return generateAndApply(args, config, whois, ts);
        } catch (Exception e) {
            log.error("Fatal: {}", e.getMessage(), e);
            return EXIT_FATAL;
        }
    }

    private static int generateAndApply(Args args, Config config, WhoisFetcher whois, String ts)
            throws Exception {

        if (!Bgpq4Client.isAvailable(config.bgpq4Path)) {
            throw new IllegalStateException("bgpq4 not found or not executable: " + config.bgpq4Path);
        }

        GenerateResult result = new FilterGenerator(config, whois)
                .generate(args.family, args.strictRpsl, args.strictRpslReverse);

        // filters          — чистий Junos для роутера (без ## заголовків)
        // annotatedFilters — читабельна версія із заголовками ## AS<n> [<ip>] <name>
        String filters = result.filters();
        String annotatedFilters = result.annotatedFilters();

        // Попередження — завжди на stderr, навіть із -q
        for (String w : result.warnings()) {
            System.err.println(w);
            System.err.println();
        }

        if (filters.isBlank()) {
            // Сусіди є (інакше NeighborLoader кинув би виняток), але жодного фільтра
            // не вийшло: або всі accept ANY, або всі впали.
            log.warn("No filters generated ({} skipped, {} failed)",
                    result.skipped(), result.failed());
            return result.hasFailures() ? EXIT_PROBLEMS : EXIT_OK;
        }

        if (args.outputFile != null) {
            Files.writeString(Path.of(args.outputFile), annotatedFilters);
            log.info("Filters written to {}", args.outputFile);
        } else if (!args.save) {
            System.out.print(annotatedFilters);
        }

        // Застосування до роутера — чистий Junos, без ## заголовків
        String compareOutput = "";
        String applyError = null;
        if (args.save) {
            String routerHost = config.routerIp(args.family);
            log.info("Applying filters to router {}", routerHost);
            try (RouterClient router = new RouterClient(routerHost, config.username, config.password)) {
                router.connect();
                compareOutput = router.applyFilters(filters);
                if ("No configuration changes detected.".equals(compareOutput)) {
                    log.info("Router reports no changes");
                } else {
                    log.info("Applied changes:\n{}", compareOutput);
                }
            } catch (Exception e) {
                // Звіт треба надіслати саме тоді, коли застосування провалилось —
                // раніше виняток летів далі й лист не надсилався взагалі.
                applyError = e.getMessage();
                log.error("Failed to apply configuration: {}", applyError);
            }
        }

        if (args.report) {
            sendReport(args, config, ts, annotatedFilters, compareOutput, applyError, result);
        }

        log.info("=== RouteFilterUpdater completed ===");
        if (applyError != null) {
            return EXIT_FATAL;
        }
        return result.hasFailures() ? EXIT_PROBLEMS : EXIT_OK;
    }

    private static void sendReport(Args args, Config config, String ts, String annotatedFilters,
                                   String compareOutput, String applyError, GenerateResult result) {
        String proto = args.family.label();
        String state = applyError != null ? "FAILED" : (args.save ? "applied" : "generated");
        String subject = String.format("RouteFilterUpdater [%s] %s — %s", proto, state, ts);

        StringBuilder body = new StringBuilder();
        if (applyError != null) {
            body.append("=== Apply FAILED ===\n\n").append(applyError).append("\n\n");
        }
        body.append("=== Route Filters (").append(proto).append(") ===\n\n").append(annotatedFilters);
        if (!compareOutput.isBlank()) {
            body.append("\n\n=== Router Changes ===\n\n").append(compareOutput);
        }
        if (!result.warnings().isEmpty()) {
            body.append("\n\n=== RPSL Warnings ===\n\n")
                    .append(String.join("\n\n", result.warnings()));
        }
        body.append("\n\n=== Summary ===\n\n")
                .append(String.format("%d generated, %d skipped, %d failed%n",
                        result.generated(), result.skipped(), result.failed()));

        try {
            new EmailReporter(config).send(subject, body.toString());
        } catch (Exception e) {
            log.error("Failed to send report: {}", e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    private static void configureLogging(Args args, Config config) {
        ch.qos.logback.classic.Logger root
                = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);

        if (args.quiet) {
            setConsoleLevel(root, "OFF");
        } else if (args.debug || config.debug) {
            root.setLevel(Level.DEBUG);
            setConsoleLevel(root, "DEBUG");
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void setConsoleLevel(ch.qos.logback.classic.Logger root, String level) {
        Appender<?> console = root.getAppender("CONSOLE");
        if (console instanceof ConsoleAppender consoleAppender) {
            ThresholdFilter f = new ThresholdFilter();
            f.setLevel(level);
            f.start();
            ConsoleAppender ca = consoleAppender;
            ca.clearAllFilters();
            ca.addFilter(f);
        }
    }
}
