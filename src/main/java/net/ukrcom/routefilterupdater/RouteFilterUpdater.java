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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * RouteFilterUpdater — BGP route filter generator / applicator for Juniper routers.
 *
 * Workflow:
 *   1. Query WHOIS for SELF_AS → parse import policies (in-memory, no cache file)
 *   2. SSH to router → read BGP group neighbors (peer-as + import policy name)
 *   3. For each unique import policy → call bgpq4 to generate Junos config block
 *   4. Write result to file / stdout, optionally apply via "load merge terminal"
 *   5. Optionally send email report
 *
 * Configuration: RouteFilterUpdater.properties (see Config.java for property list)
 */
public class RouteFilterUpdater {

    private static final Logger log = LoggerFactory.getLogger(RouteFilterUpdater.class);

    private static final String PROPERTIES_FILE = "RouteFilterUpdater.properties";
    private static final String LOCK_FILE
            = System.getProperty("java.io.tmpdir") + File.separator + "RouteFilterUpdater.lock";

    public static void main(String[] argv) {
        File lock = new File(LOCK_FILE);
        try {
            if (!lock.createNewFile()) {
                System.err.println("Lock file exists: " + LOCK_FILE
                        + " — another instance may be running. Remove it if stale.");
                System.exit(1);
            }
        } catch (IOException e) {
            System.err.println("Cannot create lock file: " + e.getMessage());
        }
        Runtime.getRuntime().addShutdownHook(new Thread(lock::delete));

        Args args = new Args(argv);
        if (args.help) {
            Args.printHelp();
            return;
        }

        try {
            run(args);
        } catch (Exception e) {
            log.error("Fatal: {}", e.getMessage(), e);
            System.exit(1);
        } finally {
            lock.delete();
        }
    }

    // -------------------------------------------------------------------------
    private static void run(Args args) throws Exception {
        Config config = new Config(PROPERTIES_FILE);
        configureLogging(args, config);

        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String proto = args.ipv6 ? "IPv6" : "IPv4";
        log.info("=== RouteFilterUpdater  {}  {} ===", proto, ts);

        if (!new Bgpq4Client(config.bgpq4Path, "").isAvailable()) {
            throw new IllegalStateException("bgpq4 not found or not executable: " + config.bgpq4Path);
        }

        // Generate Junos filter blocks
        GenerateResult result = new FilterGenerator(config)
                .generate(args.ipv6, args.strictRpsl, args.strictRpslReverse);
        String filters = result.filters();

        // Print RPSL warnings to stderr (always visible, even with -q)
        for (String w : result.warnings()) {
            System.err.println(w);
            System.err.println();
        }

        if (filters.isBlank()) {
            log.warn("No filters generated — nothing to do.");
            return;
        }

        // Output
        if (args.outputFile != null) {
            Files.writeString(Path.of(args.outputFile), filters);
            log.info("Filters written to {}", args.outputFile);
        } else if (!args.save) {
            System.out.print(filters);
        }

        // Apply to router via SSH (load merge terminal)
        String compareOutput = "";
        if (args.save) {
            String routerHost = config.routerIp(args.ipv6);
            log.info("Applying filters to router {}", routerHost);
            try (RouterClient router = new RouterClient(routerHost, config.username, config.password)) {
                router.connect();
                compareOutput = router.applyFilters(filters);
            }
            if ("No configuration changes detected.".equals(compareOutput)) {
                log.info("Router reports no changes");
            } else {
                log.info("Applied changes:\n{}", compareOutput);
            }
        }

        // Email report
        if (args.report) {
            String subject = String.format("RouteFilterUpdater [%s] %s — %s",
                    proto, args.save ? "applied" : "generated", ts);
            String warningSection = result.warnings().isEmpty() ? ""
                    : "\n\n=== RPSL Warnings ===\n\n" + String.join("\n\n", result.warnings());
            String body = "=== Route Filters (" + proto + ") ===\n\n" + filters
                    + (compareOutput.isBlank() ? "" : "\n\n=== Router Changes ===\n\n" + compareOutput)
                    + warningSection;
            new EmailReporter(config).send(subject, body);
        }

        log.info("=== RouteFilterUpdater completed ===");
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
