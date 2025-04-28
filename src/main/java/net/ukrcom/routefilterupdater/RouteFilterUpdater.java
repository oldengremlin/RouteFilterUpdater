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

import com.jcraft.jsch.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.net.whois.WhoisClient;
import javax.mail.*;
import javax.mail.internet.*;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;
import java.util.stream.Collectors;

// Внутрішні класи на початку
class Neighbor {

    String ip;
    String peerAs;
    String importPolicy;
    String description;

    Neighbor(String ip) {
        this.ip = ip;
    }
}

class Args {

    String outputFile;
    boolean ipv4 = true;
    boolean ipv6 = false;
    boolean debug = false;
    boolean save = false;
    boolean report = false;
    boolean quiet = false;
    boolean forceIPv6 = false;

    Args(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("-o".equals(args[i]) && i + 1 < args.length) {
                outputFile = args[++i];
            } else if ("-4".equals(args[i])) {
                ipv4 = true;
                ipv6 = false;
            } else if ("-6".equals(args[i])) {
                ipv4 = false;
                ipv6 = true;
            } else if ("-d".equals(args[i]) || "--debug".equals(args[i])) {
                debug = true;
            } else if ("-s".equals(args[i]) || "--save".equals(args[i])) {
                save = true;
            } else if ("-r".equals(args[i]) || "--report".equals(args[i])) {
                report = true;
            } else if ("-q".equals(args[i]) || "--quiet".equals(args[i])) {
                quiet = true;
            } else if ("-w6".equals(args[i])) {
                forceIPv6 = true;
            } else if ("-?".equals(args[i]) || "-h".equals(args[i]) || "--help".equals(args[i])) {
                printHelp();
                System.exit(0);
            }
        }
    }

    private void printHelp() {
        System.out.println("""
            RouteFilterUpdater - Utility to generate and apply BGP route filters
            Usage: java -jar RouteFilterUpdater.jar [options]
            Options:
              -4              Generate IPv4 route filters (default)
              -6              Generate IPv6 route filters
              -w6             Force IPv6 prefix generation even if WHOIS lacks peering info
              -o <file>       Output route filters to <file>
              -d, --debug     Enable debug logging
              -s, --save      Apply generated configuration to the router
              -r, --report    Send execution log to REPORT_TO email
              -q, --quiet     Suppress console output (for cron jobs)
              -?, -h, --help  Display this help message
            """);
    }
}

public class RouteFilterUpdater {

    // Поля класу
//    private static final String IPV4_REGEX = "[0-9.]+";
//    private static final String IPV6_REGEX = "[0-9a-fA-F:]+";
    private static final String IPV4_REGEX = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
            + "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    private static final String IPV6_REGEX
            = "(?:"
            // Повний формат
            + "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
            // Скорочення справа
            + "|(?:[0-9a-fA-F]{1,4}:){1,7}:"
            // Скорочення зліва
            + "|:(?:[0-9a-fA-F]{1,4}:){1,7}"
            // Скорочення посередині
            + "|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
            + "|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
            + "|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
            + "|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
            + "|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
            + "|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
            + "|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
            + "|::[0-9a-fA-F]{1,4}"
            // Скорочення до ::
            + "|::"
            + ")(?:\\%[\\w\\d]+)?";
    private static final Logger LOGGER = LoggerFactory.getLogger(RouteFilterUpdater.class);
    private static String ROUTER_IP;
    private static String ROUTER_IP_IPV6;
    private static String USERNAME;
    private static String PASSWORD;
    private static String BGP_GROUP_IPV4;
    private static String BGP_GROUP_IPV6;
    private static String SELF_AS;
    private static String IRR_CACHE_FILE;
    private static String[] EXCEPT_REGEX_VALUES;
    private static String[] IRR_SOURCES;
    private static String RTCONFIG_PATH;
    private static String WHOIS_SERVER;
    private static String WHOIS_OPTIONS;
    private static String SMTP_SERVER;
    private static String SMTP_PORT;
    private static String SMTP_USER;
    private static String SMTP_PASSWORD;
    private static String REPORT_TO;
    private static String REPORT_FROM;

    // Основний метод
    public static void main(String[] args) {
        File lockFile = new File(System.getProperty("java.io.tmpdir"), "RouteFilterUpdater.lock");
        try {
            if (!lockFile.createNewFile()) {
                LOGGER.error("Another instance is running, exiting");
                System.exit(1);
            }
        } catch (IOException ex) {
            LOGGER.error("Can't create lock file: {}", ex.getMessage());
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (lockFile.exists()) {
                lockFile.delete();
                LOGGER.debug("Deleted lock file on shutdown: {}", lockFile.getAbsolutePath());
            }
        }));

        try {
            Args config = new Args(args);
            ch.qos.logback.core.FileAppender<ch.qos.logback.classic.spi.ILoggingEvent> sessionFileAppender = null;
            File sessionLogFile = null;
            try {
                String sessionId = UUID.randomUUID().toString();
                System.setProperty("session.id", sessionId);
                sessionLogFile = new File(System.getProperty("java.io.tmpdir"), "routefilterupdater-session-" + sessionId + ".log");

                JSch.setLogger(new com.jcraft.jsch.Logger() {
                    @Override
                    public boolean isEnabled(int level) {
                        return true;
                    }

                    @Override
                    public void log(int level, String message) {
                        if (message.contains("Socket closed")) {
                            LOGGER.debug("JSch [{}]: {}", level, message);
                            return;
                        }
                        switch (level) {
                            case com.jcraft.jsch.Logger.DEBUG ->
                                LOGGER.debug("JSch [{}]: {}", level, message);
                            case com.jcraft.jsch.Logger.INFO ->
                                LOGGER.debug("JSch [{}]: {}", level, message);
                            case com.jcraft.jsch.Logger.WARN ->
                                LOGGER.warn("JSch [{}]: {}", level, message);
                            case com.jcraft.jsch.Logger.ERROR ->
                                LOGGER.error("JSch [{}]: {}", level, message);
                            default ->
                                LOGGER.debug("JSch [{}]: {}", level, message);
                        }
                    }
                });

                ch.qos.logback.classic.Logger rootLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
                sessionFileAppender = new ch.qos.logback.core.FileAppender<>();
                sessionFileAppender.setContext(rootLogger.getLoggerContext());
                sessionFileAppender.setFile(sessionLogFile.getAbsolutePath());
                ch.qos.logback.classic.encoder.PatternLayoutEncoder encoder = new ch.qos.logback.classic.encoder.PatternLayoutEncoder();
                encoder.setContext(rootLogger.getLoggerContext());
                encoder.setPattern("%d{yyyy-MM-dd HH:mm:ss} %-5level %logger{36} - %msg%n");
                encoder.start();
                sessionFileAppender.setEncoder(encoder);
                sessionFileAppender.start();
                rootLogger.addAppender(sessionFileAppender);

                boolean debugProp = loadProperties();
                if (config.quiet) {
                    ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
                    ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent> consoleAppender = root.getAppender("CONSOLE");
                    if (consoleAppender != null && consoleAppender instanceof ch.qos.logback.core.ConsoleAppender) {
                        ch.qos.logback.classic.filter.ThresholdFilter filter = new ch.qos.logback.classic.filter.ThresholdFilter();
                        filter.setLevel("OFF");
                        filter.start();
                        consoleAppender.clearAllFilters();
                        consoleAppender.addFilter(filter);
                        LOGGER.debug("Console appender set to OFF level (quiet mode)");
                    }
                } else if (config.debug || debugProp) {
                    ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
                    ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent> consoleAppender = root.getAppender("CONSOLE");
                    if (consoleAppender != null && consoleAppender instanceof ch.qos.logback.core.ConsoleAppender) {
                        ch.qos.logback.classic.filter.ThresholdFilter filter = new ch.qos.logback.classic.filter.ThresholdFilter();
                        filter.setLevel("DEBUG");
                        filter.start();
                        consoleAppender.clearAllFilters();
                        consoleAppender.addFilter(filter);
                        LOGGER.debug("Console appender set to DEBUG level");
                    }
                }
                if (config.debug || debugProp) {
                    ((ch.qos.logback.classic.Logger) LOGGER).setLevel(ch.qos.logback.classic.Level.DEBUG);
                    ((ch.qos.logback.classic.Logger) LoggerFactory.getLogger("com.jcraft.jsch")).setLevel(ch.qos.logback.classic.Level.DEBUG);
                    ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
                    root.setLevel(ch.qos.logback.classic.Level.DEBUG);
                    LOGGER.debug("Debug logging enabled for all appenders");
                }
                if (!config.debug && !debugProp) {
                    ((ch.qos.logback.classic.Logger) LOGGER).setLevel(ch.qos.logback.classic.Level.INFO);
                }

                LOGGER.info("Starting RouteFilterUpdater, session ID: {}", sessionId);
                LOGGER.debug("Session log file path: {}", sessionLogFile.getAbsolutePath());
                LOGGER.debug("Session file appender started: {}", sessionFileAppender.isStarted());
                LOGGER.debug("Checking if session log file exists: {}", sessionLogFile.exists());

                cleanOldSessionLogs();
                checkSystemUtilities();
                LOGGER.debug("Attempting to clear IRR_CACHE_FILE: {}", IRR_CACHE_FILE);
                Path irrCachePath = Paths.get(IRR_CACHE_FILE);
                try {
                    if (Files.exists(irrCachePath)) {
                        Files.delete(irrCachePath);
                        LOGGER.debug("Successfully deleted IRR_CACHE_FILE: {}", IRR_CACHE_FILE);
                    } else {
                        LOGGER.debug("IRR_CACHE_FILE does not exist, no deletion needed: {}", IRR_CACHE_FILE);
                    }
                } catch (IOException e) {
                    LOGGER.error("Failed to delete IRR_CACHE_FILE {}: {}", IRR_CACHE_FILE, e.getMessage());
                    throw new IOException("Cannot delete IRR_CACHE_FILE: " + IRR_CACHE_FILE, e);
                }
                if (config.ipv4) {
                    generateIrrObjects(false);
                }
                if (config.ipv6) {
                    generateIrrObjects(true);
                }
                validateIrrFile();
                generateRouteFilters(config);
                if (config.save && config.outputFile != null) {
                    applyConfiguration(config.outputFile);
                }
                if (config.report && REPORT_TO != null && !REPORT_TO.isEmpty() && REPORT_FROM != null && !REPORT_FROM.isEmpty()) {
                    sendReport(sessionLogFile);
                }
                LOGGER.info("RouteFilterUpdater completed successfully");
            } catch (JSchException | IOException e) {
                LOGGER.error("Error in RouteFilterUpdater", e);
                System.exit(1);
            } finally {
                if (sessionFileAppender != null) {
                    sessionFileAppender.stop();
                    LOGGER.debug("Session file appender stopped");
                }
                if (sessionLogFile != null && sessionLogFile.exists()) {
                    try {
                        Files.delete(sessionLogFile.toPath());
                        LOGGER.debug("Deleted session log file: {}", sessionLogFile.getAbsolutePath());
                    } catch (IOException e) {
                        LOGGER.warn("Failed to delete session log file {}: {}", sessionLogFile.getAbsolutePath(), e.getMessage());
                    }
                }
            }
        } finally {
            lockFile.delete();
        }
    }

    // Методи в порядку виклику з main
    private static void cleanOldSessionLogs() {
        File tmpDir = new File(System.getProperty("java.io.tmpdir"));
        File[] oldLogs = tmpDir.listFiles((dir, name) -> name.startsWith("routefilterupdater-session-") && name.endsWith(".log"));
        if (oldLogs != null) {
            long cutoff = System.currentTimeMillis() - (7 * 24 * 60 * 60 * 1000);
            for (File log : oldLogs) {
                if (log.lastModified() < cutoff) {
                    try {
                        Files.delete(log.toPath());
                        LOGGER.debug("Deleted old session log: {}", log.getAbsolutePath());
                    } catch (IOException e) {
                        LOGGER.warn("Failed to delete old session log {}: {}", log.getAbsolutePath(), e.getMessage());
                    }
                }
            }
        }
    }

    private static boolean loadProperties() throws IOException {
        Properties props = new Properties();
        try (InputStream input = Files.newInputStream(Paths.get("RouteFilterUpdater.properties"))) {
            props.load(input);
        }
        ROUTER_IP = props.getProperty("ROUTER_IP");
        ROUTER_IP_IPV6 = props.getProperty("ROUTER_IP_IPV6");
        USERNAME = props.getProperty("USERNAME");
        PASSWORD = System.getenv("ROUTER_PASSWORD") != null ? System.getenv("ROUTER_PASSWORD") : props.getProperty("PASSWORD");
        BGP_GROUP_IPV4 = props.getProperty("BGP_GROUP_IPV4");
        BGP_GROUP_IPV6 = props.getProperty("BGP_GROUP_IPV6");
        SELF_AS = props.getProperty("SELF_AS");
        IRR_CACHE_FILE = props.getProperty("IRR_CACHE_FILE", "as12593_irr_objects.txt");
        EXCEPT_REGEX_VALUES = props.getProperty("EXCEPT_REGEX", "Client_world_uaix_in,Client_PFTS_in,TE_IN").split(",\\s*");
        IRR_SOURCES = props.getProperty("IRR_SOURCES", "RADB,RIPE,APNIC,ARIN,LACNIC,AFRINIC,RIPE-NONAUTH,BELL,NTTCOM,ALTDB,PANIX,NESTEGG,LEVEL3,JPIRR,BBOI,CANARIE,REACH,TC").split(",\\s*");
        RTCONFIG_PATH = props.getProperty("RTCONFIG_PATH", "/usr/local/bin/rtconfig");
        WHOIS_SERVER = props.getProperty("WHOIS_SERVER", "whois.radb.net");
        WHOIS_OPTIONS = props.getProperty("WHOIS_OPTIONS", "-r");
        SMTP_SERVER = props.getProperty("SMTP_SERVER");
        SMTP_PORT = props.getProperty("SMTP_PORT", "25");
        SMTP_USER = props.getProperty("SMTP_USER");
        SMTP_PASSWORD = props.getProperty("SMTP_PASSWORD");
        REPORT_TO = props.getProperty("REPORT_TO");
        REPORT_FROM = props.getProperty("REPORT_FROM");
        boolean debugProp = Boolean.parseBoolean(props.getProperty("DEBUG", "false"));

        LOGGER.debug("Loaded REPORT_TO: {}", REPORT_TO);
        LOGGER.debug("Loaded REPORT_FROM: {}", REPORT_FROM);
        LOGGER.debug("Loaded BGP_GROUP_IPV4: {}", BGP_GROUP_IPV4);
        LOGGER.debug("Loaded BGP_GROUP_IPV6: {}", BGP_GROUP_IPV6);
        LOGGER.debug("Loaded ROUTER_IP_IPV6: {}", ROUTER_IP_IPV6);

        for (String prop : new String[]{ROUTER_IP, ROUTER_IP_IPV6, USERNAME, PASSWORD, BGP_GROUP_IPV4, BGP_GROUP_IPV6, SELF_AS, IRR_CACHE_FILE, RTCONFIG_PATH}) {
            if (prop == null || prop.isEmpty()) {
                throw new IOException("Missing or empty required property in RouteFilterUpdater.properties");
            }
        }
        if (EXCEPT_REGEX_VALUES == null || EXCEPT_REGEX_VALUES.length == 0) {
            throw new IOException("EXCEPT_REGEX is empty in RouteFilterUpdater.properties");
        }
        return debugProp;
    }

    private static void checkSystemUtilities() throws IOException {
        LOGGER.debug("Checking availability of system utilities");
        for (String util : new String[]{RTCONFIG_PATH}) {
            if (!Files.isExecutable(Paths.get(util))) {
                throw new IOException("Utility not found or not executable: " + util);
            }
            LOGGER.debug("Found utility: {}", util);
        }
    }

    private static void generateIrrObjects(boolean isIPv6) throws JSchException, IOException {
        LOGGER.info("Generating IRR objects for {}", isIPv6 ? "IPv6" : "IPv4");
        com.jcraft.jsch.Session session = connect();
        try {
            String bgpGroup = isIPv6 ? BGP_GROUP_IPV6 : BGP_GROUP_IPV4;
            String routerIp = isIPv6 ? ROUTER_IP_IPV6 : ROUTER_IP;
            String peeringSetName = isIPv6 ? "prng-fictionalinternetexchangev6" : "prng-fictionalinternetexchangev4";
            String ipRegex = isIPv6 ? "(" + IPV6_REGEX + ")" : "(" + IPV4_REGEX + ")";
            String forbiddenPrefixes = isIPv6
                    ? "NOT { ::/0^+, fe80::/10^+ }"
                    : "NOT { 10.0.0.0/8^+, 169.254.0.0/16^+, 172.16.0.0/12^+, 192.0.2.0/24^+, 192.168.0.0/16^+, 198.18.0.0/15^+, 203.0.113.0/24^+, 0.0.0.0/0, 127.0.0.0/8^+, 224.0.0.0/3^+ }";

            String bgpConfig = executeSshCommand(session,
                    "show configuration protocols bgp group " + bgpGroup + " | display set | match neighbor | match peer-as | no-more");
            String whoisData = executeWhoisQuery("-r " + SELF_AS, WHOIS_SERVER);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("whoisData: {}", whoisData);
                try (PrintWriter writer = new PrintWriter("whois_debug.txt", "UTF-8")) {
                    writer.println(whoisData);
                }
            }

            StringBuilder irrContent = new StringBuilder();
            irrContent.append("# ").append(isIPv6 ? "IPv6" : "IPv4").append(" Objects\n");
            irrContent.append("peering-set: ").append(peeringSetName).append("\n");

            Map<String, String> neighborIps = new HashMap<>();
            Map<String, List<String>> neighborPrefixes = new HashMap<>();
//            Pattern neighborPattern = Pattern.compile("set\\s+protocols\\s+bgp\\s+group\\s+" + Pattern.quote(bgpGroup) + "\\s+neighbor\\s+" + ipRegex + "\\s+peer-as\\s+(\\d+)");
            Pattern neighborPattern = Pattern.compile("group\\s+" + Pattern.quote(bgpGroup) + "\\s+neighbor\\s+" + ipRegex + "\\s+peer-as\\s+(\\d+)");
            Matcher matcher = neighborPattern.matcher(bgpConfig);
            while (matcher.find()) {
                String neighborIp = matcher.group(1);
                String asNumber = matcher.group(2);
                String peerAs = "AS" + asNumber;
                if (isPrivateAs(peerAs)) {
                    LOGGER.info("Skipping neighbor {} with private AS {}", neighborIp, peerAs);
                    continue;
                }
                String peeringLine = isIPv6
                        ? String.format("mp-peering: %s %s at %s", peerAs, neighborIp, routerIp)
                        : String.format("peering: %s %s at %s", peerAs, neighborIp, routerIp);
                irrContent.append(peeringLine).append("\n");
                neighborIps.put(peerAs, neighborIp);
                if (isIPv6) {
                    List<String> prefixes = getV6Networks(peerAs);
                    neighborPrefixes.put(peerAs, prefixes);
                }
            }

            irrContent.append("\n");
            irrContent.append("aut-num: ").append(SELF_AS).append("\n");
            if (isIPv6) {
                irrContent.append("mp-export: to ").append(peeringSetName).append(" announce ANY;\n");
                irrContent.append("mp-import: { from AS-ANY accept ").append(forbiddenPrefixes).append("; }\n");
                irrContent.append(" refine { from AS-ANY accept ANY; }\n");
            } else {
                irrContent.append("export: to ").append(peeringSetName).append(" announce ANY;\n");
                irrContent.append("import: { from AS-ANY accept ").append(forbiddenPrefixes).append("; }\n");
                irrContent.append(" refine { from AS-ANY accept ANY; }\n");
            }
            irrContent.append(" refine {\n");

            String importField = isIPv6
                    ? "mp-import:\\s*afi ipv6\\.unicast\\s*from\\s+AS(\\d+)\\s*(.*?)\\s*(?:#.*)?$"
                    : "^import:\\s*from\\s+AS(\\d+)\\s*(.*?)\\s*(?:#.*)?$";
            Pattern importPattern = Pattern.compile(importField, Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
            matcher = importPattern.matcher(whoisData);
            Set<String> fromAsns = new TreeSet<>();
            Map<String, String> importRules = new HashMap<>();
            while (matcher.find()) {
                String as = matcher.group(1);
                String rule = matcher.group(2).trim();
                String peerAs = "AS" + as;
                if (isPrivateAs(peerAs)) {
                    LOGGER.info("Skipping import rule for private AS{}", peerAs);
                    continue;
                }
                fromAsns.add(as);
                importRules.put(as, rule);
            }
            LOGGER.debug("fromAsns: {}", fromAsns);

            for (Map.Entry<String, String> entry : neighborIps.entrySet()) {
                String peerAs = entry.getKey();
                String neighborIp = entry.getValue();
                String asNumber = peerAs.replace("AS", "");
                String rule;
                if (isIPv6 && neighborPrefixes.containsKey(peerAs) && !neighborPrefixes.get(peerAs).isEmpty()) {
                    rule = "{ " + String.join(", ", neighborPrefixes.get(peerAs)) + " }";
                } else {
                    rule = importRules.getOrDefault(asNumber, "");
                    if (rule.isEmpty()) {
                        String whoisExport = executeWhoisQuery("-r AS" + asNumber, WHOIS_SERVER);
                        String exportField = isIPv6
                                ? "^mp-import:\\s*afi ipv6\\.unicast\\s*from\\s+AS" + asNumber + "\\s+accept\\s+(\\S+)"
                                : "^import:\\s*from\\s+AS" + asNumber + "\\s+accept\\s+(\\S+)";
                        Pattern exportPattern = Pattern.compile(exportField, Pattern.MULTILINE);
                        Matcher exportMatcher = exportPattern.matcher(whoisExport);
                        rule = exportMatcher.find() ? exportMatcher.group(1) : peerAs;
                    }
                    rule = rule.replaceFirst("^accept\\s+", "").trim();
                }
                irrContent.append(String.format("   from %s %s at %s accept %s;\n", peerAs, neighborIp, routerIp, rule));
            }

            irrContent.append(" }\n");

            LOGGER.debug("Generated IRR content: {}", irrContent.toString());
            try (PrintWriter writer = new PrintWriter(new FileOutputStream(IRR_CACHE_FILE, false), true, StandardCharsets.UTF_8)) {
                writer.println(irrContent);
            }
            validateIrrFile();
            LOGGER.info("IRR objects for {} written to {}", isIPv6 ? "IPv6" : "IPv4", IRR_CACHE_FILE);
        } finally {
            disconnectAndSleep(session);
        }
    }

    private static com.jcraft.jsch.Session connect() throws JSchException {
        LOGGER.debug("Connecting to router {}", ROUTER_IP);
        JSch jsch = new JSch();
        com.jcraft.jsch.Session session = jsch.getSession(USERNAME, ROUTER_IP, 22);
        session.setPassword(PASSWORD);
        session.setConfig("StrictHostKeyChecking", "no");
        //session.setConfig("ServerAliveInterval", "60");
        //session.setConfig("ServerAliveCountMax", "3");
        session.connect();
        return session;
    }

    private static String executeSshCommand(com.jcraft.jsch.Session session, String command) throws JSchException, IOException {
        LOGGER.debug("Executing SSH command: {}", command);
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand(command);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();
        channel.setOutputStream(output);
        channel.setErrStream(error);
        channel.connect();

        long startTime = System.currentTimeMillis();
        int timeoutMs = 10000;
        while (!channel.isClosed() && System.currentTimeMillis() - startTime < timeoutMs) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during SSH command execution", e);
            }
        }

        if (!channel.isClosed()) {
            LOGGER.warn("SSH command '{}' did not complete within {} ms, forcing disconnect", command, timeoutMs);
            disconnectAndSleep(channel);
        }

        disconnectAndSleep(channel);

        String result = output.toString("UTF-8");
        String errorOutput = error.toString("UTF-8");
        if (!errorOutput.isEmpty()) {
            LOGGER.warn("SSH command '{}' error output: {}", command, replaceControlCharsWithUnicode(errorOutput));
        }
        LOGGER.debug("SSH command '{}' output: {}", command, replaceControlCharsWithUnicode(result));
        return result;
    }

    private static String executeWhoisQuery(String query, String server) throws IOException {
        LOGGER.debug("Executing WHOIS query: {} on server: {}", query, server);
        int maxRetries = 3;
        int retryDelayMs = 1000;
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            WhoisClient whois = new WhoisClient();
            whois.setConnectTimeout(5000);
            whois.setDefaultTimeout(10000);
            try {
                whois.connect(server);
                String fullQuery = WHOIS_OPTIONS + " " + query;
                String response = whois.query(fullQuery);
                LOGGER.debug("WHOIS response: {}", response);
                return response;
            } catch (IOException e) {
                LOGGER.warn("WHOIS query attempt {}/{} failed: {}", attempt, maxRetries, e.getMessage());
                if (attempt == maxRetries) {
                    LOGGER.error("Failed to execute WHOIS query: {} on server: {}", query, server, e);
                    throw e;
                }
                try {
                    Thread.sleep(retryDelayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted during WHOIS retry", ie);
                }
            } finally {
                try {
                    disconnectAndSleep(whois);
                } catch (IOException e) {
                    LOGGER.warn("Failed to disconnect WHOIS client", e);
                }
            }
        }
        throw new IOException("Unreachable code");
    }

    private static List<String> getV6Networks(String peerAs) throws IOException {
        LOGGER.info("Fetching v6networks for {}", peerAs);
        String asNumber = peerAs.replace("AS", "");
        ProcessBuilder pb = new ProcessBuilder(
                RTCONFIG_PATH,
                "-h", WHOIS_SERVER,
                "-protocol", "rawhoisd",
                "-s", String.join(",", IRR_SOURCES)
        );
        LOGGER.debug("Starting rtconfig process: {}", String.join(" ", pb.command()));
        Process process = pb.start();
        BufferedReader stdoutReader = null;
        BufferedReader stderrReader = null;
        String errorOutput;
        try {
            try (OutputStream stdin = process.getOutputStream(); BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(stdin))) {
                writer.write("@rtconfig v6networks " + peerAs + "\n");
                writer.newLine();
                writer.flush();
                writer.close();
                LOGGER.debug("Sent rtconfig command: @rtconfig v6networks {}", peerAs);
            }

            stdoutReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            stderrReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            LOGGER.debug("Reading stderr for peerAs: {}", peerAs);
            StringBuilder errorOutputBuilder = new StringBuilder();
            long startTime = System.currentTimeMillis();
            long timeoutMs = 5000;
            while (System.currentTimeMillis() - startTime < timeoutMs) {
                String line = stderrReader.readLine();
                if (line == null) {
                    break;
                }
                errorOutputBuilder.append(line).append("\n");
            }
            errorOutput = errorOutputBuilder.toString();
            if (!errorOutput.isEmpty()) {
                LOGGER.warn("rtconfig stderr for {}: {}", peerAs, errorOutput);
            } else {
                LOGGER.debug("No stderr output for peerAs: {}", peerAs);
            }

            LOGGER.debug("Reading stdout for peerAs: {}", peerAs);
            List<String> prefixes = new ArrayList<>();
            Pattern networkPattern = Pattern.compile("^\\s*network\\s+([0-9a-fA-F:]+)\\s+mask\\s+([0-9a-fA-F:]+)\\s*$");
            StringBuilder rawOutput = new StringBuilder();
            String line;
            while ((line = stdoutReader.readLine()) != null) {
                LOGGER.debug("stdoutReader: {}", line);
                rawOutput.append(line).append("\n");
                Matcher matcher = networkPattern.matcher(line);
                if (matcher.find()) {
                    String network = matcher.group(1);
                    String mask = matcher.group(2);
                    LOGGER.debug("found: {} {}", network, mask);
                    String prefix = convertToCidr(network, mask);
                    LOGGER.debug("prefix: {}", prefix);
                    prefixes.add(prefix);
                }
            }
            LOGGER.debug("Raw rtconfig output for {}: {}", peerAs, rawOutput.toString().replace("\n", "\\n"));

            LOGGER.debug("Waiting for rtconfig process to complete for peerAs: {}", peerAs);
            try {
                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    LOGGER.error("rtconfig timed out for peerAs: {}", peerAs);
                    throw new IOException("rtconfig timed out for " + peerAs);
                }
                int exitCode = process.exitValue();
                if (exitCode != 0) {
                    LOGGER.error("rtconfig failed with exit code {}: {}", exitCode, rawOutput.toString().replace("\n", "\\n"));
                    LOGGER.error("Error output: {}", errorOutput);
                    throw new IOException("rtconfig failed with exit code " + exitCode + ": " + errorOutput);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.error("Interrupted while waiting for rtconfig for peerAs: {}", peerAs, e);
                throw new IOException("Interrupted while executing rtconfig", e);
            }

            return prefixes;
        } finally {
            if (stdoutReader != null) {
                LOGGER.debug("Closing stdoutReader for peerAs: {}", peerAs);
                try {
                    stdoutReader.close();
                } catch (IOException e) {
                    LOGGER.warn("Failed to close stdoutReader for peerAs: {}: {}", peerAs, e.getMessage());
                }
            }
            if (stderrReader != null) {
                LOGGER.debug("Closing stderrReader for peerAs: {}", peerAs);
                try {
                    stderrReader.close();
                } catch (IOException e) {
                    LOGGER.warn("Failed to close stderrReader for peerAs: {}: {}", peerAs, e.getMessage());
                }
            }
            if (process != null && process.isAlive()) {
                LOGGER.debug("Destroying process for peerAs: {}", peerAs);
                process.destroy();
            }
        }
    }

    private static String convertToCidr(String network, String mask) {
        try {
            InetAddress maskAddr = InetAddress.getByName(mask);
            int prefixLength = 0;
            for (byte b : maskAddr.getAddress()) {
                prefixLength += Integer.bitCount(b & 0xFF);
            }
            return network + "/" + prefixLength;
        } catch (UnknownHostException e) {
            LOGGER.error("Invalid mask {} for network {}", mask, network, e);
            return network + "/128";
        }
    }

    private static boolean isPrivateAs(String as) {
        try {
            long asNumber = Long.parseLong(as.replace("AS", ""));
            if (asNumber == 0 || asNumber == 23456 || asNumber >= 64496 && asNumber <= 65535) {
                return true;
            }
            if (asNumber >= 4200000000L && asNumber <= 4294967295L) {
                return true;
            }
            return false;
        } catch (NumberFormatException e) {
            LOGGER.warn("Invalid AS number format: {}", as);
            return true;
        }
    }

    private static void validateIrrFile() throws IOException {
        LOGGER.debug("Validating IRR file: {}", IRR_CACHE_FILE);
        if (!Files.exists(Paths.get(IRR_CACHE_FILE))) {
            throw new IOException("IRR file does not exist: " + IRR_CACHE_FILE);
        }
        List<String> lines = Files.readAllLines(Paths.get(IRR_CACHE_FILE));
        if (lines.isEmpty()) {
            throw new IOException("IRR file is empty: " + IRR_CACHE_FILE);
        }
        boolean hasPeeringSet = lines.stream().anyMatch(line -> line.startsWith("peering-set:"));
        boolean hasAutNum = lines.stream().anyMatch(line -> line.startsWith("aut-num:"));
        if (!hasPeeringSet || !hasAutNum) {
            throw new IOException("IRR file missing required sections (peering-set or aut-num): " + IRR_CACHE_FILE);
        }
        LOGGER.debug("IRR file validated successfully");
    }

    private static void generateRouteFilters(Args config) throws JSchException, IOException {
        LOGGER.info("Generating route filters for {}", config.ipv6 ? "IPv6" : "IPv4");
        com.jcraft.jsch.Session session = connect();
        try (PrintWriter out = config.outputFile != null
                ? new PrintWriter(config.outputFile, "UTF-8")
                : new PrintWriter(System.out)) {
            List<Neighbor> neighbors = parseNeighbors(session, config.ipv6).stream()
                    .sorted(Comparator.comparing((Neighbor n) -> n.ip))
                    .collect(Collectors.toList());
            LOGGER.info("Processing {} BGP neighbors", neighbors.size());
            Set<String> processedNeighbors = new HashSet<>();
            for (Neighbor neighbor : neighbors) {
                if (!processedNeighbors.add(neighbor.ip)) {
                    LOGGER.warn("Skipping duplicate neighbor: {}", neighbor.ip);
                    continue;
                }
                if (isPrivateAs(neighbor.peerAs)) {
                    LOGGER.info("Skipping neighbor {} with private AS {}", neighbor.ip, neighbor.peerAs);
                    out.printf("# Skipped neighbor %s: private AS %s\n", neighbor.ip, neighbor.peerAs);
                    continue;
                }
                LOGGER.debug("Processing neighbor: IP={}, AS={}", neighbor.ip, neighbor.peerAs);
                String export = getWhoisExport(neighbor, session, out, config.ipv6, config.forceIPv6);
                if (config.ipv6) {
                    if (export == null) {
                        continue;
                    }
                    printHeader(out, neighbor, export);
                    List<String> prefixes = getV6Networks(neighbor.peerAs);
                    if (prefixes.isEmpty()) {
                        LOGGER.warn("No IPv6 prefixes for {} via @rtconfig v6networks", neighbor.peerAs);
                        out.printf("# No IPv6 prefixes found for %s via @rtconfig v6networks\n", neighbor.peerAs);
                        out.printf("deactivate protocols bgp group %s neighbor %s\n", BGP_GROUP_IPV6, neighbor.ip);
                        continue;
                    }
                    List<String> routeFilters = prefixes.stream()
                            .map(p -> "route-filter " + p + " exact accept")
                            .filter(rf -> isValidPrefix(rf, config.ipv4, config.ipv6))
                            .collect(Collectors.toList());
                    printRouteFilters(true, out, neighbor, "p", routeFilters);
                } else {
                    String bgpState = checkBgpState(session, neighbor.ip);
                    if (export == null && !"Established".equals(bgpState)) {
                        LOGGER.debug("Skipping neighbor {} (not established)", neighbor.ip);
                        out.printf("deactivate protocols bgp group %s neighbor %s\n", BGP_GROUP_IPV4, neighbor.ip);
                        continue;
                    }
                    printHeader(out, neighbor, export != null ? export : "None");
                    List<String> routeFilters = getRouteFilters(neighbor, out, config.ipv6);
                    if (!routeFilters.isEmpty()) {
                        routeFilters = routeFilters.stream()
                                .filter(rf -> isValidPrefix(rf, config.ipv4, config.ipv6))
                                .collect(Collectors.toList());
                        printRouteFilters(false, out, neighbor, "r", routeFilters);
                    } else {
                        LOGGER.warn("No route-filters for {}, trying prefixes", neighbor.peerAs);
                        out.println("# Type: rtconfig did not return any information…");
                        List<String> prefixes = getPrefixes(export != null ? export : neighbor.peerAs, config.ipv6);
                        prefixes = prefixes.stream()
                                .filter(p -> isValidPrefix(p, config.ipv4, config.ipv6))
                                .collect(Collectors.toList());
                        if (!prefixes.isEmpty()) {
                            printRouteFilters(false, out, neighbor, "p", prefixes);
                        } else if ("Established".equals(bgpState)) {
                            out.println("#! Manual analysis required.");
                            prefixes = getPrefixes(neighbor.peerAs, config.ipv6).stream()
                                    .filter(p -> isValidPrefix(p, config.ipv4, config.ipv6))
                                    .collect(Collectors.toList());
                            if (!prefixes.isEmpty()) {
                                printRouteFilters(false, out, neighbor, "p", prefixes);
                            }
                        } else {
                            out.printf("deactivate protocols bgp group %s neighbor %s\n", BGP_GROUP_IPV4, neighbor.ip);
                        }
                    }
                }
                out.println();
            }
        } finally {
            disconnectAndSleep(session);
        }
    }

    private static List<Neighbor> parseNeighbors(com.jcraft.jsch.Session session, boolean isIPv6) throws JSchException, IOException {
        String bgpGroup = isIPv6 ? BGP_GROUP_IPV6 : BGP_GROUP_IPV4;
        String exceptClause = " except \"" + String.join("|", EXCEPT_REGEX_VALUES) + "\"";
        String command = "show configuration protocols bgp group " + bgpGroup
                + " | display set | match \"(peer-as|import|description)\" | match neighbor |" + exceptClause + " | no-more";
        String output = executeSshCommand(session, command);
        LOGGER.debug("Raw line before processing: [{}]", replaceControlCharsWithUnicode(output));
        if (output.contains("error:") || output.trim().isEmpty()) {
            LOGGER.error("Failed to retrieve BGP neighbors: {}", output);
            throw new IOException("Failed to retrieve BGP neighbors: " + output);
        }
        String ipRegex = isIPv6 ? IPV6_REGEX : IPV4_REGEX;
        Pattern reDescription = Pattern.compile("neighbor\\s+(" + ipRegex + ")\\s+description\\s+(.+)");
        Pattern reImport = Pattern.compile("neighbor\\s+(" + ipRegex + ")\\s+import\\s+(.+)");
        Pattern rePeerAs = Pattern.compile("neighbor\\s+(" + ipRegex + ")\\s+peer-as\\s+(.+)");
        Map<String, Neighbor> neighbors = new HashMap<>();

        for (String line : output.split("\n")) {
            if (line.trim().isEmpty()) {
                continue;
            }
            LOGGER.debug("Raw line before processing: [{}]", replaceControlCharsWithUnicode(line));
            line = line.replaceAll("[\\p{Cntrl}]", "").trim();
            Matcher md = reDescription.matcher(line);
            Matcher mi = reImport.matcher(line);
            Matcher mp = rePeerAs.matcher(line);
            if (md.find()) {
                neighbors.computeIfAbsent(md.group(1), Neighbor::new).description = md.group(2);
                LOGGER.debug("Matched description: IP={}, Description={}", md.group(1), md.group(2));

            } else if (mi.find()) {
                neighbors.computeIfAbsent(mi.group(1), Neighbor::new).importPolicy = mi.group(2);
                LOGGER.debug("Matched import: IP={}, Import={}", mi.group(1), mi.group(2));

            } else if (mp.find()) {
                neighbors.computeIfAbsent(mp.group(1), Neighbor::new).peerAs = "AS" + mp.group(2);
                LOGGER.debug("Matched peer-as: IP={}, PeerAs=AS{}", mp.group(1), mp.group(2));
            } else {
                LOGGER.debug("Line did not match any pattern: {}", line);
            }
        }
        if (neighbors.isEmpty()) {
            LOGGER.warn("No BGP neighbors found for group {}", bgpGroup);
        } else {
            for (Neighbor neighbor : neighbors.values()) {
                if (neighbor.peerAs == null) {
                    LOGGER.warn("Neighbor {} is missing peer-as", neighbor.ip);
                }
                if (LOGGER.isDebugEnabled()) {
                    if (neighbor.importPolicy == null) {
                        LOGGER.debug("Neighbor {} has no import policy", neighbor.ip);
                    }
                    if (neighbor.description == null) {
                        LOGGER.debug("Neighbor {} has no description", neighbor.ip);
                    }
                }
            }
        }
        return new ArrayList<>(neighbors.values());
    }

    private static String getWhoisExport(Neighbor neighbor, com.jcraft.jsch.Session session, PrintWriter out, boolean isIPv6, boolean forceIPv6) throws IOException, JSchException {
        String whoisOutput = executeWhoisQuery("-r " + neighbor.peerAs, WHOIS_SERVER);
        if (isIPv6) {
            Pattern exportPattern = Pattern.compile("^mp-export:\\s*afi ipv6\\.unicast\\s*to\\s+" + SELF_AS + "\\s+announce\\s+(\\S+)", Pattern.MULTILINE);
            Pattern importPattern = Pattern.compile("^mp-import:\\s*afi ipv6\\.unicast\\s*from\\s+" + SELF_AS + "\\s+accept\\s+(\\S+)", Pattern.MULTILINE);
            Matcher exportMatcher = exportPattern.matcher(whoisOutput);
            Matcher importMatcher = importPattern.matcher(whoisOutput);
            boolean hasRelation = exportMatcher.find() || importMatcher.find();
            String export = hasRelation ? (exportMatcher.find(0) ? exportMatcher.group(1) : importMatcher.group(1)) : "";
            if (!hasRelation) {
                printHeader(out, neighbor, "None");
                LOGGER.info("NO MP-EXPORT/MP-IMPORT INFORMATION FOR {} WITH {} IN RIPE-DB", neighbor.peerAs, SELF_AS);
                out.printf("# The %s does not contain mp-export/mp-import information for %s in RIPE-DB\n", neighbor.peerAs, SELF_AS);
                String state = checkBgpState(session, neighbor.ip);
                out.printf("#> Type: External    State: %s\n", state);
                if (forceIPv6) {
                    LOGGER.warn("FORCEIPV6 ENABLED: GENERATING PREFIXES FOR {} USING V6NETWORKS DESPITE MISSING WHOIS DATA", neighbor.peerAs);
                    return neighbor.peerAs;
                } else {
                    out.printf("deactivate protocols bgp group %s neighbor %s\n", isIPv6 ? BGP_GROUP_IPV6 : BGP_GROUP_IPV4, neighbor.ip);
                    return null;
                }
            }
            return export;
        } else {
            String exportField = "^export:\\s+to\\s+" + SELF_AS + "\\s+announce\\s+(\\S+)";
            Pattern exportPattern = Pattern.compile(exportField, Pattern.MULTILINE);
            Matcher matcher = exportPattern.matcher(whoisOutput);
            String export = matcher.find() ? matcher.group(1) : "";
            if (export.isEmpty()) {
                printHeader(out, neighbor, "None");
                LOGGER.info("No export information for {} in RIPE-DB", neighbor.peerAs);
                out.printf("# The %s does not contain \"export\" information about the %s in RIPE-DB\n", neighbor.peerAs, SELF_AS);
                String state = checkBgpState(session, neighbor.ip);
                out.printf("#> Type: External    State: %s\n", state);
                if ("Established".equals(state)) {
                    out.println("#! Manual analysis required.");
                    List<String> prefixes = getPrefixes(neighbor.peerAs, isIPv6);
                    if (!prefixes.isEmpty()) {
                        printRouteFilters(isIPv6, out, neighbor, "p", prefixes);
                        return neighbor.peerAs;
                    }
                }
                out.printf("deactivate protocols bgp group %s neighbor %s\n", isIPv6 ? BGP_GROUP_IPV6 : BGP_GROUP_IPV4, neighbor.ip);
                return null;
            }
            return export;
        }
    }

    private static String checkBgpState(com.jcraft.jsch.Session session, String neighborIp) throws JSchException, IOException {
        String command = String.format("show bgp neighbor %s | match \"(Type:.*State:|Last State:)\"", neighborIp);
        String output = executeSshCommand(session, command);
        LOGGER.debug("Raw BGP state output for {}: {}", neighborIp, replaceControlCharsWithUnicode(output));
        String state = "Unknown";
        for (String line : output.split("\n")) {
            if (line.contains("State:")) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length > 3 && parts[1].equals("External")) {
                    state = parts[3];
                    LOGGER.debug("Parsed BGP state for {}: {}", neighborIp, state);
                    return state;
                }
            }
        }
        LOGGER.warn("Failed to parse BGP state for {}, output: {}", neighborIp, replaceControlCharsWithUnicode(output));
        return state;
    }

    private static List<String> getRouteFilters(Neighbor neighbor, PrintWriter out, boolean isIPv6) throws IOException {
        String rtconfigInput = String.format("@rtconfig import %s %s %s %s",
                SELF_AS, isIPv6 ? ROUTER_IP_IPV6 : ROUTER_IP, neighbor.peerAs, neighbor.ip);
        out.println("# Type: rtconfig import…");
        out.println("# " + rtconfigInput);
        String output = executeRtconfigCommand(rtconfigInput, isIPv6);
        LOGGER.debug("rtconfig import output for {}: {}", neighbor.peerAs, output);
        List<String> routeFilters = output.lines()
                .filter(line -> line.trim().startsWith("route-filter"))
                .map(line -> line.replaceFirst("^\\s+", "").replace(";", ""))
                .collect(Collectors.toList());
        if (routeFilters.isEmpty()) {
            LOGGER.warn("No route-filters for {}, rtconfig output: {}, checking WHOIS data", neighbor.peerAs, output);
            LOGGER.debug("IRR content: {}", Files.readString(Paths.get(IRR_CACHE_FILE)));
            out.println("# Type: rtconfig did not return any information…");
            out.println("# rtconfig output: " + output);
            String whoisExport = executeWhoisQuery("-r " + neighbor.peerAs, WHOIS_SERVER);
            LOGGER.debug("WHOIS data for {}: {}", neighbor.peerAs, whoisExport);
            String exportField = isIPv6 ? "^mp-import:\\s*afi ipv6\\.unicast\\s*from\\s+AS" + neighbor.peerAs.replace("AS", "") + "\\s+accept\\s+(\\S+)" : "^import:\\s*from\\s+AS" + neighbor.peerAs.replace("AS", "") + "\\s+accept\\s+(\\S+)";
            Pattern exportPattern = Pattern.compile(exportField, Pattern.MULTILINE);
            Matcher exportMatcher = exportPattern.matcher(whoisExport);
            String rule = exportMatcher.find() ? exportMatcher.group(1) : neighbor.peerAs;
            String prefixInput = String.format("@rtconfig printPrefixes \"%%p/%%l\\n\" filter %s", rule);
            String prefixOutput = executeRtconfigCommand(prefixInput, isIPv6);
            LOGGER.debug("rtconfig printPrefixes output for {}: {}", rule, prefixOutput);
            routeFilters = prefixOutput.lines()
                    .filter(line -> !line.trim().isEmpty())
                    .map(p -> "route-filter " + p + " exact accept")
                    .collect(Collectors.toList());
        } else {
            LOGGER.info("Route filters retrieved for {}: {}", neighbor.peerAs, routeFilters);
        }
        return routeFilters;
    }

    private static List<String> getPrefixes(String export, boolean isIPv6) throws IOException {
        String rtconfigInput = String.format("@rtconfig printPrefixes \"%%p/%%l\\n\" filter %s", export);
        String output = executeRtconfigCommand(rtconfigInput, isIPv6);
        List<String> prefixes = output.isEmpty() ? new ArrayList<>() : Arrays.asList(output.split("\n"));
        if (!prefixes.isEmpty()) {
            LOGGER.info("Retrieved prefixes for {}: {}", export, prefixes);
        }
        return prefixes;
    }

    private static void printHeader(PrintWriter out, Neighbor neighbor, String export) {
        out.printf("## %s : %s : %s : %s : %s\n", neighbor.ip, neighbor.peerAs, export, neighbor.importPolicy, neighbor.description);
    }

    private static void printRouteFilters(boolean isIPv6, PrintWriter out, Neighbor neighbor, String type, List<String> routeFilters) {
        out.printf("delete policy-options policy-statement %s term accept" + (isIPv6 ? "_v6" : "") + " from\n", neighbor.importPolicy);
        for (String rf : routeFilters) {
            String cleanRf = rf.replace(";", "").trim();
            out.printf("set policy-options policy-statement %s term accept" + (isIPv6 ? "_v6" : "") + " from %s\n", neighbor.importPolicy, cleanRf);
            if (cleanRf.contains("accept")) {
                String nextPolicy = cleanRf.replace(" accept", " next policy");
                out.printf("set policy-options policy-statement %s term accept" + (isIPv6 ? "_v6" : "") + " from %s\n", neighbor.importPolicy, nextPolicy);
            }
        }
    }

    private static boolean isValidPrefix(String prefix, boolean ipv4, boolean ipv6) {
        if (prefix.contains("::") && !ipv6) {
            return false;
        }
        return !(!prefix.contains("::") && !ipv4);
    }

    private static void applyConfiguration(String configFile) throws JSchException, IOException {
        String result;
        LOGGER.info("Applying configuration from {} to router {}", configFile, ROUTER_IP);
        com.jcraft.jsch.Session session = connect();
        ChannelShell channel = null;
        try {
            channel = (ChannelShell) session.openChannel("shell");

            channel.setPty(true);
            channel.setPtyType("vt100");
            LOGGER.debug("PTY enabled, type: vt100");

            InputStream in = channel.getInputStream();
            OutputStream out = channel.getOutputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
            channel.connect(3000);
            LOGGER.debug("Channel connected, isConnected: {}, isClosed: {}, isEOF: {}",
                    channel.isConnected(), channel.isClosed(), in.available() == -1);

            String initialPrompt = waitForPrompt(reader, in, "operational");
            LOGGER.debug("Found initial prompt: {}", replaceControlCharsWithUnicode(initialPrompt));

            LOGGER.debug("Executing initial configure private");
            result = executeCommandWithRetries(channel, in, reader, writer, "configure private\r\n", "config", 30000);
            LOGGER.debug("configure private output: {}", replaceControlCharsWithUnicode(result));

            List<String> configCommands = Files.readAllLines(Paths.get(configFile)).stream()
                    .filter(line -> !line.trim().startsWith("#") && !line.trim().isEmpty())
                    .collect(Collectors.toList());

            LOGGER.debug("Applying {} configuration commands", configCommands.size());
            for (String command : configCommands) {
                result = executeCommandWithRetries(channel, in, reader, writer, command + "\r\n", "config", 30000);
                LOGGER.debug("Command '{}' output: {}", command, replaceControlCharsWithUnicode(result));
            }

            String compareResult = executeCommandWithRetries(channel, in, reader, writer, "show | compare | no-more\r\n", "config", 60000);
            LOGGER.debug("Raw show | compare output before cleaning: [{}]", replaceControlCharsWithUnicode(compareResult));
            String cleanedCompare = cleanCompareOutput(compareResult);
            LOGGER.debug("Cleaned show | compare output: [{}]", replaceControlCharsWithUnicode(cleanedCompare));

            if (REPORT_TO != null && !REPORT_TO.isEmpty() && REPORT_FROM != null && !REPORT_FROM.isEmpty()) {
                String sessionId = System.getProperty("session.id", UUID.randomUUID().toString());
                File tempFile = File.createTempFile("show_compare", ".txt");
                try (PrintWriter writerFile = new PrintWriter(tempFile, "UTF-8")) {
                    writerFile.println("RouteFilterUpdater Configuration Changes:\n");
                    writerFile.println(cleanedCompare);
                }
                sendReport(tempFile);
                tempFile.delete();
            }

            try {
                result = executeCommandWithRetries(channel, in, reader, writer, "commit and-quit\r\n", "operational", 120000);
                LOGGER.debug("commit and-quit output: {}", replaceControlCharsWithUnicode(result));
            } catch (IOException e) {
                LOGGER.error("commit and-quit failed: {}", e.getMessage());
                throw e;
            }
            LOGGER.info("Configuration committed successfully");
        } finally {
            if (channel != null) {
                try {
                    disconnectAndSleep(channel);
                } catch (Exception e) {
                    LOGGER.debug("Channel disconnect exception: {}", e.getMessage());
                }
            }
            if (session != null) {
                try {
                    disconnectAndSleep(session);
                } catch (Exception e) {
                    LOGGER.debug("Session disconnect exception: {}", e.getMessage());
                }
            }
        }
    }

    private static void sendCommand(ChannelShell channel, BufferedWriter writer, String command) throws IOException {
        if (!channel.isConnected()) {
            LOGGER.error("Channel is not connected, cannot send command: {}", command.trim());
            throw new IOException("Channel is not connected");
        }
        LOGGER.debug("Sending command: {}, channel connected: {}", command.trim(), channel.isConnected());
        writer.write(command);
        writer.flush();
        LOGGER.debug("Command flushed to BufferedWriter, channel state: isConnected={}, isClosed={}",
                channel.isConnected(), channel.isClosed());
    }

    private static String waitForPrompt(BufferedReader reader, InputStream in, String mode) throws IOException {
        long startTime = System.currentTimeMillis();
        int timeoutMs = mode.equals("operational") ? 120000 : 30000;
        StringBuilder result = new StringBuilder();
        String promptRegex = mode.equals("operational") ? USERNAME + "@[^>]+>\\s*" : USERNAME + "@[^#]+#\\s*";
        Pattern promptPattern = Pattern.compile("(?s)" + promptRegex + "$", Pattern.DOTALL);
        Pattern promptSkipper = Pattern.compile("(?s)^.*?" + USERNAME + "@[^>#]+[>#](?![\\s\\r\\n]*$)", Pattern.DOTALL);

        while (System.currentTimeMillis() - startTime < timeoutMs) {
            if (reader.ready()) {
                char[] buffer = new char[16384];
                int bytesRead = reader.read(buffer);
                if (bytesRead > 0) {
                    String data = new String(buffer, 0, bytesRead);
                    data = data.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]|[\\x1B]\\[[0-9;]*[a-zA-Z]", "");

                    Matcher skipperMatcher = promptSkipper.matcher(data);
                    if (skipperMatcher.find()) {
                        data = skipperMatcher.replaceAll("");
                    }

                    Matcher promptMatcher = promptPattern.matcher(data);
                    if (promptMatcher.find()) {
                        data = data.substring(0, promptMatcher.end());
                    }

                    result.append(data);
                    String sData = replaceControlCharsWithUnicode(data);
                    if (LOGGER.isDebugEnabled() && (data.length() > 1 || data.contains("commit") || data.contains("Exiting") || data.contains("noc@"))) {
                        String oData = sData.length() > 80 ? sData.substring(sData.length() - 80) : sData;
                        LOGGER.debug("Received data: [{}] (length: {})", oData, data.length());
                    }
                    String currentOutput = result.toString();
                    if (LOGGER.isDebugEnabled()) {
                        String sResult = replaceControlCharsWithUnicode(currentOutput);
                        String oResult = sResult.length() > 80 ? sResult.substring(sResult.length() - 80) : sResult;
                        LOGGER.debug("Current output buffer: [{}]", oResult);
                    }
                    if (promptPattern.matcher(currentOutput).find()) {
                        LOGGER.debug("Found prompt in output: {}", replaceControlCharsWithUnicode(currentOutput));
                        return currentOutput.trim();
                    }
                }
            } else {
                int available = in.available();
                if (available > 0) {
                    byte[] rawBytes = new byte[available];
                    int bytesRead = in.read(rawBytes);
                    if (bytesRead > 0) {
                        String rawData = new String(rawBytes, StandardCharsets.UTF_8);
                        rawData = rawData.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]|[\\x1B]\\[[0-9;]*[a-zA-Z]", "");

                        Matcher skipperMatcher = promptSkipper.matcher(rawData);
                        if (skipperMatcher.find()) {
                            rawData = skipperMatcher.replaceAll("");
                        }

                        Matcher promptMatcher = promptPattern.matcher(rawData);
                        if (promptMatcher.find()) {
                            rawData = rawData.substring(0, promptMatcher.end());
                        }

                        result.append(rawData);
                        if (LOGGER.isDebugEnabled() && (rawData.length() > 1 || rawData.contains("commit") || rawData.contains("Exiting") || rawData.contains("noc@"))) {
                            String sRawData = replaceControlCharsWithUnicode(rawData);
                            LOGGER.debug("Direct InputStream read: {} bytes, data: [{}]", bytesRead,
                                    sRawData.length() > 80 ? sRawData.substring(sRawData.length() - 80) : sRawData);
                        }
                    }
                }
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("No data available, reader.ready(): false, channel EOF: {}", in.available() == -1);
                }
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted in waitForPrompt", e);
                }
            }
        }

        LOGGER.error("Timeout waiting for prompt (mode: {}): {}. Final output: {}", mode, promptRegex,
                result.toString().replaceAll("[\\p{Cntrl}]", "\\\\u"));
        throw new IOException("Timeout waiting for prompt (mode: " + mode + ")");
    }

    private static String executeCommandWithRetries(ChannelShell channel, InputStream in, BufferedReader reader,
            BufferedWriter writer, String command, String mode, int timeoutMs) throws IOException {
        int maxRetries = 3;
        int retryDelayMs = 1000;
        IOException lastException = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                sendCommand(channel, writer, command);
                LOGGER.debug("Command sent, attempt {}/{}, channel state: isConnected={}, isClosed={}",
                        attempt, maxRetries, channel.isConnected(), channel.isClosed());
                String originalThreadName = Thread.currentThread().getName();
                Thread.currentThread().setName(command.trim());
                try {
                    return waitForPrompt(reader, in, mode);
                } finally {
                    Thread.currentThread().setName(originalThreadName);
                }
            } catch (IOException e) {
                LOGGER.warn("Attempt {}/{} failed for command '{}': {}", attempt, maxRetries, command.trim(), e.getMessage());
                lastException = e;
                if (attempt < maxRetries) {
                    try {
                        Thread.sleep(retryDelayMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during retry for command: " + command, ie);
                    }
                }
            }
        }
        LOGGER.error("All {} attempts failed for command '{}'", maxRetries, command.trim());
        throw lastException != null ? lastException : new IOException("Failed to execute command: " + command);
    }

    private static String cleanCompareOutput(String output) {
        String[] lines = output.split("\n");
        StringBuilder cleaned = new StringBuilder();
        for (String line : lines) {
            line = line.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]|[\\x1B]\\[[0-9;]*[a-zA-Z]", "").trim();
            if (line.isEmpty() || line.matches("^" + USERNAME + "@[^>#]+[>#].*")) {
                continue;
            }
            cleaned.append(line).append("\n");
        }
        String result = cleaned.toString().trim();
        if (result.isEmpty()) {
            result = "No configuration changes detected.";
        }
        return result;
    }

    private static void sendReport(File reportFile) throws IOException {
        if (SMTP_SERVER == null || REPORT_TO == null || REPORT_TO.isEmpty() || REPORT_FROM == null || REPORT_FROM.isEmpty()) {
            LOGGER.warn("SMTP_SERVER, REPORT_TO, or REPORT_FROM not configured, skipping report sending");
            return;
        }
        LOGGER.info("Sending report from {} to {}", REPORT_FROM, REPORT_TO);
        Properties props = new Properties();
        props.put("mail.smtp.host", SMTP_SERVER);
        props.put("mail.smtp.port", SMTP_PORT != null ? SMTP_PORT : "25");
        props.put("mail.smtp.auth", SMTP_USER != null && SMTP_PASSWORD != null ? "true" : "false");

        if ("127.0.0.1".equals(SMTP_SERVER)) {
            props.put("mail.smtp.starttls.enable", "false");
        } else {
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.ssl.trust", "*");
        }

        javax.mail.Session mailSession;
        if (SMTP_USER != null && SMTP_PASSWORD != null) {
            mailSession = javax.mail.Session.getInstance(props, new javax.mail.Authenticator() {
                @Override
                protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                    return new javax.mail.PasswordAuthentication(SMTP_USER, SMTP_PASSWORD);
                }
            });
        } else {
            mailSession = javax.mail.Session.getInstance(props);
        }

        try {
            MimeMessage message = new MimeMessage(mailSession);
            message.setFrom(new InternetAddress(REPORT_FROM));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(REPORT_TO));
            message.setSubject("RouteFilterUpdater Execution Report");

            String reportContent;
            if (reportFile.exists()) {
                reportContent = Files.readString(reportFile.toPath());
            } else {
                LOGGER.warn("Session log file {} does not exist, sending empty report", reportFile.getAbsolutePath());
                reportContent = "No session log available. The log file was not created during execution.";
            }
            message.setText("RouteFilterUpdater report:\n\n" + reportContent);

            Transport.send(message);
            LOGGER.info("Report sent successfully to {}", REPORT_TO);
        } catch (MessagingException e) {
            LOGGER.error("Failed to send report to {}: {}", REPORT_TO, e.getMessage());
            throw new IOException("Failed to send report", e);
        }
    }

    private static String executeRtconfigCommand(String rtconfigInput, boolean isIPv6) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(
                RTCONFIG_PATH,
                "-h", WHOIS_SERVER,
                "-protocol", "rawhoisd",
                "-config", "junos",
                "-f", IRR_CACHE_FILE,
                "-s", String.join(",", IRR_SOURCES)
        );
        LOGGER.debug("Starting rtconfig process: {}", String.join(" ", pb.command()));
        Process process = pb.start();
        BufferedReader stdoutReader = null;
        BufferedReader stderrReader = null;
        String errorOutput;
        try {
            try (OutputStream stdin = process.getOutputStream(); BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(stdin))) {
                writer.write(rtconfigInput + "\n");
                writer.newLine();
                writer.flush();
                writer.close();
                LOGGER.debug("Sent rtconfig command: {}", rtconfigInput);
            }

            stdoutReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            stderrReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            StringBuilder errorOutputBuilder = new StringBuilder();
            long startTime = System.currentTimeMillis();
            long timeoutMs = 5000;
            while (System.currentTimeMillis() - startTime < timeoutMs) {
                String line = stderrReader.readLine();
                if (line == null) {
                    break;
                }
                errorOutputBuilder.append(line).append("\n");
            }
            errorOutput = errorOutputBuilder.toString();
            if (!errorOutput.isEmpty()) {
                LOGGER.warn("rtconfig stderr: {}", errorOutput);
            }

            StringBuilder output = new StringBuilder();
            String line;
            while ((line = stdoutReader.readLine()) != null) {
                output.append(line).append("\n");
            }

            try {
                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    LOGGER.error("rtconfig timed out for command: {}", rtconfigInput);
                    throw new IOException("rtconfig timed out");
                }
                int exitCode = process.exitValue();
                if (exitCode != 0) {
                    LOGGER.error("rtconfig failed with exit code {}: {}", exitCode, errorOutput);
                    throw new IOException("rtconfig failed with exit code " + exitCode + ": " + errorOutput);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.error("Interrupted while waiting for rtconfig", e);
                throw new IOException("Interrupted while executing rtconfig", e);
            }

            return output.toString();
        } finally {
            if (stdoutReader != null) {
                try {
                    stdoutReader.close();
                } catch (IOException e) {
                    LOGGER.warn("Failed to close stdoutReader: {}", e.getMessage());
                }
            }
            if (stderrReader != null) {
                try {
                    stderrReader.close();
                } catch (IOException e) {
                    LOGGER.warn("Failed to close stderrReader: {}", e.getMessage());
                }
            }
            if (process != null && process.isAlive()) {
                process.destroy();
            }
        }
    }

    private static void disconnectAndSleep(Object c) throws IOException {
        if (c != null) {
            switch (c) {
                case ChannelExec channelExec ->
                    channelExec.disconnect();
                case com.jcraft.jsch.Session session ->
                    session.disconnect();
                case WhoisClient whoisClient ->
                    whoisClient.disconnect();
                case ChannelShell channelShell ->
                    channelShell.disconnect();
                default -> {
                    LOGGER.error("Unknown type of Object for disconnect: {}", c.toString());
                    throw new IOException("Unknown type of Object for disconnect: " + c.toString());
                }
            }
            LOGGER.debug("Disconnect: {}", c.toString());
        }
        try {
            long st = 100 + (long) (Math.random() * 1000);
            LOGGER.debug("Sleep: {}", st);
            Thread.sleep(st);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during SSH command execution", e);
        }

    }

    public static String replaceControlCharsWithUnicode(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        Pattern pattern = Pattern.compile("[\\p{Cntrl}]");
        Matcher matcher = pattern.matcher(input);

        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            char ch = matcher.group().charAt(0);
            String unicode = String.format("\\\\U+%04X", (int) ch);
            matcher.appendReplacement(result, unicode);
        }
        matcher.appendTail(result);

        return result.toString();
    }
}
