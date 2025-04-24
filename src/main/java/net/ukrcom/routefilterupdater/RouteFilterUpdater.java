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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.*;
import java.util.stream.Collectors;

public class RouteFilterUpdater {

    private static final Logger LOGGER = LoggerFactory.getLogger(RouteFilterUpdater.class);
    private static String ROUTER_IP;
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

    static class Neighbor {

        String ip;
        String peerAs;
        String importPolicy;
        String description;

        Neighbor(String ip) {
            this.ip = ip;
        }
    }

    static class Args {

        String outputFile;
        boolean ipv4 = true;
        boolean ipv6 = false;
        boolean debug = false;
        boolean save = false;
        boolean report = false;
        boolean quiet = false;

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
                  -o <file>       Output route filters to <file>
                  -d, --debug     Enable debug logging
                  -s, --save      Apply generated configuration to the router
                  -r, --report    Send execution log to REPORT_TO email
                  -q, --quiet     Suppress console output (for cron jobs)
                  -?, -h, --help  Display this help message
                """);
        }
    }

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

        // Додаємо shutdown hook для видалення lock-файлу при Ctrl+C
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
                generateIrrObjects();
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

        for (String prop : new String[]{ROUTER_IP, USERNAME, PASSWORD, BGP_GROUP_IPV4, BGP_GROUP_IPV6, SELF_AS, IRR_CACHE_FILE, RTCONFIG_PATH}) {
            if (prop == null || prop.isEmpty()) {
                throw new IOException("Missing or empty required property in RouteFilterUpdater.properties");
            }
        }
        if (EXCEPT_REGEX_VALUES == null || EXCEPT_REGEX_VALUES.length == 0) {
            throw new IOException("EXCEPT_REGEX is empty in RouteFilterUpdater.properties");
        }
        return debugProp;
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
                    whois.disconnect();
                } catch (IOException e) {
                    LOGGER.warn("Failed to disconnect WHOIS client", e);
                }
            }
        }
        throw new IOException("Unreachable code");
    }

    private static String executeRtconfigCommand(String rtconfigInput) throws IOException {
        LOGGER.debug("Executing rtconfig command with input: {}", rtconfigInput);
        ProcessBuilder pb = new ProcessBuilder(
                RTCONFIG_PATH,
                "-h", WHOIS_SERVER,
                "-f", IRR_CACHE_FILE,
                "-protocol", "rawhoisd",
                "-config", "junos",
                "-s", String.join(",", IRR_SOURCES)
        );
        Process process = pb.start();
        try (OutputStream stdin = process.getOutputStream(); BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(stdin))) {
            writer.write(rtconfigInput);
            writer.newLine();
            writer.flush();
        }
        BufferedReader stdoutReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader stderrReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        String result = stdoutReader.lines().collect(Collectors.joining("\n"));
        String error = stderrReader.lines().collect(Collectors.joining("\n"));
        try {
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                LOGGER.error("rtconfig failed with exit code {}: {}", exitCode, rtconfigInput);
                LOGGER.error("Error output: {}", error);
                throw new IOException("rtconfig failed with exit code " + exitCode + ": " + error);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while executing rtconfig", e);
        }
        LOGGER.debug("rtconfig output: {}", result);
        return result;
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

    private static com.jcraft.jsch.Session connect() throws JSchException {
        LOGGER.debug("Connecting to router {}", ROUTER_IP);
        JSch jsch = new JSch();
        com.jcraft.jsch.Session session = jsch.getSession(USERNAME, ROUTER_IP, 22);
        session.setPassword(PASSWORD);
        session.setConfig("StrictHostKeyChecking", "no");
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
            channel.disconnect();
        }

        channel.disconnect();
        String result = output.toString("UTF-8");
        String errorOutput = error.toString("UTF-8");
        if (!errorOutput.isEmpty()) {
            LOGGER.warn("SSH command '{}' error output: {}", command, errorOutput.replace("\n", "\\n").replace("\r", "\\r"));
        }
        LOGGER.debug("SSH command '{}' output: {}", command, result.replace("\n", "\\n").replace("\r", "\\r"));
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
            LOGGER.info("Report sent successfully from {} to {}", REPORT_FROM, REPORT_TO);
        } catch (MessagingException e) {
            LOGGER.error("Failed to send report", e);
            throw new IOException("Failed to send report", e);
        } finally {
            if (reportFile.exists()) {
                try {
                    Files.delete(reportFile.toPath());
                    LOGGER.debug("Deleted session log file after sending report: {}", reportFile.getAbsolutePath());
                } catch (IOException e) {
                    LOGGER.warn("Failed to delete session log file {} after sending report: {}", reportFile.getAbsolutePath(), e.getMessage());
                }
            }
        }
    }

    private static void generateIrrObjects() throws JSchException, IOException {
        LOGGER.info("Generating IRR objects");
        com.jcraft.jsch.Session session = connect();
        try {
            String bgpConfig = executeSshCommand(session,
                    "show configuration protocols bgp group " + BGP_GROUP_IPV4 + " | display set | match neighbor | match peer-as | no-more");
            String whoisData = executeWhoisQuery("-r " + SELF_AS, WHOIS_SERVER);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("whoisData: {}", whoisData);
                try (PrintWriter writer = new PrintWriter("whois_debug.txt", "UTF-8")) {
                    writer.println(whoisData);
                }
            }

            StringBuilder irrContent = new StringBuilder();
            irrContent.append("peering-set: prng-fictionalinternetexchangev4\n");
            Pattern neighborPattern = Pattern.compile("set\\s+protocols\\s+bgp\\s+group\\s+" + Pattern.quote(BGP_GROUP_IPV4) + "\\s+neighbor\\s+([0-9.]+)\\s+peer-as\\s+(\\d+)");
            Matcher matcher = neighborPattern.matcher(bgpConfig);
            while (matcher.find()) {
                String neighborIp = matcher.group(1);
                String asNumber = matcher.group(2);
                String peerAs = "AS" + asNumber;
                if (isPrivateAs(peerAs)) {
                    LOGGER.info("Skipping neighbor {} with private AS {}", neighborIp, peerAs);
                    continue;
                }
                irrContent.append(String.format("peering: %s %s at %s\n", peerAs, neighborIp, ROUTER_IP));
            }

            irrContent.append("\n");
            irrContent.append("aut-num: ").append(SELF_AS).append("\n");
            irrContent.append("export: to prng-fictionalinternetexchangev4 announce ANY;\n");
            irrContent.append("import: { from AS-ANY accept NOT { 10.0.0.0/8^+,169.254.0.0/16^+,172.16.0.0/12^+,192.0.2.0/24^+,192.168.0.0/16^+,198.18.0.0/15^+,203.0.113.0/24^+,0.0.0.0/0,127.0.0.0/8^+,224.0.0.0/3^+};}\n");
            irrContent.append(" refine { from AS-ANY accept ANY; }\n");
            irrContent.append("  refine {\n");

            Pattern importPattern = Pattern.compile("^import:\\s*from\\s+AS(\\d+)\\s*(.*?)\\s*(?:#.*)?$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
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

            matcher = neighborPattern.matcher(bgpConfig);
            while (matcher.find()) {
                String neighborIp = matcher.group(1);
                String as = matcher.group(2);
                String peerAs = "AS" + as;
                if (isPrivateAs(peerAs)) {
                    LOGGER.info("Skipping neighbor {} with private AS {}", neighborIp, peerAs);
                    continue;
                }
                String rule = importRules.getOrDefault(as, "");
                if (rule.isEmpty()) {
                    String whoisExport = executeWhoisQuery("-r AS" + as, WHOIS_SERVER);
                    Pattern exportPattern = Pattern.compile("^import:\\s*from\\s+AS" + as + "\\s+accept\\s+(\\S+)", Pattern.MULTILINE);
                    Matcher exportMatcher = exportPattern.matcher(whoisExport);
                    rule = exportMatcher.find() ? exportMatcher.group(1) : peerAs;
                }
                rule = rule.replaceFirst("^accept\\s+", "").trim();
                irrContent.append(String.format("   from %s %s at %s accept %s;\n", peerAs, neighborIp, ROUTER_IP, rule));
            }

            irrContent.append(" }\n");

            try (PrintWriter writer = new PrintWriter(IRR_CACHE_FILE, "UTF-8")) {
                writer.println(irrContent);
            }
            validateIrrFile();
            LOGGER.info("IRR objects written to {}", IRR_CACHE_FILE);
        } finally {
            session.disconnect();
        }
    }

    private static List<Neighbor> parseNeighbors(com.jcraft.jsch.Session session) throws JSchException, IOException {
        String exceptClause = " except \"" + String.join("|", EXCEPT_REGEX_VALUES) + "\"";
        String command = "show configuration protocols bgp group " + BGP_GROUP_IPV4
                + " | display set | match \"(peer-as|import|description)\" | match neighbor |" + exceptClause + " | no-more";
        String output = executeSshCommand(session, command);
        LOGGER.debug("Raw BGP config output: {}", output);
        if (output.contains("error:") || output.trim().isEmpty()) {
            LOGGER.error("Failed to retrieve BGP neighbors: {}", output);
            throw new IOException("Failed to retrieve BGP neighbors: " + output);
        }
        Pattern reDescription = Pattern.compile("^set[^0-9]+([0-9.]+) description (.+)");
        Pattern reImport = Pattern.compile("^set[^0-9]+([0-9.]+) import (.+)");
        Pattern rePeerAs = Pattern.compile("^set[^0-9]+([0-9.]+) peer-as (.+)");
        Map<String, Neighbor> neighbors = new HashMap<>();

        for (String line : output.split("\n")) {
            if (line.trim().isEmpty()) {
                continue;
            }
            Matcher md = reDescription.matcher(line);
            Matcher mi = reImport.matcher(line);
            Matcher mp = rePeerAs.matcher(line);
            if (md.matches()) {
                neighbors.computeIfAbsent(md.group(1), Neighbor::new).description = md.group(2);
            } else if (mi.matches()) {
                neighbors.computeIfAbsent(mi.group(1), Neighbor::new).importPolicy = mi.group(2);
            } else if (mp.matches()) {
                neighbors.computeIfAbsent(mp.group(1), Neighbor::new).peerAs = "AS" + mp.group(2);
            }
        }
        if (neighbors.isEmpty()) {
            LOGGER.warn("No BGP neighbors found for group {}", BGP_GROUP_IPV4);
        }
        return new ArrayList<>(neighbors.values());
    }

    private static String getWhoisExport(Neighbor neighbor, com.jcraft.jsch.Session session, PrintWriter out) throws IOException, JSchException {
        String whoisOutput = executeWhoisQuery("-r " + neighbor.peerAs, WHOIS_SERVER);
        Pattern exportPattern = Pattern.compile("^export:\\s+to\\s+" + SELF_AS + "\\s+announce\\s+(\\S+)", Pattern.MULTILINE);
        Matcher matcher = exportPattern.matcher(whoisOutput);
        String export = matcher.find() ? matcher.group(1) : "";
        if (export.isEmpty()) {
            printHeader(out, neighbor, "None");
            LOGGER.info("No export information for {} in RIPE-DB", neighbor.peerAs);
            out.printf("# The %s does not contain \"export:\" information about the %s in RIPE-DB\n", neighbor.peerAs, SELF_AS);
            String state = checkBgpState(session, neighbor.ip);
            out.printf("#> Type: External    State: %s\n", state);
            if ("Established".equals(state)) {
                out.println("#! Manual analysis required.");
                List<String> prefixes = getPrefixes(neighbor.peerAs);
                if (!prefixes.isEmpty()) {
                    printRouteFilters(out, neighbor, "p", prefixes);
                    return neighbor.peerAs;
                }
            }
            out.printf("deactivate protocols bgp group %s neighbor %s\n", BGP_GROUP_IPV4, neighbor.ip);
            return null;
        }
        return export;
    }

    private static List<String> getRouteFilters(Neighbor neighbor, PrintWriter out) throws IOException {
        String rtconfigInput = String.format("@rtconfig import %s %s %s %s",
                SELF_AS, ROUTER_IP, neighbor.peerAs, neighbor.ip);
        out.println("# Type: rtconfig import…");
        out.println("# " + rtconfigInput);
        String output = executeRtconfigCommand(rtconfigInput);
        List<String> routeFilters = output.lines()
                .filter(line -> line.trim().startsWith("route-filter"))
                .map(line -> line.replaceFirst("^\\s+", "").replace(";", ""))
                .collect(Collectors.toList());
        if (routeFilters.isEmpty()) {
            LOGGER.warn("No route-filters for {}, rtconfig output: {}, trying prefixes", neighbor.peerAs, output);
            out.println("# Type: rtconfig did not return any information…");
            out.println("# rtconfig output: " + output);
            String prefixInput = String.format("@rtconfig printPrefixes \"%%p/%%l\\n\" filter %s", neighbor.peerAs);
            String prefixOutput = executeRtconfigCommand(prefixInput);
            routeFilters = prefixOutput.lines()
                    .filter(line -> !line.trim().isEmpty())
                    .map(p -> "route-filter " + p + " exact accept")
                    .collect(Collectors.toList());
        } else {
            LOGGER.info("Route filters retrieved for {}: {}", neighbor.peerAs, routeFilters);
        }
        return routeFilters;
    }

    private static List<String> getPrefixes(String export) throws IOException {
        String rtconfigInput = String.format("@rtconfig printPrefixes \"%%p/%%l\\n\" filter %s", export);
        String output = executeRtconfigCommand(rtconfigInput);
        List<String> prefixes = output.isEmpty() ? new ArrayList<>() : Arrays.asList(output.split("\n"));
        if (!prefixes.isEmpty()) {
            LOGGER.info("Retrieved prefixes for {}: {}", export, prefixes);
        }
        return prefixes;
    }

    private static void printHeader(PrintWriter out, Neighbor neighbor, String export) {
        out.printf("## %s : %s : %s : %s : %s\n", neighbor.ip, neighbor.peerAs, export, neighbor.importPolicy, neighbor.description);
    }

    private static void printRouteFilters(PrintWriter out, Neighbor neighbor, String type, List<String> routeFilters) {
        out.printf("delete policy-options policy-statement %s term accept from\n", neighbor.importPolicy);
        for (String rf : routeFilters) {
            String cleanRf = rf.replace(";", "").trim();
            out.printf("set policy-options policy-statement %s term accept from %s\n", neighbor.importPolicy, cleanRf);
            if (cleanRf.contains("accept")) {
                String nextPolicy = cleanRf.replace(" accept", " next policy");
                out.printf("set policy-options policy-statement %s term accept from %s\n", neighbor.importPolicy, nextPolicy);
            }
        }
    }

    private static String checkBgpState(com.jcraft.jsch.Session session, String neighborIp) throws JSchException, IOException {
        String command = String.format("show bgp neighbor %s | match \"(Type:.*State:|Last State:)\"", neighborIp);
        String output = executeSshCommand(session, command);
        String state = "Unknown";
        for (String line : output.split("\n")) {
            if (line.contains("State:")) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length > 3) {
                    state = parts[3];
                }
                LOGGER.debug("BGP state for {}: {}", neighborIp, line.trim());
            }
        }
        return state;
    }

    private static boolean isValidPrefix(String prefix, boolean ipv4, boolean ipv6) {
        if (prefix.contains("::") && !ipv6) {
            return false;
        }
        return !(!prefix.contains("::") && !ipv4);
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

    private static void generateRouteFilters(Args config) throws JSchException, IOException {
        LOGGER.info("Generating route filters");
        com.jcraft.jsch.Session session = connect();
        try (PrintWriter out = config.outputFile != null
                ? new PrintWriter(config.outputFile, "UTF-8")
                : new PrintWriter(System.out)) {
            List<Neighbor> neighbors = parseNeighbors(session).stream()
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
                String export = getWhoisExport(neighbor, session, out);
                if (export == null && !"Established".equals(checkBgpState(session, neighbor.ip))) {
                    LOGGER.debug("Skipping neighbor {} (not established)", neighbor.ip);
                    continue;
                }
                printHeader(out, neighbor, export != null ? export : "None");
                List<String> routeFilters = getRouteFilters(neighbor, out);
                if (!routeFilters.isEmpty()) {
                    routeFilters = routeFilters.stream()
                            .filter(rf -> isValidPrefix(rf, config.ipv4, config.ipv6))
                            .collect(Collectors.toList());
                    printRouteFilters(out, neighbor, "r", routeFilters);
                } else {
                    LOGGER.warn("No route-filters for {}, trying prefixes", neighbor.peerAs);
                    out.println("# Type: rtconfig did not return any information…");
                    List<String> prefixes = getPrefixes(export != null ? export : neighbor.peerAs);
                    prefixes = prefixes.stream()
                            .filter(p -> isValidPrefix(p, config.ipv4, config.ipv6))
                            .collect(Collectors.toList());
                    if (!prefixes.isEmpty()) {
                        printRouteFilters(out, neighbor, "p", prefixes);
                    } else {
                        String state = checkBgpState(session, neighbor.ip);
                        if ("Established".equals(state)) {
                            out.println("#! Manual analysis required.");
                            prefixes = getPrefixes(neighbor.peerAs).stream()
                                    .filter(p -> isValidPrefix(p, config.ipv4, config.ipv6))
                                    .collect(Collectors.toList());
                            if (!prefixes.isEmpty()) {
                                printRouteFilters(out, neighbor, "p", prefixes);
                            }
                        } else {
                            out.printf("deactivate protocols bgp group %s neighbor %s\n", BGP_GROUP_IPV4, neighbor.ip);
                        }
                    }
                }
                out.println();
            }
        } finally {
            session.disconnect();
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

                    // Видаляємо всі промпти, які не є останнім очікуваним промптом
                    Matcher skipperMatcher = promptSkipper.matcher(data);
                    if (skipperMatcher.find()) {
                        data = skipperMatcher.replaceAll("");
                    }

                    // Зберігаємо тільки вивід до останнього очікуваного промпту
                    Matcher promptMatcher = promptPattern.matcher(data);
                    if (promptMatcher.find()) {
                        data = data.substring(0, promptMatcher.end());
                    }

                    result.append(data);
                    String sData = data.replace("\n", "\\n").replace("\r", "\\r");
                    if (LOGGER.isDebugEnabled() && (data.length() > 1 || data.contains("commit") || data.contains("Exiting") || data.contains("noc@"))) {
                        String oData = sData.length() > 80 ? sData.substring(sData.length() - 80) : sData;
                        LOGGER.debug("Received data: [{}] (length: {})", oData, data.length());
                    }
                    String currentOutput = result.toString();
                    if (LOGGER.isDebugEnabled()) {
                        String sResult = currentOutput.replace("\n", "\\n").replace("\r", "\\r");
                        String oResult = sResult.length() > 80 ? sResult.substring(sResult.length() - 80) : sResult;
                        LOGGER.debug("Current output buffer: [{}]", oResult);
                    }
                    if (promptPattern.matcher(currentOutput).find()) {
                        LOGGER.debug("Found prompt in output: {}", currentOutput.replace("\n", "\\n").replace("\r", "\\r"));
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

                        // Видаляємо всі промпти, які не є останнім очікуваним промптом
                        Matcher skipperMatcher = promptSkipper.matcher(rawData);
                        if (skipperMatcher.find()) {
                            rawData = skipperMatcher.replaceAll("");
                        }

                        // Зберігаємо тільки вивід до останнього очікуваного промпту
                        Matcher promptMatcher = promptPattern.matcher(rawData);
                        if (promptMatcher.find()) {
                            rawData = rawData.substring(0, promptMatcher.end());
                        }

                        result.append(rawData);
                        if (LOGGER.isDebugEnabled() && (rawData.length() > 1 || rawData.contains("commit") || rawData.contains("Exiting") || rawData.contains("noc@"))) {
                            String sRawData = rawData.replace("\n", "\\n").replace("\r", "\\r");
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
                result.toString().replace("\n", "\\n").replace("\r", "\\r"));
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
            //BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 8192);
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
            channel.connect(3000);
            LOGGER.debug("Channel connected, isConnected: {}, isClosed: {}, isEOF: {}",
                    channel.isConnected(), channel.isClosed(), in.available() == -1);

            String initialPrompt = waitForPrompt(reader, in, "operational");
            LOGGER.debug("Found initial prompt: {}", initialPrompt.replace("\n", "\\n").replace("\r", "\\r"));

            /*
            LOGGER.debug("Setting terminal as vt100");
            result = executeCommandWithRetries(channel, in, reader, writer, "set cli terminal vt100", "operational", 30000);

            LOGGER.debug("Setting the screen length to 0");
            result = executeCommandWithRetries(channel, in, reader, writer, "set cli screen-length 0", "operational", 30000);
             */
            LOGGER.debug("Executing initial configure private");
            result = executeCommandWithRetries(channel, in, reader, writer, "configure private\r\n", "config", 30000);
            LOGGER.debug("configure private output: {}", result.replace("\n", "\\n").replace("\r", "\\r"));

            List<String> configCommands = Files.readAllLines(Paths.get(configFile)).stream()
                    .filter(line -> !line.trim().startsWith("#") && !line.trim().isEmpty())
                    .collect(Collectors.toList());

            LOGGER.debug("Applying {} configuration commands", configCommands.size());
            for (String command : configCommands) {
                result = executeCommandWithRetries(channel, in, reader, writer, command + "\r\n", "config", 30000);
                LOGGER.debug("Command '{}' output: {}", command, result.replace("\n", "\\n").replace("\r", "\\r"));
            }

            String compareResult = executeCommandWithRetries(channel, in, reader, writer, "show | compare | no-more\r\n", "config", 60000);
            LOGGER.debug("Raw show | compare output before cleaning: [{}]", compareResult.replace("\n", "\\n").replace("\r", "\\r"));
            String cleanedCompare = cleanCompareOutput(compareResult);
            LOGGER.debug("Cleaned show | compare output: [{}]", cleanedCompare.replace("\n", "\\n").replace("\r", "\\r"));

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
                LOGGER.debug("commit and-quit output: {}", result.replace("\n", "\\n").replace("\r", "\\r"));
            } catch (IOException e) {
                LOGGER.error("commit and-quit failed: {}", e.getMessage());
                throw e;
            }
            LOGGER.info("Configuration committed successfully");
        } finally {
            if (channel != null) {
                try {
                    channel.disconnect();
                } catch (Exception e) {
                    LOGGER.debug("Channel disconnect exception: {}", e.getMessage());
                }
            }
            if (session != null) {
                try {
                    session.disconnect();
                } catch (Exception e) {
                    LOGGER.debug("Session disconnect exception: {}", e.getMessage());
                }
            }
        }
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
}
