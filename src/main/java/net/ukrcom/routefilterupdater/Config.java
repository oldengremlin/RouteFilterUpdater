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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * Loads and validates RouteFilterUpdater.properties.
 *
 * Required properties:
 *   ROUTER_IP, USERNAME, PASSWORD (or env ROUTER_PASSWORD),
 *   BGP_GROUP_IPV4, SELF_AS, BGPQ4_PATH, EXCEPT_REGEX
 *
 * Optional:
 *   ROUTER_IP_IPV6, BGP_GROUP_IPV6  — needed only for -6 mode
 *   BGPQ4_SOURCES                   — passed as bgpq4 -S flag
 *   WHOIS_SERVER                    — default: whois.ripe.net
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, REPORT_TO, REPORT_FROM
 *   DEBUG
 */
public class Config {

    public final String routerIp;
    public final String routerIpV6;
    public final String username;
    public final String password;
    public final String bgpGroupV4;
    public final String bgpGroupV6;
    public final long selfAs;
    public final String[] exceptPatterns;
    public final String bgpq4Path;
    public final String bgpq4Sources;
    public final String whoisServer;
    public final String smtpHost;
    public final int smtpPort;
    public final String smtpUser;
    public final String smtpPass;
    public final String reportTo;
    public final String reportFrom;
    public final boolean debug;

    public Config(String propertiesFile) throws IOException {
        Properties p = new Properties();
        try (InputStream is = Files.newInputStream(Paths.get(propertiesFile))) {
            p.load(is);
        }

        routerIp = require(p, "ROUTER_IP");
        routerIpV6 = p.getProperty("ROUTER_IP_IPV6", "");
        username = require(p, "USERNAME");

        String envPass = System.getenv("ROUTER_PASSWORD");
        password = (envPass != null && !envPass.isBlank()) ? envPass : require(p, "PASSWORD");

        bgpGroupV4 = require(p, "BGP_GROUP_IPV4");
        bgpGroupV6 = p.getProperty("BGP_GROUP_IPV6", "");
        selfAs = parseSelfAs(require(p, "SELF_AS"));

        String except = p.getProperty("EXCEPT_REGEX", "");
        exceptPatterns = except.isBlank() ? new String[0] : except.split(",\\s*");

        bgpq4Path = require(p, "BGPQ4_PATH");
        // Accept legacy IRR_SOURCES as fallback
        bgpq4Sources = p.getProperty("BGPQ4_SOURCES", p.getProperty("IRR_SOURCES", ""));
        whoisServer = p.getProperty("WHOIS_SERVER", "whois.ripe.net");

        // Accept both old (SMTP_SERVER / SMTP_PASSWORD) and new naming
        smtpHost = p.getProperty("SMTP_HOST", p.getProperty("SMTP_SERVER", ""));
        smtpPort = Integer.parseInt(p.getProperty("SMTP_PORT", "25"));
        smtpUser = p.getProperty("SMTP_USER", "");
        smtpPass = p.getProperty("SMTP_PASS", p.getProperty("SMTP_PASSWORD", ""));
        reportTo = p.getProperty("REPORT_TO", "");
        reportFrom = p.getProperty("REPORT_FROM", "");
        debug = Boolean.parseBoolean(p.getProperty("DEBUG", "false"));
    }

    /** Returns the router host for the given address family.
     * @param ipv6
     * @return  */
    public String routerIp(boolean ipv6) {
        return ipv6 ? routerIpV6 : routerIp;
    }

    /** Returns the BGP group name for the given address family.
     * @param ipv6
     * @return  */
    public String bgpGroup(boolean ipv6) {
        return ipv6 ? bgpGroupV6 : bgpGroupV4;
    }

    /**
     * Builds a combined regex from EXCEPT_REGEX entries for use in Junos pipe filters,
     * e.g. "(Client_world_uaix_in|Client_PFTS_in|TE_IN)". Returns null if empty.
     * @return 
     */
    public String exceptRegex() {
        if (exceptPatterns.length == 0) {
            return null;
        }
        return "(" + String.join("|", exceptPatterns) + ")";
    }

    private static String require(Properties p, String key) {
        String v = p.getProperty(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("Missing required property: " + key);
        }
        return v.trim();
    }

    private static long parseSelfAs(String s) {
        return Long.parseLong(s.trim().replaceFirst("(?i)^AS", ""));
    }
}
