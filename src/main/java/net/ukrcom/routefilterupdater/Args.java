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

public class Args {

    public String outputFile = null;
    public String sqlitePath = null;
    public boolean ipv6 = false;
    public boolean debug = false;
    public boolean save = false;
    public boolean report = false;
    public boolean quiet = false;
    public boolean strictRpsl = false;
    public boolean strictRpslReverse = false;
    public boolean help = false;

    public Args(String[] argv) {
        for (int i = 0; i < argv.length; i++) {
            switch (argv[i]) {
                case "-4" ->
                    ipv6 = false;
                case "-6" ->
                    ipv6 = true;
                case "-d", "--debug" ->
                    debug = true;
                case "-s", "--save" ->
                    save = true;
                case "-r", "--report" ->
                    report = true;
                case "-q", "--quiet" ->
                    quiet = true;
                case "--strict-rpsl" ->
                    strictRpsl = true;
                case "--strict-rpsl-reverse" ->
                    strictRpslReverse = true;
                case "-h", "-?", "--help" ->
                    help = true;
                case "-o" -> {
                    if (i + 1 < argv.length) {
                        outputFile = argv[++i];
                    }
                }
                case "--sqlite" -> {
                    if (i + 1 < argv.length) {
                        sqlitePath = argv[++i];
                    }
                }
                default -> {
                    /* ignore unknown */ }
            }
        }
    }

    public static void printHelp() {
        System.out.println("""
            RouteFilterUpdater — BGP route filter generator for Juniper routers (bgpq4 edition)
            Usage: java -jar RouteFilterUpdater-all.jar [options]
            Options:
              -4              Generate IPv4 route filters (default)
              -6              Generate IPv6 route filters
              -o <file>       Write filters to <file> (stdout if omitted)
              -s, --save      Apply generated configuration to the router via SSH
              -r, --report    Send result to REPORT_TO email
              -d, --debug     Enable debug logging
              -q, --quiet     Suppress console output (for cron jobs)
              --sqlite <file>        Use local SQLite DB for WHOIS lookups; falls back to live WHOIS
                                    if the AS record is not found in the DB
              --strict-rpsl         Warn when a peer's RPSL import policy is 'accept ANY'
              --strict-rpsl-reverse Warn when peer's export to us doesn't match our expected import set
                                    (makes one extra WHOIS query per peer)
              -h, --help      Show this help
            """);
    }
}
