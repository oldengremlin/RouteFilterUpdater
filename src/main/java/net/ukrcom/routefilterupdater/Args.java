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
    public boolean ipv6 = false;
    public boolean debug = false;
    public boolean save = false;
    public boolean report = false;
    public boolean quiet = false;
    public boolean help = false;

    public Args(String[] argv) {
        for (int i = 0; i < argv.length; i++) {
            switch (argv[i]) {
                case "-4"                  -> ipv6 = false;
                case "-6"                  -> ipv6 = true;
                case "-d", "--debug"       -> debug = true;
                case "-s", "--save"        -> save = true;
                case "-r", "--report"      -> report = true;
                case "-q", "--quiet"       -> quiet = true;
                case "-h", "-?", "--help"  -> help = true;
                case "-o" -> {
                    if (i + 1 < argv.length) outputFile = argv[++i];
                }
                default -> { /* ignore unknown */ }
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
              -h, --help      Show this help
            """);
    }
}
