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

/**
 * Stores the accepted route sets (from WHOIS import policies) for a single peer AS.
 * Built from mp-import / import lines of the SELF_AS WHOIS record.
 */
public class WhoisPolicy {

    private final long peerAs;
    private String ipv4Set;
    private String ipv6Set;

    public WhoisPolicy(long peerAs) {
        this.peerAs = peerAs;
    }

    public long getPeerAs() {
        return peerAs;
    }

    public String getIpv4Set() {
        return ipv4Set;
    }

    public String getIpv6Set() {
        return ipv6Set;
    }

    void setIpv4Set(String s) {
        this.ipv4Set = s;
    }

    void setIpv6Set(String s) {
        this.ipv6Set = s;
    }

    /** Returns the accept set appropriate for the given address family.
     * @param ipv6
     * @return  */
    public String getAcceptSet(boolean ipv6) {
        return ipv6 ? ipv6Set : ipv4Set;
    }

    @Override
    public String toString() {
        return "AS" + peerAs + " [v4=" + ipv4Set + ", v6=" + ipv6Set + "]";
    }
}
