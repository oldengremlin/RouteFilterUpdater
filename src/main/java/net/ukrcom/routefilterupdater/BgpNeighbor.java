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

public class BgpNeighbor {

    private final String ip;
    private final long peerAs;
    private final String importPolicy;

    public BgpNeighbor(String ip, long peerAs, String importPolicy) {
        this.ip = ip;
        this.peerAs = peerAs;
        this.importPolicy = importPolicy;
    }

    public String getIp() {
        return ip;
    }

    public long getPeerAs() {
        return peerAs;
    }

    public String getImportPolicy() {
        return importPolicy;
    }

    @Override
    public String toString() {
        return ip + " peer-as " + peerAs + " import " + importPolicy;
    }
}
