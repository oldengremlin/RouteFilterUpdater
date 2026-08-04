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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Завантаження списку BGP-сусідів з роутера.
 *
 * Винесено окремо, бо однаковий блок (вибір хоста, перевірка групи, SSH-сесія)
 * потрібен і {@link FilterGenerator}, і {@link RpslProposalRunner}.
 */
final class NeighborLoader {

    private static final Logger log = LoggerFactory.getLogger(NeighborLoader.class);

    private NeighborLoader() {
    }

    /**
     * Підключається до роутера і повертає сусідів заданої BGP-групи.
     *
     * @throws IllegalStateException якщо група не налаштована або роутер не повернув жодного сусіда
     */
    static List<BgpNeighbor> load(Config config, AddressFamily af) throws Exception {
        String bgpGroup = config.bgpGroup(af);
        if (bgpGroup.isBlank()) {
            throw new IllegalStateException(
                    "BGP_GROUP_IP" + (af.isV6() ? "V6" : "V4") + " not configured");
        }

        String routerHost = config.routerIp(af);
        if (af.isV6() && config.routerIpV6.isBlank()) {
            log.warn("ROUTER_IP_IPV6 not set — using ROUTER_IP ({}) for IPv6 processing", routerHost);
        }

        List<BgpNeighbor> neighbors;
        try (RouterClient router = new RouterClient(routerHost, config.username, config.password)) {
            router.connect();
            neighbors = router.getNeighbors(bgpGroup, config.exceptRegex);
        }

        // Порожній список — це майже завжди відмова (недоступний роутер, змінена назва
        // групи, надто широкий EXCEPT_REGEX), а не легітимний стан. Раніше це тихо
        // призводило до нульового результату й коду виходу 0.
        if (neighbors.isEmpty()) {
            throw new IllegalStateException(
                    "Router returned no BGP neighbors for group '" + bgpGroup + "' ("
                    + af.label() + ") — check the group name and EXCEPT_REGEX");
        }
        return neighbors;
    }
}
