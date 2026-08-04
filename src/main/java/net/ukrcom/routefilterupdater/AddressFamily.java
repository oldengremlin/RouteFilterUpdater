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
 * Сімейство адрес (address family), з яким працює запуск.
 *
 * Замінює наскрізний {@code boolean ipv6}, який раніше тягнувся через усі класи
 * і породжував десяток однакових тернарників на кшталт {@code ipv6 ? "IPv6" : "IPv4"}.
 * Уся залежна від сімейства «мова» (мітка для логів, RPSL-afi, назва Junos-терму)
 * зібрана тут в одному місці.
 */
public enum AddressFamily {

    /** IPv4: RPSL {@code afi ipv4.unicast}, Junos {@code term accept}. */
    V4("IPv4", "ipv4.unicast", "accept"),
    /** IPv6: RPSL {@code afi ipv6.unicast}, Junos {@code term accept_v6}. */
    V6("IPv6", "ipv6.unicast", "accept_v6");

    private final String label;
    private final String afi;
    private final String termName;

    AddressFamily(String label, String afi, String termName) {
        this.label = label;
        this.afi = afi;
        this.termName = termName;
    }

    /** Мітка для логів і звітів: {@code "IPv4"} / {@code "IPv6"}. */
    public String label() {
        return label;
    }

    /** RPSL-значення afi: {@code "ipv4.unicast"} / {@code "ipv6.unicast"}. */
    public String afi() {
        return afi;
    }

    /** Назва терму в Junos policy-statement: {@code "accept"} / {@code "accept_v6"}. */
    public String termName() {
        return termName;
    }

    public boolean isV6() {
        return this == V6;
    }

    public static AddressFamily of(boolean ipv6) {
        return ipv6 ? V6 : V4;
    }
}
