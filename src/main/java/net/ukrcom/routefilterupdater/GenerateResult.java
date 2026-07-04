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

import java.util.List;

/**
 * Return value of FilterGenerator.generate().
 *
 * filters          — pure Junos config blocks, safe to send via "load merge terminal"
 * annotatedFilters — same blocks with "## AS<n> [<ip>] <name>" section headers,
 *                    intended for file output (-o) and email reports (-r)
 * warnings         — RPSL diagnostic messages (--strict-rpsl / --strict-rpsl-reverse)
 */
public record GenerateResult(String filters, String annotatedFilters, List<String> warnings) {}
