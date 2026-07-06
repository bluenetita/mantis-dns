/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

export const STRATEGY_LABELS: Record<string, string> = {
  round_robin: "Round-robin",
  weighted_round_robin: "Weighted RR",
  failover: "Failover",
  latency: "Latency",
};

export const MATCH_TYPE_OPTIONS = [
  { value: "domain_suffix", label: "Domain suffix" },
  { value: "domain_exact", label: "Exact domain" },
  { value: "qtype", label: "Query type" },
  { value: "category", label: "Category" },
  { value: "default", label: "Default (catch-all)" },
];

export const DNSSEC_OPTIONS = [
  { value: "strict", label: "Strict — require AD bit" },
  { value: "opportunistic", label: "Opportunistic — propagate AD bit" },
  { value: "disabled", label: "Disabled — strip AD bit" },
];
