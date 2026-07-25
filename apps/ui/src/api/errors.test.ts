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

import { formatError } from "./errors";

describe("formatError", () => {
  it("maps a known status prefix onto a plain-text detail", () => {
    expect(formatError(new Error("503: upstream"))).toBe("Service unavailable: upstream");
  });

  it("extracts a JSON {detail: string} body", () => {
    expect(formatError(new Error('422: {"detail":"subnet overlaps scope 4f2a"}'))).toBe(
      "Invalid input: subnet overlaps scope 4f2a"
    );
  });

  it("joins a FastAPI/Pydantic validation error list", () => {
    const body = JSON.stringify({
      detail: [
        { loc: ["body", "name"], msg: "field required", type: "value_error" },
        { loc: ["body", "url"], msg: "invalid url", type: "value_error" },
      ],
    });
    expect(formatError(new Error(`422: ${body}`))).toBe("Invalid input: field required; invalid url");
  });

  it("falls back to a generic label for an unmapped status", () => {
    expect(formatError(new Error("418: teapot"))).toBe("Error 418: teapot");
  });

  it("passes through a message with no leading status code unchanged", () => {
    expect(formatError(new Error("network request failed"))).toBe("network request failed");
  });

  it("stringifies a non-Error thrown value", () => {
    expect(formatError("plain string")).toBe("plain string");
  });
});
