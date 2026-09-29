import { describe, expect, it } from "vitest";

import { accessTokenClaims } from "./token-claims";

function jwt(payload: object): string {
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `header.${body}.signature`;
}

describe("accessTokenClaims", () => {
  it("reads a base64url payload without its padding", () => {
    expect(
      accessTokenClaims(jwt({ sub: "u1", exp: 1_900_000_000, n: "??>" })),
    ).toEqual({
      sub: "u1",
      exp: 1_900_000_000,
      n: "??>",
    });
  });

  it("is null for something that is not a JWT", () => {
    expect(accessTokenClaims("opaque-token")).toBeNull();
    expect(accessTokenClaims("a.@@@.c")).toBeNull();
  });
});
