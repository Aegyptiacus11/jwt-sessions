import { describe, expect, it, vi } from "vitest";

import { AuthRequestError, tandemServer } from "./server";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("tandemServer", () => {
  it("speaks the contract: paths, cookies, bodies", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(json({ access_token: "a1", token_type: "bearer" }))
      .mockResolvedValueOnce(json({ access_token: "a2", token_type: "bearer" }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const server = tandemServer({ baseUrl: "https://api.test/api/v1/", fetch });

    expect(await server.login("ada@example.com", "pw")).toBe("a1");
    expect(await server.refresh()).toBe("a2");
    await server.logout();
    await server.logoutAll("a2");

    const calls = fetch.mock.calls.map(([url, init]) => ({
      url,
      method: init?.method,
      credentials: init?.credentials,
    }));
    expect(calls).toEqual([
      {
        url: "https://api.test/api/v1/auth/login",
        method: "POST",
        credentials: "include",
      },
      {
        url: "https://api.test/api/v1/auth/refresh",
        method: "POST",
        credentials: "include",
      },
      {
        url: "https://api.test/api/v1/auth/logout",
        method: "POST",
        credentials: "include",
      },
      {
        url: "https://api.test/api/v1/auth/logout-all",
        method: "POST",
        credentials: "include",
      },
    ]);
    expect(JSON.parse(fetch.mock.calls[0]![1]!.body as string)).toEqual({
      email: "ada@example.com",
      password: "pw",
    });
    expect(
      new Headers(fetch.mock.calls[3]![1]!.headers).get("Authorization"),
    ).toBe("Bearer a2");
    // No call ever carries a refresh token: the browser sends the cookie.
    for (const [, init] of fetch.mock.calls) {
      expect(String(init?.body ?? "")).not.toContain("refresh");
    }
  });

  it("surfaces the server's detail and status on failure", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(json({ detail: "Invalid email or password" }, 401));
    const server = tandemServer({ baseUrl: "https://api.test", fetch });
    const failure = await server.login("a", "b").catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(AuthRequestError);
    expect(failure).toMatchObject({
      status: 401,
      message: "Invalid email or password",
    });
  });
});
