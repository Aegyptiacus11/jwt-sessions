import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useSession } from "./context";
import { AuthProvider, type AuthConfig } from "./provider";
import type { AuthServer } from "./server";
import { requestTokenRefresh } from "./unauthorized";

/** An access token with the given expiry, in seconds since the epoch. */
function tokenExpiringAt(exp: number): string {
  const payload = btoa(JSON.stringify({ sub: "u1", exp }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `h.${payload}.s`;
}

function fakeServer(overrides: Partial<AuthServer> = {}): AuthServer {
  return {
    login: vi.fn().mockResolvedValue(tokenExpiringAt(Date.now() / 1000 + 900)),
    refresh: vi.fn().mockRejectedValue(new Error("no session")),
    logout: vi.fn().mockResolvedValue(undefined),
    logoutAll: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function config(
  server: AuthServer,
  extra: Partial<AuthConfig> = {},
): AuthConfig {
  return {
    server,
    fetchMe: vi
      .fn()
      .mockResolvedValue({ id: "u1", email: "ada@example.com", roles: [] }),
    ...extra,
  };
}

let session: ReturnType<typeof useSession>;
function Probe() {
  session = useSession();
  return <span data-testid="status">{session.status}</span>;
}

const status = () => screen.getByTestId("status").textContent;

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("AuthProvider", () => {
  it("is anonymous when there is no session to restore", async () => {
    render(
      <AuthProvider config={config(fakeServer())}>
        <Probe />
      </AuthProvider>,
    );
    expect(status()).toBe("loading");
    await waitFor(() => expect(status()).toBe("anonymous"));
  });

  it("restores a session from the refresh cookie on load", async () => {
    const server = fakeServer({
      refresh: vi
        .fn()
        .mockResolvedValue(tokenExpiringAt(Date.now() / 1000 + 900)),
    });
    render(
      <AuthProvider config={config(server)}>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(status()).toBe("authenticated"));
    expect(session.user?.email).toBe("ada@example.com");
  });

  it("signs in, and signs out server first - and locally even if that fails", async () => {
    const order: string[] = [];
    const server = fakeServer({
      logout: vi.fn().mockImplementation(async () => {
        order.push("server");
        throw new Error("network down");
      }),
    });
    const onSessionLost = vi.fn(() => order.push("local"));
    render(
      <AuthProvider config={config(server, { onSessionLost })}>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(status()).toBe("anonymous"));
    order.length = 0;

    await act(() => session.signIn("ada@example.com", "pw"));
    expect(status()).toBe("authenticated");
    expect(session.token).toBeTruthy();

    await act(() => session.signOut());
    expect(status()).toBe("anonymous");
    expect(session.token).toBeNull();
    expect(order).toEqual(["server", "local"]);
  });

  it("gives concurrent 401s one refresh between them", async () => {
    // The server spends a refresh token on use: two refreshes from one tab
    // would present the same token twice and look like theft.
    let resolve!: (t: string) => void;
    const refresh = vi
      .fn()
      .mockRejectedValueOnce(new Error("no session")) // the restore on load
      .mockImplementation(() => new Promise<string>((r) => (resolve = r)));
    render(
      <AuthProvider config={config(fakeServer({ refresh }))}>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(status()).toBe("anonymous"));
    await act(() => session.signIn("ada@example.com", "pw"));

    const fresh = tokenExpiringAt(Date.now() / 1000 + 900);
    const a = requestTokenRefresh();
    const b = requestTokenRefresh();
    const c = requestTokenRefresh();
    await act(async () => resolve(fresh));
    expect(await Promise.all([a, b, c])).toEqual([fresh, fresh, fresh]);
    expect(refresh).toHaveBeenCalledTimes(2); // the restore, and one more
  });

  it("renews shortly before the access token expires", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const now = Date.now();
    const refresh = vi
      .fn()
      .mockResolvedValueOnce(tokenExpiringAt(now / 1000 + 300))
      .mockResolvedValue(tokenExpiringAt(now / 1000 + 1200));
    render(
      <AuthProvider
        config={config(fakeServer({ refresh }), { renewMarginMs: 60_000 })}
      >
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(status()).toBe("authenticated"));
    expect(refresh).toHaveBeenCalledTimes(1);

    await act(() => vi.advanceTimersByTimeAsync(230_000)); // 4 min: not yet
    expect(refresh).toHaveBeenCalledTimes(1);
    await act(() => vi.advanceTimersByTimeAsync(20_000)); // past exp - 60 s
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(status()).toBe("authenticated");
  });

  it("signs out everywhere with the current access token", async () => {
    const server = fakeServer();
    render(
      <AuthProvider config={config(server)}>
        <Probe />
      </AuthProvider>,
    );
    await waitFor(() => expect(status()).toBe("anonymous"));
    await act(() => session.signIn("ada@example.com", "pw"));
    const token = session.token;
    await act(() => session.signOutEverywhere());
    expect(server.logoutAll).toHaveBeenCalledWith(token);
    expect(status()).toBe("anonymous");
  });
});
