/**
 * The client and the server are two packages in two languages that have to
 * agree on paths, bodies, status codes and the cookie. This runs the real
 * Python router (python/examples/demo_app.py) and drives it through the real
 * `tandemServer`, with a cookie jar standing in for the browser.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AuthRequestError, tandemServer } from "../src/server";

const PYTHON = fileURLToPath(new URL("../../python", import.meta.url));

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const probe = createServer().listen(0, () => {
      const { port } = probe.address() as { port: number };
      probe.close(() => resolve(port));
    });
  });
}

/** A browser's cookie handling, as far as this contract needs it. */
function cookieJar() {
  const jar = new Map<string, string>();
  const jarFetch: typeof fetch = async (input, init = {}) => {
    const headers = new Headers(init.headers);
    if (jar.size) {
      headers.set("Cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
    }
    const response = await fetch(input, { ...init, headers });
    for (const cookie of response.headers.getSetCookie()) {
      const [pair = ""] = cookie.split(";");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (/max-age=0/i.test(cookie) || value === '""' || value === "")
        jar.delete(name);
      else jar.set(name, value);
    }
    return response;
  };
  return { jar, fetch: jarFetch };
}

let server: ChildProcess;
let base = "";

beforeAll(async () => {
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  server = spawn(
    "uv",
    [
      "run",
      "uvicorn",
      "examples.demo_app:app",
      "--port",
      String(port),
      "--log-level",
      "warning",
    ],
    // No grace window, so a replay is always a replay here.
    {
      cwd: PYTHON,
      env: { ...process.env, DEMO_REUSE_GRACE: "0" },
      stdio: "inherit",
    },
  );
  for (let i = 0; i < 200; i++) {
    try {
      if ((await fetch(`${base}/openapi.json`)).ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("the demo app did not start");
});

afterAll(() => {
  server?.kill();
});

describe("the contract, client against server", () => {
  it("signs in, refreshes by cookie alone, and reads the user", async () => {
    const browser = cookieJar();
    const api = tandemServer({ baseUrl: `${base}/api`, fetch: browser.fetch });

    const access = await api.login("Ada@example.com", "correct-horse");
    expect(browser.jar.has("refresh_token")).toBe(true);
    const me = await fetch(`${base}/api/me`, {
      headers: { Authorization: `Bearer ${access}` },
    });
    expect(await me.json()).toEqual({
      id: "u-ada",
      email: "ada@example.com",
      roles: ["admin"],
    });

    const before = browser.jar.get("refresh_token");
    const renewed = await api.refresh();
    expect(renewed).not.toBe(access);
    expect(browser.jar.get("refresh_token")).not.toBe(before);
  });

  it("rejects bad credentials with the server's detail", async () => {
    const api = tandemServer({
      baseUrl: `${base}/api`,
      fetch: cookieJar().fetch,
    });
    await expect(api.login("ada@example.com", "wrong")).rejects.toMatchObject({
      status: 401,
      message: "Invalid email or password",
    });
  });

  it("a stolen cookie replayed after the owner refreshed ends both sessions", async () => {
    const owner = cookieJar();
    const api = tandemServer({ baseUrl: `${base}/api`, fetch: owner.fetch });
    await api.login("ada@example.com", "correct-horse");

    const thief = cookieJar();
    thief.jar.set("refresh_token", owner.jar.get("refresh_token")!);

    await api.refresh(); // the owner, first
    const stolen = tandemServer({ baseUrl: `${base}/api`, fetch: thief.fetch });
    const replay = await stolen.refresh().catch((e: unknown) => e);
    expect(replay).toBeInstanceOf(AuthRequestError);
    expect(thief.jar.has("refresh_token")).toBe(false); // told to drop it

    // The owner is signed out too: nobody can tell which of the two was real.
    await expect(api.refresh()).rejects.toMatchObject({ status: 401 });
  });

  it("logout ends the session on the server, not only the cookie", async () => {
    const browser = cookieJar();
    const api = tandemServer({ baseUrl: `${base}/api`, fetch: browser.fetch });
    await api.login("ada@example.com", "correct-horse");
    const copy = browser.jar.get("refresh_token")!;
    await api.logout();
    expect(browser.jar.has("refresh_token")).toBe(false);

    const later = cookieJar();
    later.jar.set("refresh_token", copy);
    await expect(
      tandemServer({ baseUrl: `${base}/api`, fetch: later.fetch }).refresh(),
    ).rejects.toMatchObject({ status: 401 });
  });

  it("logout-all ends every device's session", async () => {
    const phone = cookieJar();
    const laptop = cookieJar();
    const onPhone = tandemServer({
      baseUrl: `${base}/api`,
      fetch: phone.fetch,
    });
    const onLaptop = tandemServer({
      baseUrl: `${base}/api`,
      fetch: laptop.fetch,
    });
    await onPhone.login("ada@example.com", "correct-horse");
    const access = await onLaptop.login("ada@example.com", "correct-horse");

    await onLaptop.logoutAll(access);
    await expect(onPhone.refresh()).rejects.toMatchObject({ status: 401 });
  });
});
