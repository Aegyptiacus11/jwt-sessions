/**
 * The server half of the contract, as the client calls it. `tandemServer()`
 * implements it against the Python package's router; anything else that
 * speaks the same contract can implement it by hand.
 *
 * None of these ever sees a refresh token: the server sets it as an httpOnly
 * cookie and the browser sends it, which is why every call asks for
 * `credentials: "include"`.
 */
export type AuthServer = {
  /** The access token; throws on bad credentials. */
  login(email: string, password: string): Promise<string>;
  /** A fresh access token from the refresh cookie; throws when the session
   * is gone. */
  refresh(): Promise<string>;
  logout(): Promise<void>;
  logoutAll(accessToken: string): Promise<void>;
};

export class AuthRequestError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "AuthRequestError";
  }
}

export type TandemServerOptions = {
  /** Where the router is mounted, e.g. "https://api.example.org/api/v1". */
  baseUrl: string;
  /** The router's own prefix. */
  prefix?: string;
  fetch?: typeof fetch;
};

export function tandemServer({
  baseUrl,
  prefix = "/auth",
  fetch: doFetch = (...args) => globalThis.fetch(...args),
}: TandemServerOptions): AuthServer {
  const root = `${baseUrl.replace(/\/+$/, "")}${prefix}`;

  // Deliberately raw fetch, not the app's HTTP client: these are the calls
  // that establish a session, and routing their own 401s through a client
  // that answers a 401 by refreshing would loop.
  async function post(path: string, init: RequestInit = {}): Promise<Response> {
    const response = await doFetch(`${root}${path}`, {
      method: "POST",
      credentials: "include",
      ...init,
    });
    if (!response.ok) {
      let detail = response.statusText || `HTTP ${response.status}`;
      try {
        const body = (await response.json()) as { detail?: unknown };
        if (typeof body.detail === "string") detail = body.detail;
      } catch {
        // Not JSON; the status text will do.
      }
      throw new AuthRequestError(response.status, detail);
    }
    return response;
  }

  async function accessToken(response: Response): Promise<string> {
    const body = (await response.json()) as { access_token?: unknown };
    if (typeof body.access_token !== "string") {
      throw new AuthRequestError(
        response.status,
        "No access token in the response",
      );
    }
    return body.access_token;
  }

  return {
    async login(email, password) {
      return accessToken(
        await post("/login", {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        }),
      );
    },
    async refresh() {
      return accessToken(await post("/refresh"));
    },
    async logout() {
      await post("/logout");
    },
    async logoutAll(token) {
      await post("/logout-all", {
        headers: { Authorization: `Bearer ${token}` },
      });
    },
  };
}
