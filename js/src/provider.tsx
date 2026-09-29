import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { SessionContext } from "./context";
import type { AuthServer } from "./server";
import { accessTokenClaims } from "./token-claims";
import type { Session, SessionUser } from "./types";
import { setTokenRefresher, setUnauthorizedHandler } from "./unauthorized";

export type AuthConfig = {
  server: AuthServer;
  /** Who the token belongs to - the app's own endpoint, since what a user
   * is differs between apps. */
  fetchMe(accessToken: string): Promise<SessionUser>;
  /** Called whenever the session ends, signed out or lost. */
  onSessionLost?(): void;
  /** How long before the access token expires to renew it. */
  renewMarginMs?: number;
};

/**
 * The session: an access token in React state (never in storage), restored
 * on load from the refresh cookie, renewed shortly before it expires, and
 * renewed once more - then given up - when a request comes back 401.
 */
export function AuthProvider({
  children,
  config,
}: {
  children: ReactNode;
  config: AuthConfig;
}) {
  const { server, fetchMe, onSessionLost, renewMarginMs = 60_000 } = config;

  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<SessionUser | null>(null);
  const [status, setStatus] = useState<Session["status"]>("loading");
  const [error, setError] = useState<Error | null>(null);

  // One refresh in flight at a time, shared by the restore on load, the
  // timer and the 401 path. The server spends a refresh token on use, so two
  // concurrent refreshes from one tab would present the same token twice.
  const inFlight = useRef<Promise<string | null> | null>(null);
  const renewTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clear = useCallback(() => {
    inFlight.current = null;
    if (renewTimer.current) {
      clearTimeout(renewTimer.current);
      renewTimer.current = null;
    }
    setToken(null);
    setUser(null);
    setStatus("anonymous");
    onSessionLost?.();
  }, [onSessionLost]);

  const runRefresh = useCallback((): Promise<string | null> => {
    if (inFlight.current) return inFlight.current;
    const attempt = (async () => {
      try {
        const next = await server.refresh();
        setToken(next);
        return next;
      } catch {
        return null;
      } finally {
        inFlight.current = null;
      }
    })();
    inFlight.current = attempt;
    return attempt;
  }, [server]);

  // Restore an existing session on load.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const restored = await runRefresh();
      if (cancelled) return;
      if (!restored) {
        clear();
        return;
      }
      try {
        const me = await fetchMe(restored);
        if (cancelled) return;
        setUser(me);
        setStatus("authenticated");
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err : new Error(String(err)));
        clear();
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runRefresh, fetchMe, clear]);

  // Renew before the token expires, so a 401 is the fallback rather than the
  // mechanism: after an idle spell the first click would otherwise pay for a
  // request, a 401, a refresh and a retry. Scheduled from the token's own
  // `exp`, since the lifetime is the server's to choose. A token already past
  // the renew point is left to the 401 path rather than refreshed in a loop.
  useEffect(() => {
    if (renewTimer.current) {
      clearTimeout(renewTimer.current);
      renewTimer.current = null;
    }
    if (!token) return;
    const exp = accessTokenClaims(token)?.exp;
    if (typeof exp !== "number") return;
    const msUntilRenew = exp * 1000 - Date.now() - renewMarginMs;
    if (msUntilRenew <= 0) return;
    renewTimer.current = setTimeout(() => {
      void runRefresh().then((next) => {
        if (!next) clear();
      });
    }, msUntilRenew);
    return () => {
      if (renewTimer.current) {
        clearTimeout(renewTimer.current);
        renewTimer.current = null;
      }
    };
  }, [token, runRefresh, clear, renewMarginMs]);

  // A 401 elsewhere means: refresh once, then give up. The handler is the
  // "session may be gone" signal; the refresher hands the HTTP client a fresh
  // token so it can retry the request that failed.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      void runRefresh().then((next) => {
        if (!next) clear();
      });
    });
    setTokenRefresher(async () => {
      const next = await runRefresh();
      if (!next) clear();
      return next;
    });
    return () => {
      setUnauthorizedHandler(null);
      setTokenRefresher(null);
    };
  }, [runRefresh, clear]);

  const signIn = useCallback(
    async (email: string, password: string) => {
      const access = await server.login(email, password);
      setToken(access);
      const me = await fetchMe(access);
      setUser(me);
      setError(null);
      setStatus("authenticated");
    },
    [server, fetchMe],
  );

  // Server first, then local - and local even if the server call fails:
  // staying signed in on screen would be worse than a session that outlives
  // the click by one unreachable request.
  const signOut = useCallback(async () => {
    await server.logout().catch(() => {});
    clear();
  }, [server, clear]);

  const signOutEverywhere = useCallback(async () => {
    if (token) await server.logoutAll(token).catch(() => {});
    clear();
  }, [server, token, clear]);

  const session = useMemo<Session>(
    () => ({ status, token, user, error, signIn, signOut, signOutEverywhere }),
    [status, token, user, error, signIn, signOut, signOutEverywhere],
  );

  return (
    <SessionContext.Provider value={session}>
      {children}
    </SessionContext.Provider>
  );
}
