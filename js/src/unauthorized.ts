type UnauthorizedHandler = () => void;

let handler: UnauthorizedHandler | null = null;

/**
 * Registered once at boot by the active auth adapter.
 *
 * This is a module-level slot, which the token store deliberately is not: a token
 * is per-request state read on every call (racing the auth provider's first render),
 * while this is a single wiring point written once and only ever read on a 401.
 */
export function setUnauthorizedHandler(next: UnauthorizedHandler | null): void {
  handler = next;
}

export function notifyUnauthorized(): void {
  handler?.();
}

/**
 * Returns a *fresh access token*, or null when the session is genuinely gone.
 *
 * Separate from `UnauthorizedHandler` above, and additive: an adapter that
 * only registers the notify-style handler keeps its previous behaviour
 * exactly. Registering this one additionally lets the transport retry the
 * request that hit the 401, which is the difference between a user seeing a
 * failed action and seeing nothing at all.
 */
type TokenRefresher = () => Promise<string | null>;

let refresher: TokenRefresher | null = null;

export function setTokenRefresher(next: TokenRefresher | null): void {
  refresher = next;
}

/** Null when no refresher is registered, or the session could not be renewed. */
export function requestTokenRefresh(): Promise<string | null> {
  return refresher ? refresher() : Promise.resolve(null);
}
