/** Reading the claims of our own access token: only its expiry is used,
 * to renew the session a minute before it runs out. Unverified by design -
 * the API verifies; this only schedules. */

/** The token's payload, or `null` when it is not a readable JWT. */
export function accessTokenClaims(
  token: string,
): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part) return null;

  try {
    // base64url -> base64, then restore the padding `atob` requires.
    const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(
      base64.length + ((4 - (base64.length % 4)) % 4),
      "=",
    );
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}
