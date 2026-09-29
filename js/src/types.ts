export type SessionUser = {
  id: string;
  email: string;
  roles: string[];
  /** Optional: `fetchMe` is free to omit it. UI should fall back to
   * `email` or `id`. */
  username?: string;
};

export type SessionStatus = "loading" | "authenticated" | "anonymous";

/** What components see: `useSession()`. */
export type Session = {
  status: SessionStatus;
  /** The access token - held in memory only, never in storage. */
  token: string | null;
  user: SessionUser | null;
  /** Why restoring or starting a session last failed, if it did. */
  error: Error | null;
  signIn: (email: string, password: string) => Promise<void>;
  /** Ends this session on the server, then locally - locally even if the
   * server cannot be reached. */
  signOut: () => Promise<void>;
  /** Ends every session of this user, on every device. */
  signOutEverywhere: () => Promise<void>;
};

export function hasRole(session: Session, ...roles: string[]): boolean {
  const user = session.user;
  if (!user) return false;
  return roles.some((role) => user.roles.includes(role));
}
