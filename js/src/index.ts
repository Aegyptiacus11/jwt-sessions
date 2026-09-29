export { AuthProvider, type AuthConfig } from "./provider";
export { useSession, SessionContext } from "./context";
export {
  hasRole,
  type Session,
  type SessionStatus,
  type SessionUser,
} from "./types";
export {
  AuthRequestError,
  tandemServer,
  type AuthServer,
  type TandemServerOptions,
} from "./server";
// For an app's HTTP client: on a 401, ask for a fresh token and retry once.
export {
  notifyUnauthorized,
  requestTokenRefresh,
  setTokenRefresher,
  setUnauthorizedHandler,
} from "./unauthorized";
export { accessTokenClaims } from "./token-claims";
