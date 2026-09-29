import { createContext, useContext } from "react";
import type { Session } from "./types";

export const SessionContext = createContext<Session | undefined>(undefined);

export function useSession(): Session {
  const session = useContext(SessionContext);
  if (!session) {
    throw new Error("useSession must be used within an auth provider");
  }
  return session;
}
