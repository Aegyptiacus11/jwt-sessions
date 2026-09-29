/**
 * Route guards for TanStack Router - an optional entry point
 * (`tandem-auth/tanstack-router`), so the core has no router dependency.
 */
import { redirect } from "@tanstack/react-router";
import type { Session } from "./types";
import { hasRole } from "./types";

/** The minimum router context every app must provide. Apps extend it. */
export type AuthRouterContext = {
  auth: Session;
};

/** Structural subset of TanStack Router's `beforeLoad` argument that guards need. */
export type GuardArgs<TContext extends AuthRouterContext = AuthRouterContext> =
  {
    context: TContext;
    location: { href: string };
  };

export type GuardPaths = {
  /** Where anonymous users go. */
  loginPath?: string;
  /** Where authenticated-but-unauthorized users go. */
  forbiddenPath?: string;
};

const DEFAULTS = {
  loginPath: "/login",
  forbiddenPath: "/",
} satisfies Required<GuardPaths>;

/**
 * `redirect()` is typed against the consumer's registered route tree, which this package
 * cannot see. Paths are validated by the consuming app's own router types at the
 * call site of `createGuards`, so the cast is contained to this one helper.
 */
function go(to: string, search?: Record<string, unknown>): never {
  throw redirect({ to, search } as never);
}

/**
 * Builds the route guards.
 *
 * Guards run in `beforeLoad`, so an unauthorized user never renders the protected
 * component for a frame - the redirect happens before the route resolves. This is
 * what replaces the wrapper components and their `return null` loading states.
 *
 * `loading` is deliberately a no-op: the app should not mount `<RouterProvider>`
 * until the session has resolved, and a guard that redirected mid-restore would
 * bounce users to login on every reload.
 *
 * Generic over the context so `requireCapability` can read app-specific fields a
 * parent route's `beforeLoad` added (a license, a permission set), not just `auth`.
 */
export function createGuards<
  TContext extends AuthRouterContext = AuthRouterContext,
>(paths: GuardPaths = {}) {
  const { loginPath, forbiddenPath } = { ...DEFAULTS, ...paths };

  function requireAuth({ context, location }: GuardArgs<TContext>): void {
    if (
      context.auth.status === "loading" ||
      context.auth.status === "authenticated"
    ) {
      return;
    }
    go(loginPath, { returnTo: location.href });
  }

  function requireRole(...roles: string[]) {
    return (args: GuardArgs<TContext>): void => {
      requireAuth(args);
      if (args.context.auth.status !== "authenticated") return;
      if (!hasRole(args.context.auth, ...roles)) {
        go(forbiddenPath);
      }
    };
  }

  /**
   * Gate on something the token does not carry - a licensed module, a
   * backend-issued permission. `has` is supplied per app.
   */
  function requireCapability(has: (context: TContext) => boolean) {
    return (args: GuardArgs<TContext>): void => {
      requireAuth(args);
      if (args.context.auth.status !== "authenticated") return;
      if (!has(args.context)) {
        go(forbiddenPath);
      }
    };
  }

  return { requireAuth, requireRole, requireCapability };
}
