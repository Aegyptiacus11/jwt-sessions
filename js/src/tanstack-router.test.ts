import { describe, expect, it } from "vitest";
import { createGuards, type GuardArgs } from "./tanstack-router";
import { type Session } from "./types";

const { requireAuth, requireRole, requireCapability } = createGuards();

function args(session: Partial<Session>, href = "/users"): GuardArgs {
  return {
    context: {
      auth: {
        status: "anonymous",
        token: null,
        user: null,
        error: null,
        signIn: async () => {},
        signOut: async () => {},
        signOutEverywhere: async () => {},
        ...session,
      },
    },
    location: { href },
  };
}

function authenticated(roles: string[] = []): Partial<Session> {
  return {
    status: "authenticated",
    token: "tok",
    user: { id: "u1", email: "a@b.c", roles },
  };
}

/**
 * TanStack Router signals redirects by throwing `redirect(...)`, which returns
 * `{ options: { to, search, statusCode } }` rather than a flat object.
 */
function redirectFrom(
  fn: () => void,
): { to: string; search?: Record<string, unknown> } | null {
  try {
    fn();
    return null;
  } catch (thrown) {
    return (
      thrown as { options: { to: string; search?: Record<string, unknown> } }
    ).options;
  }
}

describe("requireAuth", () => {
  it("redirects an anonymous user to login", () => {
    const redirect = redirectFrom(() =>
      requireAuth(args({ status: "anonymous" })),
    );
    expect(redirect?.to).toBe("/login");
  });

  it("preserves where they were going", () => {
    const redirect = redirectFrom(() =>
      requireAuth(args({ status: "anonymous" }, "/datasets?page=2")),
    );
    expect(redirect?.search).toEqual({ returnTo: "/datasets?page=2" });
  });

  it("lets an authenticated user through", () => {
    expect(redirectFrom(() => requireAuth(args(authenticated())))).toBeNull();
  });

  it("does not bounce a session that is still restoring", () => {
    expect(
      redirectFrom(() => requireAuth(args({ status: "loading" }))),
    ).toBeNull();
  });
});

describe("requireRole", () => {
  it("lets a matching role through", () => {
    expect(
      redirectFrom(() => requireRole("admin")(args(authenticated(["admin"])))),
    ).toBeNull();
  });

  it("accepts any one of several roles", () => {
    const guard = requireRole("moderator", "admin");
    expect(
      redirectFrom(() => guard(args(authenticated(["moderator"])))),
    ).toBeNull();
  });

  it("sends a wrong-role user to the forbidden path, not to login", () => {
    const redirect = redirectFrom(() =>
      requireRole("admin")(args(authenticated(["annotator"]))),
    );
    expect(redirect?.to).toBe("/");
  });

  it("sends an anonymous user to login rather than forbidden", () => {
    const redirect = redirectFrom(() =>
      requireRole("admin")(args({ status: "anonymous" })),
    );
    expect(redirect?.to).toBe("/login");
  });

  it("does not evaluate roles while the session is loading", () => {
    expect(
      redirectFrom(() => requireRole("admin")(args({ status: "loading" }))),
    ).toBeNull();
  });
});

describe("requireCapability", () => {
  it("gates on something the token does not carry, like a licensed module", () => {
    const licensed = new Set(["scheduling"]);
    const guard = requireCapability(() => licensed.has("billing"));
    expect(redirectFrom(() => guard(args(authenticated(["admin"]))))?.to).toBe(
      "/",
    );
  });

  it("allows when the capability is present", () => {
    const guard = requireCapability(() => true);
    expect(redirectFrom(() => guard(args(authenticated())))).toBeNull();
  });
});

describe("requireCapability with an extended context", () => {
  // What a parent route's beforeLoad returns is merged into child context, which
  // is how a licensed-module or permission check gets its data.
  type LicensedContext = {
    auth: Session;
    license: { modules: string[] };
  };

  const licensed = createGuards<LicensedContext>();

  function licensedArgs(modules: string[]): GuardArgs<LicensedContext> {
    return {
      context: {
        ...args(authenticated(["admin"])).context,
        license: { modules },
      },
      location: { href: "/billing" },
    };
  }

  it("allows a module the license includes", () => {
    const guard = licensed.requireCapability((ctx) =>
      ctx.license.modules.includes("billing"),
    );
    expect(
      redirectFrom(() => guard(licensedArgs(["billing", "clinical"]))),
    ).toBeNull();
  });

  it("blocks a module the license omits", () => {
    const guard = licensed.requireCapability((ctx) =>
      ctx.license.modules.includes("billing"),
    );
    expect(redirectFrom(() => guard(licensedArgs(["clinical"])))?.to).toBe("/");
  });
});

describe("custom paths", () => {
  it("honours app-supplied login and forbidden paths", () => {
    const guards = createGuards({
      loginPath: "/sign-in",
      forbiddenPath: "/datasets",
    });
    expect(
      redirectFrom(() => guards.requireAuth(args({ status: "anonymous" })))?.to,
    ).toBe("/sign-in");
    expect(
      redirectFrom(() =>
        guards.requireRole("admin")(args(authenticated(["annotator"]))),
      )?.to,
    ).toBe("/datasets");
  });
});
