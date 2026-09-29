import { defineConfig } from "vitest/config";

// The cross-language contract test: starts the Python demo app, so it runs
// on its own (`pnpm test:e2e`) and needs uv on the PATH.
export default defineConfig({
  test: {
    environment: "node",
    include: ["e2e/**/*.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
