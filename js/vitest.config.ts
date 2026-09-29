import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The provider is a React component; its tests render it.
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
