import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    setupFiles: "./src/test/setup.ts",
    env: {
      NODE_ENV: "test",
    },
    testTimeout: 30000, // 30 seconds for slow Argon2 tests
    hookTimeout: 30000, // 30 seconds for DB cleanup (prevent deadlock timeouts)
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules/",
        "src/test/",
        "**/*.d.ts",
        "**/*.config.*",
        "src/index.ts",
      ],
    },
  },
});
