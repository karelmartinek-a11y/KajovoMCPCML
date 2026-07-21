import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/coverage/**", "**/node_modules/**", "**/._*", "eslint.config.js", "vitest.config.mjs", "deploy/alert-sink/*.mjs", "deploy/handler-runtime/*.mjs", "deploy/scripts/*.mjs", "scripts/onboarding/*.mjs", "scripts/clean-appledouble.mjs", "scripts/external-api-soak.mjs", "scripts/generate-mcp-onboarding-catalog.mjs"]
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      "no-console": ["error", { "allow": ["warn", "error"] }],
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/require-await": "off"
    }
  }
);
