import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import tsParser from "@typescript-eslint/parser";       // Parser for TypeScript files

/** @type {import('eslint').Linter.Config[]} */

export default [
  {
    // Apply ESLint to all JavaScript and TypeScript files
    files: ["**/*.{js,mjs,cjs,ts}"],

    // Common language options (e.g., browser globals)
    languageOptions: {
      parser: tsParser, // Use TypeScript parser for all files
      globals: globals.browser,
    },

    // Extend recommended configs for JS and TypeScript
    rules: {
      ...pluginJs.configs.recommended.rules,
      ...tseslint.configs.recommended.rules,
    }
  },
  {
    // Override settings specifically for JavaScript files
    files: ["**/*.{js,mjs,cjs}"],
    rules: {
      "no-unused-vars": "off",
      "no-undef": "off",
      "@typescript-eslint/no-unused-vars": "off", // Disable unused variable checks for JS
      "@typescript-eslint/no-undef": "off",      // Disable "undefined variable" errors
      "@typescript-eslint/no-explicit-any": "off", // Allow `any` in JS files
    },
  },

  {
    // Override settings specifically for TypeScript files
    files: ["**/*.ts"],
    rules: {
      "no-unused-vars": "off",
      "no-undef": "off"
    },
  },
];
