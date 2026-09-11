import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules", "src/api/schema.d.ts"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // CLAUDE.md: TypeScript strict, no `any`, no `@ts-ignore`.
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/ban-ts-comment": [
        "error",
        {
          "ts-ignore": true,
          "ts-nocheck": true,
          "ts-check": false,
          "ts-expect-error": "allow-with-description",
        },
      ],
      "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "No tokens or app state in web storage (CLAUDE.md)." },
        { name: "sessionStorage", message: "No tokens or app state in web storage (CLAUDE.md)." },
      ],
      "no-restricted-properties": [
        "error",
        { object: "window", property: "localStorage", message: "No web storage (CLAUDE.md)." },
        { object: "window", property: "sessionStorage", message: "No web storage (CLAUDE.md)." },
      ],
    },
  },
);
