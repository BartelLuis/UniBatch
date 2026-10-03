import js from "@eslint/js";
import globals from "globals";

export default [
  { ignores: ["node_modules/**", ".venv/**", "artifacts/**"] },
  {
    ...js.configs.recommended,
    files: ["app/static/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "script",
      globals: { ...globals.browser, UI: "readonly" }
    }
  },
  {
    ...js.configs.recommended,
    files: ["eslint.config.mjs", "tools/*.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.node
    }
  }
];
