// SPDX-FileCopyrightText: 2026 Alex Mextner
// SPDX-License-Identifier: MIT
import js from "@eslint/js";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import security from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", "web-ext-artifacts/"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  security.configs.recommended,
  noUnsanitized.configs.recommended,
  {
    languageOptions: {
      globals: { ...globals.browser, ...globals.webextensions },
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // Pages are hostile: nothing they control may reach a sink that parses HTML or code.
      "no-restricted-properties": [
        "error",
        { object: "document", property: "write", message: "never write markup into pages" },
      ],
      "no-restricted-syntax": [
        "error",
        { selector: "CallExpression[callee.name='eval']", message: "no eval" },
        { selector: "NewExpression[callee.name='Function']", message: "no Function()" },
      ],
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      // Flags every `obj[key]`, including typed Record lookups and array indexing that the
      // type checker already constrains; the no-unsanitized and DOM-sink rules cover the real
      // risk in this code base (page text reaching markup).
      "security/detect-object-injection": "off",
    },
  },
  {
    // Test tables index fixtures by name; the object-injection rule cannot tell those apart
    // from attacker-controlled keys and only produces noise there.
    files: ["test/**/*.ts", "scripts/**/*.ts"],
    rules: {
      "security/detect-object-injection": "off",
      "security/detect-non-literal-fs-filename": "off",
    },
  },
  {
    files: ["eslint.config.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
