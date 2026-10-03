import { globSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { lint } from "markdownlint/sync";

// Resolve files with Node's glob implementation and read JSON configuration only.
const root = fileURLToPath(new URL("../", import.meta.url));
const files = ["README.md", ...globSync("docs/**/*.md", { cwd: root }).sort()];
const config = JSON.parse(readFileSync(join(root, ".markdownlint.json"), "utf8"));
const strings = Object.fromEntries(files.map(file => [
  file.replaceAll("\\", "/"), readFileSync(join(root, file), "utf8")
]));
const report = Object.entries(lint({ strings, config })).flatMap(([file, issues]) =>
  issues.map(issue => `${file}:${issue.lineNumber}:${issue.errorRange?.[0] ?? 1} ` +
    `${issue.ruleNames[0]} ${issue.ruleDescription}` +
    (issue.errorDetail ? ` (${issue.errorDetail})` : ""))
).join("\n");

if (report) {
  console.error(report);
  process.exitCode = 1;
} else {
  console.log(`Markdown: ${files.length} files checked, no issues.`);
}
