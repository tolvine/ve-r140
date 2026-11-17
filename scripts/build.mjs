// scripts/ (rev 3)
// scripts/build.mjs — render public/ into dist/ with a build stamp.
import { mkdirSync, copyFileSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
mkdirSync("dist", { recursive: true });
for (const f of readdirSync("public")) copyFileSync(`public/${f}`, `dist/${f}`);
writeFileSync("dist/buildstamp.txt", new Date().toISOString() + "\n");
console.log("build: rendered dist/");
