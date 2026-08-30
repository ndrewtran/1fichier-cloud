import { cp, mkdir, rm } from "node:fs/promises";
import { build } from "esbuild";

await rm("dist/public", { recursive: true, force: true });
await mkdir("dist", { recursive: true });
await mkdir("dist/public", { recursive: true });

await build({
  entryPoints: ["src/public/app.ts"],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  outfile: "dist/public/app.js",
  sourcemap: false,
});

await cp("src/public/index.html", "dist/public/index.html");
await cp("src/public/styles.css", "dist/public/styles.css");
