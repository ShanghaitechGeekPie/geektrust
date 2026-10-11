// @vitest-environment node

import { mkdtemp, mkdir, writeFile, readFile, readdir, realpath, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { gzipSync, gunzipSync } from "node:zlib";
import { build } from "vite";
import { expect, test } from "vitest";
import { embeddedAssets } from "./embed";

test("packed assets restore Vite output and preserve the checkout marker and existing gzip sidecars", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "panel-packed-assets-")));
  const root = path.join(directory, "web");
  const destination = path.join(directory, "internal/webui/dist");
  try {
    await mkdir(path.join(root, "public"), { recursive: true });
    await mkdir(destination, { recursive: true });
    await writeFile(path.join(destination, ".gitkeep"), "checkout marker");
    await writeFile(path.join(destination, "stale.js"), "old build");
    await writeFile(path.join(root, "index.html"), '<script type="module" src="/main.js"></script>');
    await writeFile(path.join(root, "main.js"), `document.body.textContent = ${JSON.stringify("compressible text ".repeat(100))};`);
    const json = JSON.stringify({ message: "current content ".repeat(100) });
    const sidecar = gzipSync(Buffer.from("previous gzip sidecar"));
    await writeFile(path.join(root, "public/data.json"), json);
    await writeFile(path.join(root, "public/data.json.gz"), sidecar);
    await build({ root, configFile: false, logLevel: "silent", plugins: [embeddedAssets()] });
    expect(await readFile(path.join(destination, ".gitkeep"), "utf8")).toBe("checkout marker");
    expect(existsSync(path.join(destination, "stale.js"))).toBe(false);
    expect(await readFile(path.join(destination, "data.json"), "utf8")).toBe(json);
    expect(await readFile(path.join(destination, "data.json.gz"))).toEqual(sidecar);
    let files = 0;
    async function compare(relative: string): Promise<void> {
      for (const entry of await readdir(path.join(root, "dist", relative), { withFileTypes: true })) {
        const name = path.join(relative, entry.name);
        if (entry.isDirectory()) await compare(name);
        else {
          const target = path.join(destination, name);
          const restored = existsSync(target) ? await readFile(target) : gunzipSync(await readFile(`${target}.gz`));
          expect(restored).toEqual(await readFile(path.join(root, "dist", name)));
          files++;
        }
      }
    }
    await compare("");
    expect(files).toBeGreaterThan(2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}, 15000);
