import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { gzipSync } from "node:zlib";
import type { Plugin, ResolvedConfig } from "vite";

// Keep Vite's output intact for preview. Only the copy embedded in Go uses
// gzip storage; the Go filesystem restores the original bytes on open.
export function embeddedAssets(): Plugin {
  let config: ResolvedConfig;
  return {
    name: "compressed-embedded-assets",
    apply: "build",
    configResolved(resolved) { config = resolved; },
    async writeBundle() {
      const source = path.resolve(config.root, config.build.outDir);
      const destination = path.resolve(config.root, "../internal/webui/dist");
      await mkdir(destination, { recursive: true });
      for (const entry of await readdir(destination)) {
        if (entry !== ".gitkeep") await rm(path.join(destination, entry), { recursive: true, force: true });
      }
      await writeFile(path.join(destination, ".gitkeep"), "", { flag: "a" });
      async function copy(directory: string): Promise<void> {
        const entries = await readdir(directory, { withFileTypes: true });
        const names = new Set(entries.map((entry) => entry.name));
        for (const entry of entries) {
          const file = path.join(directory, entry.name);
          const output = path.join(destination, path.relative(source, file));
          if (entry.isDirectory()) {
            await mkdir(output, { recursive: true });
            await copy(file);
          } else {
            const data = await readFile(file);
            // Do not overwrite an existing public gzip sidecar.
            const compress = /\.(?:html|js|css|svg|json)$/.test(file) && !names.has(`${entry.name}.gz`);
            const compressed = compress ? gzipSync(data, { level: 9 }) : data;
            if (compressed.length < data.length) await writeFile(`${output}.gz`, compressed);
            else await writeFile(output, data);
          }
        }
      }
      await copy(source);
    },
  };
}
