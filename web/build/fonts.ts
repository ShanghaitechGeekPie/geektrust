import { readFile, readdir, mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import subsetFont from "subset-font";
import type { Plugin, ResolvedConfig } from "vite";

// Include backend messages as well as panel text. Unknown dynamic characters
// continue through the existing CSS system-font fallback.
export async function collectFontText(root: string): Promise<string> {
  const characters = new Set<string>();
  async function collect(file: string): Promise<void> {
    const source = await readFile(file, "utf8");
    const decoded = source.replace(
      /\\u\{([\da-f]+)\}|\\u([\da-f]{4})|&#x([\da-f]+);|&#(\d+);/gi,
      (match, braced, escaped, hex, decimal) => {
        const point = parseInt(braced ?? escaped ?? hex ?? decimal, decimal ? 10 : 16);
        return point <= 0x10ffff ? String.fromCodePoint(point) : match;
      },
    );
    for (const character of decoded) {
      // Geist already supplies Latin; do not duplicate it in Noto Sans SC.
      if (character.codePointAt(0)! > 0xff) characters.add(character);
    }
  }
  async function walk(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "test" && entry.name !== "dist") await walk(file);
      } else if (/\.(?:[jt]sx?|css|html|json|svg|go)$/.test(entry.name) &&
                 !/(?:\.test\.|_test\.go$)/.test(entry.name)) {
        await collect(file);
      }
    }
  }
  await walk(path.join(root, "src"));
  await walk(path.join(root, "..", "internal"));
  await walk(path.join(root, "..", "cmd"));
  await collect(path.join(root, "index.html"));
  return [...characters].sort((a, b) => a.codePointAt(0)! - b.codePointAt(0)!).join("");
}

function withinRange(character: string, range: string): boolean {
  const point = character.codePointAt(0)!;
  return range.split(",").some((part) => {
    const match = /^U\+([\da-f?]+)(?:-([\da-f]+))?$/i.exec(part.trim());
    if (!match) throw new Error(`Unsupported font unicode-range: ${part}`);
    const low = parseInt(match[1].replace(/\?/g, "0"), 16);
    const high = parseInt((match[2] ?? match[1]).replace(/\?/g, "f"), 16);
    return point >= low && point <= high;
  });
}

export function panelFonts(): Plugin {
  let config: ResolvedConfig;
  return {
    name: "panel-font-subsets",
    configResolved(resolved) { config = resolved; },
    async buildStart() {
      const packageRoot = path.join(config.root, "node_modules/@fontsource-variable/noto-sans-sc");
      const generated = path.join(config.root, ".generated", config.command === "serve" ? "fonts-dev" : "fonts");
      const source = await readFile(path.join(packageRoot, "index.css"), "utf8");
      await rm(generated, { recursive: true, force: true });
      await mkdir(generated, { recursive: true });
      let css: string;
      if (config.command === "serve") {
        // Development keeps the complete font so newly typed text also works
        // before the next production build, including during hot reload.
        css = source.replaceAll("./files/", "../../node_modules/@fontsource-variable/noto-sans-sc/files/");
      } else {
        const text = await collectFontText(config.root);
        const faces: string[] = [];
        let bytes = 0;
        for (const match of source.matchAll(/@font-face\s*\{[^}]+\}/g)) {
          const face = match[0];
          const range = /unicode-range:\s*([^;]+);/.exec(face)?.[1];
          const url = /url\(([^)]+)\)/.exec(face)?.[1];
          if (!range || !url) throw new Error("Noto Sans SC font face is missing its source or unicode-range");
          const selected = [...text].filter((character) => withinRange(character, range));
          if (!selected.length) continue;
          const filename = path.basename(url);
          const font = await subsetFont(await readFile(path.join(packageRoot, url)), selected.join(""), {
            targetFormat: "woff2",
            // Preserve copyright and OFL licensing alongside names and weight
            // axes. Hinting and every layout feature are retained by default.
            preserveNameIds: [0, 7, 13, 14],
          });
          await writeFile(path.join(generated, filename), font);
          bytes += font.length;
          const unicodeRange = selected.map((character) => `U+${character.codePointAt(0)!.toString(16)}`).join(",");
          faces.push(face.replace(url, `./${filename}`).replace(range, unicodeRange));
        }
        css = faces.join("\n");
        config.logger.info(`[fonts] Noto Sans SC: ${[...text].length} source characters, ${faces.length} subsets, ${(bytes / 1000).toFixed(1)} kB`);
      }
      await writeFile(path.join(generated, "noto-sans-sc.css"), css);
    },
  };
}
