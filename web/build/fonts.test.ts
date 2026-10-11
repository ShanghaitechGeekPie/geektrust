// @vitest-environment node

import { mkdtemp, mkdir, writeFile, readFile, realpath, cp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { build, createServer } from "vite";
import { collectFontText, panelFonts } from "./fonts";

test("new frontend and backend text, escaped Unicode and HTML entities enter the font subset", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "panel-font-text-"));
  try {
    const root = path.join(directory, "web");
    for (const name of ["web/src/test", "internal/messages", "cmd/panel"]) {
      await mkdir(path.join(directory, name), { recursive: true });
    }
    await writeFile(path.join(root, "src/Panel.tsx"), 'export const label = "新界面\\u9a8c\\u{20bb7}";');
    await writeFile(path.join(root, "src/message.js"), 'export const label = "脚";');
    await writeFile(path.join(root, "src/messages.json"), '{"label":"翻译\\u8bed"}');
    await writeFile(path.join(directory, "internal/messages/message.go"), 'const message = "服务端"');
    await writeFile(path.join(root, "index.html"), "<title>&#x72b6;&#24577;</title>");
    await writeFile(path.join(root, "src/Panel.test.tsx"), "测试专用");
    await writeFile(path.join(root, "src/test/setup.ts"), "测试专用");
    await writeFile(path.join(directory, "internal/messages/message_test.go"), "测试专用");
    const text = await collectFontText(root);
    expect(new Set(text)).toEqual(new Set("新界面验𠮷服务端状态脚翻译语"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a production build leaves the development font stylesheet and files intact", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "panel-font-modes-")));
  const root = path.join(directory, "web");
  const devCSS = path.join(root, ".generated/fonts-dev/noto-sans-sc.css");
  let server: Awaited<ReturnType<typeof createServer>> | undefined;
  try {
    for (const name of ["web/src", "internal", "cmd"]) {
      await mkdir(path.join(directory, name), { recursive: true });
    }
    await cp(fileURLToPath(new URL("../node_modules/@fontsource-variable/noto-sans-sc", import.meta.url)),
      path.join(root, "node_modules/@fontsource-variable/noto-sans-sc"), { recursive: true });
    await writeFile(path.join(root, "index.html"), '<script type="module" src="/src/main.ts"></script>');
    await writeFile(path.join(root, "src/main.ts"), 'import "./styles.css"; document.body.textContent = "新界面";');
    await writeFile(path.join(root, "src/styles.css"), '@import "@panel-fonts";');
    server = await createServer({
      root, configFile: false, logLevel: "silent", plugins: [panelFonts()],
      resolve: { alias: { "@panel-fonts": devCSS } },
      server: { middlewareMode: true, hmr: false, watch: null },
    });
    const before = await server.transformRequest("/src/styles.css");
    expect(before?.code).toContain("Noto Sans SC Variable");
    const fullCSS = await readFile(devCSS, "utf8");
    await build({
      root, configFile: false, logLevel: "silent", plugins: [panelFonts()],
      resolve: { alias: { "@panel-fonts": path.join(root, ".generated/fonts/noto-sans-sc.css") } },
    });
    expect(await readFile(devCSS, "utf8")).toBe(fullCSS);
    expect((await server.transformRequest("/src/styles.css"))?.code).toBe(before?.code);
    const subsetCSS = await readFile(path.join(root, ".generated/fonts/noto-sans-sc.css"), "utf8");
    expect(subsetCSS).toContain("@font-face");
    expect(subsetCSS.match(/@font-face/g)!.length).toBeLessThan(fullCSS.match(/@font-face/g)!.length);
  } finally {
    await server?.close();
    await rm(directory, { recursive: true, force: true });
  }
}, 15000);
