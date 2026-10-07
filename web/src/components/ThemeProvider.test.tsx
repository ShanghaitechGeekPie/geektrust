import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ThemeProvider, useTheme } from "./ThemeProvider";
function Controls() {
  const { theme, setTheme } = useTheme();
  return (
    <>
      <span>{theme}</span>
      <button onClick={() => setTheme("light")}>light</button>
      <button onClick={() => setTheme("dark")}>dark</button>
      <button onClick={() => setTheme("system")}>system</button>
    </>
  );
}
let systemDark = false;
let listeners: Set<() => void>;
beforeEach(() => {
  localStorage.clear();
  document.documentElement.className = "";
  systemDark = false;
  listeners = new Set();
  vi.stubGlobal("matchMedia", () => ({
    get matches() {
      return systemDark;
    },
    addEventListener: (_: string, fn: () => void) => listeners.add(fn),
    removeEventListener: (_: string, fn: () => void) => listeners.delete(fn),
  }));
});
it("follows live system changes and removes the listener when unmounted", () => {
  const { unmount } = render(
    <ThemeProvider>
      <Controls />
    </ThemeProvider>,
  );
  expect(document.documentElement.classList.contains("dark")).toBe(false);
  act(() => {
    systemDark = true;
    listeners.forEach((fn) => fn());
  });
  expect(document.documentElement.classList.contains("dark")).toBe(true);
  expect(document.documentElement.style.colorScheme).toBe("dark");
  unmount();
  expect(listeners.size).toBe(0);
});
it("persists an explicit choice and ignores later system changes", () => {
  const { unmount } = render(
    <ThemeProvider>
      <Controls />
    </ThemeProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "light" }));
  act(() => {
    systemDark = true;
    listeners.forEach((fn) => fn());
  });
  expect(document.documentElement.classList.contains("dark")).toBe(false);
  expect(localStorage.getItem("geektrust-theme")).toBe("light");
  unmount();
  render(
    <ThemeProvider>
      <Controls />
    </ThemeProvider>,
  );
  expect(document.documentElement.classList.contains("dark")).toBe(false);
  fireEvent.click(screen.getByRole("button", { name: "system" }));
  expect(document.documentElement.classList.contains("dark")).toBe(true);
});
it("falls back to system for invalid saved data and works when storage is blocked", () => {
  localStorage.setItem("geektrust-theme", "invalid");
  systemDark = true;
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
    throw new Error("blocked");
  });
  render(
    <ThemeProvider>
      <Controls />
    </ThemeProvider>,
  );
  expect(document.documentElement.classList.contains("dark")).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: "light" }));
  expect(document.documentElement.classList.contains("dark")).toBe(false);
});
