import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ThemeProvider } from "./ThemeProvider";
import { ThemeToggle } from "./ThemeToggle";

let systemDark = false;
let listeners: Set<() => void>;
beforeEach(() => {
  localStorage.clear();
  document.documentElement.className = "";
  systemDark = false;
  listeners = new Set();
  vi.stubGlobal("matchMedia", () => ({
    get matches() { return systemDark; },
    addEventListener: (_: string, fn: () => void) => listeners.add(fn),
    removeEventListener: (_: string, fn: () => void) => listeners.delete(fn),
  }));
});

function openMenu() {
  const button = screen.getByRole("button", { name: "切换主题" });
  fireEvent(button, new MouseEvent("pointerdown", { bubbles: true, button: 0 }));
  return screen.findByRole("menu");
}

it("selects each mode from the icon menu and remembers the selection", async () => {
  const first = render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
  await openMenu();
  fireEvent.click(screen.getByRole("menuitemradio", { name: "浅色" }));
  expect(localStorage.getItem("geektrust-theme")).toBe("light");
  expect(document.documentElement.classList.contains("dark")).toBe(false);
  first.unmount();
  render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
  await openMenu();
  expect(screen.getByRole("menuitemradio", { name: "浅色" }).getAttribute("aria-checked")).toBe("true");
  fireEvent.click(screen.getByRole("menuitemradio", { name: "深色" }));
  expect(document.documentElement.classList.contains("dark")).toBe(true);
  await openMenu();
  fireEvent.click(screen.getByRole("menuitemradio", { name: "跟随系统" }));
  expect(localStorage.getItem("geektrust-theme")).toBe("system");
  expect(document.documentElement.classList.contains("dark")).toBe(false);
  act(() => { systemDark = true; listeners.forEach(fn => fn()); });
  expect(document.documentElement.classList.contains("dark")).toBe(true);
});

it("opens from the keyboard and restores focus to the icon after Escape", async () => {
  render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
  const button = screen.getByRole("button", { name: "切换主题" });
  button.focus();
  fireEvent.keyDown(button, { key: "Enter" });
  const menu = await screen.findByRole("menu");
  fireEvent.keyDown(menu, { key: "Escape" });
  await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(button));
});
