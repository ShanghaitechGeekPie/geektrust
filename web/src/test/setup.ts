import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
class ResizeObserverStub { observe() {} unobserve() {} disconnect() {} }
vi.stubGlobal("ResizeObserver", ResizeObserverStub);
if (typeof document !== "undefined") {
  Element.prototype.scrollIntoView = () => {};
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.setPointerCapture = () => {};
  Element.prototype.releasePointerCapture = () => {};
  document.elementFromPoint = () => null;
}
