import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
function fallbackCopy(text: string): boolean {
  const previous = document.activeElement;
  const input = document.createElement("textarea");
  input.value = text;
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    input.remove();
    if (previous instanceof HTMLElement) previous.focus();
  }
}
export function CopyButton({
  value,
  label = "复制",
}: {
  value: string;
  label?: string;
}) {
  const [result, setResult] = useState<"ok" | "fail" | null>(null);
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    let ok = false;
    try {
      await navigator.clipboard.writeText(value);
      ok = true;
    } catch {
      ok = fallbackCopy(value);
    }
    setResult(ok ? "ok" : "fail");
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setResult(null), 2000);
  };
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => void copy()}
      aria-label={`${label} ${value}`}
    >
      {result === "ok" ? <Check /> : <Copy />}
      <span aria-live="polite">
        {result === "ok" ? "已复制" : result === "fail" ? "复制失败" : label}
      </span>
    </Button>
  );
}
