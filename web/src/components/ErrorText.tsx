import { useState } from "react";
import { friendlyError } from "../errors";

// ErrorText shows the actionable line and keeps the original Go error chain
// behind a toggle: out of the way for normal use, still there when the raw
// controller code or transport detail is what you actually need.
export function ErrorText({ raw, prefix }: { raw: string; prefix?: string }) {
  const [open, setOpen] = useState(false);
  const { summary, detail } = friendlyError(raw);
  return (
    <div className="error-block">
      <p className="error-text">
        {prefix}
        {summary}
        {detail && (
          <button
            type="button"
            className="link detail-toggle"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
          >
            {open ? "收起" : "详情"}
          </button>
        )}
      </p>
      {open && detail && <pre className="error-detail mono">{detail}</pre>}
    </div>
  );
}
