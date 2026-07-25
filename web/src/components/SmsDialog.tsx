import { useEffect, useRef, useState } from "react";
import { post, ApiError } from "../api";
import type { Snapshot } from "../types";

// SmsDialog pops up whenever the controller demands SMS verification. The
// submission carries the current generation so a stale dialog can never
// deliver a code into a newer prompt. All local state resets whenever the
// generation changes (or a new challenge starts), so a previous challenge
// can never leave the input disabled.
export function SmsDialog({ snap }: { snap: Snapshot }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resendMsg, setResendMsg] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(60);
  const inputRef = useRef<HTMLInputElement>(null);

  const gen = snap.sms_pending ? snap.sms_gen : 0;
  useEffect(() => {
    if (gen === 0) return;
    setCode("");
    setBusy(false);
    setError(null);
    setResendMsg(null);
    setRemaining(60);
    inputRef.current?.focus();
    const timer = setInterval(() => setRemaining((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(timer);
  }, [gen]);

  if (!snap.sms_pending) return null;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post("/api/sms", { code, gen: snap.sms_gen });
      // Accepted: the panel state change (pushed via SSE) closes the dialog.
    } catch (err) {
      setBusy(false);
      setError(err instanceof ApiError ? err.message : "提交失败");
    }
  };

  const resend = async () => {
    setResendMsg(null);
    setError(null);
    try {
      await post("/api/sms/resend", { gen: snap.sms_gen });
      setResendMsg("已重新发送");
      setRemaining(60);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "重发失败");
    }
  };

  return (
    <div className="dialog-backdrop">
      <form className="dialog" onSubmit={submit}>
        <h2>短信验证</h2>
        <p className="muted">验证码已发送至你的手机,{remaining > 0 ? `${remaining} 秒内有效` : "可能已过期,请重发"}。</p>
        <input
          ref={inputRef}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          placeholder="6 位验证码"
          inputMode="numeric"
          autoComplete="one-time-code"
          disabled={busy}
          className="code-input mono"
        />
        {error && <p className="error-text">{error}</p>}
        {resendMsg && <p className="ok-text">{resendMsg}</p>}
        <div className="actions">
          <button type="submit" disabled={busy || code.length !== 6}>
            {busy ? "验证中…" : "验证"}
          </button>
          <button type="button" className="secondary" onClick={resend} disabled={busy}>
            重新发送
          </button>
        </div>
      </form>
    </div>
  );
}
