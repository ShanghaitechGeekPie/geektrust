import { useEffect, useRef, useState } from "react";
import { post, ApiError, errorText } from "../api";
import type { Snapshot } from "../types";

const RESEND_COOLDOWN = 60;

// SmsDialog pops up whenever the controller demands SMS verification. The
// submission carries the current generation so a stale dialog can never
// deliver a code into a newer prompt; all local state resets whenever the
// generation changes. The resend button carries a client-side cooldown —
// the controller rate-limits resends anyway (429), so don't invite it.
export function SmsDialog({ snap }: { snap: Snapshot }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(RESEND_COOLDOWN);
  const inputRef = useRef<HTMLInputElement>(null);

  const gen = snap.sms_pending ? snap.sms_gen : 0;
  useEffect(() => {
    if (gen === 0) return;
    setCode("");
    setBusy(false);
    setError(null);
    setNotice(null);
    setCooldown(RESEND_COOLDOWN);
    inputRef.current?.focus();
    const timer = window.setInterval(() => setCooldown((s) => (s > 0 ? s - 1 : 0)), 1000);
    return () => window.clearInterval(timer);
  }, [gen]);

  if (!snap.sms_pending) return null;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy || code.length !== 6) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await post("/api/sms", { code, gen: snap.sms_gen });
      // 202 = 已投递;登录结果经 SSE 推送。验证失败会结束本次登录,
      // 弹窗随之关闭,状态卡片会显示失败原因。
      setNotice("已提交,等待控制器验证…");
    } catch (err) {
      setBusy(false);
      setError(
        errorText(err, "提交失败", {
          400: "验证码需为 6 位数字",
          409: "验证码已被其他通道提交,或本轮验证已结束",
        }),
      );
    }
  };

  const resend = async () => {
    if (busy || cooldown > 0) return;
    setError(null);
    setNotice(null);
    try {
      await post("/api/sms/resend", { gen: snap.sms_gen });
      setNotice("验证码已重新发送");
      setCooldown(RESEND_COOLDOWN);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        // 上一条验证码仍在有效期内:直接输入它,同时进入冷却防止连点。
        setCooldown(RESEND_COOLDOWN);
        setError(err.message || "发送过于频繁,上一条验证码仍然有效");
      } else {
        setError(errorText(err, "重发失败", { 409: "本轮验证已结束" }));
      }
    }
  };

  return (
    <div className="dialog-backdrop">
      <form
        className="dialog"
        onSubmit={submit}
        role="dialog"
        aria-modal="true"
        aria-labelledby="sms-title"
      >
        <h2 id="sms-title">短信验证</h2>
        <p className="muted">控制器已向你的手机发送 6 位验证码,输入后继续登录。</p>
        <input
          ref={inputRef}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          placeholder="6 位验证码"
          inputMode="numeric"
          autoComplete="one-time-code"
          disabled={busy}
          className="code-input mono"
          aria-label="6 位短信验证码"
        />
        {error && <p className="error-text">{error}</p>}
        {notice && <p className="ok-text">{notice}</p>}
        <div className="actions">
          <button type="submit" disabled={busy || code.length !== 6}>
            {busy ? "验证中…" : "验证"}
          </button>
          <button type="button" className="secondary" onClick={() => void resend()} disabled={busy || cooldown > 0}>
            {cooldown > 0 ? `重新发送(${cooldown}s)` : "重新发送"}
          </button>
        </div>
        <p className="muted small">也可以直接在运行 geektrust 的终端里输入验证码,两个通道先到先用。</p>
      </form>
    </div>
  );
}
