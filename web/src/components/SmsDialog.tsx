import { useEffect, useRef, useState } from "react";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { post, postJSON, ApiError, errorText } from "../api";
import type { FriendlyError } from "../errors";
import type { Snapshot } from "../types";
import { ErrorText } from "./ErrorText";
export function SmsDialog({
  snap,
  connected,
  open,
  onOpenChange,
}: {
  snap: Snapshot;
  connected: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [resending, setResending] = useState(false);
  const [error, setError] = useState<FriendlyError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(60);
  const active = useRef(true);
  const inFlight = useRef(false);
  useEffect(() => {
    active.current = true;
    const timer = window.setInterval(
      () => setCooldown((value) => Math.max(0, value - 1)),
      1000,
    );
    return () => {
      active.current = false;
      window.clearInterval(timer);
    };
  }, []);
  // App keys this dialog by SMS generation, so old responses cannot affect a new prompt.
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!connected || inFlight.current || code.length !== 6) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await post("/api/sms", { code, gen: snap.sms_gen });
      if (active.current) setNotice("已提交，等待服务端验证…");
    } catch (error) {
      if (!active.current) return;
      inFlight.current = false;
      setBusy(false);
      setError(
        errorText(error, "提交失败", {
          400: "验证码需为 6 位数字",
          409: "验证码已提交，或本轮验证已结束",
        }),
      );
    }
  };
  const resend = async () => {
    if (!connected || inFlight.current || cooldown > 0) return;
    inFlight.current = true;
    setResending(true);
    setError(null);
    setNotice(null);
    try {
      const result = await postJSON<{ restarting?: boolean }>(
        "/api/sms/resend",
        { gen: snap.sms_gen },
      );
      if (!active.current) return;
      setNotice(
        result.restarting
          ? "验证已过期，正在重新登录并发送新验证码…"
          : "验证码已重新发送",
      );
      setCooldown(60);
    } catch (error) {
      if (!active.current) return;
      if (error instanceof ApiError && error.status === 429) setCooldown(60);
      setError(
        errorText(error, "重发失败", {
          409: "本轮验证已结束",
          429: "发送过于频繁，上一条验证码仍然有效",
        }),
      );
    } finally {
      if (active.current) {
        inFlight.current = false;
        setResending(false);
      }
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sms-dialog">
        <div className="dialog-icon">
          <KeyRound className="size-5" />
        </div>
        <DialogHeader>
          <DialogTitle>短信验证</DialogTitle>
          <DialogDescription>
            6 位验证码已发送到你的手机，输入后继续登录。
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={(event) => void submit(event)}
          className="flex flex-col gap-4"
        >
          <InputOTP
            maxLength={6}
            pattern={REGEXP_ONLY_DIGITS}
            value={code}
            onChange={setCode}
            disabled={busy || resending || !connected}
            aria-label="6 位短信验证码"
            autoFocus
          >
            <InputOTPGroup className="w-full justify-center">
              {Array.from({ length: 6 }, (_, index) => (
                <InputOTPSlot
                  className="h-12 flex-1 max-w-14"
                  key={index}
                  index={index}
                />
              ))}
            </InputOTPGroup>
          </InputOTP>
          {error && <ErrorText error={error} />}
          {notice && (
            <p className="text-sm text-success" role="status">
              {notice}
            </p>
          )}
          {!connected && (
            <p className="text-sm text-warning" role="status">
              面板连接已断开，恢复后可继续验证。
            </p>
          )}
          <Button
            type="submit"
            disabled={!connected || busy || resending || code.length !== 6}
          >
            {busy ? "验证中…" : "验证并连接"}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!connected || busy || resending || cooldown > 0}
            onClick={() => void resend()}
          >
            {resending
              ? "发送中…"
              : cooldown > 0
                ? `重新发送（${cooldown}s）`
                : "重新发送"}
          </Button>
          <p className="text-xs leading-5 text-muted-foreground">
            也可以在运行 geektrust 的终端中输入验证码，以先提交的为准。
          </p>
        </form>
      </DialogContent>
    </Dialog>
  );
}
