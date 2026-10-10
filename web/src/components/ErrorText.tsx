import type { FriendlyError } from "../errors";
export function ErrorText({
  error,
  prefix,
}: {
  error: FriendlyError;
  prefix?: string;
}) {
  return (
    <div className="error-block" role="alert">
      <p>
        {prefix}
        {error.summary}
      </p>
      {error.detail && (
        <details className="mt-1">
          <summary className="cursor-pointer text-xs">错误详情</summary>
          <pre className="mt-2 whitespace-pre-wrap break-all font-mono text-xs">
            {error.detail}
          </pre>
        </details>
      )}
    </div>
  );
}
