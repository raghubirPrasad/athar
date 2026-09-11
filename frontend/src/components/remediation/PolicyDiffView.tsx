import type { PolicyDiffOut } from "../../api/types";
import { prettyJson } from "../../lib/download";
import { Badge } from "../ui/Badge";
import { CloudIcon } from "../ui/CloudIcon";
import { CodeBlock } from "../ui/CodeBlock";

/**
 * Provider-native before/after for a proposed change (SPEC §11.5). Copy-pasteable
 * on purpose: an operator who does not trust the "Apply" button can run the diff
 * by hand.
 */
export function PolicyDiffView({ diff }: { diff: PolicyDiffOut }) {
  const before = diff.before ?? {};
  const after = diff.after ?? {};
  const operations = diff.operations ?? [];

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        {diff.cloud && <Badge icon={<CloudIcon cloud={diff.cloud} size={13} />}>{diff.cloud.toUpperCase()}</Badge>}
        {diff.summary && <p className="text-[13px] text-fg">{diff.summary}</p>}
      </div>

      {operations.length > 0 && (
        <ul className="flex flex-col gap-1">
          {operations.map((op) => (
            <li key={`${op.op}:${op.target}`} className="text-[13px] text-fg-muted">
              <code className="font-mono text-[12.5px] text-fg">{op.op}</code> → {op.target}
              {op.detail && <span className="text-fg-faint"> · {op.detail}</span>}
            </li>
          ))}
        </ul>
      )}

      <div className="grid gap-2 lg:grid-cols-2">
        <CodeBlock label="Before" value={prettyJson(before)} maxHeight="16rem" />
        <CodeBlock label="After" value={prettyJson(after)} maxHeight="16rem" />
      </div>
    </div>
  );
}
