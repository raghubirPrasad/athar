import type { ActivityOut, CredentialOut, PrincipalOut } from "../../api/types";
import { formatDate, formatInt } from "../../lib/format";
import { Badge } from "../ui/Badge";
import { CloudIcon } from "../ui/CloudIcon";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";

/**
 * The rows the dormancy, stale-credential and linker rules read (SPEC §5.1,
 * §6): per-category usage, credentials with their age, and how each cloud
 * principal was tied to this identity — with the link confidence, as SPEC §6
 * requires at the evidence altitude.
 */
export function UsageEvidence({
  activity,
  credentials,
  principals,
}: {
  activity: readonly ActivityOut[];
  credentials: readonly CredentialOut[];
  principals: readonly PrincipalOut[];
}) {
  return (
    <div className="flex flex-col gap-4">
      <section>
        <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
          Activity by service category
        </h4>
        {activity.length === 0 ? (
          <p className="text-[13px] text-fg-muted">No recorded activity in this snapshot — the dormancy rule's input.</p>
        ) : (
          <TableWrap>
            <Table>
              <THead>
                <tr>
                  <Th>Cloud</Th>
                  <Th>Category</Th>
                  <Th>Last activity</Th>
                  <Th numeric>Operations</Th>
                </tr>
              </THead>
              <TBody>
                {activity.map((row) => (
                  <Tr key={`${row.cloud}:${row.service_category}:${row.snapshot_month}`}>
                    <Td>
                      <CloudIcon cloud={row.cloud} size={15} />
                    </Td>
                    <Td>{row.service_category}</Td>
                    <Td>{formatDate(row.last_activity_at)}</Td>
                    <Td numeric>{formatInt(row.operation_count)}</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </TableWrap>
        )}
      </section>

      <section>
        <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">Credentials</h4>
        {credentials.length === 0 ? (
          <p className="text-[13px] text-fg-muted">No long-lived credential on this identity.</p>
        ) : (
          <TableWrap>
            <Table>
              <THead>
                <tr>
                  <Th>Reference</Th>
                  <Th>Cloud</Th>
                  <Th>Kind</Th>
                  <Th>Last rotated</Th>
                  <Th>Last used</Th>
                  <Th numeric>Age (days)</Th>
                  <Th>State</Th>
                </tr>
              </THead>
              <TBody>
                {credentials.map((credential) => (
                  <Tr key={credential.credential_ref}>
                    <Td mono>{credential.credential_ref}</Td>
                    <Td>
                      <CloudIcon cloud={credential.cloud} size={15} />
                    </Td>
                    <Td>{credential.kind}</Td>
                    <Td>{formatDate(credential.last_rotated_at)}</Td>
                    <Td>{formatDate(credential.last_used_at)}</Td>
                    <Td numeric>{credential.age_days ?? "—"}</Td>
                    <Td>
                      <Badge tone={credential.active ? "warn" : "neutral"}>
                        {credential.active ? "Active" : "Inactive"}
                      </Badge>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </TableWrap>
        )}
      </section>

      <section>
        <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
          Cloud principals and how they were linked
        </h4>
        {principals.length === 0 ? (
          <p className="text-[13px] text-fg-muted">No cloud principal is linked to this identity.</p>
        ) : (
          <TableWrap>
            <Table>
              <THead>
                <tr>
                  <Th>Principal</Th>
                  <Th>Cloud</Th>
                  <Th>Type</Th>
                  <Th>Link method</Th>
                  <Th>Confidence</Th>
                </tr>
              </THead>
              <TBody>
                {principals.map((principal) => (
                  <Tr key={principal.principal_ref}>
                    <Td mono className="max-w-[22rem] truncate" title={principal.principal_ref}>
                      {principal.principal_ref}
                    </Td>
                    <Td>
                      <CloudIcon cloud={principal.cloud} size={15} />
                    </Td>
                    <Td>{principal.principal_type}</Td>
                    <Td mono>{principal.link_method}</Td>
                    <Td>
                      <Badge tone={principal.link_confidence === "exact" ? "ok" : "warn"}>
                        {principal.link_confidence}
                      </Badge>
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </TableWrap>
        )}
      </section>
    </div>
  );
}
