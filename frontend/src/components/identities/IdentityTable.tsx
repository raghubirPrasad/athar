import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useNavigate } from "react-router-dom";
import type { IdentityRow } from "../../api/types";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";
import { identityColumns } from "./identityColumns";
import { formatSort, NUMERIC_COLUMNS, parseSort, SORTABLE_COLUMNS } from "./sort";

export interface IdentityTableProps {
  rows: readonly IdentityRow[];
  sort: string;
  onSortChange: (sort: string) => void;
}

/**
 * Identity table (SPEC §14). Sorting and pagination are server-side: TanStack
 * owns the column model, the API owns the rows. Row click opens the drill-down.
 */
export function IdentityTable({ rows, sort, onSortChange }: IdentityTableProps) {
  const navigate = useNavigate();
  const sorting = parseSort(sort);

  const table = useReactTable<IdentityRow>({
    data: rows as IdentityRow[],
    columns: identityColumns,
    state: { sorting },
    manualSorting: true,
    manualFiltering: true,
    manualPagination: true,
    getCoreRowModel: getCoreRowModel(),
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      onSortChange(formatSort(next, sort));
    },
  });

  return (
    <TableWrap>
      <Table>
        <THead>
          {table.getHeaderGroups().map((group) => (
            <tr key={group.id}>
              {group.headers.map((header) => {
                const sortable = SORTABLE_COLUMNS.has(header.column.id);
                const dir = header.column.getIsSorted();
                return (
                  <Th
                    key={header.id}
                    numeric={NUMERIC_COLUMNS.has(header.column.id)}
                    sortDir={dir === false ? null : dir}
                    onSort={sortable ? () => header.column.toggleSorting(dir !== "desc") : undefined}
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </Th>
                );
              })}
            </tr>
          ))}
        </THead>
        <TBody>
          {table.getRowModel().rows.map((row) => (
            <Tr
              key={row.id}
              clickable
              tabIndex={0}
              onClick={() => navigate(`/identities/${encodeURIComponent(row.original.identity_id)}`)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  navigate(`/identities/${encodeURIComponent(row.original.identity_id)}`);
                }
              }}
            >
              {row.getVisibleCells().map((cell) => (
                <Td key={cell.id} numeric={NUMERIC_COLUMNS.has(cell.column.id)}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </Td>
              ))}
            </Tr>
          ))}
        </TBody>
      </Table>
    </TableWrap>
  );
}
