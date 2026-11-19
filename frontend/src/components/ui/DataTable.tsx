import { useMemo, useState, type ReactNode } from "react";
import { SkewButton } from "./controls";
import { CodeValue } from "./display";
import { EmptyState, ErrorState, Skeleton } from "./feedback";

export interface Column<T> {
  key: string;
  header: string;
  /** Cell content; defaults to String(row[key]). */
  render?: (row: T) => ReactNode;
  /** Value used for sorting; omit to make the column unsortable. */
  sort?: (row: T) => string | number | null | undefined;
  align?: "left" | "right";
  /** Render as a mono value with a copy button (IPs, JA3/JA4, hashes). */
  code?: (row: T) => string | null | undefined;
  width?: number | string;
}

type SortState = { key: string; dir: "asc" | "desc" } | null;

export interface DataTableProps<T> {
  caption: string;
  columns: Column<T>[];
  rows: T[] | null;
  rowKey: (row: T) => string | number;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  empty?: { title: string; body?: ReactNode; action?: ReactNode };
  onRowClick?: (row: T) => void;
  selectedKey?: string | number | null;
  /** Client-side page size (ignored when `virtual`). */
  pageSize?: number;
  /** Window long lists instead of paginating: only visible rows are in the DOM. */
  virtual?: boolean;
  /** Max height of the scroll container (px). */
  maxHeight?: number;
  initialSort?: SortState;
}

const ROW_H = 38;
const OVERSCAN = 8;

export function compareValues(a: unknown, b: unknown): number {
  if (a === b) return 0;
  if (a === null || a === undefined) return 1; // blanks last
  if (b === null || b === undefined) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  loading,
  error,
  onRetry,
  empty = { title: "Nothing here yet" },
  onRowClick,
  selectedKey,
  pageSize = 25,
  virtual = false,
  maxHeight = 520,
  initialSort = null,
}: DataTableProps<T>) {
  const [sort, setSort] = useState<SortState>(initialSort);
  const [page, setPage] = useState(0);
  const [scrollTop, setScrollTop] = useState(0);

  const sorted = useMemo(() => {
    if (!rows) return [];
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sort) return rows;
    const get = col.sort;
    const out = [...rows].sort((a, b) => compareValues(get(a), get(b)));
    return sort.dir === "desc" ? out.reverse() : out;
  }, [rows, sort, columns]);

  if (error) return <ErrorState title={`Could not load ${caption.toLowerCase()}`} detail={error} onRetry={onRetry} />;
  if (loading && !rows) {
    return (
      <div className="sx-table-wrap" role="status" style={{ padding: 16 }}>
        <span className="sx-visually-hidden">Loading {caption}…</span>
        <Skeleton lines={6} height={18} />
      </div>
    );
  }
  if (sorted.length === 0) return <EmptyState title={empty.title} action={empty.action}>{empty.body}</EmptyState>;

  const pages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const current = Math.min(page, pages - 1);

  let visible: T[];
  let padTop = 0;
  let padBottom = 0;
  if (virtual) {
    const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
    const count = Math.ceil(maxHeight / ROW_H) + OVERSCAN * 2;
    visible = sorted.slice(first, first + count);
    padTop = first * ROW_H;
    padBottom = Math.max(0, (sorted.length - first - visible.length) * ROW_H);
  } else {
    visible = sorted.slice(current * pageSize, current * pageSize + pageSize);
  }

  const toggleSort = (key: string) => {
    setPage(0);
    setSort((s) => (s?.key !== key ? { key, dir: "asc" } : s.dir === "asc" ? { key, dir: "desc" } : null));
  };

  return (
    <div className="sx-table-root">
      <div
        className="sx-table-wrap"
        style={{ maxHeight }}
        onScroll={virtual ? (e) => setScrollTop(e.currentTarget.scrollTop) : undefined}
        tabIndex={0}
        role="region"
        aria-label={`${caption} (scrollable)`}
      >
        <table className="sx-table" aria-rowcount={virtual ? sorted.length + 1 : undefined}>
          <caption className="sx-visually-hidden">{caption}</caption>
          <thead>
            <tr>
              {columns.map((c) => {
                const active = sort?.key === c.key;
                return (
                  <th
                    key={c.key}
                    scope="col"
                    data-align={c.align}
                    style={{ width: c.width }}
                    aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : c.sort ? "none" : undefined}
                  >
                    {c.sort ? (
                      <button type="button" className="sx-sort" onClick={() => toggleSort(c.key)}>
                        {c.header}
                        <span aria-hidden style={{ opacity: active ? 1 : 0.35 }}>
                          {active && sort!.dir === "desc" ? "▼" : "▲"}
                        </span>
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {padTop > 0 ? (
              <tr aria-hidden style={{ height: padTop }}>
                <td colSpan={columns.length} style={{ padding: 0, border: 0 }} />
              </tr>
            ) : null}
            {visible.map((row) => {
              const k = rowKey(row);
              return (
                <tr
                  key={k}
                  data-clickable={onRowClick ? true : undefined}
                  aria-selected={selectedKey !== undefined ? selectedKey === k : undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            onRowClick(row);
                          }
                        }
                      : undefined
                  }
                >
                  {columns.map((c) => {
                    const code = c.code?.(row);
                    return (
                      <td key={c.key} data-align={c.align} className={c.align === "right" ? "sx-mono" : undefined}>
                        {c.code ? (
                          code ? <CodeValue value={code} label={c.header} /> : <span style={{ color: "var(--text-3)" }}>—</span>
                        ) : c.render ? (
                          c.render(row)
                        ) : (
                          String((row as Record<string, unknown>)[c.key] ?? "—")
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
            {padBottom > 0 ? (
              <tr aria-hidden style={{ height: padBottom }}>
                <td colSpan={columns.length} style={{ padding: 0, border: 0 }} />
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      <div className="sx-table-foot">
        <span>
          {sorted.length.toLocaleString()} row{sorted.length === 1 ? "" : "s"}
          {loading ? " · refreshing…" : ""}
        </span>
        {!virtual && pages > 1 ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <SkewButton variant="ghost" size="sm" disabled={current === 0} onClick={() => setPage(current - 1)}>
              Previous
            </SkewButton>
            <span className="sx-mono" aria-live="polite">
              {current + 1} / {pages}
            </span>
            <SkewButton variant="ghost" size="sm" disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>
              Next
            </SkewButton>
          </span>
        ) : null}
      </div>
    </div>
  );
}
