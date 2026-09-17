/**
 * The ATHAR mark — a "trace": a fixed point with two echoing arcs, the ripple a
 * permission leaves behind. Drawn once here; the wordmark composes it with the name.
 */
export function Brandmark({ size = 22, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className={className}
    >
      <circle cx="8" cy="12" r="2.4" fill="currentColor" />
      <path d="M13 6.5a8 8 0 0 1 0 11" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" opacity="0.85" />
      <path d="M16.5 4a12 12 0 0 1 0 16" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" opacity="0.45" />
    </svg>
  );
}

/** Full lockup: mark + wordmark, with the letter-spacing that makes it read as an identity. */
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={className}>
      <span className="flex items-center gap-2">
        <Brandmark size={20} />
        <span className="text-[15px] font-semibold tracking-[0.22em] text-fg">ATHAR</span>
      </span>
    </span>
  );
}
