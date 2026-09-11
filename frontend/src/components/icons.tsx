import type { SVGProps } from "react";

/**
 * Inline 16px stroke icons — no icon package, no network fetch. Icons are always
 * decorative here: every nav item and badge carries its own text label.
 */
type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Icon({ size = 16, children, ...rest }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconOverview = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="3" width="7" height="8" rx="1" />
    <rect x="14" y="3" width="7" height="5" rx="1" />
    <rect x="14" y="11" width="7" height="10" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
  </Icon>
);

export const IconIdentities = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="9" cy="8" r="3.2" />
    <path d="M3.5 20a5.5 5.5 0 0 1 11 0" />
    <path d="M16 5.5a3 3 0 0 1 0 5.6M17.5 14.2A5.5 5.5 0 0 1 20.5 19" />
  </Icon>
);

export const IconFindings = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3.5 21 19.5H3L12 3.5Z" />
    <path d="M12 9.5v4" />
    <path d="M12 16.6h.01" />
  </Icon>
);

export const IconRemediation = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14.5 4.5a4.5 4.5 0 0 0-5.6 5.6L4 15l5 5 4.9-4.9a4.5 4.5 0 0 0 5.6-5.6l-3 3-2.6-2.6 3-3Z" />
  </Icon>
);

export const IconLedger = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3" y="4" width="7" height="6" rx="1" />
    <rect x="14" y="14" width="7" height="6" rx="1" />
    <path d="M10 7h4a3 3 0 0 1 3 3v4" />
  </Icon>
);

export const IconTimeline = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3 12h4l3-7 4 14 3-7h4" />
  </Icon>
);

export const IconEvaluation = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <circle cx="12" cy="12" r="4" />
    <circle cx="12" cy="12" r="0.8" fill="currentColor" />
  </Icon>
);

export const IconSettings = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 7h10M18 7h2M4 17h4M12 17h8" />
    <circle cx="16" cy="7" r="2" />
    <circle cx="10" cy="17" r="2" />
  </Icon>
);

export const IconMenu = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 6h16M4 12h16M4 18h16" />
  </Icon>
);

export const IconLogout = (p: IconProps) => (
  <Icon {...p}>
    <path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" />
    <path d="M10 8 6 12l4 4M6 12h9" />
  </Icon>
);

export const IconScan = (p: IconProps) => (
  <Icon {...p}>
    <path d="M20 12a8 8 0 1 1-2.6-5.9" />
    <path d="M20 4v4h-4" />
  </Icon>
);

export const IconAdvance = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 5l8 7-8 7z" />
    <path d="M18 5v14" />
  </Icon>
);

export const IconCalendar = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3.5" y="5" width="17" height="15" rx="2" />
    <path d="M3.5 10h17M8 3.5v3M16 3.5v3" />
  </Icon>
);

export const IconChevron = (p: IconProps) => (
  <Icon {...p}>
    <path d="m8 10 4 4 4-4" />
  </Icon>
);
