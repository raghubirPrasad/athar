import type { Cloud } from "../../api/types";

export type { Cloud };

export const CLOUDS: readonly Cloud[] = ["aws", "azure", "gcp"];

export interface Monogram {
  label: string;
  text: string;
  fill: string;
  fg: string;
}

/** Provider monograms — our own marks, not the providers' logos. */
export const MONOGRAM: Record<Cloud, Monogram> = {
  aws: { label: "AWS", text: "aws", fill: "#f59e0b", fg: "#1a1200" },
  azure: { label: "Azure", text: "Az", fill: "#2563eb", fg: "#ffffff" },
  gcp: { label: "GCP", text: "G", fill: "#16a34a", fg: "#ffffff" },
};

export function isCloud(value: unknown): value is Cloud {
  return typeof value === "string" && (CLOUDS as readonly string[]).includes(value);
}

export function cloudLabel(cloud: string): string {
  return isCloud(cloud) ? MONOGRAM[cloud].label : cloud.toUpperCase();
}
