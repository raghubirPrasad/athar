import type { Altitude } from "../../api/types";
import { ALTITUDE_GLYPH, ALTITUDE_HINT, ALTITUDE_LABEL, ALTITUDES } from "../../lib/altitude";
import { Toggle, type ToggleOption } from "../ui/Toggle";

const OPTIONS: readonly ToggleOption<Altitude>[] = ALTITUDES.map((altitude) => ({
  value: altitude,
  label: ALTITUDE_LABEL[altitude],
  icon: ALTITUDE_GLYPH[altitude],
  hint: ALTITUDE_HINT[altitude],
}));

export interface AltitudeToggleProps {
  value: Altitude;
  onChange: (value: Altitude) => void;
  size?: "sm" | "md";
  className?: string;
}

/**
 * The altitude switch (SPEC §10.2). One control changes who the page is written
 * for; the facts underneath never change.
 */
export function AltitudeToggle({ value, onChange, size = "md", className }: AltitudeToggleProps) {
  return (
    <Toggle label="Altitude" value={value} options={OPTIONS} onChange={onChange} size={size} className={className} />
  );
}
