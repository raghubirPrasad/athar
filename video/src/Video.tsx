import React from "react";
import { AbsoluteFill, Sequence, interpolate, useCurrentFrame } from "remotion";
import "./fonts";
import { C, MONO, SANS } from "./theme";
import { Brand } from "./components/kit";
import { Callout, Caption, Cursor, Flare, Kinetic, Screen, Shot, ease } from "./components/tour";

/* ------------------------------------------------------------- backdrop */
const Backdrop: React.FC = () => {
  const frame = useCurrentFrame();
  const d = Math.sin(frame / 150) * 12;
  return (
    <AbsoluteFill
      style={{
        background: `radial-gradient(1500px 780px at ${80 + d / 10}% -10%, rgba(39,198,223,.13), transparent 60%),
                     radial-gradient(1200px 780px at -6% 112%, rgba(11,124,147,.18), transparent 55%), ${C.bg}`,
      }}
    >
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 5,
          background: `linear-gradient(90deg,${C.cyanDeep},#1596b0 45%,${C.cyan})`,
        }}
      />
      <AbsoluteFill
        style={{
          backgroundImage:
            "linear-gradient(rgba(255,255,255,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.02) 1px,transparent 1px)",
          backgroundSize: "72px 72px",
          maskImage: "radial-gradient(circle at 50% 40%, black, transparent 82%)",
        }}
      />
    </AbsoluteFill>
  );
};

/* ------------------------------------------------------------- open */
const Open: React.FC = () => {
  const frame = useCurrentFrame();
  const draw = ease(frame, 2, 28);
  const ring = ease(frame, 6, 46);
  const ring2 = ease(frame, 16, 58);
  const lift = ease(frame, 16, 40);
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", fontFamily: SANS }}>
      <div style={{ position: "relative" }}>
        {[ring, ring2].map((r, i) => (
          <div
            key={i}
            style={{
              position: "absolute",
              left: "50%",
              top: "50%",
              width: 320,
              height: 320,
              marginLeft: -160,
              marginTop: -160,
              borderRadius: 999,
              border: `1px solid rgba(39,198,223,${0.4 - i * 0.12})`,
              transform: `scale(${0.35 + r * (1.2 + i * 0.5)})`,
              opacity: (1 - r) * 0.9,
            }}
          />
        ))}
        <svg
          width="96"
          height="96"
          viewBox="0 0 24 24"
          fill="none"
          style={{ transform: `scale(${0.85 + draw * 0.15})`, filter: "drop-shadow(0 0 26px rgba(39,198,223,.55))" }}
        >
          <circle cx="8" cy="12" r="2.4" fill={C.cyan} />
          <path d="M13 6.5a8 8 0 0 1 0 11" stroke={C.cyan} strokeWidth="1.6" strokeLinecap="round" opacity={0.9 * draw} />
          <path d="M16.5 4a12 12 0 0 1 0 16" stroke={C.cyan} strokeWidth="1.6" strokeLinecap="round" opacity={0.5 * draw} />
        </svg>
      </div>
      <div style={{ textAlign: "center", marginTop: 30 }}>
        <div
          style={{
            fontSize: 52,
            fontWeight: 300,
            letterSpacing: `${interpolate(lift, [0, 1], [0.55, 0.36])}em`,
            color: C.fg,
            opacity: lift,
            textIndent: "0.36em",
          }}
        >
          ATHAR
        </div>
        <div style={{ marginTop: 20, display: "flex", justifyContent: "center" }}>
          <Kinetic text="Multi-cloud access governance." at={34} size={26} weight={300} color={C.muted} />
        </div>
      </div>
      <Flare at={22} len={52} y={46} power={0.85} />
    </AbsoluteFill>
  );
};

/* ------------------------------------------------------------- MCP terminal */
const Mcp: React.FC = () => {
  const frame = useCurrentFrame();
  const ent = ease(frame, 0, 34);
  const rows: [React.ReactNode, number][] = [
    [<span><span style={{ color: C.cyan }}>$</span> athar-mcp <span style={{ color: C.faint }}>▸ analyst</span></span>, 10],
    [<span><span style={{ color: C.ok }}>→</span> list_identities <span style={{ color: C.faint }}>· 507 identities</span></span>, 24],
    [<span><span style={{ color: C.ok }}>→</span> explain_finding <span style={{ color: C.faint }}>· R4 · proof-bound</span></span>, 36],
    [<span><span style={{ color: C.ok }}>→</span> propose_remediation <span style={{ color: C.cyan }}>−12.8%</span> <span style={{ color: C.ok }}>[ok]</span></span>, 48],
    [<span>&nbsp;</span>, 60],
    [<span><span style={{ color: C.cyan }}>$</span> athar-mcp <span style={{ color: C.faint }}>▸ viewer</span></span>, 68],
    [<span><span style={{ color: C.ok }}>→</span> list_identities <span style={{ color: C.faint }}>· ok</span></span>, 80],
    [<span><span style={{ color: C.crit }}>→</span> propose_remediation</span>, 92],
    [<span style={{ color: C.crit }}>&nbsp;&nbsp;&nbsp;✕ 403 · requires role analyst</span>, 102],
  ];
  const flash = ease(frame, 102, 116);
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", fontFamily: SANS, perspective: 2300 }}>
      <div
        style={{
          width: 1260,
          borderRadius: 22,
          overflow: "hidden",
          border: `1px solid ${flash > 0 ? `rgba(255,106,94,${0.25 + flash * 0.4})` : C.border2}`,
          background: "#0a0f14",
          boxShadow: `0 60px 140px rgba(0,0,0,.66), inset 0 1px 0 rgba(255,255,255,.08)${
            flash > 0 ? `, 0 0 70px rgba(255,106,94,${flash * 0.26})` : ""
          }`,
          opacity: ent,
          transform: `translateY(${(1 - ent) * 220}px) rotateX(${
            interpolate(ent, [0, 1], [13, 0]) + Math.sin(frame / 105) * 0.6
          }deg) scale(${interpolate(ent, [0, 1], [0.94, 1])})`,
          transformStyle: "preserve-3d",
        }}
      >
        <div style={{ height: 40, background: "#0f1720", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 9, padding: "0 18px" }}>
          {[0, 1, 2].map((i) => (
            <span key={i} style={{ width: 11, height: 11, borderRadius: 999, background: "#2a3a48" }} />
          ))}
          <span style={{ marginLeft: 16, font: `400 14px/1 ${MONO}`, color: C.faint }}>
            ATHAR-MCP · model context protocol
          </span>
        </div>
        <div style={{ padding: "34px 44px", font: `400 27px/1.85 ${MONO}`, color: C.fg }}>
          {rows.map(([node, at], i) => {
            const p = ease(frame, at, at + 10);
            return (
              <div key={i} style={{ opacity: p, transform: `translateX(${(1 - p) * 14}px)` }}>
                {node}
              </div>
            );
          })}
        </div>
      </div>
      <Flare at={104} len={40} y={52} power={0.5} />
    </AbsoluteFill>
  );
};

/* ------------------------------------------------------------- close */
const Close: React.FC = () => {
  const frame = useCurrentFrame();
  const r = ease(frame, 4, 26);
  const askP = ease(frame, 46, 66);
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", fontFamily: SANS, textAlign: "center" }}>
      <div style={{ opacity: r, transform: `translateY(${(1 - r) * 16}px)` }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 22, filter: "drop-shadow(0 0 22px rgba(39,198,223,.5))" }}>
          <Brand size={62} />
        </div>
        <div style={{ fontSize: 48, fontWeight: 300, letterSpacing: "0.36em", color: C.fg, textIndent: "0.36em" }}>
          ATHAR
        </div>
      </div>
      <div style={{ marginTop: 24 }}>
        <Kinetic text="Every permission leaves a trace." at={20} size={28} weight={300} color={C.muted} />
      </div>
      <div
        style={{
          marginTop: 44,
          opacity: askP,
          transform: `translateY(${(1 - askP) * 18}px)`,
          border: `1px solid rgba(39,198,223,.4)`,
          background: C.cyanSoft,
          borderRadius: 16,
          padding: "20px 34px",
          fontSize: 27,
          fontWeight: 300,
          color: C.fg,
        }}
      >
        Give us the exports — ATHAR gives you the record.
      </div>
      <Flare at={12} len={54} y={44} power={0.75} />
    </AbsoluteFill>
  );
};

/* ------------------------------------------------------------- beats */
const D = {
  open: 96,
  ovWide: 152,
  ovStats: 150,
  ovNever: 142,
  idWide: 168,
  idScore: 152,
  idCloud: 122,
  drHero: 144,
  drFormula: 192,
  drCausal: 150,
  tlWide: 162,
  tlHalf: 132,
  reWide: 142,
  reStats: 176,
  reRules: 132,
  ledger: 142,
  mcp: 238,
  close: 140,
};
/** Beats overlap so every cut is a dissolve, never a flash. */
const LAP = 11;
export const DURATION = Object.values(D).reduce((a, b) => a + b, 0) - LAP * 17;

export const AtharVideo: React.FC = () => {
  let t = 0;
  const seq = (d: number) => {
    const from = t;
    t += d - LAP;
    return from;
  };

  return (
    <AbsoluteFill>
      <Backdrop />

      {/* 1 · open */}
      <Sequence from={seq(D.open)} durationInFrames={D.open}>
        <Shot><Open /></Shot>
      </Sequence>

      {/* 2 · overview — the screen rises in */}
      <Sequence from={seq(D.ovWide)} durationInFrames={D.ovWide}>
        <Shot>
          <Screen src="shots/overview.png" from={{ x: 50, y: 12, z: 1.0 }} to={{ x: 50, y: 20, z: 1.06 }} rise={360} tilt={17} sweep={34} />
          <Cursor path={[[52, 96], [46, 62], [44, 58]]} at={40} step={20} hideAt={132} />
          <Caption kicker="Overview" text="One estate. Three clouds." accent={["Three"]} />
          <Flare at={6} len={46} y={54} power={0.7} />
        </Shot>
      </Sequence>

      {/* 3 · stat tiles */}
      <Sequence from={seq(D.ovStats)} durationInFrames={D.ovStats}>
        <Shot>
          <Screen
            src="shots/overview.png"
            from={{ x: 35, y: 24, z: 1.06 }}
            to={{ x: 35, y: 24, z: 1.4 }}
            move={[0, 46]}
            ring={{ at: 42, w: 42, h: 12 }}
            rise={120}
            tilt={6}
          />
          <Cursor path={[[38, 66], [30, 34]]} at={16} step={22} clickAt={[44]} hideAt={124} />
          <Caption text="507 identities, one model." accent={["507"]} at={26} />
        </Shot>
      </Sequence>

      {/* 4 · half-life */}
      <Sequence from={seq(D.ovNever)} durationInFrames={D.ovNever}>
        <Shot>
          <Screen src="shots/overview.png" from={{ x: 30, y: 56, z: 1.18 }} to={{ x: 30, y: 60, z: 1.4 }} move={[0, 46]} rise={110} tilt={5} />
          <Cursor path={[[60, 40], [33, 61]]} at={12} step={24} clickAt={[40]} hideAt={118} />
          <Callout label="offboarding · Never" x={35} y={61} dir="right" at={40} len={150} />
          <Caption text="Granted — and never taken away." accent={["never"]} at={16} />
        </Shot>
      </Sequence>

      {/* 5 · identities */}
      <Sequence from={seq(D.idWide)} durationInFrames={D.idWide}>
        <Shot>
          <Screen src="shots/identities.png" from={{ x: 50, y: 14, z: 1.0 }} to={{ x: 50, y: 26, z: 1.1 }} rise={330} tilt={16} sweep={30} />
          <Cursor path={[[80, 88], [58, 48], [55, 42], [55, 42]]} at={26} step={20} clickAt={[86]} />
          <Caption kicker="Identities" text="Every identity, ranked by risk." accent={["ranked"]} />
          <Flare at={4} len={44} y={50} power={0.7} />
        </Shot>
      </Sequence>

      {/* 6 · score column */}
      <Sequence from={seq(D.idScore)} durationInFrames={D.idScore}>
        <Shot>
          <Screen
            src="shots/identities.png"
            from={{ x: 54, y: 45, z: 1.15 }}
            to={{ x: 54, y: 45, z: 1.46 }}
            move={[0, 46]}
            ring={{ at: 42, w: 17, h: 26 }}
            rise={110}
            tilt={5}
          />
          <Cursor path={[[40, 70], [55, 50]]} at={14} step={22} hideAt={126} />
          <Caption text="Measured blast radius — not a hand-picked number." accent={["Measured"]} at={22} size={30} pos="br" />
        </Shot>
      </Sequence>

      {/* 7 · cross-cloud */}
      <Sequence from={seq(D.idCloud)} durationInFrames={D.idCloud}>
        <Shot>
          <Screen src="shots/identities.png" from={{ x: 46, y: 45, z: 1.5 }} to={{ x: 46, y: 45, z: 1.72 }} move={[0, 40]} ring={{ at: 34, w: 9, h: 22 }} rise={90} tilt={4} />
          <Caption text="Admin in AWS, Azure and GCP at once." accent={["AWS,", "Azure", "GCP"]} at={14} />
        </Shot>
      </Sequence>

      {/* 8 · drill-down */}
      <Sequence from={seq(D.drHero)} durationInFrames={D.drHero}>
        <Shot>
          <Screen src="shots/identity-detail.png" from={{ x: 40, y: 16, z: 1.02 }} to={{ x: 36, y: 26, z: 1.35 }} rise={340} tilt={16} sweep={28} />
          <Cursor path={[[24, 78], [20, 30]]} at={22} step={22} hideAt={110} />
          <Caption kicker="Why a 100" text="Open it — the score is in the open." accent={["open."]} />
          <Flare at={4} len={46} y={48} power={0.8} />
        </Shot>
      </Sequence>

      {/* 9 · the formula */}
      <Sequence from={seq(D.drFormula)} durationInFrames={D.drFormula}>
        <Shot>
          <Screen
            src="shots/identity-detail.png"
            from={{ x: 42, y: 68, z: 1.3 }}
            to={{ x: 42, y: 70, z: 1.55 }}
            move={[0, 50]}
            ring={{ at: 46, w: 44, h: 11 }}
            rise={110}
            tilt={5}
          />
          <Cursor path={[[70, 40], [40, 80]]} at={16} step={26} hideAt={120} />
          <Callout label="reach × exploitability × controls" x={54} y={72} dir="right" at={58} len={130} out={D.drFormula - 14} />
          <Caption text="You can read the formula, term by term." accent={["formula,"]} at={20} />
        </Shot>
      </Sequence>

      {/* 10 · causal history */}
      <Sequence from={seq(D.drCausal)} durationInFrames={D.drCausal}>
        <Shot>
          <Screen src="shots/identity-detail.png" from={{ x: 80, y: 60, z: 1.3 }} to={{ x: 80, y: 70, z: 1.44 }} move={[0, 46]} rise={100} tilt={5} />
          <Cursor path={[[45, 45], [78, 70]]} at={12} step={24} hideAt={124} />
          <Caption text="And the exact grants that caused it." accent={["grants"]} at={14} />
        </Shot>
      </Sequence>

      {/* 11 · timeline */}
      <Sequence from={seq(D.tlWide)} durationInFrames={D.tlWide}>
        <Shot>
          <Screen src="shots/timeline.png" from={{ x: 50, y: 20, z: 1.0 }} to={{ x: 50, y: 40, z: 1.22 }} rise={340} tilt={16} sweep={30} />
          <Cursor path={[[70, 90], [22, 24], [22, 24]]} at={26} step={22} clickAt={[74]} hideAt={140} />
          <Caption kicker="Timeline" text="A year of drift, replayed." accent={["drift,"]} />
          <Flare at={4} len={46} y={52} power={0.7} />
        </Shot>
      </Sequence>

      {/* 12 · half-life curve */}
      <Sequence from={seq(D.tlHalf)} durationInFrames={D.tlHalf}>
        <Shot>
          <Screen src="shots/timeline.png" from={{ x: 50, y: 60, z: 1.3 }} to={{ x: 50, y: 66, z: 1.36 }} move={[0, 44]} rise={90} tilt={4} />
          <Caption text="Permission half-life: a broken process, not risky people." accent={["half-life:"]} at={14} size={30} />
        </Shot>
      </Sequence>

      {/* 13 · real export */}
      <Sequence from={seq(D.reWide)} durationInFrames={D.reWide}>
        <Shot>
          <Screen src="shots/realexport.png" from={{ x: 50, y: 14, z: 1.0 }} to={{ x: 50, y: 24, z: 1.14 }} rise={350} tilt={17} sweep={30} />
          <Cursor path={[[75, 90], [30, 34]]} at={24} step={22} hideAt={116} />
          <Caption kicker="Real export" text="Same engine. A real AWS export." accent={["real"]} />
          <Flare at={4} len={48} y={50} power={0.85} />
        </Shot>
      </Sequence>

      {/* 14 · real numbers */}
      <Sequence from={seq(D.reStats)} durationInFrames={D.reStats}>
        <Shot>
          <Screen
            src="shots/realexport.png"
            from={{ x: 50, y: 30, z: 1.2 }}
            to={{ x: 62, y: 30, z: 1.44 }}
            move={[0, 52]}
            ring={{ at: 56, w: 26, h: 16 }}
            rise={110}
            tilt={5}
          />
          <Cursor path={[[35, 70], [66, 34]]} at={16} step={26} hideAt={150} />
          <Caption text="318 findings. R7 fires 36 times — zero on synthetic." accent={["318", "36"]} at={30} size={30} pos="br" />
        </Shot>
      </Sequence>

      {/* 15 · rule table */}
      <Sequence from={seq(D.reRules)} durationInFrames={D.reRules}>
        <Shot>
          <Screen src="shots/realexport.png" from={{ x: 50, y: 58, z: 1.25 }} to={{ x: 50, y: 62, z: 1.34 }} move={[0, 42]} rise={90} tilt={4} />
          <Caption text="Landing on genuinely admin and privesc roles." accent={["privesc"]} at={14} size={30} />
        </Shot>
      </Sequence>

      {/* 16 · ledger */}
      <Sequence from={seq(D.ledger)} durationInFrames={D.ledger}>
        <Shot>
          <Screen src="shots/ledger.png" from={{ x: 50, y: 22, z: 1.04 }} to={{ x: 50, y: 38, z: 1.35 }} rise={330} tilt={16} sweep={28} />
          <Cursor path={[[68, 86], [40, 46], [40, 46]]} at={24} step={22} clickAt={[74]} hideAt={132} />
          <Caption kicker="Ledger" text="Anchored on-chain. Verify it yourself." accent={["Verify"]} />
          <Flare at={4} len={46} y={50} power={0.75} />
        </Shot>
      </Sequence>

      {/* 17 · MCP */}
      <Sequence from={seq(D.mcp)} durationInFrames={D.mcp}>
        <Shot>
          <Mcp />
          <Caption kicker="ATHAR-MCP" text="Any AI can query it. None of them can decide." accent={["None"]} at={120} out={D.mcp - 12} size={31} />
        </Shot>
      </Sequence>

      {/* 18 · close */}
      <Sequence from={seq(D.close)} durationInFrames={D.close}>
        <Shot><Close /></Shot>
      </Sequence>
    </AbsoluteFill>
  );
};
