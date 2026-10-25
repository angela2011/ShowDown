// Decorative, code-native radar for the hero. Hosts and positions are sample
// data only; the figure carries an explicit "illustrative" label.
const CENTER = 200;
const RINGS = [48, 92, 136, 180];

// angle (deg), distance from centre, severity tone. Closer to the centre = more urgent.
const NODES = [
  { a: -38, d: 70, tone: "high", size: 8 },
  { a: 196, d: 114, tone: "medium", size: 6.5 },
  { a: 74, d: 120, tone: "medium", size: 6 },
  { a: 146, d: 156, tone: "low", size: 6 },
  { a: 18, d: 152, tone: "low", size: 5.5 },
  { a: 252, d: 174, tone: "clean", size: 5.5 },
  { a: -96, d: 164, tone: "low", size: 5.5 },
  { a: 322, d: 176, tone: "clean", size: 5 },
];

const point = ({ a, d }) => {
  const rad = (a * Math.PI) / 180;
  return { x: CENTER + d * Math.cos(rad), y: CENTER + d * Math.sin(rad) };
};

const LEGEND = [
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["clean", "No findings"],
];

export default function RadarPreview() {
  return (
    <div
      className="lp-radar-figure"
      role="img"
      aria-label="Illustrative radar showing sample hosts placed by severity, with the most urgent closest to the centre"
    >
      <div className="lp-radar">
        <div className="lp-sweep" />
        <svg viewBox="0 0 400 400" focusable="false">
          {RINGS.map((r, i) => (
            <circle key={r} className="lp-ring" style={{ "--i": i }} cx={CENTER} cy={CENTER} r={r} />
          ))}
          <line className="lp-axis" x1={CENTER} y1="14" x2={CENTER} y2="386" />
          <line className="lp-axis" x1="14" y1={CENTER} x2="386" y2={CENTER} />
          <circle className="lp-core-halo" cx={CENTER} cy={CENTER} r="15" />
          <circle className="lp-core" cx={CENTER} cy={CENTER} r="5" />
          {NODES.map((n, i) => {
            const { x, y } = point(n);
            return (
              <g key={i} className={`lp-node lp-node--${n.tone}`} style={{ "--i": i }}>
                {n.tone === "high" && <circle className="lp-node-pulse" cx={x} cy={y} r={n.size} />}
                <circle className="lp-node-dot" cx={x} cy={y} r={n.size} />
              </g>
            );
          })}
        </svg>
      </div>
      <div className="lp-radar-caption">
        <ul className="lp-legend">
          {LEGEND.map(([tone, label]) => (
            <li key={tone}>
              <i className={`lp-dot lp-dot--${tone}`} />
              {label}
            </li>
          ))}
        </ul>
        <span className="lp-caption">Illustrative preview with sample hosts.</span>
      </div>
    </div>
  );
}
