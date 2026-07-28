// Presentational components for the dashboard, grouped in one module for
// simplicity. Each is a pure function of its props.

import React from "react";

// Severity -> color, kept in sync with the Python rubric.
export const SCORE_COLORS = {
  critical: "#b91c1c",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#0891b2",
  pass: "#16a34a",
};

const SCORE_ORDER = ["pass", "low", "medium", "high", "critical"];

// -- Stat tiles for the executive summary -----------------------------------
export function SummaryCards({ summary }) {
  if (!summary) return null;
  const tiles = [
    { label: "Safety Score", value: `${summary.safety_score}/100` },
    { label: "Total Attacks", value: summary.total_attacks },
    { label: "Breaches", value: summary.total_breaches },
    { label: "Critical", value: summary.critical_breaches },
    { label: "Breach Rate", value: `${summary.breach_rate_pct}%` },
  ];
  return (
    <div className="cards">
      {tiles.map((t) => (
        <div className="card" key={t.label}>
          <div className="card-value">{t.value}</div>
          <div className="card-label">{t.label}</div>
        </div>
      ))}
    </div>
  );
}

// -- Heatmap: category (rows) x severity (cols) ------------------------------
export function Heatmap({ report }) {
  if (!report?.per_category) return null;
  const categories = Object.keys(report.per_category);
  // Build a per-category severity count from the prompt inventory.
  const counts = {};
  for (const cat of categories) counts[cat] = { pass: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const p of report.prompt_inventory ?? []) {
    if (counts[p.category]) counts[p.category][p.score] += 1;
  }
  const maxCount = Math.max(
    1,
    ...categories.flatMap((c) => SCORE_ORDER.map((s) => counts[c][s]))
  );

  return (
    <div className="heatmap">
      <h3>Score Heatmap</h3>
      <table>
        <thead>
          <tr>
            <th>Category</th>
            {SCORE_ORDER.map((s) => (
              <th key={s}>{s}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {categories.map((cat) => (
            <tr key={cat}>
              <td className="cat-name">{cat}</td>
              {SCORE_ORDER.map((s) => {
                const n = counts[cat][s];
                // Opacity encodes magnitude; hue encodes severity.
                const alpha = n === 0 ? 0.06 : 0.2 + 0.8 * (n / maxCount);
                return (
                  <td
                    key={s}
                    className="cell"
                    style={{ background: hexWithAlpha(SCORE_COLORS[s], alpha) }}
                    title={`${cat} / ${s}: ${n}`}
                  >
                    {n || ""}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// -- Breach transcript viewer ------------------------------------------------
export function TranscriptViewer({ breaches }) {
  if (!breaches?.length) {
    return <p className="muted">No breaches recorded for this run. 🎉</p>;
  }
  return (
    <div className="transcripts">
      <h3>Breach Transcripts</h3>
      {breaches.map((b, i) => (
        <details key={b.attack_id ?? i} className="transcript">
          <summary>
            <span className="pill" style={{ background: SCORE_COLORS[b.score] }}>
              {b.score}
            </span>
            <span className="cat">{b.category}</span>
            <span className="btype">{b.breach_type}</span>
          </summary>
          <div className="turn user">
            <strong>Adversarial prompt</strong>
            <pre>{b.prompt}</pre>
          </div>
          <div className="turn model">
            <strong>Target response</strong>
            <pre>{b.response}</pre>
          </div>
          <div className="judge">
            <strong>Judge:</strong> {b.reasoning}
          </div>
        </details>
      ))}
    </div>
  );
}

// -- Live attack feed (during a run) -----------------------------------------
export function LiveFeed({ events }) {
  if (!events?.length) return null;
  return (
    <div className="live-feed">
      <h3>Live Attack Feed</h3>
      <ul>
        {events.map((e, i) => (
          <li key={i}>
            <span className="pill" style={{ background: SCORE_COLORS[e.judgement.score] }}>
              {e.judgement.score}
            </span>
            <span className="cat">{e.attack.category}</span>
            <span className="muted">
              variant {e.attack.variant} · round {e.attack.mutation_round}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// Convert a #rrggbb hex + alpha (0..1) to an rgba() string.
function hexWithAlpha(hex, alpha) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha.toFixed(3)})`;
}