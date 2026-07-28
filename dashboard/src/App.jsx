import React, { useEffect, useState } from "react";
import { api } from "./api.js";
import {
  SummaryCards,
  Heatmap,
  TranscriptViewer,
  LiveFeed,
} from "./components.jsx";

// Top-level dashboard: lists past runs, lets you launch a new one (watching a
// live feed), and renders the full report for a selected run.
export default function App() {
  const [runs, setRuns] = useState([]);
  const [selected, setSelected] = useState(null); // run_id
  const [report, setReport] = useState(null);
  const [provider, setProvider] = useState("");
  const [liveEvents, setLiveEvents] = useState([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  // Initial load: health (provider) + past runs.
  useEffect(() => {
    api.health().then((h) => setProvider(h.provider)).catch(() => {});
    refreshRuns();
  }, []);

  function refreshRuns() {
    api.listRuns().then(setRuns).catch((e) => setError(String(e)));
  }

  // Load a run's full report when one is selected.
  useEffect(() => {
    if (!selected) return;
    setReport(null);
    api.getRun(selected).then(setReport).catch((e) => setError(String(e)));
  }, [selected]);

  // Launch a new campaign and stream live results.
  async function handleLaunch() {
    setError("");
    setLiveEvents([]);
    setRunning(true);
    try {
      const { stream_token } = await api.launchRun({});
      api.streamRun(
        stream_token,
        (result) => setLiveEvents((prev) => [result, ...prev].slice(0, 200)),
        (done) => {
          setRunning(false);
          refreshRuns();
          if (done.run_id) setSelected(done.run_id);
        }
      );
    } catch (e) {
      setError(String(e));
      setRunning(false);
    }
  }

  return (
    <div className="app">
      <header>
        <h1>🛡️ Adversarial Red-Team Automation</h1>
        <div className="provider">
          Backend provider: <strong>{provider || "…"}</strong>
          {provider === "mock" && (
            <span className="badge">MOCK (no API key)</span>
          )}
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <div className="layout">
        {/* Sidebar: runs + launch */}
        <aside>
          <button className="launch" disabled={running} onClick={handleLaunch}>
            {running ? "Running…" : "▶ Launch campaign"}
          </button>
          <h3>Past runs</h3>
          <ul className="run-list">
            {runs.map((r) => (
              <li
                key={r.id}
                className={r.id === selected ? "active" : ""}
                onClick={() => setSelected(r.id)}
              >
                <div className="run-target">{r.target_name}</div>
                <div className="muted small">
                  {r.total_breaches}/{r.total_attacks} breaches · {r.provider}
                </div>
              </li>
            ))}
            {runs.length === 0 && <li className="muted">No runs yet.</li>}
          </ul>
        </aside>

        {/* Main panel */}
        <main>
          {running && <LiveFeed events={liveEvents} />}

          {report ? (
            <>
              <SummaryCards summary={report.executive_summary} />
              {report.executive_summary?.narrative && (
                <section className="narrative">
                  <h3>Executive Summary</h3>
                  <p>{report.executive_summary.narrative}</p>
                </section>
              )}
              <Heatmap report={report} />
              <TranscriptViewer breaches={report.breach_examples} />
            </>
          ) : (
            !running && (
              <div className="empty">
                Select a run on the left, or launch a new campaign.
              </div>
            )
          )}
        </main>
      </div>
    </div>
  );
}