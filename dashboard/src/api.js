// Thin client for the FastAPI backend. All requests go through the Vite proxy
// (/api -> http://localhost:8000) during development.

const BASE = "/api";

async function getJSON(path) {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  health: () => getJSON("/health"),
  categories: () => getJSON("/categories"),
  listRuns: () => getJSON("/runs"),
  getRun: (id) => getJSON(`/runs/${id}`),

  // Launch a campaign; returns { stream_token }.
  launchRun: async (body) => {
    const res = await fetch(`${BASE}/runs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    if (!res.ok) throw new Error(`launch failed: ${res.status}`);
    return res.json();
  },

  // Subscribe to the SSE live feed for a launched campaign.
  // `onResult(result)` fires per attack; `onDone(payload)` fires once at end.
  streamRun: (token, onResult, onDone) => {
    const source = new EventSource(`${BASE}/stream/${token}`);
    source.onmessage = (ev) => {
      const data = JSON.parse(ev.data);
      if (data.event === "done") {
        onDone?.(data);
        source.close();
      } else {
        onResult?.(data);
      }
    };
    source.onerror = () => source.close();
    return source;
  },
};