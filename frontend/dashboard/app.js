const { useEffect, useMemo, useState } = React;

const API_BASE_URL = window.location.port === "8000"
  ? "http://localhost:8080/api"
  : `${window.location.origin}/api`;

const analysisPresets = [
  {
    name: "Basic Analysis",
    description: "Run without blocking rules using the default 2 x 2 thread layout.",
    request: { blockApps: [], blockIps: [], blockDomains: [], lbs: 2, fps: 2 },
  },
  {
    name: "Block YouTube",
    description: "Block YouTube traffic and refresh the report.",
    request: { blockApps: ["YouTube"], blockIps: [], blockDomains: [], lbs: 2, fps: 2 },
  },
  {
    name: "Block YouTube + TikTok",
    description: "Apply two app blocking rules for a stronger filtering demo.",
    request: { blockApps: ["YouTube", "TikTok"], blockIps: [], blockDomains: [], lbs: 2, fps: 2 },
  },
  {
    name: "Strict Security Mode",
    description: "Block apps, a sample IP, and a domain in one run.",
    request: {
      blockApps: ["YouTube", "TikTok"],
      blockIps: ["192.168.1.50"],
      blockDomains: ["facebook"],
      lbs: 2,
      fps: 2,
    },
  },
  {
    name: "High Throughput Mode",
    description: "Increase load balancers and fast-path workers to show scaling knobs.",
    request: { blockApps: ["YouTube"], blockIps: [], blockDomains: [], lbs: 4, fps: 4 },
  },
];

const sampleReport = {
  project: "DPI Engine",
  version: "1.0",
  input_file: "test_dpi.pcap",
  output_file: "output.pcap",
  configuration: {
    load_balancers: 2,
    fast_paths_per_load_balancer: 2,
    total_fast_path_threads: 4,
  },
  packet_statistics: {
    total_packets: 77,
    total_bytes: 5738,
    tcp_packets: 73,
    udp_packets: 4,
    other_packets: 0,
  },
  filtering_statistics: {
    forwarded_packets: 76,
    dropped_packets: 1,
    drop_rate_percent: 1.3,
  },
  thread_statistics: {
    load_balancer_received: 77,
    load_balancer_dispatched: 77,
    fast_path_processed: 77,
    fast_path_forwarded: 76,
    fast_path_dropped: 1,
    active_connections: 43,
  },
  classification: {
    total_connections: 43,
    classified_connections: 22,
    unidentified_connections: 21,
    app_distribution: [
      { app: "Unknown", count: 21, percentage: 48.8 },
      { app: "DNS", count: 4, percentage: 9.3 },
      { app: "Twitter/X", count: 3, percentage: 7.0 },
      { app: "HTTPS", count: 2, percentage: 4.7 },
      { app: "YouTube", count: 1, percentage: 2.3 },
    ],
  },
  blocking_rules: {
    counts: {
      blocked_ips: 1,
      blocked_apps: 2,
      blocked_domains: 1,
      blocked_ports: 0,
    },
    ips: ["192.168.1.50"],
    apps: ["YouTube", "TikTok"],
    domains: ["facebook"],
    ports: [],
  },
};

function formatNumber(value) {
  return new Intl.NumberFormat().format(value ?? 0);
}

function formatPercent(value) {
  return `${Number(value ?? 0).toFixed(2)}%`;
}

function StatCard({ title, value, sub }) {
  return React.createElement(
    "article",
    { className: "card" },
    React.createElement("div", { className: "stat-title" }, title),
    React.createElement("div", { className: "stat-value" }, value),
    sub ? React.createElement("div", { className: "stat-sub" }, sub) : null
  );
}

function MiniList({ items }) {
  return React.createElement(
    "ul",
    { className: "mini-list" },
    items.map(([label, value]) =>
      React.createElement(
        "li",
        { key: label },
        React.createElement("span", null, label),
        React.createElement("strong", null, value)
      )
    )
  );
}

function Chips({ values }) {
  if (!values || values.length === 0) {
    return React.createElement("p", { className: "empty" }, "No rules configured");
  }

  return React.createElement(
    "div",
    { className: "chips" },
    values.map((value) => React.createElement("span", { className: "chip", key: value }, value))
  );
}

function joinOrNone(values) {
  return values && values.length > 0 ? values.join(", ") : "None";
}

function PresetButton({ preset, isRunning, isActive, onRun }) {
  return React.createElement(
    "button",
    {
      className: isActive ? "preset-button active" : "preset-button",
      disabled: isRunning,
      onClick: () => onRun(preset),
      type: "button",
    },
    React.createElement("span", { className: "preset-title" }, preset.name),
    React.createElement("span", { className: "preset-description" }, preset.description)
  );
}

function App() {
  const [report, setReport] = useState(sampleReport);
  const [status, setStatus] = useState("Showing sample data. Generate report.json or upload a JSON report.");
  const [isRunning, setIsRunning] = useState(false);
  const [lastCommand, setLastCommand] = useState([]);
  const [activePreset, setActivePreset] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    fetch("report.json", { cache: "no-store" })
      .then((response) => {
        if (!response.ok) {
          throw new Error("report.json not found");
        }
        return response.json();
      })
      .then((data) => {
        setReport(data);
        setStatus("Loaded report.json from the dashboard folder.");
        setLastUpdated(new Date());
      })
      .catch(() => {
        setStatus("Showing sample data. Upload report.json or serve this folder after generating it.");
      });
  }, []);

  const appDistribution = useMemo(
    () => report.classification?.app_distribution ?? [],
    [report]
  );

  const blockedRuleValues = [
    ...(report.blocking_rules?.apps ?? []).map((value) => `App: ${value}`),
    ...(report.blocking_rules?.ips ?? []).map((value) => `IP: ${value}`),
    ...(report.blocking_rules?.domains ?? []).map((value) => `Domain: ${value}`),
    ...(report.blocking_rules?.ports ?? []).map((value) => `Port: ${value}`),
  ];

  function handleFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result);
        setReport(data);
        setStatus(`Loaded ${file.name}.`);
      } catch (error) {
        setStatus(`Could not parse ${file.name}: ${error.message}`);
      }
    };
    reader.readAsText(file);
  }

  async function runPreset(preset) {
    setActivePreset(preset);
    setIsRunning(true);
    setStatus(`Running ${preset.name} through Spring Boot REST API...`);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(preset.request),
      });

      const payload = await response.json();

      if (!response.ok || !payload.success) {
        const consoleHint = payload.consoleOutput ? ` Console: ${payload.consoleOutput.slice(-260)}` : "";
        throw new Error(`${payload.message || "Analysis failed"}.${consoleHint}`);
      }

      setReport(payload.report);
      setLastCommand(payload.command || []);
      setLastUpdated(new Date());
      setStatus(`${preset.name} completed. Dashboard refreshed from API response.`);
    } catch (error) {
      setStatus(`Could not run analysis: ${error.message}. Make sure Spring Boot is running on port 8080.`);
    } finally {
      setIsRunning(false);
    }
  }

  return React.createElement(
    "main",
    { className: "app" },
    React.createElement(
      "section",
      { className: "hero" },
      React.createElement(
        "div",
        null,
        React.createElement("p", { className: "eyebrow" }, "Packet Analyzer Dashboard"),
        React.createElement("h1", null, report.project || "DPI Engine"),
        React.createElement(
          "p",
          { className: "hero-copy" },
          "A browser-based view of packet filtering, application classification, thread activity, and configured blocking rules."
        )
      ),
      React.createElement(
        "div",
        { className: "actions" },
        React.createElement(
          "label",
          { className: "file-label" },
          "Upload JSON Report",
          React.createElement("input", { type: "file", accept: ".json,application/json", onChange: handleFile })
        ),
        React.createElement(
          "button",
          {
            className: "ghost-button",
            disabled: isRunning,
            onClick: () => runPreset(analysisPresets[3]),
            type: "button",
          },
          isRunning ? "Running Analysis..." : "Run Strict Demo"
        ),
        React.createElement("div", { className: "status" }, status)
        ,
        lastUpdated
          ? React.createElement("div", { className: "status timestamp" }, `Last update: ${lastUpdated.toLocaleTimeString()}`)
          : null
      )
    ),

    React.createElement(
      "section",
      { className: "card preset-panel" },
      React.createElement("div", { className: "panel-heading" },
        React.createElement("div", null,
          React.createElement("p", { className: "eyebrow" }, "REST API Controls"),
          React.createElement("h2", { className: "section-title" }, "Run Backend Analysis from Website")
        ),
        React.createElement("span", { className: isRunning ? "api-pill running" : "api-pill" },
          isRunning ? "Running..." : "Spring Boot API"
        )
      ),
      React.createElement(
        "div",
        { className: "preset-grid" },
        analysisPresets.map((preset) =>
          React.createElement(PresetButton, {
            key: preset.name,
            preset,
            isRunning,
            isActive: activePreset?.name === preset.name,
            onRun: runPreset,
          })
        )
      ),
      activePreset
        ? React.createElement(
            "div",
            { className: "active-run" },
            React.createElement(
              "div",
              null,
              React.createElement("span", { className: "active-label" }, "Selected mode"),
              React.createElement("strong", null, activePreset.name),
              React.createElement("p", null, activePreset.description)
            ),
            React.createElement(
              "div",
              { className: "active-metrics" },
              React.createElement("span", null, `Apps: ${joinOrNone(activePreset.request.blockApps)}`),
              React.createElement("span", null, `IPs: ${joinOrNone(activePreset.request.blockIps)}`),
              React.createElement("span", null, `Domains: ${joinOrNone(activePreset.request.blockDomains)}`),
              React.createElement("span", null, `Threads: ${activePreset.request.lbs} LB x ${activePreset.request.fps} FP`)
            )
          )
        : React.createElement(
            "div",
            { className: "active-run muted-run" },
            React.createElement("span", { className: "active-label" }, "Selected mode"),
            React.createElement("strong", null, "No button run yet"),
            React.createElement("p", null, "Click any preset to run the backend and update this panel.")
          ),
      React.createElement(
        "div",
        { className: "result-strip" },
        React.createElement("span", null, `Blocked packets: ${formatNumber(report.filtering_statistics?.dropped_packets)}`),
        React.createElement("span", null, `Drop rate: ${formatPercent(report.filtering_statistics?.drop_rate_percent)}`),
        React.createElement("span", null, `Load balancing: ${formatNumber(report.configuration?.load_balancers)} x ${formatNumber(report.configuration?.fast_paths_per_load_balancer)}`),
        React.createElement("span", null, `Rules active: ${blockedRuleValues.length}`)
      ),
      lastCommand.length > 0
        ? React.createElement(
            "div",
            { className: "command-box" },
            React.createElement("span", null, "Last command"),
            React.createElement("code", null, lastCommand.join(" "))
          )
        : null
    ),

    React.createElement(
      "section",
      { className: "grid stats-grid" },
      React.createElement(StatCard, {
        title: "Total Packets",
        value: formatNumber(report.packet_statistics?.total_packets),
        sub: `${formatNumber(report.packet_statistics?.total_bytes)} bytes`,
      }),
      React.createElement(StatCard, {
        title: "Forwarded",
        value: formatNumber(report.filtering_statistics?.forwarded_packets),
        sub: "Allowed traffic",
      }),
      React.createElement(StatCard, {
        title: "Blocked",
        value: formatNumber(report.filtering_statistics?.dropped_packets),
        sub: `${formatPercent(report.filtering_statistics?.drop_rate_percent)} drop rate`,
      }),
      React.createElement(StatCard, {
        title: "Connections",
        value: formatNumber(report.classification?.total_connections),
        sub: `${formatNumber(report.classification?.classified_connections)} classified`,
      })
    ),

    React.createElement(
      "section",
      { className: "grid content-grid" },
      React.createElement(
        "article",
        { className: "card" },
        React.createElement("h2", { className: "section-title" }, "Application Distribution"),
        React.createElement(
          "div",
          { className: "bars" },
          appDistribution.map((entry) =>
            React.createElement(
              "div",
              { className: "bar-row", key: entry.app },
              React.createElement("div", { className: "app-name" }, entry.app),
              React.createElement(
                "div",
                { className: "bar-track" },
                React.createElement("div", {
                  className: "bar-fill",
                  style: { width: `${Math.min(Number(entry.percentage ?? 0), 100)}%` },
                })
              ),
              React.createElement(
                "div",
                { className: "bar-meta" },
                `${formatNumber(entry.count)} | ${Number(entry.percentage ?? 0).toFixed(1)}%`
              )
            )
          )
        )
      ),
      React.createElement(
        "article",
        { className: "card" },
        React.createElement("h2", { className: "section-title" }, "Blocking Rules"),
        React.createElement(Chips, { values: blockedRuleValues })
      )
    ),

    React.createElement(
      "section",
      { className: "two-column" },
      React.createElement(
        "article",
        { className: "card" },
        React.createElement("h2", { className: "section-title" }, "Thread Pipeline"),
        React.createElement(MiniList, {
          items: [
            ["Load balancers", formatNumber(report.configuration?.load_balancers)],
            ["FPs per LB", formatNumber(report.configuration?.fast_paths_per_load_balancer)],
            ["Total FP threads", formatNumber(report.configuration?.total_fast_path_threads)],
            ["LB received", formatNumber(report.thread_statistics?.load_balancer_received)],
            ["FP processed", formatNumber(report.thread_statistics?.fast_path_processed)],
          ],
        })
      ),
      React.createElement(
        "article",
        { className: "card" },
        React.createElement("h2", { className: "section-title" }, "Capture Details"),
        React.createElement(MiniList, {
          items: [
            ["Input PCAP", report.input_file || "-"],
            ["Output PCAP", report.output_file || "-"],
            ["TCP packets", formatNumber(report.packet_statistics?.tcp_packets)],
            ["UDP packets", formatNumber(report.packet_statistics?.udp_packets)],
            ["Unidentified connections", formatNumber(report.classification?.unidentified_connections)],
          ],
        })
      )
    )
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(React.createElement(App));
