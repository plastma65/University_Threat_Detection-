(function () {
  const chartStore = {};

  const palette = {
    accent: "#6dc8ff",
    accentSoft: "rgba(109, 200, 255, 0.18)",
    critical: "#ff5d73",
    high: "#ff9a3c",
    medium: "#ffd166",
    low: "#5ed3a6",
    unknown: "#8ca0bc",
  };

  function emptyTargetId(canvasId) {
    return canvasId.replace("-chart", "-empty");
  }

  function toggleEmptyState(canvasId, isEmpty, message) {
    const emptyNode = document.getElementById(emptyTargetId(canvasId));
    if (!emptyNode) {
      return;
    }

    if (message) {
      emptyNode.textContent = message;
    }

    emptyNode.classList.toggle("d-none", !isEmpty);
  }

  function ensureChart(canvasId, config) {
    if (chartStore[canvasId]) {
      return chartStore[canvasId];
    }

    const canvas = document.getElementById(canvasId);
    chartStore[canvasId] = new Chart(canvas, config);
    return chartStore[canvasId];
  }

  function updateChart(canvasId, type, labels, values, datasetLabel, datasetOptions) {
    const baseDataset = {
      label: datasetLabel,
      data: values,
      borderWidth: 2,
      tension: 0.3,
      ...datasetOptions,
    };

    const chart = ensureChart(canvasId, {
      type,
      data: {
        labels,
        datasets: [baseDataset],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: "#edf4ff" },
          },
        },
        scales: type === "doughnut" ? {} : {
          x: {
            ticks: { color: "#8ca0bc" },
            grid: { color: "rgba(116, 145, 182, 0.08)" },
          },
          y: {
            beginAtZero: true,
            ticks: {
              color: "#8ca0bc",
              precision: 0,
            },
            grid: { color: "rgba(116, 145, 182, 0.08)" },
          },
        },
      },
    });

    chart.data.labels = labels;
    chart.data.datasets[0] = baseDataset;
    chart.update();
  }

  function renderTimelineChart(data) {
    const points = Array.isArray(data) ? data : [];
    const labels = points.map(function (point) {
      return new Date(point.bucket).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    });
    const values = points.map(function (point) {
      return point.count;
    });

    toggleEmptyState("timeline-chart", points.length === 0, "No timeline data yet.");
    updateChart("timeline-chart", "line", labels, values, "Alerts", {
      borderColor: palette.accent,
      backgroundColor: palette.accentSoft,
      fill: true,
      pointRadius: 3,
      pointHoverRadius: 5,
    });
  }

  function renderEventTypeChart(data) {
    const points = Array.isArray(data) ? data : [];
    const labels = points.map(function (point) {
      return point.event_type;
    });
    const values = points.map(function (point) {
      return point.count;
    });

    toggleEmptyState("event-type-chart", points.length === 0, "No event type data yet.");
    updateChart("event-type-chart", "doughnut", labels, values, "Event Types", {
      backgroundColor: [
        palette.accent,
        palette.high,
        palette.medium,
        palette.low,
        palette.critical,
        palette.unknown,
      ],
      borderColor: "#08111c",
      hoverOffset: 6,
    });
  }

  function renderSeverityChart(data) {
    const points = Array.isArray(data) ? data : [];
    const labels = points.map(function (point) {
      return point.severity;
    });
    const values = points.map(function (point) {
      return point.count;
    });
    const colors = points.map(function (point) {
      return palette[point.severity] || palette.unknown;
    });

    toggleEmptyState("severity-chart", points.length === 0, "No severity data yet.");
    updateChart("severity-chart", "bar", labels, values, "Severity", {
      backgroundColor: colors,
      borderRadius: 8,
    });
  }

  window.DashboardCharts = {
    renderEventTypeChart,
    renderSeverityChart,
    renderTimelineChart,
  };
}());
