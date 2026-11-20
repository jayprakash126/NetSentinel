
import { useEffect, useState } from "react";
import axios from "axios";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from "recharts";
import {
  Activity,
  ShieldAlert,
  Network,
  CheckCircle,
} from "lucide-react";

const API_URL = "http://localhost:5000/api/analytics";

const SEVERITY_COLORS = {
  High: "#ef4444",
  Medium: "#f97316",
  Low: "#22c55e",
};

const getSeverityLabel = (level) => {
  const value = Number(level);

  if (value === 1) return "High";
  if (value === 2) return "Medium";
  if (value === 3) return "Low";

  return "Unknown";
};

function AnalyticsDashboard() {
  const [overview, setOverview] = useState(null);
  const [protocols, setProtocols] = useState([]);
  const [severity, setSeverity] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [topIPs, setTopIPs] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      setError("");

      const [
        overviewResponse,
        protocolsResponse,
        severityResponse,
        timelineResponse,
        topIPsResponse,
      ] = await Promise.all([
        axios.get(`${API_URL}/overview`),
        axios.get(`${API_URL}/protocols`),
        axios.get(`${API_URL}/severity`),
        axios.get(`${API_URL}/timeline`),
        axios.get(`${API_URL}/top-ips`),
      ]);

      setOverview(overviewResponse.data.overview);
      setProtocols(protocolsResponse.data.protocols || []);
      setSeverity(severityResponse.data.severity || []);
      setTimeline(timelineResponse.data.timeline || []);

      setTopIPs(
        (topIPsResponse.data.topSourceIPs || []).map((item) => ({
          ...item,
          sourceIP: item.sourceIP.replace(/\/32$/, ""),
        }))
      );
    } catch (err) {
      console.error("Analytics fetch failed:", err);
      setError("Unable to load network analytics. Please check the backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const formatHour = (value) => {
    return new Date(value).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (loading) {
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-900 p-8 text-center text-slate-300">
        Loading network analytics...
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-red-400">
        {error}
        <button
          onClick={fetchAnalytics}
          className="ml-3 rounded-lg bg-red-500/20 px-3 py-2 text-sm hover:bg-red-500/30"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!overview) {
    return null;
  }

  // Normalize severity labels using Suricata's numeric severity values.
  const normalizedSeverity = severity.map((item) => ({
    ...item,
    label: getSeverityLabel(item.level),
    total: Number(item.total) || 0,
  }));

  // Calculate High severity alerts from the normalized severity data.
  const highSeverityCount = normalizedSeverity
    .filter((item) => Number(item.level) === 1)
    .reduce((total, item) => total + item.total, 0);

  const overviewCards = [
    {
      title: "Total Network Events",
      value: overview.totalEvents,
      icon: Activity,
      color: "text-blue-400",
    },
    {
      title: "Total Security Alerts",
      value: overview.totalAlerts,
      icon: ShieldAlert,
      color: "text-orange-400",
    },
    {
      title: "High Severity Alerts",
      value: highSeverityCount,
      icon: Network,
      color: "text-red-400",
    },
    {
      title: "Resolved Alerts",
      value: overview.status?.resolved ?? 0,
      icon: CheckCircle,
      color: "text-green-400",
    },
  ];

  return (
    <section className="space-y-6">

      {/* Analytics Overview */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {overviewCards.map((card) => {
          const Icon = card.icon;

          return (
            <div
              key={card.title}
              className="rounded-xl border border-slate-700 bg-slate-900 p-5 shadow-lg"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400">
                  {card.title}
                </span>
                <Icon className={card.color} size={22} />
              </div>

              <h2 className="mt-4 text-3xl font-bold text-white">
                {card.value}
              </h2>
            </div>
          );
        })}
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">

        {/* Protocol Distribution */}
        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <h3 className="mb-5 text-lg font-semibold text-white">
            Network Protocol Distribution
          </h3>

          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocols}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="protocol" stroke="#94a3b8" />
                <YAxis allowDecimals={false} stroke="#94a3b8" />

                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                    color: "#fff",
                  }}
                />

                <Bar
                  dataKey="total"
                  name="Events"
                  fill="#3b82f6"
                  radius={[6, 6, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <h3 className="mb-5 text-lg font-semibold text-white">
            Alert Severity Distribution
          </h3>

          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={normalizedSeverity.filter(
                    (item) => item.label !== "Unknown"
                  )}
                  dataKey="total"
                  nameKey="label"
                  cx="50%"
                  cy="50%"
                  outerRadius={95}
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {normalizedSeverity
                    .filter((item) => item.label !== "Unknown")
                    .map((item) => (
                      <Cell
                        key={item.level}
                        fill={SEVERITY_COLORS[item.label]}
                      />
                    ))}
                </Pie>

                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                    color: "#fff",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">

        {/* Network Activity Timeline */}
        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <h3 className="mb-5 text-lg font-semibold text-white">
            Network Activity — Last 24 Hours
          </h3>

          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />

                <XAxis
                  dataKey="time"
                  tickFormatter={formatHour}
                  stroke="#94a3b8"
                  minTickGap={25}
                />

                <YAxis allowDecimals={false} stroke="#94a3b8" />

                <Tooltip
                  labelFormatter={(value) =>
                    new Date(value).toLocaleString()
                  }
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                    color: "#fff",
                  }}
                />

                <Area
                  type="monotone"
                  dataKey="total"
                  name="Network Events"
                  stroke="#06b6d4"
                  fill="#0891b2"
                  fillOpacity={0.25}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Source IPs */}
        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <h3 className="mb-5 text-lg font-semibold text-white">
            Top Source IP Addresses
          </h3>

          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topIPs} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />

                <XAxis
                  type="number"
                  allowDecimals={false}
                  stroke="#94a3b8"
                />

                <YAxis
                  type="category"
                  dataKey="sourceIP"
                  width={115}
                  stroke="#94a3b8"
                  tick={{ fontSize: 11 }}
                />

                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                    color: "#fff",
                  }}
                />

                <Bar
                  dataKey="total"
                  name="Events"
                  fill="#8b5cf6"
                  radius={[0, 6, 6, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

    </section>
  );
}

export default AnalyticsDashboard;
