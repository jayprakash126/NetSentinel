
import { useState, useEffect } from "react";
import axios from "axios";
import { io } from "socket.io-client";

import {
  Shield,
  LayoutDashboard,
  Activity,
  Bell,
  Network,
  Settings,
  Search,
  RefreshCw,
  Clock,
  Menu,
  X,
  CheckCircle,
  Server,
  Database,
  FileText,
} from "lucide-react";

import "./App.css";
import AnalyticsDashboard from "./components/AnalyticsDashboard";
import NetworkEvents from "./components/NetworkEvents";

const API_URL = "http://localhost:5000/api/alerts";
const MONITORING_URL = "http://localhost:5000/api/monitoring";

function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [backendConnected, setBackendConnected] = useState(false);
  const [updatingAlert, setUpdatingAlert] = useState(null);

  const [monitoring, setMonitoring] = useState(null);
  const [monitoringLoading, setMonitoringLoading] = useState(false);
  const [monitoringError, setMonitoringError] = useState("");

  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      setError("");

      const response = await axios.get(API_URL);

      setAlerts(response.data.alerts || []);
      setBackendConnected(true);
    } catch (err) {
      console.error("Failed to fetch alerts:", err);
      setBackendConnected(false);
      setError("Unable to connect to the backend. Please check the server.");
    } finally {
      setLoading(false);
    }
  };

  const fetchMonitoring = async () => {
    try {
      setMonitoringLoading(true);
      setMonitoringError("");

      const response = await axios.get(MONITORING_URL);
      setMonitoring(response.data);
    } catch (err) {
      console.error("Failed to fetch monitoring data:", err);
      setMonitoringError(
        "Unable to retrieve monitoring information. Please check the backend."
      );
    } finally {
      setMonitoringLoading(false);
    }
  };

  const formatMonitoringTime = (timestamp) => {
    if (!timestamp) return "Not available";

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
      return "Not available";
    }

    return date.toLocaleString();
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  useEffect(() => {
    if (activePage !== "Monitoring") return;

    fetchMonitoring();

    const interval = setInterval(fetchMonitoring, 5000);

    return () => clearInterval(interval);
  }, [activePage]);

  useEffect(() => {
    const socket = io("http://localhost:5000");

    const handleNewAlert = (newAlert) => {
      setAlerts((previousAlerts) => {
        const exists = previousAlerts.some(
          (alert) => alert.id === newAlert.id
        );

        return exists
          ? previousAlerts
          : [newAlert, ...previousAlerts];
      });
    };

    socket.on("connect", () => setBackendConnected(true));
    socket.on("disconnect", () => setBackendConnected(false));

    socket.on("connect_error", (err) => {
      console.error("Socket.IO connection error:", err.message);
      setBackendConnected(false);
    });

    socket.on("alert:new", handleNewAlert);

    return () => {
      socket.off("alert:new", handleNewAlert);
      socket.disconnect();
    };
  }, []);

  const updateAlertStatus = async (alertId, status) => {
    try {
      setUpdatingAlert(alertId);
      setError("");

      await axios.patch(`${API_URL}/${alertId}/status`, { status });

      await fetchAlerts();
    } catch (err) {
      console.error("Failed to update alert:", err);
      setError(
        err.response?.data?.message || "Unable to update alert status."
      );
    } finally {
      setUpdatingAlert(null);
    }
  };

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSeverity =
      !severityFilter ||
      Number(alert.severity) === Number(severityFilter);

    const matchesStatus =
      !statusFilter || alert.status === statusFilter;

    const search = searchTerm.toLowerCase().trim();

    const matchesSearch =
      !search ||
      alert.source_ip?.toLowerCase().includes(search) ||
      alert.destination_ip?.toLowerCase().includes(search) ||
      alert.attack_type?.toLowerCase().includes(search) ||
      alert.signature?.toLowerCase().includes(search);

    return matchesSeverity && matchesStatus && matchesSearch;
  });

  // Suricata severity mapping: 1 = High, 2 = Medium, 3 = Low.
  const getSeverity = (severity) => {
    const value = Number(severity);

    if (value === 1) return "High";
    if (value === 2) return "Medium";
    if (value === 3) return "Low";

    return "Unknown";
  };

  const clearFilters = () => {
    setSearchTerm("");
    setSeverityFilter("");
    setStatusFilter("");
  };

  const navigation = [
    { name: "Dashboard", icon: LayoutDashboard },
    { name: "Alerts", icon: Bell },
    { name: "Network Events", icon: Network },
    { name: "Monitoring", icon: Activity },
    { name: "Settings", icon: Settings },
  ];

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={24} />
          </div>

          <div>
            <h2>NetSentinel</h2>
            <span>SECURITY MONITOR</span>
          </div>
        </div>

        <div className="nav-label">MAIN MENU</div>

        <nav>
          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <button
                key={item.name}
                className={`nav-item ${
                  activePage === item.name ? "active" : ""
                }`}
                onClick={() => setActivePage(item.name)}
              >
                <Icon size={19} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="system-indicator"></div>
          <div>
            <strong>System Online</strong>
            <span>NetSentinel v1.0</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            <Menu size={20} />
            <span>Security Center</span>
            <span className="breadcrumb-divider">/</span>
            <strong>{activePage}</strong>
          </div>

          <div className="topbar-actions">
            <div className="connection-status">
              <span
                className="status-dot"
                style={{
                  background: backendConnected ? "#22c55e" : "#ef4444",
                }}
              ></span>

              {backendConnected
                ? "Backend Connected"
                : "Backend Disconnected"}
            </div>

            <button
              className="icon-button"
              aria-label="Refresh current page"
              onClick={
                activePage === "Monitoring"
                  ? fetchMonitoring
                  : fetchAlerts
              }
              disabled={
                activePage === "Monitoring"
                  ? monitoringLoading
                  : loading
              }
            >
              <RefreshCw
                size={19}
                className={
                  (activePage === "Monitoring" && monitoringLoading) ||
                  (activePage !== "Monitoring" && loading)
                    ? "animate-spin"
                    : ""
                }
              />
            </button>
          </div>
        </header>

        <section className="dashboard-content">
          <div className="page-heading">
            <div>
              <h1 className="text-3xl font-extrabold tracking-tight text-blue-400">
                {activePage}
              </h1>

              <p>
                {activePage === "Dashboard" &&
                  "Monitor network activity and security threats."}
                {activePage === "Alerts" &&
                  "Review, investigate and manage detected security threats."}
                {activePage === "Network Events" &&
                  "Explore detailed network traffic and event records."}
                {activePage === "Monitoring" &&
                  "Monitor the health and connectivity of security services."}
                {activePage === "Settings" &&
                  "Manage NetSentinel application configuration."}
              </p>
            </div>

            <div className="date-label">
              <Clock size={16} />
              Security Monitoring
            </div>
          </div>

          {/* DASHBOARD PAGE */}
          {activePage === "Dashboard" && (
            <>
              <AnalyticsDashboard />

              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Recent Security Alerts</h2>
                    <p>
                      Latest threats detected by the intrusion detection engine
                    </p>
                  </div>

                  <button
                    className="view-all-button"
                    onClick={() => setActivePage("Alerts")}
                  >
                    View All Alerts
                  </button>
                </div>

                {loading ? (
                  <div className="empty-state">
                    <RefreshCw size={30} />
                    <h3>Loading alerts...</h3>
                  </div>
                ) : alerts.length === 0 ? (
                  <div className="empty-state">
                    <Shield size={34} />
                    <h3>No security alerts found</h3>
                    <p>New detected threats will appear here.</p>
                  </div>
                ) : (
                  <div className="alerts-table-wrapper">
                    <table className="alerts-table">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Source IP</th>
                          <th>Attack Type</th>
                          <th>Severity</th>
                          <th>Status</th>
                          <th>Detected At</th>
                        </tr>
                      </thead>

                      <tbody>
                        {alerts.slice(0, 5).map((alert) => (
                          <tr key={alert.id}>
                            <td>#{alert.id}</td>
                            <td>{alert.source_ip || "N/A"}</td>
                            <td>{alert.attack_type}</td>
                            <td>
                              <span
                                className={`severity-badge severity-${alert.severity}`}
                              >
                                {getSeverity(alert.severity)}
                              </span>
                            </td>
                            <td>
                              <span
                                className={`status-badge status-${alert.status}`}
                              >
                                {alert.status}
                              </span>
                            </td>
                            <td>
                              {new Date(alert.created_at).toLocaleString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </>
          )}

          {/* ALERTS PAGE */}
          {activePage === "Alerts" && (
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Security Alerts</h2>
                  <p>Complete list of detected security threats</p>
                </div>

                <button
                  className="icon-button"
                  onClick={fetchAlerts}
                  disabled={loading}
                  aria-label="Refresh alerts"
                >
                  <RefreshCw
                    size={18}
                    className={loading ? "animate-spin" : ""}
                  />
                </button>
              </div>

              {error && (
                <p className="px-5 py-3 text-sm text-red-400">{error}</p>
              )}

              {loading ? (
                <div className="empty-state">
                  <RefreshCw size={30} />
                  <h3>Loading security alerts...</h3>
                </div>
              ) : (
                <>
                  <div className="flex flex-col gap-3 border-b border-slate-700/70 bg-slate-900/60 p-4 md:flex-row md:items-center">
                    <div className="flex min-w-0 flex-1 items-center gap-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5">
                      <Search size={18} className="shrink-0 text-slate-400" />

                      <input
                        type="text"
                        placeholder="Search IP address or attack type..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full min-w-0 bg-transparent text-sm text-slate-200 outline-none placeholder:text-slate-500"
                      />

                      {searchTerm && (
                        <button
                          onClick={() => setSearchTerm("")}
                          aria-label="Clear search"
                          className="text-slate-400 hover:text-white"
                        >
                          <X size={16} />
                        </button>
                      )}
                    </div>

                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-200"
                    >
                      <option value="">All Severities</option>
                      <option value="1">High</option>
                      <option value="2">Medium</option>
                      <option value="3">Low</option>
                    </select>

                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-200"
                    >
                      <option value="">All Statuses</option>
                      <option value="new">New</option>
                      <option value="acknowledged">Acknowledged</option>
                      <option value="resolved">Resolved</option>
                    </select>

                    <button
                      onClick={clearFilters}
                      disabled={!searchTerm && !severityFilter && !statusFilter}
                      className="rounded-lg border border-slate-700 px-4 py-2.5 text-sm text-slate-300 hover:border-blue-500 disabled:opacity-40"
                    >
                      Clear Filters
                    </button>
                  </div>

                  <div className="flex items-center justify-between border-b border-slate-700/70 px-5 py-3">
                    <span className="text-xs text-slate-400">
                      Showing{" "}
                      <strong className="text-slate-200">
                        {filteredAlerts.length}
                      </strong>{" "}
                      of{" "}
                      <strong className="text-slate-200">
                        {alerts.length}
                      </strong>{" "}
                      alerts
                    </span>
                  </div>

                  {filteredAlerts.length === 0 ? (
                    <div className="empty-state">
                      <Search size={30} />
                      <h3>No matching alerts</h3>
                      <p>
                        Try changing your search or filter criteria.
                      </p>

                      <button
                        onClick={clearFilters}
                        className="mt-3 rounded-lg bg-blue-600 px-4 py-2 text-sm text-white"
                      >
                        Clear Filters
                      </button>
                    </div>
                  ) : (
                    <div className="alerts-table-wrapper">
                      <table className="alerts-table">
                        <thead>
                          <tr>
                            <th>ID</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Attack Type</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Detected At</th>
                            <th>Actions</th>
                          </tr>
                        </thead>

                        <tbody>
                          {filteredAlerts.map((alert) => (
                            <tr key={alert.id}>
                              <td>#{alert.id}</td>
                              <td>{alert.source_ip || "N/A"}</td>
                              <td>{alert.destination_ip || "N/A"}</td>
                              <td>{alert.attack_type}</td>

                              <td>
                                <span
                                  className={`severity-badge severity-${alert.severity}`}
                                >
                                  {getSeverity(alert.severity)}
                                </span>
                              </td>

                              <td>
                                <span
                                  className={`status-badge status-${alert.status}`}
                                >
                                  {alert.status}
                                </span>
                              </td>

                              <td>
                                {new Date(alert.created_at).toLocaleString()}
                              </td>

                              <td>
                                <div className="alert-actions flex flex-wrap items-center gap-2">
                                  {alert.status === "new" && (
                                    <button
                                      className="acknowledge-button"
                                      disabled={updatingAlert === alert.id}
                                      onClick={() =>
                                        updateAlertStatus(
                                          alert.id,
                                          "acknowledged"
                                        )
                                      }
                                    >
                                      {updatingAlert === alert.id
                                        ? "Updating..."
                                        : "Acknowledge"}
                                    </button>
                                  )}

                                  {alert.status !== "resolved" && (
                                    <button
                                      className="resolve-button"
                                      disabled={updatingAlert === alert.id}
                                      onClick={() =>
                                        updateAlertStatus(
                                          alert.id,
                                          "resolved"
                                        )
                                      }
                                    >
                                      {updatingAlert === alert.id
                                        ? "Updating..."
                                        : "Resolve"}
                                    </button>
                                  )}

                                  {alert.status === "resolved" && (
                                    <span className="resolved-label">
                                      Completed
                                    </span>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </>
              )}
            </section>
          )}

          {/* NETWORK EVENTS PAGE */}
          {activePage === "Network Events" && <NetworkEvents />}

          {/* MONITORING PAGE */}
          {activePage === "Monitoring" && (
            <div className="space-y-5">
              <div className="panel flex flex-wrap items-center justify-between gap-4 p-5">
                <div>
                  <h2 className="text-lg font-bold">
                    System Health Overview
                  </h2>
                  <p className="mt-1 text-sm text-slate-400">
                    Live status of NetSentinel services and log ingestion.
                  </p>
                </div>

                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <RefreshCw
                    size={15}
                    className={monitoringLoading ? "animate-spin" : ""}
                  />
                  Auto-refresh: 5 seconds
                </div>
              </div>

              {monitoringError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
                  {monitoringError}
                </div>
              )}

              {!monitoring && monitoringLoading && (
                <div className="panel p-8 text-center text-slate-400">
                  <RefreshCw
                    size={28}
                    className="mx-auto mb-3 animate-spin"
                  />
                  Loading system monitoring information...
                </div>
              )}

              {monitoring && (
                <>
                  <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
                    <div className="panel p-5">
                      <div className="flex items-center justify-between">
                        <Server size={25} className="text-blue-400" />
                        <span
                          className={`rounded-full px-3 py-1 text-xs font-semibold ${
                            monitoring.backend?.status === "Healthy"
                              ? "bg-green-500/15 text-green-400"
                              : "bg-red-500/15 text-red-400"
                          }`}
                        >
                          {monitoring.backend?.status || "Unknown"}
                        </span>
                      </div>

                      <h3 className="mt-4 font-semibold">Backend Service</h3>
                      <p className="mt-1 text-sm text-slate-400">
                        NetSentinel API server
                      </p>
                      <p className="mt-3 text-sm text-slate-300">
                        Port: {monitoring.backend?.port || "N/A"}
                      </p>
                    </div>

                    <div className="panel p-5">
                      <div className="flex items-center justify-between">
                        <Database size={25} className="text-blue-400" />
                        <span
                          className={`rounded-full px-3 py-1 text-xs font-semibold ${
                            monitoring.database?.status === "Connected"
                              ? "bg-green-500/15 text-green-400"
                              : "bg-red-500/15 text-red-400"
                          }`}
                        >
                          {monitoring.database?.status || "Unknown"}
                        </span>
                      </div>

                      <h3 className="mt-4 font-semibold">
                        PostgreSQL Database
                      </h3>
                      <p className="mt-1 text-sm text-slate-400">
                        Database connectivity
                      </p>
                      <p className="mt-3 text-sm text-slate-300">
                        {monitoring.database?.version || "Version unavailable"}
                      </p>
                    </div>

                    <div className="panel p-5">
                      <div className="flex items-center justify-between">
                        <Shield size={25} className="text-blue-400" />
                        <span
                          className={`rounded-full px-3 py-1 text-xs font-semibold ${
                            monitoring.suricata?.eveFile?.available
                              ? "bg-green-500/15 text-green-400"
                              : "bg-red-500/15 text-red-400"
                          }`}
                        >
                          {monitoring.suricata?.status || "Unknown"}
                        </span>
                      </div>

                      <h3 className="mt-4 font-semibold">Suricata Engine</h3>
                      <p className="mt-1 text-sm text-slate-400">
                        EVE log:{" "}
                        {monitoring.suricata?.eveFile?.available
                          ? "Available"
                          : "Missing"}
                      </p>
                      <p className="mt-3 text-sm text-slate-300">
                        Mode: {monitoring.suricata?.mode || "Unknown"}
                      </p>
                      <p className="mt-2 text-xs text-amber-400">
                        Process:{" "}
                        {monitoring.suricata?.process?.status ||
                          "Not Monitored"}
                      </p>
                    </div>

                    <div className="panel p-5">
                      <div className="flex items-center justify-between">
                        <Activity size={25} className="text-blue-400" />
                        <span
                          className={`rounded-full px-3 py-1 text-xs font-semibold ${
                            monitoring.ingestion?.status === "Monitoring Log"
                              ? "bg-green-500/15 text-green-400"
                              : "bg-yellow-500/15 text-yellow-400"
                          }`}
                        >
                          {monitoring.ingestion?.status || "Unknown"}
                        </span>
                      </div>

                      <h3 className="mt-4 font-semibold">Log Ingestion</h3>
                      <p className="mt-1 text-sm text-slate-400">
                        Automatic log monitoring
                      </p>
                      <p className="mt-3 text-sm text-slate-300">
                        Interval:{" "}
                        {monitoring.ingestion?.intervalSeconds ?? "N/A"} seconds
                      </p>
                    </div>
                  </div>

                  {/* DATABASE-WIDE STATISTICS */}
                  <section className="panel p-5">
                    <div className="mb-5 flex items-center gap-3">
                      <Database size={22} className="text-blue-400" />
                      <div>
                        <h2 className="text-lg font-bold">
                          Database Statistics
                        </h2>
                        <p className="text-sm text-slate-400">
                          Total records currently stored in PostgreSQL
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                      <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
                        <p className="text-sm text-slate-400">
                          Total Network Events
                        </p>
                        <h3 className="mt-2 text-2xl font-bold text-blue-400">
                          {monitoring.database?.statistics?.totalNetworkEvents ?? "N/A"}
                        </h3>
                      </div>

                      <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
                        <p className="text-sm text-slate-400">
                          Total Security Alerts
                        </p>
                        <h3 className="mt-2 text-2xl font-bold text-orange-400">
                          {monitoring.database?.statistics?.totalAlerts ?? "N/A"}
                        </h3>
                      </div>
                    </div>
                  </section>

                  {/* CURRENT SESSION INGESTION STATISTICS */}
                  <section className="panel p-5">
                    <div className="mb-5 flex items-center gap-3">
                      <Activity size={22} className="text-blue-400" />
                      <div>
                        <h2 className="text-lg font-bold">
                          Current Session Ingestion
                        </h2>
                        <p className="text-sm text-slate-400">
                          Records imported since the backend was last started
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
                        <p className="text-sm text-slate-400">
                          Events Imported
                        </p>
                        <h3 className="mt-2 text-2xl font-bold text-blue-400">
                          {monitoring.ingestion?.totalImportedEvents ?? 0}
                        </h3>
                      </div>

                      <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
                        <p className="text-sm text-slate-400">
                          Alerts Imported
                        </p>
                        <h3 className="mt-2 text-2xl font-bold text-orange-400">
                          {monitoring.ingestion?.totalImportedAlerts ?? 0}
                        </h3>
                      </div>

                      <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
                        <p className="text-sm text-slate-400">
                          Ingestion Errors
                        </p>
                        <h3 className="mt-2 text-2xl font-bold text-red-400">
                          {monitoring.ingestion?.ingestionErrors ?? 0}
                        </h3>
                      </div>

                      <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
                        <p className="text-sm text-slate-400">
                          Events in Latest Poll
                        </p>
                        <h3 className="mt-2 text-2xl font-bold text-green-400">
                          {monitoring.ingestion?.lastImportedEvents ?? 0}
                        </h3>
                      </div>
                    </div>
                  </section>

                  {/* SURICATA EVE LOG DETAILS */}
                  <section className="panel p-5">
                    <div className="mb-5 flex items-center gap-3">
                      <FileText size={22} className="text-blue-400" />
                      <div>
                        <h2 className="text-lg font-bold">
                          Suricata EVE Log Details
                        </h2>
                        <p className="text-sm text-slate-400">
                          Information about the detected network event log file
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
                      <div>
                        <p className="text-sm text-slate-400">
                          File Availability
                        </p>
                        <p className="mt-1 font-semibold text-slate-200">
                          {monitoring.suricata?.eveFile?.available
                            ? "Available"
                            : "Not Available"}
                        </p>
                      </div>

                      <div>
                        <p className="text-sm text-slate-400">File Size</p>
                        <p className="mt-1 font-semibold text-slate-200">
                          {monitoring.suricata?.eveFile?.sizeBytes != null
                            ? `${(
                                monitoring.suricata.eveFile.sizeBytes / 1024
                              ).toFixed(2)} KB`
                            : "N/A"}
                        </p>
                      </div>

                      <div>
                        <p className="text-sm text-slate-400">
                          Total Log Lines
                        </p>
                        <p className="mt-1 font-semibold text-slate-200">
                          {monitoring.suricata?.eveFile?.totalLines ?? 0}
                        </p>
                      </div>

                      <div>
                        <p className="text-sm text-slate-400">Last Modified</p>
                        <p className="mt-1 text-sm font-semibold text-slate-200">
                          {formatMonitoringTime(
                            monitoring.suricata?.eveFile?.lastModified
                          )}
                        </p>
                      </div>

                      <div>
                        <p className="text-sm text-slate-400">Last Checked</p>
                        <p className="mt-1 text-sm font-semibold text-slate-200">
                          {formatMonitoringTime(
                            monitoring.ingestion?.lastChecked
                          )}
                        </p>
                      </div>

                      <div>
                        <p className="text-sm text-slate-400">
                          Last Successful Ingestion
                        </p>
                        <p className="mt-1 text-sm font-semibold text-slate-200">
                          {formatMonitoringTime(
                            monitoring.ingestion?.lastSuccessfulIngestion
                          )}
                        </p>
                      </div>
                    </div>
                  </section>

                  {/* CURRENT SYSTEM STATUS */}
                  <section className="panel p-5">
                    <div className="mb-4 flex items-center gap-3">
                      <CheckCircle
                        size={22}
                        className="text-green-400"
                      />
                      <h2 className="text-lg font-bold">System Status</h2>
                    </div>

                    <div className="space-y-3 text-sm">
                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-slate-400">Backend</span>
                        <span className="text-slate-200">
                          {monitoring.backend?.status || "Unknown"}
                        </span>
                      </div>

                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-slate-400">Database</span>
                        <span className="text-slate-200">
                          {monitoring.database?.status || "Unknown"}
                        </span>
                      </div>

                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-slate-400">Suricata Mode</span>
                        <span className="text-slate-200">
                          {monitoring.suricata?.mode || "Unknown"}
                        </span>
                      </div>

                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-slate-400">Suricata Process</span>
                        <span className="text-amber-400">
                          {monitoring.suricata?.process?.status ||
                            "Not Monitored"}
                        </span>
                      </div>

                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-slate-400">Live Capture</span>
                        <span className="text-slate-200">
                          {monitoring.suricata?.process?.liveCapture
                            ? "Active"
                            : "Not Active"}
                        </span>
                      </div>

                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-slate-400">
                          Ingestion Process
                        </span>
                        <span className="text-slate-200">
                          {monitoring.ingestion?.ingestionInProgress
                            ? "Currently importing"
                            : "Idle"}
                        </span>
                      </div>

                      <div className="flex flex-wrap justify-between gap-2">
                        <span className="text-slate-400">
                          Last Monitoring Update
                        </span>
                        <span className="text-slate-200">
                          {formatMonitoringTime(
                            monitoring.backend?.timestamp
                          )}
                        </span>
                      </div>
                    </div>
                  </section>
                </>
              )}
            </div>
          )}

          {/* SETTINGS PAGE */}
          {activePage === "Settings" && (
            <section className="panel p-6">
              <div className="flex items-center gap-3">
                <Settings size={25} className="text-blue-400" />
                <h2 className="text-xl font-bold">
                  Application Settings
                </h2>
              </div>

              <p className="mt-4 text-sm text-slate-400">
                NetSentinel configuration options will be added here.
              </p>

              <div className="mt-6 rounded-lg border border-slate-700 p-4">
                <h3 className="font-semibold">
                  Application Information
                </h3>
                <p className="mt-2 text-sm text-slate-400">
                  NetSentinel v1.0
                </p>
                <p className="text-sm text-slate-400">
                  Network Intrusion Detection and Security Monitoring System
                </p>
              </div>
            </section>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
