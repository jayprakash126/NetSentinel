
import { Fragment, useEffect, useState } from "react";
import axios from "axios";
import { io } from "socket.io-client";
import {
  Activity,
  Search,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Network,
  Database,
} from "lucide-react";

const API_URL = "http://localhost:5000/api/network-events";
const SOCKET_URL = "http://localhost:5000";

function NetworkEvents() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [page, setPage] = useState(1);
  const [limit] = useState(20);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);

  const [eventType, setEventType] = useState("");
  const [protocol, setProtocol] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  const [expandedEvent, setExpandedEvent] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  // Fetch network events from the backend
  useEffect(() => {
    const fetchEvents = async () => {
      try {
        setLoading(true);
        setError("");

        const response = await axios.get(API_URL, {
          params: {
            page,
            limit,
            ...(eventType && { event_type: eventType }),
            ...(protocol && { protocol }),
            ...(searchTerm.trim() && { search: searchTerm.trim() }),
          },
        });

        setEvents(response.data.events || []);
        setTotal(response.data.pagination?.total || 0);
        setTotalPages(response.data.pagination?.totalPages || 1);
      } catch (err) {
        console.error("Failed to fetch network events:", err);

        setError(
          err.response?.data?.message ||
            "Unable to retrieve network events. Check the backend."
        );

        setEvents([]);
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
  }, [page, limit, eventType, protocol, searchTerm, refreshKey]);

  // Listen for new events through Socket.IO
  useEffect(() => {
    const socket = io(SOCKET_URL);

    let refreshTimer;

    const handleNewEvent = () => {
      // Wait until a batch of incoming events finishes
      // before making one API request.
      clearTimeout(refreshTimer);

      refreshTimer = setTimeout(() => {
        setRefreshKey((current) => current + 1);
      }, 300);
    };

    socket.on("network_event:new", handleNewEvent);

    return () => {
      clearTimeout(refreshTimer);
      socket.off("network_event:new", handleNewEvent);
      socket.disconnect();
    };
  }, []);

  const clearFilters = () => {
    setEventType("");
    setProtocol("");
    setSearchTerm("");
    setPage(1);
    setExpandedEvent(null);
  };

  const formatIP = (ip) => {
    if (!ip) return "N/A";
    return ip.replace(/\/32$/, "");
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return "N/A";
    return new Date(timestamp).toLocaleString();
  };

  const getEventStyle = (type) => {
    switch (type?.toLowerCase()) {
      case "alert":
        return "border-red-500/30 bg-red-500/10 text-red-400";
      case "flow":
        return "border-blue-500/30 bg-blue-500/10 text-blue-400";
      case "stats":
        return "border-purple-500/30 bg-purple-500/10 text-purple-400";
      default:
        return "border-slate-500/30 bg-slate-500/10 text-slate-400";
    }
  };

  const handleFilterChange = (setter, value) => {
    setter(value);
    setPage(1);
    setExpandedEvent(null);
  };

  return (
    <section className="space-y-5">
      {/* Summary cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Total Network Events</p>
              <h2 className="mt-2 text-3xl font-bold text-white">
                {total}
              </h2>
            </div>
            <Activity size={30} className="text-blue-400" />
          </div>
        </div>

        <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Events on This Page</p>
              <h2 className="mt-2 text-3xl font-bold text-white">
                {events.length}
              </h2>
            </div>
            <Database size={30} className="text-purple-400" />
          </div>
        </div>
      </div>

      {/* Main events panel */}
      <div className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900">
        <div className="flex flex-col gap-3 border-b border-slate-700 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Network Event Logs
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Inspect network traffic captured by the Suricata engine.
            </p>
          </div>

          <button
            onClick={() => setRefreshKey((value) => value + 1)}
            disabled={loading}
            className="flex items-center justify-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-blue-500 hover:text-blue-400 disabled:opacity-50"
          >
            <RefreshCw
              size={16}
              className={loading ? "animate-spin" : ""}
            />
            Refresh
          </button>
        </div>

        {/* Filters */}
        <div className="flex flex-col gap-3 border-b border-slate-700 p-4 lg:flex-row">
          <div className="flex flex-1 items-center gap-3 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 focus-within:border-blue-500">
            <Search size={18} className="shrink-0 text-slate-400" />

            <input
              type="text"
              placeholder="Search source or destination IP..."
              value={searchTerm}
              onChange={(e) =>
                handleFilterChange(setSearchTerm, e.target.value)
              }
              className="w-full bg-transparent text-sm text-slate-200 outline-none placeholder:text-slate-500"
            />
          </div>

          <select
            value={eventType}
            onChange={(e) =>
              handleFilterChange(setEventType, e.target.value)
            }
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-200 outline-none focus:border-blue-500"
          >
            <option value="">All Event Types</option>
            <option value="alert">Alert</option>
            <option value="flow">Flow</option>
            <option value="stats">Stats</option>
          </select>

          <select
            value={protocol}
            onChange={(e) =>
              handleFilterChange(setProtocol, e.target.value)
            }
            className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-200 outline-none focus:border-blue-500"
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>

          <button
            onClick={clearFilters}
            disabled={!eventType && !protocol && !searchTerm}
            className="rounded-lg border border-slate-700 px-4 py-2.5 text-sm text-slate-300 transition hover:border-blue-500 hover:text-blue-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear
          </button>
        </div>

        {/* Event count */}
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-3">
          <span className="text-xs text-slate-400">
            Showing {events.length} of {total} events
          </span>

          <span className="text-xs text-slate-400">
            Page {page} of {totalPages}
          </span>
        </div>

        {/* Loading, error and empty states */}
        {loading ? (
          <div className="flex flex-col items-center gap-3 p-12 text-slate-400">
            <RefreshCw size={30} className="animate-spin" />
            <p>Loading network events...</p>
          </div>
        ) : error ? (
          <div className="flex flex-col items-center gap-3 p-12 text-red-400">
            <AlertTriangle size={32} />
            <h3 className="font-semibold">Unable to Load Events</h3>
            <p className="text-sm">{error}</p>
          </div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center gap-3 p-12 text-slate-400">
            <Network size={34} />
            <h3 className="font-semibold text-white">No Events Found</h3>
            <p className="text-sm">
              Try changing your filters or importing network traffic.
            </p>
          </div>
        ) : (
          <>
            {/* Events table */}
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1050px] text-left text-sm">
                <thead className="bg-slate-950 text-xs uppercase text-slate-400">
                  <tr>
                    <th className="px-5 py-4">ID</th>
                    <th className="px-5 py-4">Event Type</th>
                    <th className="px-5 py-4">Source IP</th>
                    <th className="px-5 py-4">Destination IP</th>
                    <th className="px-5 py-4">Ports</th>
                    <th className="px-5 py-4">Protocol</th>
                    <th className="px-5 py-4">Timestamp</th>
                    <th className="px-5 py-4">Details</th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-800">
                  {events.map((event) => (
                    <Fragment key={event.id}>
                      <tr className="transition hover:bg-slate-800/50">
                        <td className="px-5 py-4 font-medium text-slate-300">
                          #{event.id}
                        </td>

                        <td className="px-5 py-4">
                          <span
                            className={`rounded-md border px-2.5 py-1 text-xs font-semibold uppercase ${getEventStyle(event.event_type)}`}
                          >
                            {event.event_type}
                          </span>
                        </td>

                        <td className="px-5 py-4 font-mono text-slate-300">
                          {formatIP(event.source_ip)}
                        </td>

                        <td className="px-5 py-4 font-mono text-slate-300">
                          {formatIP(event.destination_ip)}
                        </td>

                        <td className="px-5 py-4 text-slate-400">
                          {event.source_port || "—"} →{" "}
                          {event.destination_port || "—"}
                        </td>

                        <td className="px-5 py-4 text-slate-300">
                          {event.protocol || "N/A"}
                        </td>

                        <td className="whitespace-nowrap px-5 py-4 text-xs text-slate-400">
                          {formatTimestamp(event.event_timestamp)}
                        </td>

                        <td className="px-5 py-4">
                          <button
                            onClick={() =>
                              setExpandedEvent(
                                expandedEvent === event.id ? null : event.id
                              )
                            }
                            className="flex items-center gap-1 text-blue-400 transition hover:text-blue-300"
                          >
                            {expandedEvent === event.id ? (
                              <>
                                Hide <ChevronUp size={15} />
                              </>
                            ) : (
                              <>
                                View <ChevronDown size={15} />
                              </>
                            )}
                          </button>
                        </td>
                      </tr>

                      {expandedEvent === event.id && (
                        <tr>
                          <td colSpan="8" className="bg-slate-950 p-5">
                            <h4 className="mb-3 font-semibold text-white">
                              Raw Event Details
                            </h4>

                            <pre className="max-h-96 overflow-auto rounded-lg border border-slate-700 bg-black/30 p-4 text-xs leading-6 text-green-300">
                              {JSON.stringify(event.raw_event, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between border-t border-slate-700 p-4">
              <p className="text-xs text-slate-400">
                Page {page} of {totalPages}
              </p>

              <div className="flex gap-2">
                <button
                  onClick={() => setPage((current) => current - 1)}
                  disabled={page <= 1 || loading}
                  className="flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-blue-500 disabled:opacity-40"
                >
                  <ChevronLeft size={16} />
                  Previous
                </button>

                <button
                  onClick={() => setPage((current) => current + 1)}
                  disabled={page >= totalPages || loading}
                  className="flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-blue-500 disabled:opacity-40"
                >
                  Next
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

export default NetworkEvents;
