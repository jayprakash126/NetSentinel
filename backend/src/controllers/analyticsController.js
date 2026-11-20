
import pool from "../config/db.js";

// 1. Dashboard overview statistics
export const getAnalyticsOverview = async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM network_events) AS total_events,
        (SELECT COUNT(*) FROM alerts) AS total_alerts,

        (SELECT COUNT(*) FROM alerts WHERE severity = 1) AS critical_alerts,
        (SELECT COUNT(*) FROM alerts WHERE severity = 2) AS high_alerts,
        (SELECT COUNT(*) FROM alerts WHERE severity = 3) AS medium_alerts,
        (SELECT COUNT(*) FROM alerts WHERE severity = 4) AS low_alerts,

        (SELECT COUNT(*) FROM alerts WHERE status = 'new') AS new_alerts,
        (SELECT COUNT(*) FROM alerts WHERE status = 'acknowledged') AS acknowledged_alerts,
        (SELECT COUNT(*) FROM alerts WHERE status = 'resolved') AS resolved_alerts
    `);

    const stats = result.rows[0];

    res.json({
      success: true,
      overview: {
        totalEvents: Number(stats.total_events),
        totalAlerts: Number(stats.total_alerts),
        severity: {
          critical: Number(stats.critical_alerts),
          high: Number(stats.high_alerts),
          medium: Number(stats.medium_alerts),
          low: Number(stats.low_alerts)
        },
        status: {
          new: Number(stats.new_alerts),
          acknowledged: Number(stats.acknowledged_alerts),
          resolved: Number(stats.resolved_alerts)
        }
      }
    });
  } catch (error) {
    console.error("Analytics overview error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to retrieve analytics overview"
    });
  }
};


// 2. Network protocol distribution
export const getProtocolAnalytics = async (req, res) => {
  try {
    const result = await pool.query(`
  SELECT
    protocol,
    COUNT(*) AS total
  FROM network_events
  WHERE protocol IS NOT NULL
    AND event_type <> 'stats'
  GROUP BY protocol
  ORDER BY total DESC
`);

    res.json({
      success: true,
      protocols: result.rows.map((row) => ({
        protocol: row.protocol,
        total: Number(row.total)
      }))
    });
  } catch (error) {
    console.error("Protocol analytics error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to retrieve protocol analytics"
    });
  }
};


// 3. Alert severity distribution
export const getSeverityAnalytics = async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        severity,
        COUNT(*) AS total
      FROM alerts
      GROUP BY severity
      ORDER BY severity ASC
    `);

    const severityNames = {
      1: "High",
      2: "Medium",
      3: "Low"
    };

    res.json({
      success: true,
      severity: result.rows.map((row) => ({
        level: Number(row.severity),
        label: severityNames[Number(row.severity)] || "Unknown",
        total: Number(row.total)
      }))
    });
  } catch (error) {
    console.error("Severity analytics error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to retrieve severity analytics"
    });
  }
};


// 4. Network activity timeline (last 24 hours)
export const getTimelineAnalytics = async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        time_bucket.hour,
        COUNT(events.id) AS total
      FROM generate_series(
        date_trunc('hour', NOW()) - INTERVAL '23 hours',
        date_trunc('hour', NOW()),
        INTERVAL '1 hour'
      ) AS time_bucket(hour)
      LEFT JOIN network_events events
        ON date_trunc('hour', events.event_timestamp) = time_bucket.hour
      GROUP BY time_bucket.hour
      ORDER BY time_bucket.hour ASC
    `);

    res.json({
      success: true,
      period: "Last 24 hours",
      timeline: result.rows.map((row) => ({
        time: row.hour,
        total: Number(row.total)
      }))
    });
  } catch (error) {
    console.error("Timeline analytics error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to retrieve network timeline"
    });
  }
};


// 5. Top source IP addresses
export const getTopIPAnalytics = async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        source_ip::TEXT AS source_ip,
        COUNT(*) AS total
      FROM network_events
      WHERE source_ip IS NOT NULL
      GROUP BY source_ip
      ORDER BY total DESC
      LIMIT 10
    `);

    res.json({
      success: true,
      topSourceIPs: result.rows.map((row) => ({
        sourceIP: row.source_ip,
        total: Number(row.total)
      }))
    });
  } catch (error) {
    console.error("Top IP analytics error:", error);
    res.status(500).json({
      success: false,
      message: "Unable to retrieve top source IP analytics"
    });
  }
};
