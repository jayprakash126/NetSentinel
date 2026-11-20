
import pool from "../config/db.js";

// Get network events with pagination and filtering
export const getNetworkEvents = async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);

    const requestedLimit = parseInt(req.query.limit, 10) || 20;
    const limit = Math.min(100, Math.max(1, requestedLimit));

    const offset = (page - 1) * limit;

    const { event_type, protocol, search } = req.query;

    const conditions = [];
    const values = [];

    // Filter by event type
    if (event_type) {
      values.push(event_type);
      conditions.push(`event_type = $${values.length}`);
    }

    // Filter by network protocol
    if (protocol) {
      values.push(protocol);
      conditions.push(`protocol = $${values.length}`);
    }

    // Search by IP address
    if (search) {
      values.push(`%${search}%`);
      const searchIndex = values.length;

      conditions.push(`
        (
          source_ip::TEXT ILIKE $${searchIndex}
          OR destination_ip::TEXT ILIKE $${searchIndex}
        )
      `);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(" AND ")}`
      : "";

    // Get total matching event count
    const countResult = await pool.query(
      `
        SELECT COUNT(*) AS total
        FROM network_events
        ${whereClause}
      `,
      values
    );

    const total = Number(countResult.rows[0].total);

    // Get paginated network events
    const eventValues = [...values, limit, offset];

    const eventsResult = await pool.query(
      `
        SELECT
          id,
          event_type,
          event_timestamp,
          source_ip::TEXT AS source_ip,
          destination_ip::TEXT AS destination_ip,
          source_port,
          destination_port,
          protocol,
          application_protocol,
          raw_event
        FROM network_events
        ${whereClause}
        ORDER BY event_timestamp DESC
        LIMIT $${values.length + 1}
        OFFSET $${values.length + 2}
      `,
      eventValues
    );

    res.status(200).json({
      success: true,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
      events: eventsResult.rows,
    });

  } catch (error) {
    console.error("Network events error:", error);

    res.status(500).json({
      success: false,
      message: "Unable to retrieve network events",
    });
  }
};
