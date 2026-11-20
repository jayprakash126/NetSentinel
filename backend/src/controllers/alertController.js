
import pool from '../config/db.js';

export const getAlerts = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      status,
      severity
    } = req.query;

    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const offset = (pageNumber - 1) * pageSize;

    const conditions = [];
    const values = [];

    if (status) {
      values.push(status);
      conditions.push(`status = $${values.length}`);
    }

    if (severity) {
      const severityNumber = Number(severity);

      if (!Number.isInteger(severityNumber) ||
          severityNumber < 1 || severityNumber > 4) {
        return res.status(400).json({
          success: false,
          message: 'Severity must be between 1 and 4'
        });
      }

      values.push(severityNumber);
      conditions.push(`severity = $${values.length}`);
    }

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM alerts ${whereClause}`,
      values
    );

    const dataValues = [...values, pageSize, offset];

    const result = await pool.query(
      `SELECT *
       FROM alerts
       ${whereClause}
       ORDER BY created_at DESC
       LIMIT $${dataValues.length - 1}
       OFFSET $${dataValues.length}`,
      dataValues
    );

    res.json({
      success: true,
      pagination: {
        page: pageNumber,
        limit: pageSize,
        total: Number(countResult.rows[0].count),
        totalPages: Math.ceil(
          Number(countResult.rows[0].count) / pageSize
        )
      },
      alerts: result.rows
    });

  } catch (error) {
    console.error('Error fetching alerts:', error);

    res.status(500).json({
      success: false,
      message: 'Unable to retrieve security alerts'
    });
  }
};

export const updateAlertStatus = async (req, res) => {
  try {
    const alertId = Number(req.params.id);
    const { status } = req.body;

    if (!Number.isInteger(alertId) || alertId <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid alert ID'
      });
    }

    const allowedStatuses = ['acknowledged', 'resolved'];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Status must be acknowledged or resolved'
      });
    }

    const result = await pool.query(
      `UPDATE alerts
       SET status = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [status, alertId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found'
      });
    }

    res.status(200).json({
      success: true,
      message: `Alert successfully marked as ${status}`,
      alert: result.rows[0]
    });

  } catch (error) {
    console.error('Error updating alert status:', error);

    res.status(500).json({
      success: false,
      message: 'Unable to update alert status'
    });
  }
};

