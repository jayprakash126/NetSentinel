
/**
 * NetSentinel - Suricata Log Ingestion Service
 *
 * Reads Suricata EVE JSON logs and stores
 * unique network events and IDS alerts.
 */

import fs from 'fs/promises';
import crypto from 'crypto';
import path from 'path';

import pool from '../config/db.js';

const EVE_FILE = path.resolve(
  process.cwd(),
  '../suricata/logs/eve.json'
);

/**
 * Classify Suricata security alerts.
 */
const getAttackType = (alert) => {
  const signature = String(alert.signature || '')
    .toLowerCase();

  const category = String(alert.category || '')
    .toLowerCase();

  if (
    signature.includes('sql injection') ||
    signature.includes('sqli') ||
    signature.includes('union select') ||
    category.includes('web application attack')
  ) {
    return 'SQL Injection';
  }

  if (signature.includes('dns')) {
    return 'Suspicious DNS Activity';
  }

  if (signature.includes('port scan')) {
    return 'Port Scan';
  }

  if (
    signature.includes('icmp flood') ||
    category.includes('attempted dos')
  ) {
    return 'Denial of Service';
  }

  return alert.category || 'Unknown';
};

/**
 * Import Suricata EVE JSON events.
 */
export const importSuricataLogs = async () => {
  let fileContent;

  try {
    fileContent = await fs.readFile(EVE_FILE, 'utf8');

  } catch (error) {
    if (error.code === 'ENOENT') {
      return {
        success: true,
        fileAvailable: false,
        totalLines: 0,
        eventsImported: 0,
        alertsImported: 0,
        duplicatesSkipped: 0,
        invalidEvents: 0,
        importedEvents: [],
        importedAlerts: []
      };
    }

    throw error;
  }

  const lines = fileContent
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0);

  let eventsImported = 0;
  let alertsImported = 0;
  let duplicatesSkipped = 0;
  let invalidEvents = 0;

  const importedEvents = [];
  const importedAlerts = [];

  const client = await pool.connect();

  let transactionStarted = false;

  try {
    await client.query('BEGIN');

    transactionStarted = true;

    for (const line of lines) {
      let event;

      try {
        event = JSON.parse(line);

      } catch {
        invalidEvents++;
        continue;
      }

      if (!event.event_type || !event.timestamp) {
        invalidEvents++;
        continue;
      }

      const eventHash = crypto
        .createHash('sha256')
        .update(line)
        .digest('hex');

      const eventResult = await client.query(
        `
          INSERT INTO network_events (
            event_type,
            event_timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            application_protocol,
            raw_event,
            event_hash
          )
          VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10
          )
          ON CONFLICT (event_hash) DO NOTHING
          RETURNING
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
        `,
        [
          event.event_type,
          event.timestamp,
          event.src_ip || null,
          event.dest_ip || null,
          event.src_port ?? null,
          event.dest_port ?? null,
          event.proto || null,
          event.app_proto || null,
          JSON.stringify(event),
          eventHash
        ]
      );

      if (eventResult.rowCount === 0) {
        duplicatesSkipped++;
        continue;
      }

      eventsImported++;

      const insertedEvent = eventResult.rows[0];

      importedEvents.push(insertedEvent);

      // Save Suricata-generated alerts.
      if (event.event_type === 'alert' && event.alert) {
        const attackType = getAttackType(event.alert);

        const severity = Number(event.alert.severity);

        const safeSeverity =
          Number.isInteger(severity) &&
          severity >= 1 &&
          severity <= 4
            ? severity
            : 3;

        const alertResult = await client.query(
          `
            INSERT INTO alerts (
              network_event_id,
              source_ip,
              destination_ip,
              attack_type,
              signature,
              severity,
              description,
              detection_method
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
          `,
          [
            insertedEvent.id,
            event.src_ip || null,
            event.dest_ip || null,
            attackType,
            event.alert.signature || 'Unknown signature',
            safeSeverity,
            event.alert.signature || 'Suricata security alert',
            'Suricata IDS'
          ]
        );

        alertsImported++;

        importedAlerts.push(alertResult.rows[0]);
      }
    }

    await client.query('COMMIT');

    transactionStarted = false;

    return {
      success: true,
      fileAvailable: true,
      totalLines: lines.length,
      eventsImported,
      alertsImported,
      duplicatesSkipped,
      invalidEvents,
      importedEvents,
      importedAlerts
    };

  } catch (error) {
    if (transactionStarted) {
      await client.query('ROLLBACK');
    }

    throw error;

  } finally {
    client.release();
  }
};
