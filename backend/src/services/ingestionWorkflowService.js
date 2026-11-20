
/**
 * NetSentinel - Centralized Ingestion Workflow
 *
 * Coordinates:
 * 1. Suricata log ingestion
 * 2. Behavioral detection
 * 3. Persistent alert deduplication
 *
 * Both automatic and manual ingestion must use this service.
 */

import crypto from 'crypto';

import pool from '../config/db.js';

import { importSuricataLogs } from './suricataService.js';

import {
  detectPortScans,
  detectHighConnectionRate
} from './behavioralDetectionService.js';

const LOCK_NAMESPACE = 74129;
const LOCK_ID = 1;

const MAX_FLOW_RECORDS = 20000;
const MAX_ANALYSIS_WINDOW_SECONDS = 3600;


// --------------------------------------------------
// INGESTION SESSION STATISTICS
// --------------------------------------------------

const ingestionSessionStats = {
  totalImportedEvents: 0,
  totalImportedAlerts: 0,
  ingestionErrors: 0,
  lastImportedEvents: 0,
  lastChecked: null,
  lastSuccessfulIngestion: null,
  ingestionInProgress: false
};

export const getIngestionStats = () => ({
  ...ingestionSessionStats
});

/**
 * Generate a deterministic SHA-256 fingerprint.
 */
const generateFingerprint = (ruleId, finding) => {
  const identity = JSON.stringify([
    ruleId,
    finding.attackType,
    finding.sourceIp,
    finding.destinationIp,
    finding.protocol,
    finding.firstSeen,
    finding.detectedAt
  ]);

  return crypto
    .createHash('sha256')
    .update(identity)
    .digest('hex');
};

/**
 * Run the appropriate behavioral detector.
 */
const runDetection = (flowEvents, rule) => {
  const ruleName = String(rule.rule_name || '')
    .trim()
    .toLowerCase();

  if (ruleName === 'port scan detection') {
    return detectPortScans(flowEvents, rule);
  }

  if (ruleName === 'high connection rate') {
    return detectHighConnectionRate(flowEvents, rule);
  }

  return [];
};

/**
 * Save behavioral findings into PostgreSQL.
 */
const persistBehavioralFindings = async (
  client,
  findings,
  rule
) => {
  const insertedAlerts = [];

  for (const finding of findings) {
    const fingerprint = generateFingerprint(
      rule.id,
      finding
    );

    const result = await client.query(
      `
        INSERT INTO alerts (
          network_event_id,
          source_ip,
          destination_ip,
          attack_type,
          signature,
          severity,
          description,
          detection_method,
          deduplication_key
        )
        VALUES (
          $1, $2, $3, $4, $5,
          $6, $7, $8, $9
        )
        ON CONFLICT (deduplication_key)
        WHERE deduplication_key IS NOT NULL
        DO NOTHING
        RETURNING *
      `,
      [
        finding.networkEventId,
        finding.sourceIp,
        finding.destinationIp,
        finding.attackType,
        finding.signature,
        finding.severity,
        finding.description,
        finding.detectionMethod,
        fingerprint
      ]
    );

    if (result.rowCount > 0) {
      insertedAlerts.push(result.rows[0]);
    }
  }

  return insertedAlerts;
};

/**
 * Run behavioral analysis using recent PostgreSQL flows.
 */
const analyzeRecentFlows = async (client) => {
  const rulesResult = await client.query(`
    SELECT
      id,
      rule_name,
      attack_type,
      detection_method,
      threshold,
      time_window_seconds,
      severity,
      enabled
    FROM detection_rules
    WHERE enabled = TRUE
      AND LOWER(detection_method) = 'behavioral'
    ORDER BY id
  `);

  const rules = rulesResult.rows;

  if (rules.length === 0) {
    return [];
  }

  const maxWindowSeconds = Math.min(
    MAX_ANALYSIS_WINDOW_SECONDS,
    Math.max(
      ...rules.map((rule) =>
        Number(rule.time_window_seconds) || 0
      )
    )
  );

  if (maxWindowSeconds <= 0) {
    return [];
  }

  const flowResult = await client.query(
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
        raw_event->>'flow_id' AS flow_id,
        raw_event
      FROM network_events
      WHERE event_type = 'flow'
        AND event_timestamp >=
          NOW() - ($1::int * INTERVAL '1 second')
      ORDER BY event_timestamp ASC, id ASC
      LIMIT $2
    `,
    [maxWindowSeconds, MAX_FLOW_RECORDS]
  );

  const flowEvents = flowResult.rows;

  const insertedAlerts = [];

  for (const rule of rules) {
    const findings = runDetection(flowEvents, rule);

    if (findings.length === 0) {
      continue;
    }

    const newAlerts = await persistBehavioralFindings(
      client,
      findings,
      rule
    );

    insertedAlerts.push(...newAlerts);
  }

  return insertedAlerts;
};

/**
 * Main centralized ingestion function.
 *
 * Uses a session-level PostgreSQL advisory lock
 * to prevent automatic/manual ingestion overlap.
 */

export const runIngestionWorkflow = async () => {
  ingestionSessionStats.lastChecked = new Date().toISOString();

  const client = await pool.connect();

  let lockAcquired = false;

  try {
    const lockResult = await client.query(
      `
        SELECT pg_try_advisory_lock($1, $2) AS locked
      `,
      [LOCK_NAMESPACE, LOCK_ID]
    );

    lockAcquired = lockResult.rows[0].locked;

    if (!lockAcquired) {
      return {
        success: true,
        skipped: true,
        reason: 'Another ingestion workflow is already running.',
        eventsImported: 0,
        alertsImported: 0,
        behavioralAlertsImported: 0,
        importedEvents: [],
        importedAlerts: []
      };
    }

    ingestionSessionStats.ingestionInProgress = true;

    // Step 1: Import Suricata events.
    const ingestionResult = await importSuricataLogs();

    const importedEvents =
      ingestionResult.importedEvents || [];

    const importedAlerts =
      ingestionResult.importedAlerts || [];

    // Step 2: Analyze recent flows.
    const behavioralAlerts =
      await analyzeRecentFlows(client);

    // Step 3: Combine newly created alerts.
    const allImportedAlerts = [
      ...importedAlerts,
      ...behavioralAlerts
    ];

    const eventsImported = importedEvents.length;
    const alertsImported = allImportedAlerts.length;

    // Step 4: Update session statistics.
    ingestionSessionStats.totalImportedEvents +=
      eventsImported;

    ingestionSessionStats.totalImportedAlerts +=
      alertsImported;

    ingestionSessionStats.lastImportedEvents =
      eventsImported;

    ingestionSessionStats.lastSuccessfulIngestion =
      new Date().toISOString();

    return {
      ...ingestionResult,

      skipped: false,

      eventsImported,

      alertsImported,

      behavioralAlertsImported: behavioralAlerts.length,

      importedEvents,

      importedAlerts: allImportedAlerts
    };

  } catch (error) {
    ingestionSessionStats.ingestionErrors += 1;
    throw error;

  } finally {
    ingestionSessionStats.ingestionInProgress = false;

    try {
      if (lockAcquired) {
        await client.query(
          `
            SELECT pg_advisory_unlock($1, $2)
          `,
          [LOCK_NAMESPACE, LOCK_ID]
        );
      }
    } finally {
      client.release();
    }
  }
};

