/**
 * NetSentinel - Ingestion Controller
 *
 * Handles manual Suricata log imports through
 * the centralized ingestion workflow.
 */

import { runIngestionWorkflow } from '../services/ingestionWorkflowService.js';

export const ingestSuricataLogs = async (req, res) => {
  try {
    const result = await runIngestionWorkflow();

    if (result.skipped) {
      return res.status(202).json({
        success: true,
        message: result.reason,
        skipped: true
      });
    }

    const io = req.app.get('io');

    // Broadcast newly imported network events.
    if (io && result.importedEvents?.length) {
      for (const event of result.importedEvents) {
        io.emit('network_event:new', event);
      }
    }

    // Broadcast newly created Suricata and behavioral alerts.
    if (io && result.importedAlerts?.length) {
      for (const alert of result.importedAlerts) {
        io.emit('alert:new', alert);
      }
    }

    return res.status(200).json({
      success: true,
      message: 'NetSentinel ingestion workflow completed.',
      eventsImported: result.eventsImported ?? 0,
      alertsImported: result.alertsImported ?? 0,
      behavioralAlertsImported:
        result.behavioralAlertsImported ?? 0,
      duplicatesSkipped: result.duplicatesSkipped ?? 0,
      invalidEvents: result.invalidEvents ?? 0
    });

  } catch (error) {
    console.error(
      'Manual ingestion failed:',
      error.message
    );

    return res.status(500).json({
      success: false,
      message: 'Failed to process Suricata logs.',
      error: error.message
    });
  }
};