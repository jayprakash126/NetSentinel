/**
 * NetSentinel - Main Backend Server
 *
 * Responsibilities:
 * 1. Express REST API
 * 2. Socket.IO real-time communication
 * 3. Automatic Suricata ingestion
 * 4. Behavioral detection workflow
 * 5. Monitoring and health endpoints
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import http from 'http';
import { Server } from 'socket.io';
import fs from 'fs/promises';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import pool from './config/db.js';

import alertRoutes from './routes/alertRoutes.js';
import ingestionRoutes from './routes/ingestionRoutes.js';
import analyticsRoutes from './routes/analyticsRoutes.js';
import networkEventRoutes from './routes/networkEventRoutes.js';

import {
  runIngestionWorkflow,
  getIngestionStats
} from './services/ingestionWorkflowService.js';

dotenv.config();

const execFileAsync = promisify(execFile);
const app = express();
const httpServer = http.createServer(app);

const PORT = Number(process.env.PORT) || 5000;

const FRONTEND_ORIGIN =
  process.env.FRONTEND_URL || 'http://localhost:5173';

const io = new Server(httpServer, {
  cors: {
    origin: FRONTEND_ORIGIN,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
  }
});

app.set('io', io);

app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));

// --------------------------------------------------
// API ROUTES
// --------------------------------------------------

app.use('/api/alerts', alertRoutes);
app.use('/api/ingestion', ingestionRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/network-events', networkEventRoutes);

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get('/', (req, res) => {
  res.json({
    name: 'NetSentinel API',
    status: 'running',
    version: '1.0.0'
  });
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      success: true,
      server: 'online',
      database: 'connected',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(503).json({
      success: false,
      server: 'online',
      database: 'disconnected',
      error: error.message
    });
  }
});

// --------------------------------------------------
// DATABASE TEST
// --------------------------------------------------

app.get('/api/db-test', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        current_database() AS database,
        NOW() AS server_time
    `);

    res.json({
      success: true,
      data: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


const getSuricataProcessStatus = async () => {
  if (process.platform !== 'win32') {
    return {
      status: 'Not Monitored',
      liveCapture: false,
      mode: 'Unsupported platform'
    };
  }

  const script = `
    $ErrorActionPreference = 'Stop'
    @(Get-CimInstance Win32_Process -Filter "Name='suricata.exe'" |
      Select-Object ProcessId, Name, ExecutablePath, CommandLine) |
      ConvertTo-Json -Compress
  `;

  try {
    const { stdout } = await execFileAsync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        script
      ],
      {
        windowsHide: true,
        timeout: 5000,
        maxBuffer: 1024 * 1024
      }
    );

    const output = stdout.trim();

    if (!output) {
      return {
        status: 'Stopped',
        liveCapture: false,
        mode: 'Not Running',
        pid: null
      };
    }

    const parsed = JSON.parse(output);
    const processes = Array.isArray(parsed)
      ? parsed
      : [parsed];

    if (processes.length === 0) {
      return {
        status: 'Stopped',
        liveCapture: false,
        mode: 'Not Running',
        pid: null
      };
    }

    const suricata = processes[0];
    const commandLine = String(
      suricata.CommandLine || ''
    ).toLowerCase();

    const offlineMode =
      /(?:^|\s)-r(?:\s|$)/.test(commandLine) ||
      commandLine.includes('--pcap-file');

    const liveMode =
      /(?:^|\s)-i(?:\s|$)/.test(commandLine) ||
      commandLine.includes('--af-packet');

    let mode = 'Mode Unknown';
    let liveCapture = false;

    if (offlineMode) {
      mode = 'Offline PCAP Processing';
    } else if (liveMode) {
      mode = 'Live Capture';
      liveCapture = true;
    }

    return {
      status: 'Running',
      liveCapture,
      mode,
      pid: suricata.ProcessId,
      executablePath: suricata.ExecutablePath
    };

  } catch (error) {
    console.error(
      '[NetSentinel] Suricata process check failed:',
      error.message
    );

    return {
      status: 'Unknown',
      liveCapture: false,
      mode: 'Unable to inspect process',
      error: error.message
    };
  }
};

// --------------------------------------------------
// MONITORING API
// --------------------------------------------------


app.get('/api/monitoring', async (req, res) => {
  try {
    const [
      eventCount,
      alertCount,
      recentAlerts,
      recentEvents,
      databaseInfo
    ] = await Promise.all([
      pool.query(`
        SELECT COUNT(*)::int AS total
        FROM network_events
      `),

      pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (
            WHERE status = 'new'
          )::int AS new_alerts
        FROM alerts
      `),

      pool.query(`
        SELECT
          id,
          attack_type,
          severity,
          status,
          source_ip::TEXT AS source_ip,
          destination_ip::TEXT AS destination_ip,
          created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT 5
      `),

      pool.query(`
        SELECT
          COUNT(*) FILTER (
            WHERE event_timestamp >= NOW() - INTERVAL '5 minutes'
          )::int AS last_5_minutes,
          COUNT(*) FILTER (
            WHERE event_timestamp >= NOW() - INTERVAL '1 hour'
          )::int AS last_hour
        FROM network_events
      `),

      pool.query(`
        SELECT
          current_database() AS database_name,
          version() AS version
      `)
    ]);

    const eveFile = path.resolve(
      process.cwd(),
      '../suricata/logs/eve.json'
    );

    let eveFileInfo = {
      available: false,
      sizeBytes: null,
      totalLines: 0,
      lastModified: null
    };

    try {
      const fileStats = await fs.stat(eveFile);
      const fileContent = await fs.readFile(eveFile, 'utf8');

      eveFileInfo = {
        available: true,
        sizeBytes: fileStats.size,
        totalLines: fileContent.length === 0
          ? 0
          : fileContent.split(/\r?\n/).filter(Boolean).length,
        lastModified: fileStats.mtime.toISOString()
      };
    } catch (fileError) {
      if (fileError.code !== 'ENOENT') {
        throw fileError;
      }
    }
const suricataProcess = await getSuricataProcessStatus();
    const timestamp = new Date().toISOString();


    res.json({
      success: true,

      backend: {
        status: 'Healthy',
        port: PORT,
        timestamp
      },

      database: {
        status: 'Connected',
        name: databaseInfo.rows[0].database_name,
        version: databaseInfo.rows[0].version,
        statistics: {
          totalNetworkEvents: eventCount.rows[0].total,
          totalAlerts: alertCount.rows[0].total,
          newAlerts: alertCount.rows[0].new_alerts,
          eventsLast5Minutes:
            recentEvents.rows[0].last_5_minutes,
          eventsLastHour:
            recentEvents.rows[0].last_hour
        }
      },

      suricata: {
  status: eveFileInfo.available
    ? 'Log Available'
    : 'Log Missing',

  mode: suricataProcess.mode,

  process: suricataProcess,

  eveFile: eveFileInfo
},

      ingestion: {
  status: ingestionTimer
    ? 'Monitoring Log'
    : 'Stopped',

  intervalSeconds: 5,

  ...getIngestionStats()
},

      recentAlerts: recentAlerts.rows,

      timestamp
    });

  } catch (error) {
    console.error(
      '[NetSentinel] Monitoring endpoint failed:',
      error.message
    );

    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


// --------------------------------------------------
// SOCKET.IO CONNECTION
// --------------------------------------------------

io.on('connection', (socket) => {
  console.log(
    `Frontend connected: ${socket.id}`
  );

  socket.on('disconnect', () => {
    console.log(
      `Frontend disconnected: ${socket.id}`
    );
  });
});

// --------------------------------------------------
// AUTOMATIC INGESTION WORKFLOW
// --------------------------------------------------

let ingestionTimer = null;
let ingestionRunning = false;

const broadcastIngestionResults = (result) => {
  if (!result || result.skipped) {
    return;
  }

  for (const event of result.importedEvents || []) {
    io.emit('network_event:new', event);
  }

  for (const alert of result.importedAlerts || []) {
    io.emit('alert:new', alert);
  }
};

const pollSuricataLogs = async () => {
  if (ingestionRunning) {
    return;
  }

  ingestionRunning = true;

  try {
    const result = await runIngestionWorkflow();

    if (result.skipped) {
      return;
    }

    broadcastIngestionResults(result);

    if (
      result.eventsImported > 0 ||
      result.alertsImported > 0
    ) {
      console.log(
        `[NetSentinel] Events: ${result.eventsImported}, ` +
        `Alerts: ${result.alertsImported}, ` +
        `Behavioral alerts: ${result.behavioralAlertsImported}`
      );
    }

  } catch (error) {
    console.error(
      '[NetSentinel] Automatic ingestion error:',
      error.message
    );

  } finally {
    ingestionRunning = false;
  }
};

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

const startServer = async () => {
  try {
    await pool.query('SELECT 1');

    console.log('[NetSentinel] Database connection successful.');

    httpServer.listen(PORT, () => {
      console.log(
        `[NetSentinel] Backend running at http://localhost:${PORT}`
      );

      console.log(
        `[NetSentinel] Frontend allowed origin: ${FRONTEND_ORIGIN}`
      );

      // Initial ingestion.
      pollSuricataLogs();

      // Repeat ingestion every 5 seconds.
      ingestionTimer = setInterval(
        pollSuricataLogs,
        5000
      );
    });

  } catch (error) {
    console.error(
      '[NetSentinel] Server startup failed:',
      error.message
    );

    process.exitCode = 1;
  }
};

// --------------------------------------------------
// GRACEFUL SHUTDOWN
// --------------------------------------------------

const shutdown = async (signal) => {
  console.log(
    `\n[NetSentinel] Received ${signal}. Shutting down...`
  );

  if (ingestionTimer) {
    clearInterval(ingestionTimer);
  }

  httpServer.close(async () => {
    try {
      await pool.end();

      console.log('[NetSentinel] Shutdown complete.');
      process.exit(0);

    } catch (error) {
      console.error(
        '[NetSentinel] Shutdown error:',
        error.message
      );

      process.exit(1);
    }
  });
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

startServer();