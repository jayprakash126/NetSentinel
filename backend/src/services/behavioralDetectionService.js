/**
 * NetSentinel - Behavioral Detection Service
 *
 * Pure analysis functions.
 * These functions never write to PostgreSQL.
 */

const isValidPort = (port) => {
  const value = Number(port);

  return Number.isInteger(value) &&
    value >= 1 &&
    value <= 65535;
};

const getTimestamp = (value) => {
  const timestamp = new Date(value).getTime();

  return Number.isFinite(timestamp) ? timestamp : null;
};

const getSeverity = (value) => {
  const severity = Number(value);

  return Number.isInteger(severity) &&
    severity >= 1 &&
    severity <= 4
      ? severity
      : 2;
};

const normalizeFlowEvents = (
  flowEvents,
  protocols = ['TCP', 'UDP']
) => {
  if (!Array.isArray(flowEvents)) return [];

  return flowEvents
    .filter((event) => {
      if (!event || typeof event !== 'object') {
        return false;
      }

      const protocol = String(
        event.protocol ?? ''
      ).toUpperCase();

      return (
        event.event_type === 'flow' &&
        typeof event.source_ip === 'string' &&
        event.source_ip.length > 0 &&
        typeof event.destination_ip === 'string' &&
        event.destination_ip.length > 0 &&
        protocols.includes(protocol) &&
        getTimestamp(event.event_timestamp) !== null
      );
    })
    .map((event) => ({
      ...event,
      protocol: String(event.protocol).toUpperCase(),
      timestamp: getTimestamp(event.event_timestamp)
    }))
    .filter((event) => {
      const packetsToServer =
        event.raw_event?.flow?.pkts_toserver;

      return (
        packetsToServer === undefined ||
        Number(packetsToServer) > 0
      );
    })
    .sort((a, b) => a.timestamp - b.timestamp);
};

const getFlowIdentity = (event) => {
  const explicitFlowId =
    event.flow_id ?? event.raw_event?.flow_id;

  if (
    explicitFlowId !== undefined &&
    explicitFlowId !== null &&
    String(explicitFlowId).trim()
  ) {
    return `flow:${String(explicitFlowId)}`;
  }

  if (event.id !== undefined && event.id !== null) {
    return `event:${String(event.id)}`;
  }

  return `tuple:${JSON.stringify([
    event.source_port ?? null,
    event.destination_port ?? null,
    event.timestamp
  ])}`;
};

const deduplicateEvents = (events) => {
  const seen = new Set();

  return events.filter((event) => {
    const identity = getFlowIdentity(event);

    if (seen.has(identity)) return false;

    seen.add(identity);
    return true;
  });
};

/**
 * Detect TCP/UDP scans by distinct destination ports.
 */
export const detectPortScans = (flowEvents, rule) => {
  if (
    !Array.isArray(flowEvents) ||
    !rule ||
    rule.enabled === false
  ) {
    return [];
  }

  const threshold = Number(rule.threshold);
  const windowSeconds = Number(rule.time_window_seconds);

  if (
    !Number.isInteger(threshold) ||
    threshold < 2 ||
    !Number.isFinite(windowSeconds) ||
    windowSeconds <= 0
  ) {
    return [];
  }

  const validEvents = normalizeFlowEvents(flowEvents)
    .filter((event) =>
      isValidPort(event.destination_port)
    )
    .map((event) => ({
      ...event,
      destination_port: Number(event.destination_port)
    }));

  const groups = new Map();

  for (const event of validEvents) {
    const key = JSON.stringify([
      event.source_ip,
      event.destination_ip,
      event.protocol
    ]);

    if (!groups.has(key)) {
      groups.set(key, []);
    }

    groups.get(key).push(event);
  }

  const findings = [];
  const windowMs = windowSeconds * 1000;

  for (const groupedEvents of groups.values()) {
    const events = deduplicateEvents(groupedEvents);

    const portCounts = new Map();

    let left = 0;
    let findingGenerated = false;

    for (
      let right = 0;
      right < events.length;
      right++
    ) {
      const current = events[right];
      const port = current.destination_port;

      portCounts.set(
        port,
        (portCounts.get(port) || 0) + 1
      );

      while (
        left <= right &&
        current.timestamp - events[left].timestamp > windowMs
      ) {
        const oldPort = events[left].destination_port;
        const count = portCounts.get(oldPort);

        if (count === 1) {
          portCounts.delete(oldPort);
        } else {
          portCounts.set(oldPort, count - 1);
        }

        left++;
      }

      if (portCounts.size < threshold) {
        findingGenerated = false;
      }

      if (
        !findingGenerated &&
        portCounts.size >= threshold
      ) {
        const observedPorts = [...portCounts.keys()]
          .sort((a, b) => a - b);

        findings.push({
          attackType: 'Port Scan',

          signature:
            `NetSentinel - Possible ${current.protocol} Port Scan`,

          detectionMethod: 'Behavioral Analysis',

          severity: getSeverity(rule.severity),

          sourceIp: current.source_ip,

          destinationIp: current.destination_ip,

          protocol: current.protocol,

          networkEventId: current.id ?? null,

          threshold,

          timeWindowSeconds: windowSeconds,

          distinctDestinationPorts: observedPorts.length,

          destinationPorts: observedPorts,

          firstSeen: events[left].event_timestamp,

          detectedAt: current.event_timestamp,

          description:
            `Detected ${observedPorts.length} distinct ` +
            `${current.protocol} destination ports from ` +
            `${current.source_ip} to ` +
            `${current.destination_ip} within ` +
            `${windowSeconds} seconds.`
        });

        findingGenerated = true;
      }
    }
  }

  return findings;
};

/**
 * Detect unusually high flow counts per source IP.
 */
export const detectHighConnectionRate = (
  flowEvents,
  rule
) => {
  if (
    !Array.isArray(flowEvents) ||
    !rule ||
    rule.enabled === false
  ) {
    return [];
  }

  const threshold = Number(rule.threshold);
  const windowSeconds = Number(rule.time_window_seconds);

  if (
    !Number.isInteger(threshold) ||
    threshold < 2 ||
    !Number.isFinite(windowSeconds) ||
    windowSeconds <= 0
  ) {
    return [];
  }

  const normalized = deduplicateEvents(
    normalizeFlowEvents(flowEvents)
  );

  const groups = new Map();

  for (const event of normalized) {
    if (!groups.has(event.source_ip)) {
      groups.set(event.source_ip, []);
    }

    groups.get(event.source_ip).push(event);
  }

  const findings = [];
  const windowMs = windowSeconds * 1000;

  for (const [sourceIp, events] of groups.entries()) {
    let left = 0;
    let findingGenerated = false;

    for (
      let right = 0;
      right < events.length;
      right++
    ) {
      const current = events[right];

      while (
        left <= right &&
        current.timestamp - events[left].timestamp > windowMs
      ) {
        left++;
      }

      const activeCount = right - left + 1;

      if (activeCount < threshold) {
        findingGenerated = false;
      }

      if (
        !findingGenerated &&
        activeCount >= threshold
      ) {
        findings.push({
          attackType: 'Suspicious Traffic',

          signature: 'NetSentinel - High Connection Rate',

          detectionMethod: 'Behavioral Analysis',

          severity: getSeverity(rule.severity),

          sourceIp,

          destinationIp: null,

          protocol: 'MULTIPLE',

          networkEventId: current.id ?? null,

          threshold,

          timeWindowSeconds: windowSeconds,

          connectionCount: activeCount,

          firstSeen: events[left].event_timestamp,

          detectedAt: current.event_timestamp,

          description:
            `Detected ${activeCount} flow records from ` +
            `${sourceIp} within ${windowSeconds} seconds, ` +
            `meeting the configured threshold of ${threshold}.`
        });

        findingGenerated = true;
      }
    }
  }

  return findings;
};