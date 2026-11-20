import test from 'node:test';
import assert from 'node:assert/strict';

import {
  detectPortScans,
  detectHighConnectionRate
} from '../src/services/behavioralDetectionService.js';

const createFlow = ({
  id,
  sourceIp = '192.168.1.100',
  destinationIp = '192.168.1.10',
  destinationPort,
  protocol = 'TCP',
  seconds = 0
}) => ({
  id,
  event_type: 'flow',
  event_timestamp: new Date(
    `2026-11-19T10:00:${String(seconds).padStart(2, '0')}.000Z`
  ),
  source_ip: sourceIp,
  destination_ip: destinationIp,
  source_port: 50000 + id,
  destination_port: destinationPort,
  protocol,
  raw_event: {
    flow_id: `flow-${id}`,
    app_proto: 'unknown'
  }
});

test('Detects a TCP port scan', () => {
  const flows = Array.from(
    { length: 10 },
    (_, index) => createFlow({
      id: index + 1,
      destinationPort: 20 + index,
      seconds: index
    })
  );

  const findings = detectPortScans(flows, {
    rule_name: 'Port Scan Detection',
    threshold: 10,
    time_window_seconds: 60,
    severity: 2,
    enabled: true
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].attackType, 'Port Scan');
  assert.equal(findings[0].sourceIp, '192.168.1.100');
  assert.equal(findings[0].protocol, 'TCP');
});

test('Detects a UDP port scan', () => {
  const flows = Array.from(
    { length: 10 },
    (_, index) => createFlow({
      id: index + 1,
      destinationPort: 100 + index,
      protocol: 'UDP',
      seconds: index
    })
  );

  const findings = detectPortScans(flows, {
    rule_name: 'Port Scan Detection',
    threshold: 10,
    time_window_seconds: 60,
    severity: 2,
    enabled: true
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].protocol, 'UDP');
});

test('Does not classify repeated traffic to one port as a port scan', () => {
  const flows = Array.from(
    { length: 15 },
    (_, index) => createFlow({
      id: index + 1,
      destinationPort: 80,
      seconds: index
    })
  );

  const findings = detectPortScans(flows, {
    rule_name: 'Port Scan Detection',
    threshold: 10,
    time_window_seconds: 60,
    severity: 2,
    enabled: true
  });

  assert.equal(findings.length, 0);
});

test('Does not detect a scan when the rule is disabled', () => {
  const flows = Array.from(
    { length: 10 },
    (_, index) => createFlow({
      id: index + 1,
      destinationPort: 200 + index,
      seconds: index
    })
  );

  const findings = detectPortScans(flows, {
    rule_name: 'Port Scan Detection',
    threshold: 10,
    time_window_seconds: 60,
    severity: 2,
    enabled: false
  });

  assert.equal(findings.length, 0);
});

test('Detects a high connection rate', () => {
  const flows = Array.from(
    { length: 10 },
    (_, index) => createFlow({
      id: index + 1,
      destinationPort: 443,
      destinationIp: `192.168.1.${index + 10}`,
      seconds: index
    })
  );

  const findings = detectHighConnectionRate(flows, {
    rule_name: 'High Connection Rate',
    threshold: 10,
    time_window_seconds: 60,
    severity: 2,
    enabled: true
  });

  assert.equal(findings.length, 1);
  assert.equal(
    findings[0].attackType,
    'Suspicious Traffic'
  );
  assert.equal(findings[0].sourceIp, '192.168.1.100');
});

test('Ignores duplicate flow records', () => {
  const original = createFlow({
    id: 1,
    destinationPort: 22,
    seconds: 1
  });

  const duplicate = {
    ...original,
    id: 999
  };

  const findings = detectPortScans(
    [
      ...Array.from(
        { length: 9 },
        (_, index) => createFlow({
          id: index + 2,
          destinationPort: 30 + index,
          seconds: index + 2
        })
      ),
      original,
      duplicate
    ],
    {
      rule_name: 'Port Scan Detection',
      threshold: 10,
      time_window_seconds: 60,
      severity: 2,
      enabled: true
    }
  );

  assert.equal(findings.length, 1);
});

test('Handles empty input safely', () => {
  assert.deepEqual(
    detectPortScans([], {
      rule_name: 'Port Scan Detection',
      threshold: 10,
      time_window_seconds: 60,
      severity: 2,
      enabled: true
    }),
    []
  );

  assert.deepEqual(
    detectHighConnectionRate([], {
      rule_name: 'High Connection Rate',
      threshold: 10,
      time_window_seconds: 60,
      severity: 2,
      enabled: true
    }),
    []
  );
});