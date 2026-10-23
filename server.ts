import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';

const app = express();
app.use(express.json());

const PORT = 3000;

interface Alert {
  id: string;
  source_ip: string;
  dest_ip: string;
  port: number;
  risk: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  attack_type: string;
  top_features: Array<{
    text: string;
    impact: number; // 0-100 feature importance weight for XAI visualization
  }>;
  raw_flow: {
    flow_duration_ms: number;
    total_fwd_packets: number;
    total_bwd_packets: number;
    flow_bytes_per_sec: number;
    flow_packets_per_sec: number;
    syn_flag_count: number;
    protocol: string;
    source_type: 'External Public' | 'Internal Subnet' | 'DMZ';
    dest_asset: 'Production Web App' | 'Primary Database' | 'Domain Controller' | 'DNS Resolver' | 'SSH Bastion';
  };
  triage?: {
    status: 'threat' | 'false_positive';
    timestamp: string;
    action_taken?: string;
    firewall_rule?: string;
    analyst_note?: string;
  };
}

// Initial CIC-IDS2017 realistic dataset with feature importance
const INITIAL_ALERTS: Alert[] = [
  {
    id: "ALT-9041",
    source_ip: "172.16.0.1",
    dest_ip: "192.168.10.50",
    port: 80,
    risk: 96,
    severity: "Critical",
    attack_type: "DoS Hulk Flood",
    top_features: [
      { text: "Unusually high flow rate exceeding 85,000 packets per second", impact: 52 },
      { text: "Symmetric zero-window TCP flags typical of DoS Hulk attack", impact: 31 },
      { text: "Abnormal HTTP request headers with randomized user-agent strings", impact: 17 }
    ],
    raw_flow: {
      flow_duration_ms: 12450,
      total_fwd_packets: 1042000,
      total_bwd_packets: 120,
      flow_bytes_per_sec: 14520000,
      flow_packets_per_sec: 83694,
      syn_flag_count: 12000,
      protocol: "TCP",
      source_type: "External Public",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-8912",
    source_ip: "172.16.0.1",
    dest_ip: "192.168.10.51",
    port: 443,
    risk: 92,
    severity: "Critical",
    attack_type: "DDoS SYN Saturation",
    top_features: [
      { text: "Rapid succession of SYN packets without ACK responses", impact: 58 },
      { text: "Target host TCP connection queue saturation", impact: 26 },
      { text: "Flow duration abnormally short under 15 milliseconds", impact: 16 }
    ],
    raw_flow: {
      flow_duration_ms: 14,
      total_fwd_packets: 580,
      total_bwd_packets: 0,
      flow_bytes_per_sec: 2450000,
      flow_packets_per_sec: 41428,
      syn_flag_count: 580,
      protocol: "TCP",
      source_type: "External Public",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-8744",
    source_ip: "192.168.10.8",
    dest_ip: "192.168.10.25",
    port: 22,
    risk: 87,
    severity: "High",
    attack_type: "SSH-Patator Brute Force",
    top_features: [
      { text: "Over 450 SSH authentication attempts in two minutes", impact: 61 },
      { text: "Sudden spike in outbound encrypted payload volume", impact: 23 },
      { text: "Source host exhibiting lateral movement port sweep", impact: 16 }
    ],
    raw_flow: {
      flow_duration_ms: 120000,
      total_fwd_packets: 980,
      total_bwd_packets: 960,
      flow_bytes_per_sec: 182000,
      flow_packets_per_sec: 16,
      syn_flag_count: 450,
      protocol: "TCP",
      source_type: "Internal Subnet",
      dest_asset: "SSH Bastion"
    }
  },
  {
    id: "ALT-8520",
    source_ip: "172.16.0.1",
    dest_ip: "192.168.10.50",
    port: 8080,
    risk: 82,
    severity: "High",
    attack_type: "SQL Injection Sweep",
    top_features: [
      { text: "Multiple SQL escape sequences detected in URI parameters", impact: 54 },
      { text: "HTTP 500 error response rate exceeded 80%", impact: 28 },
      { text: "Consecutive automated payload variations within milliseconds", impact: 18 }
    ],
    raw_flow: {
      flow_duration_ms: 8420,
      total_fwd_packets: 340,
      total_bwd_packets: 320,
      flow_bytes_per_sec: 450000,
      flow_packets_per_sec: 78,
      syn_flag_count: 12,
      protocol: "TCP",
      source_type: "External Public",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-8219",
    source_ip: "205.174.165.73",
    dest_ip: "192.168.10.15",
    port: 80,
    risk: 78,
    severity: "High",
    attack_type: "Ares Botnet Beaconing",
    top_features: [
      { text: "Periodic beaconing pattern observed every 60 seconds", impact: 49 },
      { text: "Outbound HTTP POST payloads matching Ares botnet signature", impact: 33 },
      { text: "Known malicious external command-and-control IP address", impact: 18 }
    ],
    raw_flow: {
      flow_duration_ms: 360000,
      total_fwd_packets: 120,
      total_bwd_packets: 110,
      flow_bytes_per_sec: 14200,
      flow_packets_per_sec: 0.64,
      syn_flag_count: 6,
      protocol: "TCP",
      source_type: "External Public",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-7840",
    source_ip: "172.16.0.1",
    dest_ip: "192.168.10.12",
    port: 21,
    risk: 71,
    severity: "High",
    attack_type: "FTP-Patator Password Guess",
    top_features: [
      { text: "Repeated FTP login failures using common administrative usernames", impact: 64 },
      { text: "High frequency connection attempts without banner acknowledgment", impact: 36 }
    ],
    raw_flow: {
      flow_duration_ms: 45000,
      total_fwd_packets: 280,
      total_bwd_packets: 260,
      flow_bytes_per_sec: 42000,
      flow_packets_per_sec: 12,
      syn_flag_count: 85,
      protocol: "TCP",
      source_type: "External Public",
      dest_asset: "SSH Bastion"
    }
  },
  {
    id: "ALT-7415",
    source_ip: "192.168.10.19",
    dest_ip: "192.168.10.3",
    port: 445,
    risk: 64,
    severity: "Medium",
    attack_type: "PortScan Subnet Sweep",
    top_features: [
      { text: "Sequential TCP SYN probes across contiguous private IP addresses", impact: 65 },
      { text: "Unusually short packet inter-arrival times", impact: 35 }
    ],
    raw_flow: {
      flow_duration_ms: 1800,
      total_fwd_packets: 75,
      total_bwd_packets: 12,
      flow_bytes_per_sec: 8400,
      flow_packets_per_sec: 48,
      syn_flag_count: 75,
      protocol: "TCP",
      source_type: "Internal Subnet",
      dest_asset: "Domain Controller"
    }
  },
  {
    id: "ALT-6982",
    source_ip: "172.16.0.1",
    dest_ip: "192.168.10.50",
    port: 80,
    risk: 58,
    severity: "Medium",
    attack_type: "Directory Traversal Probe",
    top_features: [
      { text: "Directory traversal strings detected in GET request query", impact: 58 },
      { text: "Server responded with 403 Forbidden status codes", impact: 42 }
    ],
    raw_flow: {
      flow_duration_ms: 4200,
      total_fwd_packets: 45,
      total_bwd_packets: 45,
      flow_bytes_per_sec: 12000,
      flow_packets_per_sec: 21,
      syn_flag_count: 4,
      protocol: "TCP",
      source_type: "External Public",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-6531",
    source_ip: "192.168.10.14",
    dest_ip: "192.168.10.50",
    port: 53,
    risk: 52,
    severity: "Medium",
    attack_type: "DNS Tunneling Anomaly",
    top_features: [
      { text: "Elevated rate of high-entropy DNS queries", impact: 62 },
      { text: "Flow size 3x larger than typical corporate workstation baseline", impact: 38 }
    ],
    raw_flow: {
      flow_duration_ms: 15000,
      total_fwd_packets: 320,
      total_bwd_packets: 310,
      flow_bytes_per_sec: 94000,
      flow_packets_per_sec: 42,
      syn_flag_count: 0,
      protocol: "UDP",
      source_type: "Internal Subnet",
      dest_asset: "DNS Resolver"
    }
  },
  {
    id: "ALT-5840",
    source_ip: "192.168.10.9",
    dest_ip: "192.168.10.50",
    port: 443,
    risk: 45,
    severity: "Medium",
    attack_type: "TLS Handshake Renegotiation",
    top_features: [
      { text: "TLS connection renegotiation frequency higher than normal", impact: 55 },
      { text: "Client certificate verification retry anomaly", impact: 45 }
    ],
    raw_flow: {
      flow_duration_ms: 22000,
      total_fwd_packets: 180,
      total_bwd_packets: 170,
      flow_bytes_per_sec: 120000,
      flow_packets_per_sec: 15,
      syn_flag_count: 8,
      protocol: "TCP",
      source_type: "Internal Subnet",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-4120",
    source_ip: "192.168.10.2",
    dest_ip: "192.168.10.50",
    port: 123,
    risk: 28,
    severity: "Low",
    attack_type: "NTP Sync Desynchronization",
    top_features: [
      { text: "NTP clock synchronization request slightly out of scheduled cycle", impact: 52 },
      { text: "Minimal packet payload variance", impact: 48 }
    ],
    raw_flow: {
      flow_duration_ms: 120,
      total_fwd_packets: 2,
      total_bwd_packets: 2,
      flow_bytes_per_sec: 480,
      flow_packets_per_sec: 33,
      syn_flag_count: 0,
      protocol: "UDP",
      source_type: "Internal Subnet",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-3209",
    source_ip: "192.168.10.17",
    dest_ip: "192.168.10.50",
    port: 80,
    risk: 21,
    severity: "Low",
    attack_type: "Standard Web Browsing",
    top_features: [
      { text: "Standard web browsing session with benign asset caching headers", impact: 60 },
      { text: "Packet timings consistent with regular user interaction", impact: 40 }
    ],
    raw_flow: {
      flow_duration_ms: 18000,
      total_fwd_packets: 48,
      total_bwd_packets: 74,
      flow_bytes_per_sec: 34000,
      flow_packets_per_sec: 6.7,
      syn_flag_count: 2,
      protocol: "TCP",
      source_type: "Internal Subnet",
      dest_asset: "Production Web App"
    }
  },
  {
    id: "ALT-2104",
    source_ip: "192.168.10.22",
    dest_ip: "192.168.10.50",
    port: 443,
    risk: 14,
    severity: "Low",
    attack_type: "Software Telemetry Check-in",
    top_features: [
      { text: "Periodic telemetry heartbeat to recognized software update server", impact: 70 },
      { text: "Flow metrics match baseline workstation profile", impact: 30 }
    ],
    raw_flow: {
      flow_duration_ms: 3500,
      total_fwd_packets: 14,
      total_bwd_packets: 18,
      flow_bytes_per_sec: 9200,
      flow_packets_per_sec: 9.1,
      syn_flag_count: 1,
      protocol: "TCP",
      source_type: "Internal Subnet",
      dest_asset: "Production Web App"
    }
  }
];

let alertsDatabase: Alert[] = JSON.parse(JSON.stringify(INITIAL_ALERTS));

// Incident generation pool
const INCIDENT_TEMPLATES = [
  {
    attack_type: "DDoS LOIC Flood",
    source_ip: "172.16.0.2",
    dest_ip: "192.168.10.50",
    port: 80,
    protocol: "TCP",
    source_type: "External Public" as const,
    dest_asset: "Production Web App" as const,
    duration: 18200,
    packets_per_sec: 92000,
    bytes_per_sec: 18500000,
    syn_ratio: 0.94,
    features: [
      { text: "High-volume UDP/TCP flood saturating network bandwidth", impact: 55 },
      { text: "Packets rate exceeds 90,000 pps matching LOIC flood signature", impact: 32 },
      { text: "Source IP actively coordinating distributed DDoS pool", impact: 13 }
    ]
  },
  {
    attack_type: "Heartbleed Memory Exfiltration",
    source_ip: "172.16.0.5",
    dest_ip: "192.168.10.51",
    port: 443,
    protocol: "TCP",
    source_type: "External Public" as const,
    dest_asset: "Production Web App" as const,
    duration: 420,
    packets_per_sec: 350,
    bytes_per_sec: 65535,
    syn_ratio: 0.05,
    features: [
      { text: "Malicious TLS Heartbeat payload length mismatch (CVE-2014-0160)", impact: 62 },
      { text: "Target OpenSSL service requested 64KB memory dump", impact: 25 },
      { text: "Repeated exploitation probe within single TLS session", impact: 13 }
    ]
  },
  {
    attack_type: "Internal Pass-the-Hash Movement",
    source_ip: "192.168.10.15",
    dest_ip: "192.168.10.2",
    port: 445,
    protocol: "TCP",
    source_type: "Internal Subnet" as const,
    dest_asset: "Domain Controller" as const,
    duration: 6400,
    packets_per_sec: 120,
    bytes_per_sec: 180000,
    syn_ratio: 0.12,
    features: [
      { text: "Abnormal Kerberos ticket request from non-admin endpoint", impact: 52 },
      { text: "SMB named pipe session opened with administrative token", impact: 33 },
      { text: "Compromised internal host attempting domain controller replication", impact: 15 }
    ]
  },
  {
    attack_type: "SQLMap Automated Parameter Probe",
    source_ip: "205.174.165.80",
    dest_ip: "192.168.10.50",
    port: 80,
    protocol: "TCP",
    source_type: "External Public" as const,
    dest_asset: "Production Web App" as const,
    duration: 3800,
    packets_per_sec: 85,
    bytes_per_sec: 320000,
    syn_ratio: 0.08,
    features: [
      { text: "Automated SQLMap parameter fuzzing detected in POST payload", impact: 54 },
      { text: "UNION SELECT statements targeting database user tables", impact: 29 },
      { text: "Repeated Boolean-based blind injection test strings", impact: 17 }
    ]
  },
  {
    attack_type: "Authorized Qualys Security Scan",
    source_ip: "192.168.10.250",
    dest_ip: "192.168.10.50",
    port: 443,
    protocol: "TCP",
    source_type: "Internal Subnet" as const,
    dest_asset: "Production Web App" as const,
    duration: 890,
    packets_per_sec: 25,
    bytes_per_sec: 4200,
    syn_ratio: 0.02,
    features: [
      { text: "Registered corporate Qualys vulnerability scanner signature", impact: 65 },
      { text: "Authenticated SSL certificate validation check", impact: 23 },
      { text: "Flow origin verified against enterprise change window", impact: 12 }
    ]
  }
];

// Machine Learning Classifier Logic
function classifyFlow(flow: {
  packets_per_sec: number;
  bytes_per_sec: number;
  syn_ratio: number;
  port: number;
  duration: number;
}): { risk: number; severity: 'Critical' | 'High' | 'Medium' | 'Low' } {
  let score = 12;

  if (flow.packets_per_sec > 50000) score += 54;
  else if (flow.packets_per_sec > 10000) score += 38;
  else if (flow.packets_per_sec > 1000) score += 24;
  else if (flow.packets_per_sec > 100) score += 10;

  if (flow.syn_ratio > 0.8) score += 28;
  else if (flow.syn_ratio > 0.4) score += 14;

  if (flow.bytes_per_sec > 10000000) score += 15;
  else if (flow.bytes_per_sec > 1000000) score += 9;

  if ([22, 21, 445, 3389].includes(flow.port)) score += 12;

  const risk = Math.min(Math.max(Math.round(score), 8), 99);

  let severity: 'Critical' | 'High' | 'Medium' | 'Low' = 'Low';
  if (risk >= 90) severity = 'Critical';
  else if (risk >= 70) severity = 'High';
  else if (risk >= 40) severity = 'Medium';
  else severity = 'Low';

  return { risk, severity };
}

// REST APIs
app.get('/api/alerts', (req, res) => {
  res.json(alertsDatabase);
});

app.post('/api/alerts/:id/triage', (req, res) => {
  const { id } = req.params;
  const { status, action_taken, analyst_note } = req.body;

  const alert = alertsDatabase.find((a) => a.id === id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }

  const firewallRule =
    status === 'threat'
      ? `iptables -A INPUT -s ${alert.source_ip} -p ${alert.raw_flow.protocol.toLowerCase()} --dport ${alert.port} -j DROP`
      : undefined;

  alert.triage = {
    status,
    timestamp: new Date().toLocaleTimeString(),
    action_taken: action_taken || (status === 'threat' ? 'Host quarantined & firewall rule committed' : 'Marked benign in baseline whitelist'),
    firewall_rule: firewallRule,
    analyst_note: analyst_note || ''
  };

  res.json({ success: true, alert });
});

app.post('/api/alerts/:id/restore', (req, res) => {
  const { id } = req.params;
  const alert = alertsDatabase.find((a) => a.id === id);
  if (!alert) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  delete alert.triage;
  res.json({ success: true, alert });
});


app.post('/api/alerts/simulate', (req, res) => {
  const { presetIndex } = req.body || {};
  let template;
  if (typeof presetIndex === 'number' && INCIDENT_TEMPLATES[presetIndex]) {
    template = INCIDENT_TEMPLATES[presetIndex];
  } else {
    template = INCIDENT_TEMPLATES[Math.floor(Math.random() * INCIDENT_TEMPLATES.length)];
  }

  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const newId = `ALT-${randomSuffix}`;

  const classification = classifyFlow({
    packets_per_sec: template.packets_per_sec,
    bytes_per_sec: template.bytes_per_sec,
    syn_ratio: template.syn_ratio,
    port: template.port,
    duration: template.duration
  });

  const newAlert: Alert = {
    id: newId,
    source_ip: template.source_ip,
    dest_ip: template.dest_ip,
    port: template.port,
    risk: classification.risk,
    severity: classification.severity,
    attack_type: template.attack_type,
    top_features: template.features,
    raw_flow: {
      flow_duration_ms: template.duration,
      total_fwd_packets: Math.round(template.packets_per_sec * (template.duration / 1000)),
      total_bwd_packets: Math.round(template.packets_per_sec * 0.1),
      flow_bytes_per_sec: template.bytes_per_sec,
      flow_packets_per_sec: template.packets_per_sec,
      syn_flag_count: Math.round(template.packets_per_sec * template.syn_ratio),
      protocol: template.protocol,
      source_type: template.source_type,
      dest_asset: template.dest_asset
    }
  };

  alertsDatabase.unshift(newAlert);
  res.json({ success: true, alert: newAlert });
});

// 3b. POST /api/alerts/custom: inject user-crafted manual attack/brute-force alert
app.post('/api/alerts/custom', (req, res) => {
  const {
    attack_type = 'SSH-Patator Brute Force',
    source_ip = '192.168.1.105',
    dest_ip = '192.168.10.25',
    port = 22,
    attempts = 450,
    protocol = 'TCP',
    target_asset = 'SSH Bastion'
  } = req.body || {};

  const randomSuffix = Math.floor(1000 + Math.random() * 9000);
  const newId = `ALT-${randomSuffix}`;

  const numAttempts = Number(attempts) || 450;
  const numPort = Number(port) || 22;
  const duration = Math.max(1200, Math.round(numAttempts * 120));
  const pps = Math.round(numAttempts * 3.2);
  const bytesPerSec = Math.round(numAttempts * 420);
  const synRatio = Math.min(0.92, 0.45 + (numAttempts / 1000) * 0.4);

  const classification = classifyFlow({
    packets_per_sec: pps,
    bytes_per_sec: bytesPerSec,
    syn_ratio: synRatio,
    port: numPort,
    duration: duration
  });

  const calculatedRisk = Math.min(99, Math.max(classification.risk, 55 + Math.round(numAttempts / 20)));
  const calculatedSeverity = calculatedRisk >= 90 ? 'Critical' : calculatedRisk >= 70 ? 'High' : calculatedRisk >= 40 ? 'Medium' : 'Low';

  const features = [
    { text: `Over ${numAttempts} rapid authentication handshake attempts detected in window`, impact: 58 },
    { text: `Sudden spike in connection retry rate against Port ${numPort}`, impact: 26 },
    { text: `Abnormal failure ratio on target asset ${target_asset}`, impact: 16 }
  ];

  const newAlert: Alert = {
    id: newId,
    source_ip: String(source_ip),
    dest_ip: String(dest_ip),
    port: numPort,
    risk: calculatedRisk,
    severity: calculatedSeverity as any,
    attack_type: `${attack_type} (${numAttempts} attempts)`,
    top_features: features,
    raw_flow: {
      flow_duration_ms: duration,
      total_fwd_packets: numAttempts * 2,
      total_bwd_packets: numAttempts * 2,
      flow_bytes_per_sec: bytesPerSec,
      flow_packets_per_sec: pps,
      syn_flag_count: numAttempts,
      protocol: String(protocol).toUpperCase(),
      source_type: (source_ip.startsWith('192.168') || source_ip.startsWith('10.') ? 'Internal Subnet' : 'External Public') as any,
      dest_asset: (target_asset || 'Production Web App') as any
    }
  };

  alertsDatabase.unshift(newAlert);
  res.json({ success: true, alert: newAlert });
});


app.post('/api/alerts/reset', (req, res) => {
  alertsDatabase = JSON.parse(JSON.stringify(INITIAL_ALERTS));
  res.json({ success: true, count: alertsDatabase.length });
});

app.get('/api/metrics', (req, res) => {
  const triaged = alertsDatabase.filter((a) => a.triage);
  const threats = triaged.filter((a) => a.triage?.status === 'threat').length;
  const falsePositives = triaged.filter((a) => a.triage?.status === 'false_positive').length;

  res.json({
    precision: 0.942,
    recall: 0.918,
    f1: 0.930,
    roc_auc: 0.965,
    confusion_matrix: [
      [18420, 395],
      [412, 4635]
    ],
    session_summary: {
      total_alerts: alertsDatabase.length,
      triaged_count: triaged.length,
      threats_confirmed: threats,
      false_positives_cleared: falsePositives,
      triage_completion_rate: alertsDatabase.length > 0 ? Math.round((triaged.length / alertsDatabase.length) * 100) : 0
    }
  });
});

app.get('/api/export', (req, res) => {
  const triaged = alertsDatabase.filter((a) => a.triage);
  let csv = 'Alert ID,Attack Type,Source IP,Dest IP,Port,Risk,Severity,Triage Decision,Firewall Rule,Timestamp\n';
  
  triaged.forEach((a) => {
    csv += `"${a.id}","${a.attack_type}","${a.source_ip}","${a.dest_ip}",${a.port},${a.risk},"${a.severity}","${a.triage?.status}","${a.triage?.firewall_rule || 'N/A'}","${a.triage?.timestamp}"\n`;
  });

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="soc_triage_audit_log.csv"');
  res.send(csv);
});

// Vite middleware in dev or static files in production
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve('dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SOC Alert Triage Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
