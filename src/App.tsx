import { useState, useEffect, useRef, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  ArrowRight,
  Download,
  RefreshCw,
  Play,
  Pause,
  Terminal,
  Copy,
  Check,
  Search,
  Keyboard,
  Server,
  Activity,
  ChevronDown,
  ChevronUp,
  Radio,
  SlidersHorizontal,
  X,
  History,
  Inbox,
  Undo2,
  BarChart3,
  Clock,
  Zap,
  Sparkles
} from 'lucide-react';

type Severity = 'Critical' | 'High' | 'Medium' | 'Low';
type FilterType = 'All' | Severity;
type TriageStatus = 'threat' | 'false_positive';
type ActiveTab = 'queue' | 'history' | 'accuracy';

interface FeatureIndicator {
  text: string;
  impact?: number;
}

interface RawFlowMetrics {
  flow_duration_ms: number;
  total_fwd_packets: number;
  total_bwd_packets: number;
  flow_bytes_per_sec: number;
  flow_packets_per_sec: number;
  syn_flag_count: number;
  protocol: string;
  source_type?: 'External Public' | 'Internal Subnet' | 'DMZ';
  dest_asset?: 'Production Web App' | 'Primary Database' | 'Domain Controller' | 'DNS Resolver' | 'SSH Bastion';
}

interface Alert {
  id: string;
  source_ip: string;
  dest_ip: string;
  port: number;
  risk: number;
  severity: Severity;
  attack_type?: string;
  top_features: Array<string | FeatureIndicator>;
  raw_flow?: RawFlowMetrics;
  triage?: {
    status: TriageStatus;
    timestamp: string;
    action_taken?: string;
    firewall_rule?: string;
    analyst_note?: string;
  };
}

interface Metrics {
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number;
  confusion_matrix?: number[][];
  session_summary?: {
    total_alerts: number;
    triaged_count: number;
    threats_confirmed: number;
    false_positives_cleared: number;
    triage_completion_rate: number;
  };
}

const STORAGE_KEY = 'soc_liquid_glass_triage_v4';

const ATTACK_PRESETS = [
  { label: 'DoS Hulk Flood', index: 0, severity: 'Critical' },
  { label: 'Heartbleed TLS', index: 1, severity: 'Critical' },
  { label: 'Pass-the-Hash', index: 2, severity: 'Medium' },
  { label: 'SQLMap Probe', index: 3, severity: 'High' },
  { label: 'Qualys Scanner', index: 4, severity: 'Low' }
];

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [currentTab, setCurrentTab] = useState<ActiveTab>('queue');
  const [filter, setFilter] = useState<FilterType>('All');
  const [historyFilter, setHistoryFilter] = useState<'All' | 'threat' | 'false_positive'>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Stored triage records (persisted across refresh)
  const [triagedHistory, setTriagedHistory] = useState<Record<string, {
    alert: Alert;
    status: TriageStatus;
    timestamp: string;
    action: string;
    rule?: string;
  }>>({});

  const [notification, setNotification] = useState<{ message: string; type: 'threat' | 'fp' | 'info' } | null>(null);
  const [showRawFlow, setShowRawFlow] = useState<boolean>(false);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);
  const [showShortcutsModal, setShowShortcutsModal] = useState<boolean>(false);
  const [showPresetsBar, setShowPresetsBar] = useState<boolean>(false);
  const [showAttackCrafterModal, setShowAttackCrafterModal] = useState<boolean>(false);
  const [attackForm, setAttackForm] = useState({
    attack_type: 'SSH-Patator Brute Force',
    source_ip: '192.168.1.105',
    dest_ip: '192.168.10.25',
    port: 22,
    attempts: 450,
    protocol: 'TCP',
    target_asset: 'SSH Bastion'
  });
  const [isExecutingAttack, setIsExecutingAttack] = useState<boolean>(false);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [copiedCurl, setCopiedCurl] = useState<boolean>(false);
  const [crafterTab, setCrafterTab] = useState<'gui' | 'cli'>('gui');

  const streamIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Restore history from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setTriagedHistory(JSON.parse(stored));
      }
    } catch {
      // Storage fallback
    }
  }, []);

  // Fetch initial data
  const fetchData = async () => {
    try {
      const [alertsRes, metricsRes] = await Promise.all([
        fetch('/api/alerts').catch(() => fetch('/data/alerts.json')),
        fetch('/api/metrics').catch(() => fetch('/data/metrics.json'))
      ]);

      if (alertsRes && alertsRes.ok) {
        const data: Alert[] = await alertsRes.json();
        setAlerts(data);
      }

      if (metricsRes && metricsRes.ok) {
        const data: Metrics = await metricsRes.json();
        setMetrics(data);
      }
    } catch (e) {
      console.error('Failed to load initial data:', e);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Active untriaged alerts
  const activeQueue = useMemo(() => {
    return alerts
      .filter((alert) => !triagedHistory[alert.id])
      .sort((a, b) => b.risk - a.risk);
  }, [alerts, triagedHistory]);

  // Triaged alerts history list
  const historyList = useMemo(() => {
    return Object.values(triagedHistory).sort((a, b) => {
      return (b.alert.risk || 0) - (a.alert.risk || 0);
    });
  }, [triagedHistory]);

  // Filtered queue
  const filteredQueue = useMemo(() => {
    return activeQueue.filter((item) => {
      const matchesFilter = filter === 'All' ? true : item.severity === filter;
      if (!matchesFilter) return false;

      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        item.source_ip.toLowerCase().includes(q) ||
        item.dest_ip.toLowerCase().includes(q) ||
        item.port.toString().includes(q) ||
        item.attack_type?.toLowerCase().includes(q) ||
        item.id.toLowerCase().includes(q)
      );
    });
  }, [activeQueue, filter, searchQuery]);

  // Filtered history list
  const filteredHistory = useMemo(() => {
    return historyList.filter((item) => {
      if (historyFilter !== 'All' && item.status !== historyFilter) return false;
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return (
        item.alert.source_ip.toLowerCase().includes(q) ||
        item.alert.dest_ip.toLowerCase().includes(q) ||
        item.alert.port.toString().includes(q) ||
        item.alert.attack_type?.toLowerCase().includes(q) ||
        item.alert.id.toLowerCase().includes(q)
      );
    });
  }, [historyList, historyFilter, searchQuery]);

  // Auto-select first active alert when queue changes
  useEffect(() => {
    if (activeQueue.length > 0) {
      if (!selectedId || !activeQueue.some((a) => a.id === selectedId)) {
        setSelectedId(activeQueue[0].id);
      }
    } else {
      setSelectedId(null);
    }
  }, [activeQueue, selectedId]);

  // Currently selected alert in active queue
  const selectedAlert = useMemo(() => {
    return activeQueue.find((a) => a.id === selectedId) || activeQueue[0] || null;
  }, [activeQueue, selectedId]);

  // Live traffic stream handler
  useEffect(() => {
    if (isStreaming) {
      streamIntervalRef.current = setInterval(async () => {
        try {
          const res = await fetch('/api/alerts/simulate', { method: 'POST' });
          if (res.ok) {
            const result = await res.json();
            if (result.alert) {
              setAlerts((prev) => [result.alert, ...prev]);
            }
          }
        } catch {
          // ignore stream error
        }
      }, 5000);
    } else {
      if (streamIntervalRef.current) {
        clearInterval(streamIntervalRef.current);
        streamIntervalRef.current = null;
      }
    }

    return () => {
      if (streamIntervalRef.current) {
        clearInterval(streamIntervalRef.current);
      }
    };
  }, [isStreaming]);

  // Triage alert: moves to history, vanishes from queue
  const handleTriageAlert = async (status: TriageStatus) => {
    if (!selectedAlert) return;

    const alertToTriage = selectedAlert;
    const protocol = (alertToTriage.raw_flow?.protocol || 'TCP').toLowerCase();
    const firewallRule =
      status === 'threat'
        ? `iptables -A INPUT -s ${alertToTriage.source_ip} -p ${protocol} --dport ${alertToTriage.port} -j DROP`
        : undefined;

    const actionTaken =
      status === 'threat'
        ? 'Firewall containment rule committed & IP quarantined'
        : 'Whitelisted from intrusion baseline model';

    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // 1. Update history map (removes from active queue)
    const newHistory = {
      ...triagedHistory,
      [alertToTriage.id]: {
        alert: alertToTriage,
        status,
        timestamp,
        action: actionTaken,
        rule: firewallRule
      }
    };

    setTriagedHistory(newHistory);

    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newHistory));
    } catch {
      // Local storage fallback
    }

    // 2. Select next alert
    const remainingInFilter = filteredQueue.filter((a) => a.id !== alertToTriage.id);
    if (remainingInFilter.length > 0) {
      setSelectedId(remainingInFilter[0].id);
    } else {
      const remainingGlobal = activeQueue.filter((a) => a.id !== alertToTriage.id);
      setSelectedId(remainingGlobal.length > 0 ? remainingGlobal[0].id : null);
    }

    // 3. Notification banner
    setNotification({
      message:
        status === 'threat'
          ? `${alertToTriage.id} quarantined as Threat · Moved to History`
          : `${alertToTriage.id} whitelisted as False Positive · Moved to History`,
      type: status === 'threat' ? 'threat' : 'fp'
    });

    setTimeout(() => {
      setNotification((curr) => (curr?.message.includes(alertToTriage.id) ? null : curr));
    }, 3500);

    // 4. Send backend sync
    try {
      await fetch(`/api/alerts/${alertToTriage.id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status,
          action_taken: actionTaken
        })
      });

      const metricsRes = await fetch('/api/metrics');
      if (metricsRes.ok) {
        const metricsData = await metricsRes.json();
        setMetrics(metricsData);
      }
    } catch {
      // Backend error fallback
    }
  };

  // Restore from history back to queue
  const handleRestoreAlert = async (id: string) => {
    const updatedHistory = { ...triagedHistory };
    delete updatedHistory[id];

    setTriagedHistory(updatedHistory);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updatedHistory));
    } catch {
      // Local storage fallback
    }

    setSelectedId(id);
    setNotification({
      message: `${id} restored to Active Queue`,
      type: 'info'
    });

    try {
      await fetch(`/api/alerts/${id}/restore`, { method: 'POST' });
    } catch {
      // Fallback
    }
  };

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      if (currentTab === 'queue' && selectedAlert) {
        if (e.key === 't' || e.key === 'T') {
          e.preventDefault();
          handleTriageAlert('threat');
        } else if (e.key === 'f' || e.key === 'F') {
          e.preventDefault();
          handleTriageAlert('false_positive');
        } else if (e.key === 'ArrowDown' || e.key === 'j' || e.key === 'J') {
          e.preventDefault();
          const currentIndex = filteredQueue.findIndex((a) => a.id === selectedAlert?.id);
          if (currentIndex < filteredQueue.length - 1) {
            setSelectedId(filteredQueue[currentIndex + 1].id);
          }
        } else if (e.key === 'ArrowUp' || e.key === 'k' || e.key === 'K') {
          e.preventDefault();
          const currentIndex = filteredQueue.findIndex((a) => a.id === selectedAlert?.id);
          if (currentIndex > 0) {
            setSelectedId(filteredQueue[currentIndex - 1].id);
          }
        }
      }

      if (e.key === '1') setCurrentTab('queue');
      if (e.key === '2') setCurrentTab('history');
      if (e.key === '3') setCurrentTab('accuracy');
      if (e.key === '?') setShowShortcutsModal((prev) => !prev);
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedAlert, filteredQueue, currentTab, triagedHistory]);

  // Ingest attack flow
  const handleSimulateNewFlow = async (presetIndex?: number) => {
    setIsSimulating(true);
    try {
      const res = await fetch('/api/alerts/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ presetIndex })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.alert) {
          setAlerts((prev) => [data.alert, ...prev]);
          setSelectedId(data.alert.id);
          setCurrentTab('queue');
          setNotification({
            message: `New incident classified: ${data.alert.attack_type || data.alert.id} (${data.alert.severity})`,
            type: 'info'
          });
        }
      }
    } catch {
      // Fail gracefully
    } finally {
      setIsSimulating(false);
    }
  };

  // Reset demo
  const handleResetDemo = async () => {
    try {
      await fetch('/api/alerts/reset', { method: 'POST' });
      localStorage.removeItem(STORAGE_KEY);
      setTriagedHistory({});
      setNotification({ message: 'Reset demo: Baseline queue restored.', type: 'info' });
      await fetchData();
    } catch {
      localStorage.removeItem(STORAGE_KEY);
      setTriagedHistory({});
      setNotification({ message: 'Reset: Local queue and history cleared.', type: 'info' });
    }
  };

  // Launch manual live attack/brute force
  const handleLaunchCustomAttack = async () => {
    setIsExecutingAttack(true);
    setTerminalLogs([
      `[ATTACK INITIALIZED] Target: ${attackForm.dest_ip}:${attackForm.port} (${attackForm.target_asset})`,
      `[SPOOFED ORIGIN] Source IP: ${attackForm.source_ip} | Protocol: ${attackForm.protocol}`,
      `[DICTIONARY SPRAY] Loaded 10,000 common credentials (rockyou.txt)...`,
    ]);

    setTimeout(() => {
      setTerminalLogs((prev) => [
        ...prev,
        `[BURST] Spraying ${attackForm.attempts} credential combinations across ${attackForm.port}...`,
        `[AUTH FAILED] User: 'admin' | Response: 401 Unauthorized`,
        `[AUTH FAILED] User: 'root' | Response: 401 Unauthorized`,
        `[AUTH FAILED] User: 'ubuntu' | Response: 401 Unauthorized`,
      ]);
    }, 350);

    setTimeout(async () => {
      try {
        setTerminalLogs((prev) => [
          ...prev,
          `[FLOW THRESHOLD EXCEEDED] ${attackForm.attempts} handshakes rejected!`,
          `[IDS CLASSIFIER] Feeding raw telemetry into CIC-IDS2017 detection engine...`,
        ]);

        const res = await fetch('/api/alerts/custom', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(attackForm)
        });

        if (res.ok) {
          const data = await res.json();
          if (data.alert) {
            setAlerts((prev) => [data.alert, ...prev]);
            setSelectedId(data.alert.id);
            setCurrentTab('queue');
            setTerminalLogs((prev) => [
              ...prev,
              `[SUCCESS] Ingested ${data.alert.id} with Risk ${data.alert.risk}/100 (${data.alert.severity})!`,
            ]);

            setNotification({
              message: `⚡ Live Attack Ingested: ${data.alert.attack_type} -> Risk ${data.alert.risk}/100 (${data.alert.severity})`,
              type: 'threat'
            });

            setTimeout(() => {
              setIsExecutingAttack(false);
              setShowAttackCrafterModal(false);
            }, 900);
          }
        }
      } catch {
        setIsExecutingAttack(false);
      }
    }, 850);
  };

  const handleGenerateRandomIP = () => {
    const octet1 = Math.floor(Math.random() * 2) === 0 ? '192.168.1' : '10.0.4';
    const octet2 = Math.floor(10 + Math.random() * 240);
    setAttackForm((prev) => ({ ...prev, source_ip: `${octet1}.${octet2}` }));
  };

  const handleCopyFirewallRule = (id: string, ruleText: string) => {
    navigator.clipboard.writeText(ruleText);
    setCopiedRuleId(id);
    setTimeout(() => setCopiedRuleId(null), 2000);
  };

  // Liquid glass color mapping
  const getSeverityGlassBadge = (severity: Severity) => {
    switch (severity) {
      case 'Critical':
        return 'text-rose-300 bg-rose-500/20 border-rose-500/40 shadow-xs shadow-rose-500/30';
      case 'High':
        return 'text-amber-300 bg-amber-500/20 border-amber-500/40 shadow-xs shadow-amber-500/30';
      case 'Medium':
        return 'text-cyan-300 bg-cyan-500/20 border-cyan-500/40 shadow-xs shadow-cyan-500/30';
      case 'Low':
        return 'text-slate-300 bg-slate-500/20 border-slate-400/30';
      default:
        return 'text-slate-300 bg-slate-500/20 border-slate-400/30';
    }
  };

  const filterOptions: FilterType[] = ['All', 'Critical', 'High', 'Medium', 'Low'];
  const threatHistoryCount = historyList.filter((h) => h.status === 'threat').length;
  const fpHistoryCount = historyList.filter((h) => h.status === 'false_positive').length;

  return (
    <div className="min-h-screen bg-[#080c16] text-slate-100 flex flex-col justify-between selection:bg-cyan-500 selection:text-black relative overflow-hidden">
      {/* 1. AMBIENT LIQUID ORBS (LIQUID CHROMATIC BACKGROUND) */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        {/* Top-left Cyan Glow */}
        <div className="absolute -top-32 -left-32 w-[520px] h-[520px] bg-cyan-500/18 rounded-full blur-[140px] animate-liquid-1" />
        {/* Center-right Violet-Indigo Glow */}
        <div className="absolute top-1/4 -right-32 w-[600px] h-[600px] bg-indigo-600/22 rounded-full blur-[160px] animate-liquid-2" />
        {/* Bottom-left Ruby Glow */}
        <div className="absolute -bottom-40 left-1/3 w-[500px] h-[500px] bg-rose-600/15 rounded-full blur-[150px] animate-liquid-1" />
      </div>

      {/* Main Glass Shell Container */}
      <div className="max-w-7xl w-full mx-auto px-4 py-6 sm:px-8 sm:py-7 flex-1 flex flex-col relative z-10">
        {/* TOP LIQUID GLASS COMMAND HEADER */}
        <header className="glass-panel rounded-2xl p-4 sm:p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/30 via-indigo-500/20 to-rose-500/30 border border-white/20 flex items-center justify-center shadow-lg shadow-cyan-500/15">
              <ShieldAlert className="w-5 h-5 text-cyan-300" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
                  SOC Alert Triage
                </h1>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs shadow-cyan-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  CIC-IDS2017 Live Feed
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Liquid Glass Security Console &amp; Automated Threat Containment
              </p>
            </div>
          </div>

          {/* Quick Action Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Live Attack Crafter Trigger */}
            <button
              onClick={() => {
                setShowAttackCrafterModal(true);
                setTerminalLogs([]);
              }}
              className="px-3.5 py-1.5 text-xs font-bold rounded-xl bg-gradient-to-r from-rose-500 via-pink-500 to-amber-500 text-white shadow-md shadow-rose-500/25 hover:brightness-110 transition-all flex items-center gap-1.5 border border-rose-400/40 cursor-pointer"
              title="Launch a live manual brute force or custom network attack"
            >
              <Zap className="w-3.5 h-3.5 fill-white" />
              <span>Craft Live Attack</span>
            </button>

            <button
              onClick={() => setShowPresetsBar(!showPresetsBar)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl border transition-all flex items-center gap-1.5 ${
                showPresetsBar
                  ? 'bg-cyan-500 text-slate-950 border-cyan-400 shadow-md shadow-cyan-500/30 font-bold'
                  : 'glass-button text-slate-200 hover:text-white'
              }`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <span>Simulate Attack</span>
            </button>

            <button
              onClick={() => handleSimulateNewFlow()}
              disabled={isSimulating}
              className="glass-button px-3 py-1.5 text-xs font-semibold rounded-xl text-slate-200 hover:text-white transition-all flex items-center gap-1.5 disabled:opacity-50"
            >
              <Activity className={`w-3.5 h-3.5 text-cyan-400 ${isSimulating ? 'animate-spin' : ''}`} />
              <span>{isSimulating ? 'Classifying...' : '+ Ingest Flow'}</span>
            </button>

            <button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl border transition-all flex items-center gap-1.5 ${
                isStreaming
                  ? 'bg-rose-500/25 text-rose-300 border-rose-500/50 shadow-md shadow-rose-500/20'
                  : 'glass-button text-slate-200 hover:text-white'
              }`}
            >
              {isStreaming ? (
                <>
                  <Pause className="w-3.5 h-3.5 text-rose-400" />
                  <span>Streaming Active</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-slate-400" />
                  <span>Live Stream</span>
                </>
              )}
            </button>

            <a
              href="/api/export"
              className="glass-button px-3 py-1.5 text-xs font-semibold rounded-xl text-slate-200 hover:text-white transition-all flex items-center gap-1.5"
              title="Download audit CSV report"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export CSV</span>
            </a>

            <button
              onClick={() => setShowShortcutsModal(true)}
              className="glass-button p-2 text-slate-300 hover:text-white rounded-xl transition-all"
              title="Hotkeys (T: Threat, F: False positive, 1: Queue, 2: History)"
            >
              <Keyboard className="w-4 h-4" />
            </button>

            <button
              onClick={handleResetDemo}
              className="glass-button p-2 text-slate-400 hover:text-white rounded-xl transition-all"
              title="Reset queue and history back to fresh baseline"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </header>

        {/* NOTIFICATION TOAST */}
        {notification && (
          <div
            className={`mt-4 py-3 px-4 rounded-xl text-xs font-medium border backdrop-blur-xl flex items-center justify-between gap-3 shadow-lg animate-in fade-in slide-in-from-top-2 duration-200 ${
              notification.type === 'threat'
                ? 'bg-rose-950/70 text-rose-200 border-rose-500/50 shadow-rose-500/10'
                : notification.type === 'fp'
                ? 'bg-slate-900/80 text-cyan-200 border-cyan-500/40 shadow-cyan-500/10'
                : 'bg-indigo-950/70 text-indigo-200 border-indigo-500/40 shadow-indigo-500/10'
            }`}
          >
            <div className="flex items-center gap-2.5">
              {notification.type === 'threat' ? (
                <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              )}
              <span>{notification.message}</span>
            </div>
            <button
              onClick={() => setNotification(null)}
              className="text-slate-400 hover:text-white text-base leading-none"
            >
              &times;
            </button>
          </div>
        )}

        {/* EXPANDABLE PRESET ATTACK INJECTOR (LIQUID GLASS BAR) */}
        {showPresetsBar && (
          <div className="mt-4 p-4 glass-panel rounded-2xl flex flex-wrap items-center justify-between gap-3 animate-in fade-in duration-150">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-400/80 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" />
                Inject Scenario:
              </span>
              <div className="flex flex-wrap items-center gap-2">
                {ATTACK_PRESETS.map((preset) => (
                  <button
                    key={preset.label}
                    onClick={() => handleSimulateNewFlow(preset.index)}
                    className="px-3 py-1 text-xs font-medium rounded-lg glass-button text-slate-200 hover:text-white transition-all flex items-center gap-1.5"
                  >
                    <span
                      className={`w-2 h-2 rounded-full ${
                        preset.severity === 'Critical'
                          ? 'bg-rose-400 shadow-xs shadow-rose-400'
                          : preset.severity === 'High'
                          ? 'bg-amber-400 shadow-xs shadow-amber-400'
                          : preset.severity === 'Medium'
                          ? 'bg-cyan-400 shadow-xs shadow-cyan-400'
                          : 'bg-slate-400'
                      }`}
                    />
                    <span>{preset.label}</span>
                  </button>
                ))}
              </div>
            </div>
            <button
              onClick={() => setShowPresetsBar(false)}
              className="text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* MAIN NAVIGATION TABS (LIQUID GLASS PILL BAR) */}
        <div className="mt-5 glass-panel rounded-2xl p-1.5 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            {/* 1. Active Queue Tab */}
            <button
              onClick={() => setCurrentTab('queue')}
              className={`px-4 py-2 text-xs font-bold rounded-xl transition-all flex items-center gap-2 ${
                currentTab === 'queue'
                  ? 'bg-gradient-to-r from-cyan-500/25 to-indigo-500/25 text-white border border-cyan-400/40 shadow-sm shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <Inbox className="w-4 h-4 text-cyan-400" />
              <span>Active Queue</span>
              <span
                className={`px-2 py-0.5 rounded-full text-[10px] tabular-nums font-extrabold ${
                  activeQueue.length > 0
                    ? 'bg-cyan-500 text-slate-950'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {activeQueue.length}
              </span>
            </button>

            {/* 2. Triage History Tab */}
            <button
              onClick={() => setCurrentTab('history')}
              className={`px-4 py-2 text-xs font-bold rounded-xl transition-all flex items-center gap-2 ${
                currentTab === 'history'
                  ? 'bg-gradient-to-r from-cyan-500/25 to-indigo-500/25 text-white border border-cyan-400/40 shadow-sm shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <History className="w-4 h-4 text-indigo-400" />
              <span>Triage History</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] tabular-nums font-bold bg-white/10 text-slate-200 border border-white/10">
                {historyList.length}
              </span>
            </button>

            {/* 3. Model Accuracy Tab */}
            <button
              onClick={() => setCurrentTab('accuracy')}
              className={`px-4 py-2 text-xs font-bold rounded-xl transition-all flex items-center gap-2 ${
                currentTab === 'accuracy'
                  ? 'bg-gradient-to-r from-cyan-500/25 to-indigo-500/25 text-white border border-cyan-400/40 shadow-sm shadow-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <BarChart3 className="w-4 h-4 text-emerald-400" />
              <span>Model Accuracy</span>
              <span className="text-[10px] font-mono text-cyan-300/80 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">
                94.2%
              </span>
            </button>
          </div>

          {/* Quick Metrics Ticker */}
          <div className="hidden sm:flex items-center gap-4 text-xs text-slate-400 pr-3">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-500 shadow-xs shadow-rose-500" />
              <span>Quarantined: </span>
              <span className="font-bold text-rose-300 tabular-nums">{threatHistoryCount}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-slate-400" />
              <span>Whitelisted: </span>
              <span className="font-bold text-slate-200 tabular-nums">{fpHistoryCount}</span>
            </span>
          </div>
        </div>

        {/* TAB 1: ACTIVE QUEUE (INBOX ZERO SPLIT VIEW) */}
        {currentTab === 'queue' && (
          <div className="mt-5 grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1">
            {/* LEFT: ALERT QUEUE */}
            <div className="lg:col-span-5 flex flex-col space-y-3">
              {/* Filter controls & Search */}
              <div className="glass-panel rounded-2xl p-3.5 space-y-3">
                {/* Severity Pills */}
                <div className="flex items-center gap-1.5 overflow-x-auto pb-0.5">
                  {filterOptions.map((item) => {
                    const count =
                      item === 'All'
                        ? activeQueue.length
                        : activeQueue.filter((a) => a.severity === item).length;

                    return (
                      <button
                        key={item}
                        onClick={() => setFilter(item)}
                        className={`px-3 py-1.5 text-xs font-bold rounded-xl whitespace-nowrap transition-all flex items-center gap-1.5 ${
                          filter === item
                            ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/25'
                            : 'glass-panel-subtle text-slate-300 hover:text-white hover:bg-white/10'
                        }`}
                      >
                        <span>{item}</span>
                        <span className="text-[10px] opacity-80 tabular-nums">({count})</span>
                      </button>
                    );
                  })}
                </div>

                {/* Search */}
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search active IP, port, or attack type..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full text-xs bg-black/30 border border-white/15 rounded-xl pl-8 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-cyan-400/80 focus:ring-1 focus:ring-cyan-400/30 transition-all"
                  />
                </div>
              </div>

              {/* Alert List Rows */}
              <div className="flex-1 space-y-2.5 overflow-y-auto max-h-[calc(100vh-320px)] pr-1">
                {activeQueue.length === 0 ? (
                  <div className="glass-panel p-8 text-center rounded-2xl space-y-3">
                    <div className="w-12 h-12 rounded-2xl bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center justify-center mx-auto shadow-lg shadow-emerald-500/20">
                      <CheckCircle2 className="w-6 h-6" />
                    </div>
                    <div>
                      <h3 className="text-base font-bold text-white">
                        Queue Cleared (Inbox Zero)
                      </h3>
                      <p className="text-xs text-slate-400 mt-1 max-w-xs mx-auto">
                        All incoming intrusion alerts have been triaged. View History or simulate a new live flow.
                      </p>
                    </div>
                    <div className="flex items-center justify-center gap-2 pt-2">
                      <button
                        onClick={() => setCurrentTab('history')}
                        className="px-3.5 py-2 text-xs font-bold rounded-xl glass-button text-slate-200 hover:text-white transition-all"
                      >
                        View History ({historyList.length})
                      </button>
                      <button
                        onClick={() => handleSimulateNewFlow()}
                        className="px-3.5 py-2 text-xs font-bold rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-500 text-slate-950 hover:brightness-110 shadow-lg shadow-cyan-500/25 transition-all"
                      >
                        + Ingest Incident
                      </button>
                    </div>
                  </div>
                ) : filteredQueue.length === 0 ? (
                  <div className="glass-panel p-8 text-center text-xs text-slate-400 rounded-2xl">
                    No active alerts match current filter or search criteria.
                  </div>
                ) : (
                  filteredQueue.map((alert) => {
                    const isSelected = selectedAlert?.id === alert.id;

                    return (
                      <button
                        key={alert.id}
                        onClick={() => setSelectedId(alert.id)}
                        className={`w-full text-left p-3.5 rounded-2xl border transition-all flex items-center justify-between gap-3 ${
                          isSelected
                            ? 'glass-panel bg-white/[0.08] border-cyan-400/60 shadow-lg shadow-cyan-500/15 ring-1 ring-cyan-400/30'
                            : 'glass-panel-subtle hover:bg-white/[0.07] hover:border-white/20'
                        }`}
                      >
                        {/* Left: Risk Score and Attack Info */}
                        <div className="flex items-center gap-3">
                          <div className="flex flex-col items-center justify-center w-11 h-11 rounded-xl bg-black/40 border border-white/10 shrink-0">
                            <span className="text-base font-black tabular-nums text-white leading-none">
                              {alert.risk}
                            </span>
                            <span className="text-[9px] text-cyan-300 font-bold mt-0.5 tracking-wider">
                              RISK
                            </span>
                          </div>

                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span
                                className={`text-[10px] font-bold px-2 py-0.5 rounded-md border ${getSeverityGlassBadge(
                                  alert.severity
                                )}`}
                              >
                                {alert.severity}
                              </span>
                              <span className="text-xs font-bold text-white truncate">
                                {alert.attack_type || alert.id}
                              </span>
                            </div>
                            <div className="text-[11px] font-mono text-slate-400 mt-1 flex items-center gap-1.5">
                              <span>{alert.source_ip}:{alert.port}</span>
                              <span className="text-slate-600">&rarr;</span>
                              <span>{alert.dest_ip}:{alert.port}</span>
                            </div>
                          </div>
                        </div>

                        {/* Right: ID & Tag */}
                        <div className="text-right shrink-0">
                          <span className="text-[10px] text-slate-400 font-mono block">
                            {alert.id}
                          </span>
                          <span className="text-[10px] text-amber-300 bg-amber-500/15 px-2 py-0.5 rounded-md border border-amber-500/30 font-semibold mt-1 inline-block">
                            Untriaged
                          </span>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </div>

            {/* RIGHT: INCIDENT INVESTIGATION & RESPONSE COCKPIT */}
            <div className="lg:col-span-7">
              {selectedAlert ? (
                <div className="glass-panel rounded-2xl p-6 sm:p-7 space-y-6">
                  {/* Top Bar: Alert ID, Severity, Risk Gauge */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-white/10">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-cyan-300 bg-cyan-500/15 px-2 py-0.5 rounded border border-cyan-500/30">
                          {selectedAlert.id}
                        </span>
                        <span
                          className={`text-xs font-bold px-2.5 py-0.5 rounded-md border ${getSeverityGlassBadge(
                            selectedAlert.severity
                          )}`}
                        >
                          {selectedAlert.severity}
                        </span>
                      </div>
                      <h2 className="text-xl font-black text-white mt-1.5 tracking-tight">
                        {selectedAlert.attack_type || 'Unclassified Intrusion Signature'}
                      </h2>
                    </div>

                    {/* Liquid Glass Risk Meter */}
                    <div className="flex items-center gap-3.5 bg-black/40 px-4 py-2.5 rounded-xl border border-white/15 shrink-0 shadow-inner">
                      <div className="text-right">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 block">
                          Assessed Risk
                        </span>
                        <div className="text-2xl font-black tabular-nums text-white leading-tight">
                          {selectedAlert.risk}
                          <span className="text-xs font-normal text-slate-400 ml-0.5">/100</span>
                        </div>
                      </div>
                      <div className="w-2.5 h-10 bg-white/10 rounded-full overflow-hidden flex flex-col justify-end p-0.5 border border-white/10">
                        <div
                          className={`w-full rounded-full transition-all duration-300 ${
                            selectedAlert.risk >= 90
                              ? 'bg-rose-500 shadow-sm shadow-rose-500'
                              : selectedAlert.risk >= 70
                              ? 'bg-amber-500 shadow-sm shadow-amber-500'
                              : selectedAlert.risk >= 40
                              ? 'bg-cyan-400 shadow-sm shadow-cyan-400'
                              : 'bg-slate-400'
                          }`}
                          style={{ height: `${selectedAlert.risk}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Flow Topology Schematic */}
                  <div>
                    <span className="text-xs font-bold uppercase tracking-wider text-cyan-300/80 block mb-2.5">
                      Network Flow Topology
                    </span>
                    <div className="glass-panel-subtle rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
                      {/* Source */}
                      <div className="flex items-center gap-3 w-full sm:w-auto">
                        <div className="w-9 h-9 rounded-xl bg-black/40 border border-white/15 flex items-center justify-center shrink-0 shadow-sm">
                          <Radio className="w-4 h-4 text-cyan-300" />
                        </div>
                        <div>
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">
                            {selectedAlert.raw_flow?.source_type || 'Source Host'}
                          </span>
                          <div className="text-xs font-mono font-bold text-white">
                            {selectedAlert.source_ip}:{selectedAlert.port}
                          </div>
                        </div>
                      </div>

                      {/* Liquid Connection Wire */}
                      <div className="flex flex-col items-center justify-center w-full sm:w-auto px-2">
                        <div className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-300 mb-1">
                          <span>{selectedAlert.raw_flow?.protocol || 'TCP'}</span>
                          <span className="text-slate-600">/</span>
                          <span>Port {selectedAlert.port}</span>
                        </div>
                        <div className="flex items-center gap-1 w-full max-w-[140px]">
                          <div className="h-0.5 flex-1 bg-gradient-to-r from-cyan-400 via-indigo-400 to-rose-400 rounded-full" />
                          <ArrowRight className="w-3.5 h-3.5 text-cyan-300 shrink-0" />
                        </div>
                        {selectedAlert.raw_flow && (
                          <span className="text-[10px] text-slate-400 mt-1 tabular-nums font-mono">
                            {Math.round(selectedAlert.raw_flow.flow_packets_per_sec).toLocaleString()} pps
                          </span>
                        )}
                      </div>

                      {/* Target */}
                      <div className="flex items-center gap-3 w-full sm:w-auto justify-start sm:justify-end text-left sm:text-right">
                        <div className="order-2 sm:order-1">
                          <span className="text-[10px] text-slate-400 block uppercase font-bold">
                            {selectedAlert.raw_flow?.dest_asset || 'Target Asset'}
                          </span>
                          <div className="text-xs font-mono font-bold text-white">
                            {selectedAlert.dest_ip}:{selectedAlert.port}
                          </div>
                        </div>
                        <div className="w-9 h-9 rounded-xl bg-black/40 border border-white/15 flex items-center justify-center shrink-0 order-1 sm:order-2 shadow-sm">
                          <Server className="w-4 h-4 text-indigo-300" />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Explainable Detection Drivers */}
                  <div>
                    <div className="flex items-center justify-between mb-2.5">
                      <span className="text-xs font-bold uppercase tracking-wider text-cyan-300/80">
                        Explainable Detection Drivers
                      </span>
                      <span className="text-[11px] text-slate-400 font-medium">
                        Feature Impact Weight
                      </span>
                    </div>

                    <div className="space-y-2.5">
                      {selectedAlert.top_features.map((feature, idx) => {
                        const text = typeof feature === 'string' ? feature : feature.text;
                        const impact =
                          typeof feature === 'object' && feature.impact !== undefined
                            ? feature.impact
                            : idx === 0
                            ? 55
                            : idx === 1
                            ? 30
                            : 15;

                        return (
                          <div
                            key={idx}
                            className="p-3.5 glass-panel-subtle rounded-xl space-y-2"
                          >
                            <div className="flex items-start justify-between gap-4 text-xs">
                              <span className="text-slate-200 font-medium leading-snug">
                                {text}
                              </span>
                              <span className="text-cyan-300 font-mono text-[11px] tabular-nums font-bold shrink-0">
                                +{impact}%
                              </span>
                            </div>
                            <div className="w-full h-1.5 bg-black/40 rounded-full overflow-hidden p-0.5 border border-white/5">
                              <div
                                className="h-full bg-gradient-to-r from-cyan-400 to-indigo-400 rounded-full transition-all duration-300 shadow-xs shadow-cyan-400"
                                style={{ width: `${impact}%` }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Raw Flow Telemetry */}
                  {selectedAlert.raw_flow && (
                    <div className="pt-2 border-t border-white/10">
                      <button
                        onClick={() => setShowRawFlow(!showRawFlow)}
                        className="text-xs font-bold text-cyan-300 hover:text-cyan-200 transition-colors flex items-center gap-1.5"
                      >
                        {showRawFlow ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        <span>{showRawFlow ? 'Hide' : 'Inspect'} Flow Telemetry (CIC-IDS2017)</span>
                      </button>

                      {showRawFlow && (
                        <div className="mt-3 glass-panel-subtle rounded-xl p-4 text-xs font-mono grid grid-cols-2 sm:grid-cols-3 gap-y-3 gap-x-4 text-slate-300 animate-in fade-in duration-150">
                          <div>
                            <span className="text-slate-500 block font-sans text-[10px]">Flow Duration</span>
                            <span className="font-bold text-white">{selectedAlert.raw_flow.flow_duration_ms.toLocaleString()} ms</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block font-sans text-[10px]">Packet Rate</span>
                            <span className="font-bold text-white">{Math.round(selectedAlert.raw_flow.flow_packets_per_sec).toLocaleString()} pps</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block font-sans text-[10px]">Payload Throughput</span>
                            <span className="font-bold text-white">{(selectedAlert.raw_flow.flow_bytes_per_sec / 1024).toFixed(1)} KB/s</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block font-sans text-[10px]">SYN Flag Count</span>
                            <span className="font-bold text-white">{selectedAlert.raw_flow.syn_flag_count.toLocaleString()}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block font-sans text-[10px]">Forward Packets</span>
                            <span className="font-bold text-white">{selectedAlert.raw_flow.total_fwd_packets.toLocaleString()}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block font-sans text-[10px]">Backward Packets</span>
                            <span className="font-bold text-white">{selectedAlert.raw_flow.total_bwd_packets.toLocaleString()}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* PRIMARY LIQUID TRIAGE ACTION BUTTONS */}
                  <div className="pt-4 border-t border-white/10">
                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                      {/* Mark as Threat: Glowing Liquid Ruby */}
                      <button
                        onClick={() => handleTriageAlert('threat')}
                        className="flex-1 py-3 px-4 text-xs font-bold rounded-xl bg-gradient-to-r from-rose-600 via-rose-500 to-pink-600 hover:brightness-110 text-white shadow-lg shadow-rose-600/30 border border-rose-400/40 transition-all flex items-center justify-center gap-2 group cursor-pointer"
                      >
                        <ShieldAlert className="w-4 h-4 text-rose-100 group-hover:scale-110 transition-transform" />
                        <span>Mark as Threat (Quarantine)</span>
                        <kbd className="text-[10px] font-mono px-1.5 py-0.5 bg-black/30 rounded text-rose-100">T</kbd>
                      </button>

                      {/* Mark as False Positive: Frosted Liquid Glass */}
                      <button
                        onClick={() => handleTriageAlert('false_positive')}
                        className="flex-1 py-3 px-4 text-xs font-bold rounded-xl glass-button hover:bg-white/15 text-slate-100 shadow-md transition-all flex items-center justify-center gap-2 group cursor-pointer"
                      >
                        <ShieldCheck className="w-4 h-4 text-cyan-300 group-hover:scale-110 transition-transform" />
                        <span>Mark as False Positive</span>
                        <kbd className="text-[10px] font-mono px-1.5 py-0.5 bg-white/15 rounded text-slate-200">F</kbd>
                      </button>
                    </div>

                    <p className="text-[11px] text-slate-400 text-center mt-3">
                      Decision removes alert from Active Queue and files it into Triage History.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="glass-panel rounded-2xl p-12 text-center text-sm text-slate-400">
                  Select an alert from the active queue to inspect telemetry.
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: TRIAGE HISTORY (LIQUID GLASS STREAM) */}
        {currentTab === 'history' && (
          <div className="mt-5 space-y-4 flex-1">
            {/* Filter and Search Bar */}
            <div className="glass-panel rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-400/80">
                  Filter Records:
                </span>
                <div className="flex items-center gap-1.5">
                  {(['All', 'threat', 'false_positive'] as const).map((hFilter) => (
                    <button
                      key={hFilter}
                      onClick={() => setHistoryFilter(hFilter)}
                      className={`px-3 py-1.5 text-xs font-bold rounded-xl transition-all ${
                        historyFilter === hFilter
                          ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/25'
                          : 'glass-panel-subtle text-slate-300 hover:text-white hover:bg-white/10'
                      }`}
                    >
                      {hFilter === 'All'
                        ? `All (${historyList.length})`
                        : hFilter === 'threat'
                        ? `Threats (${threatHistoryCount})`
                        : `False Positives (${fpHistoryCount})`}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search history records..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="text-xs bg-black/30 border border-white/15 rounded-xl pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-cyan-400"
                  />
                </div>

                <a
                  href="/api/export"
                  className="px-3.5 py-1.5 text-xs font-bold rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-500 text-slate-950 hover:brightness-110 shadow-md shadow-cyan-500/20 transition-all flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export CSV</span>
                </a>
              </div>
            </div>

            {/* History Records Cards */}
            {filteredHistory.length === 0 ? (
              <div className="glass-panel rounded-2xl p-12 text-center text-sm text-slate-400 space-y-3">
                <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/10 text-slate-400 flex items-center justify-center mx-auto">
                  <History className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">No Triage Records Found</h3>
                  <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                    When you triage alerts in the Active Queue, they will be archived here with containment actions.
                  </p>
                </div>
                <button
                  onClick={() => setCurrentTab('queue')}
                  className="px-4 py-2 text-xs font-bold rounded-xl glass-button text-cyan-300 hover:text-white transition-all"
                >
                  Return to Active Queue
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredHistory.map((item) => (
                  <div
                    key={item.alert.id}
                    className="glass-panel p-5 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all hover:border-cyan-400/40"
                  >
                    {/* Left: Decision Badge, Alert ID, Attack Type */}
                    <div className="flex items-start gap-3.5">
                      <div
                        className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 mt-0.5 border ${
                          item.status === 'threat'
                            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-sm shadow-rose-500/20'
                            : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                        }`}
                      >
                        {item.status === 'threat' ? (
                          <ShieldAlert className="w-5 h-5" />
                        ) : (
                          <ShieldCheck className="w-5 h-5" />
                        )}
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[11px] font-extrabold px-2.5 py-0.5 rounded-md uppercase tracking-wider ${
                              item.status === 'threat'
                                ? 'bg-rose-500/25 text-rose-300 border border-rose-500/40'
                                : 'bg-slate-500/20 text-slate-300 border border-slate-500/30'
                            }`}
                          >
                            {item.status === 'threat' ? 'Threat Blocked' : 'False Positive'}
                          </span>
                          <span className="text-xs font-mono font-bold text-cyan-300">
                            {item.alert.id}
                          </span>
                          <span className="text-xs font-bold text-white">
                            {item.alert.attack_type || 'Intrusion Flow'}
                          </span>
                        </div>

                        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                          <span>
                            {item.alert.source_ip}:{item.alert.port} &rarr; {item.alert.dest_ip}:{item.alert.port}
                          </span>
                          <span className="text-slate-600">&bull;</span>
                          <span className="font-sans text-slate-300">
                            Risk {item.alert.risk}/100 ({item.alert.severity})
                          </span>
                          <span className="text-slate-600">&bull;</span>
                          <span className="flex items-center gap-1 font-sans text-slate-400">
                            <Clock className="w-3 h-3" />
                            {item.timestamp}
                          </span>
                        </div>

                        {/* Firewall Command */}
                        {item.rule && (
                          <div className="mt-2 text-xs font-mono bg-black/60 text-cyan-200 border border-cyan-500/30 px-3.5 py-2 rounded-xl flex items-center justify-between gap-3 max-w-xl">
                            <span className="truncate">{item.rule}</span>
                            <button
                              onClick={() => handleCopyFirewallRule(item.alert.id, item.rule!)}
                              className="text-cyan-400 hover:text-white shrink-0 text-[11px] flex items-center gap-1 font-sans"
                            >
                              {copiedRuleId === item.alert.id ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                              <span>{copiedRuleId === item.alert.id ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Right: Actions */}
                    <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                      <button
                        onClick={() => handleRestoreAlert(item.alert.id)}
                        className="glass-button px-3.5 py-2 text-xs font-bold rounded-xl text-slate-200 hover:text-white transition-all flex items-center gap-1.5"
                        title="Move back to Active Queue"
                      >
                        <Undo2 className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Restore to Queue</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: ACCURACY & CONFUSION MATRIX */}
        {currentTab === 'accuracy' && metrics && (
          <div className="mt-5 space-y-6 flex-1 animate-in fade-in duration-200">
            <div className="glass-panel rounded-2xl p-6 sm:p-7 space-y-6">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400/80 mb-4">
                  Baseline Model Benchmark (CIC-IDS2017 Dataset)
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                  <div className="p-4 glass-panel-subtle rounded-xl">
                    <div className="text-3xl font-black tabular-nums text-white">
                      {(metrics.precision * 100).toFixed(1)}%
                    </div>
                    <div className="text-xs font-bold text-cyan-300 mt-1">
                      Precision
                    </div>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                      When the model flags an alert as an attack, it is correct {(metrics.precision * 100).toFixed(1)}% of the time.
                    </p>
                  </div>

                  <div className="p-4 glass-panel-subtle rounded-xl">
                    <div className="text-3xl font-black tabular-nums text-white">
                      {(metrics.recall * 100).toFixed(1)}%
                    </div>
                    <div className="text-xs font-bold text-cyan-300 mt-1">
                      Recall
                    </div>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                      The model successfully catches {(metrics.recall * 100).toFixed(1)}% of all actual attacks in the traffic.
                    </p>
                  </div>

                  <div className="p-4 glass-panel-subtle rounded-xl">
                    <div className="text-3xl font-black tabular-nums text-white">
                      {(metrics.f1 * 100).toFixed(1)}%
                    </div>
                    <div className="text-xs font-bold text-cyan-300 mt-1">
                      F1 Score
                    </div>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                      The balanced score between catching threats and avoiding false alarms is {(metrics.f1 * 100).toFixed(1)}%.
                    </p>
                  </div>

                  <div className="p-4 glass-panel-subtle rounded-xl">
                    <div className="text-3xl font-black tabular-nums text-white">
                      {(metrics.roc_auc * 100).toFixed(1)}%
                    </div>
                    <div className="text-xs font-bold text-cyan-300 mt-1">
                      ROC-AUC
                    </div>
                    <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                      The model has a {(metrics.roc_auc * 100).toFixed(1)}% likelihood of ranking a real attack higher in risk than benign traffic.
                    </p>
                  </div>
                </div>
              </div>

              {/* Confusion Matrix Table */}
              {metrics.confusion_matrix && (
                <div className="pt-6 border-t border-white/10">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400/80">
                      Evaluation Confusion Matrix (23,862 Network Flows)
                    </h3>
                    <span className="text-xs text-slate-400">
                      Ground truth labeled CIC-IDS2017 test evaluation
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/30">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-emerald-300">
                          True Negatives (Normal Flows Passed)
                        </span>
                        <span className="text-lg font-black font-mono text-emerald-200 tabular-nums">
                          {metrics.confusion_matrix[0][0].toLocaleString()}
                        </span>
                      </div>
                      <p className="text-xs text-emerald-300/70 mt-1">
                        Harmless background traffic correctly ignored without triggering analyst alarms.
                      </p>
                    </div>

                    <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-950/30">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-amber-300">
                          False Positives (False Alarms)
                        </span>
                        <span className="text-lg font-black font-mono text-amber-200 tabular-nums">
                          {metrics.confusion_matrix[0][1].toLocaleString()}
                        </span>
                      </div>
                      <p className="text-xs text-amber-300/70 mt-1">
                        Normal user or system flows that triggered an alert and required analyst review (1.6% rate).
                      </p>
                    </div>

                    <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-950/30">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-rose-300">
                          False Negatives (Missed Attacks)
                        </span>
                        <span className="text-lg font-black font-mono text-rose-200 tabular-nums">
                          {metrics.confusion_matrix[1][0].toLocaleString()}
                        </span>
                      </div>
                      <p className="text-xs text-rose-300/70 mt-1">
                        Actual attacks that evaded detection and slipped below the threshold.
                      </p>
                    </div>

                    <div className="p-4 rounded-xl border border-cyan-500/30 bg-cyan-950/30">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-cyan-300">
                          True Positives (Attacks Caught)
                        </span>
                        <span className="text-lg font-black font-mono text-cyan-200 tabular-nums">
                          {metrics.confusion_matrix[1][1].toLocaleString()}
                        </span>
                      </div>
                      <p className="text-xs text-cyan-300/70 mt-1">
                        Real cyber attacks (DDoS, Botnets, PortScans) successfully caught and queued for containment.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* KEYBOARD SHORTCUTS MODAL (LIQUID GLASS) */}
      {showShortcutsModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-md flex items-center justify-center p-4">
          <div className="glass-panel rounded-2xl max-w-sm w-full p-6 shadow-2xl border border-white/20 space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Keyboard className="w-4 h-4 text-cyan-300" />
                Keyboard Shortcuts
              </h3>
              <button
                onClick={() => setShowShortcutsModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-300">Mark alert as threat</span>
                <kbd className="px-2 py-1 bg-black/40 border border-white/20 rounded font-mono font-bold text-cyan-300">T</kbd>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-300">Mark as false positive</span>
                <kbd className="px-2 py-1 bg-black/40 border border-white/20 rounded font-mono font-bold text-cyan-300">F</kbd>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-300">Navigate queue alerts</span>
                <div className="flex gap-1">
                  <kbd className="px-2 py-1 bg-black/40 border border-white/20 rounded font-mono font-bold text-cyan-300">↓</kbd>
                  <kbd className="px-2 py-1 bg-black/40 border border-white/20 rounded font-mono font-bold text-cyan-300">J</kbd>
                </div>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-300">Active Queue tab</span>
                <kbd className="px-2 py-1 bg-black/40 border border-white/20 rounded font-mono font-bold text-cyan-300">1</kbd>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-300">Triage History tab</span>
                <kbd className="px-2 py-1 bg-black/40 border border-white/20 rounded font-mono font-bold text-cyan-300">2</kbd>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-slate-300">Model Accuracy tab</span>
                <kbd className="px-2 py-1 bg-black/40 border border-white/20 rounded font-mono font-bold text-cyan-300">3</kbd>
              </div>
            </div>

            <div className="pt-2">
              <button
                onClick={() => setShowShortcutsModal(false)}
                className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-indigo-500 text-slate-950 rounded-xl text-xs font-bold hover:brightness-110 shadow-lg shadow-cyan-500/25 transition-all"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* LIVE ATTACK CRAFTER & BRUTE FORCE STUDIO MODAL */}
      {showAttackCrafterModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="glass-panel rounded-2xl max-w-2xl w-full p-5 sm:p-6 shadow-2xl border border-rose-500/30 space-y-5 animate-in fade-in zoom-in-95 duration-150">
            {/* Header */}
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-rose-500/30 to-amber-500/30 border border-rose-500/40 flex items-center justify-center shadow-lg shadow-rose-500/20">
                  <Zap className="w-5 h-5 text-rose-300 fill-rose-400/40" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    Live Attack &amp; Brute Force Crafter
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Manually execute a simulated attack flow into the SOC triage queue
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowAttackCrafterModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Sub-tabs: GUI Crafter vs Terminal CLI copy */}
            <div className="flex items-center gap-2 border-b border-white/10 pb-2">
              <button
                onClick={() => setCrafterTab('gui')}
                className={`px-3 py-1 text-xs font-bold rounded-lg transition-all ${
                  crafterTab === 'gui'
                    ? 'bg-rose-500/30 text-rose-200 border border-rose-500/50'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Interactive Crafter
              </button>
              <button
                onClick={() => setCrafterTab('cli')}
                className={`px-3 py-1 text-xs font-bold rounded-lg transition-all ${
                  crafterTab === 'cli'
                    ? 'bg-rose-500/30 text-rose-200 border border-rose-500/50'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Terminal / cURL Command
              </button>
            </div>

            {crafterTab === 'gui' ? (
              <div className="space-y-4">
                {/* Attack Quick Presets */}
                <div>
                  <label className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                    Select Attack Template
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    {[
                      { type: 'SSH-Patator Brute Force', port: 22, asset: 'SSH Bastion', proto: 'TCP', count: 450 },
                      { type: 'FTP-Patator Password Spray', port: 21, asset: 'SSH Bastion', proto: 'TCP', count: 320 },
                      { type: 'Web Admin Brute Force', port: 443, asset: 'Production Web App', proto: 'TCP', count: 750 },
                      { type: 'Postgres Auth Flooding', port: 5432, asset: 'Primary Database', proto: 'TCP', count: 900 }
                    ].map((preset) => (
                      <button
                        key={preset.type}
                        type="button"
                        onClick={() =>
                          setAttackForm((prev) => ({
                            ...prev,
                            attack_type: preset.type,
                            port: preset.port,
                            target_asset: preset.asset,
                            protocol: preset.proto,
                            attempts: preset.count
                          }))
                        }
                        className={`p-2.5 rounded-xl text-left border transition-all ${
                          attackForm.attack_type === preset.type
                            ? 'bg-rose-500/20 border-rose-500/60 text-white shadow-xs'
                            : 'glass-panel-subtle text-slate-300 hover:border-white/20'
                        }`}
                      >
                        <span className="text-[10px] text-rose-300 font-mono block">Port {preset.port}</span>
                        <span className="text-xs font-bold block leading-tight mt-0.5">{preset.type}</span>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Form Controls: Source IP & Target Asset */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-[11px] font-bold text-slate-300">Attacker Source IP</label>
                      <button
                        type="button"
                        onClick={handleGenerateRandomIP}
                        className="text-[10px] text-cyan-300 hover:underline"
                      >
                        Random IP
                      </button>
                    </div>
                    <input
                      type="text"
                      value={attackForm.source_ip}
                      onChange={(e) => setAttackForm({ ...attackForm, source_ip: e.target.value })}
                      className="w-full text-xs font-mono bg-black/40 border border-white/15 rounded-xl px-3 py-2 text-white focus:outline-hidden focus:border-rose-400"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] font-bold text-slate-300 block mb-1">Target Asset &amp; Destination</label>
                    <select
                      value={attackForm.target_asset}
                      onChange={(e) => {
                        const asset = e.target.value;
                        const destMap: Record<string, string> = {
                          'SSH Bastion': '192.168.10.25',
                          'Production Web App': '192.168.10.50',
                          'Primary Database': '192.168.10.15',
                          'Domain Controller': '192.168.10.2'
                        };
                        setAttackForm({
                          ...attackForm,
                          target_asset: asset,
                          dest_ip: destMap[asset] || '192.168.10.50'
                        });
                      }}
                      className="w-full text-xs bg-black/40 border border-white/15 rounded-xl px-3 py-2 text-white focus:outline-hidden focus:border-rose-400"
                    >
                      <option value="SSH Bastion">SSH Bastion (192.168.10.25)</option>
                      <option value="Production Web App">Production Web App (192.168.10.50)</option>
                      <option value="Primary Database">Primary Database (192.168.10.15)</option>
                      <option value="Domain Controller">Domain Controller (192.168.10.2)</option>
                    </select>
                  </div>
                </div>

                {/* Brute Force Attempts Slider */}
                <div>
                  <div className="flex items-center justify-between mb-1 text-xs">
                    <span className="font-bold text-slate-300">Burst Authentication Attempts</span>
                    <span className="font-mono text-rose-300 font-bold">{attackForm.attempts} failed logins</span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="1500"
                    step="50"
                    value={attackForm.attempts}
                    onChange={(e) => setAttackForm({ ...attackForm, attempts: Number(e.target.value) })}
                    className="w-full accent-rose-500 cursor-pointer"
                  />
                  <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-0.5">
                    <span>50 attempts (Medium Risk)</span>
                    <span>500 (High Risk)</span>
                    <span>1,500 (Critical Risk)</span>
                  </div>
                </div>

                {/* Real-time Simulated Terminal Output */}
                {terminalLogs.length > 0 && (
                  <div className="bg-black/80 rounded-xl p-3 border border-rose-500/30 font-mono text-[11px] text-rose-300 space-y-1 max-h-32 overflow-y-auto">
                    {terminalLogs.map((log, i) => (
                      <div key={i} className="leading-snug">{log}</div>
                    ))}
                  </div>
                )}

                {/* Launch Action */}
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={handleLaunchCustomAttack}
                    disabled={isExecutingAttack}
                    className="w-full py-3 bg-gradient-to-r from-rose-600 via-pink-600 to-amber-600 hover:brightness-110 text-white font-bold rounded-xl text-xs shadow-lg shadow-rose-600/30 transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <Zap className={`w-4 h-4 fill-white ${isExecutingAttack ? 'animate-bounce' : ''}`} />
                    <span>{isExecutingAttack ? 'Launching Live Brute Force...' : 'Launch Live Attack & Ingest Alert'}</span>
                  </button>
                </div>
              </div>
            ) : (
              /* CLI / cURL Instructions */
              <div className="space-y-3 text-xs">
                <p className="text-slate-300 leading-relaxed">
                  You can also trigger a live attack externally from any terminal, script, or Postman.
                  Run this command to ingest an attack into the dashboard in real time:
                </p>

                <div className="bg-black/90 rounded-xl p-3.5 border border-white/15 font-mono text-xs text-cyan-300 relative select-all overflow-x-auto">
                  {`curl -X POST http://localhost:3000/api/alerts/custom \\
  -H "Content-Type: application/json" \\
  -d '{
    "attack_type": "${attackForm.attack_type}",
    "source_ip": "${attackForm.source_ip}",
    "dest_ip": "${attackForm.dest_ip}",
    "port": ${attackForm.port},
    "attempts": ${attackForm.attempts},
    "target_asset": "${attackForm.target_asset}"
  }'`}
                </div>

                <div className="flex items-center justify-between pt-2">
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(
                        `curl -X POST http://localhost:3000/api/alerts/custom -H "Content-Type: application/json" -d '{"attack_type":"${attackForm.attack_type}","source_ip":"${attackForm.source_ip}","dest_ip":"${attackForm.dest_ip}","port":${attackForm.port},"attempts":${attackForm.attempts},"target_asset":"${attackForm.target_asset}"}'`
                      );
                      setCopiedCurl(true);
                      setTimeout(() => setCopiedCurl(false), 2000);
                    }}
                    className="px-3.5 py-2 glass-button text-xs font-bold rounded-xl text-white hover:bg-white/15 transition-all flex items-center gap-1.5"
                  >
                    {copiedCurl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedCurl ? 'cURL Copied!' : 'Copy cURL Command'}</span>
                  </button>

                  <button
                    onClick={() => setCrafterTab('gui')}
                    className="text-xs text-rose-300 hover:underline"
                  >
                    Back to Interactive Crafter &rarr;
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
