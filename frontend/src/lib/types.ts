/** Shapes returned by the API. Kept in one place so a backend change surfaces
 *  as a type error here rather than as undefined at runtime. */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type IncidentStatus = 'NEW' | 'ACK' | 'INVESTIGATING' | 'CLOSED'
export type Judgement = 'TP' | 'FP' | 'BENIGN'
export type Role = 'viewer' | 'analyst' | 'admin'

export interface Contribution {
  feature: string
  value: number
  baseline: number
  impact: number
  direction: 'above' | 'below'
}

export interface Incident {
  id: number
  family: string
  family_title: string
  src: string
  dst: string
  dport: number
  proto: string
  first_seen: string | null
  last_seen: string | null
  occurrences: number
  score_max: number
  score_mean: number
  threshold: number
  confidence: number
  severity: Severity
  priority: number
  criticality: number
  asset_name: string
  status: IncidentStatus
  assignee: string | null
  verdict: Judgement | null
  mitre_technique: string
  mitre_tactic: string
  contributions: Contribution[]
  total_bytes: number
  total_packets: number
  distinct_dports: number
  distinct_peers: number
  is_new?: boolean
}

export interface AlertRow {
  id: number
  ts: string
  src: string
  sport: number
  dst: string
  dport: number
  proto: string
  score: number
  threshold: number
  family: string
  confidence: number
  severity: Severity
  packets: number
  bytes: number
  duration: number
  truth: string | null
  contributions: Contribution[]
  flow_start: number
  flow_end: number
}

export interface IncidentDetail extends Incident {
  alerts: AlertRow[]
  timeline: { ts: string; count: number; score_max: number }[]
  ports: { port: number; count: number }[]
  peers: { ip: string; count: number }[]
  ground_truth: Record<string, number>
  guidance: { title: string; technique: string; tactic: string; description: string; triage: string }
  note?: string | null
}

export interface BucketPoint {
  ts: string
  flows: number
  alerts: number
  bytes: number
  score_mean: number
  score_max: number
  threshold: number
  packets?: number
}

export interface Overview {
  window_hours: number
  open_by_severity: Partial<Record<Severity, number>>
  by_status: Partial<Record<IncidentStatus, number>>
  by_family: Record<string, number>
  top_sources: { ip: string; incidents: number; alerts: number; max_severity: number }[]
  top_targets: { ip: string; incidents: number; asset: string; criticality: number }[]
  incidents_total: number
  alerts_total: number
  closed_total: number
  mean_time_to_close_minutes: number | null
  feedback: { true_positive: number; false_positive: number; precision_observed: number | null }
  buckets: BucketPoint[]
  hourly: { hour: string; total: number; critical?: number; high?: number; medium?: number; low?: number }[]
}

export interface HostRow {
  ip: string
  asset_name: string
  criticality: number
  first_seen: string | null
  last_seen: string | null
  flows_out: number
  flows_in: number
  bytes_out: number
  bytes_in: number
  alerts: number
  score_mean: number
  threshold: number
  calibrated: boolean
}

export interface HostDetail extends HostRow { incidents: Incident[] }

export interface SourceInfo {
  name: string
  kind: 'lab' | 'pcap' | 'live' | 'generic'
  packets: number
  progress: number | null
  finished: boolean
  speed?: number
  seed?: number
  simulated_seconds?: number
  capture_seconds?: number
  file?: string
  iface?: string
  bpf?: string
  dropped?: number
  queued?: number
  attacks?: { family: string; start: number; duration: number; intensity: number; stealth: boolean }[]
}

export interface EngineStats {
  packets: number
  flows: number
  alerts: number
  suppressed: number
  bytes: number
  span: number
  score_mean: number
  score_max: number
  alerts_per_hour: number
  by_family: Record<string, number>
}

export interface PipelineStatus {
  running: boolean
  started_at: string | null
  error: string | null
  source: SourceInfo | null
  stats: EngineStats
  active_flows: number
  open_incidents: number
  incidents_opened: number
  alerts_merged: number
  written: { incidents: number; alerts: number; alerts_dropped: number }
  subscribers: number
  model: { trained_at: string; classes: string[] }
}

export interface FamilyGuidance {
  title: string; technique: string; tactic: string; description: string; triage: string
}

export interface ModelInfo {
  trained_at: string
  train_flows_benign: number
  train_flows_labelled: number
  train_seeds: number[]
  test_seeds: number[]
  classes: string[]
  notes: string
  metrics: ModelMetrics
  features: string[]
  feature_count: number
  operating_point: Record<string, number>
  families: Record<string, FamilyGuidance>
}

export interface ModelMetrics {
  pr_auc?: number
  roc_auc?: number
  precision?: number
  recall?: number
  f1?: number
  tp?: number; fp?: number; fn?: number; tn?: number
  benign_alerts_per_hour?: number
  benign_incidents_per_hour?: number
  benign_fp_rate?: number
  benign_flows?: number
  hosts_threshold_raised?: number
  family_recall?: Record<string, number>
  family_support?: Record<string, number>
  latency_p50?: number
  latency_p95?: number
  latency_by_family?: Record<string, number>
  classifier_macro_f1?: number
  classifier_report?: Record<string, { precision: number; recall: number; f1: number; support: number }>
  confusion?: { labels: string[]; matrix: number[][] }
  throughput_pkts_per_sec?: number
  incidents?: number
  alerts?: number
  stealth?: Partial<ModelMetrics>
}

export interface ThresholdRow {
  host: string; samples: number; median: number; p99: number
  threshold: number; calibrated: boolean; raised: boolean
}

export interface AssetEntry { cidr: string; name: string; criticality: number; tags: string[] }

export interface SettingsPayload {
  detection: Record<string, number>
  assets: AssetEntry[]
}

export interface AuditRow {
  id: number; ts: string; actor: string; action: string; target: string; detail: Record<string, unknown>
}

export interface PcapEntry { name: string; size: number; modified: string }

/** WebSocket frames. */
export type StreamEvent =
  | { type: 'hello'; version: string; history: TickEvent[]; status: PipelineStatus }
  | ({ type: 'tick' } & TickEvent)
  | { type: 'pipeline'; state: 'started' | 'stopped' | 'finished' | 'error'; source?: SourceInfo; error?: string }

export interface TickEvent extends BucketPoint {
  incidents: Incident[]
  stats: EngineStats
  source: SourceInfo
  active_flows: number
  open_incidents: number
}
