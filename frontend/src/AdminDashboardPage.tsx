import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, BarChart3, ChevronLeft, ChevronRight, ClipboardList, Database,
  DownloadCloud, ExternalLink, LogOut, RefreshCw, Search, ShieldAlert,
  ShieldCheck, Siren, Waypoints,
} from 'lucide-react'
import {
  Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api, type AdminAnalytics, type AdminInvestigationDetail, type AdminInvestigationPage, type AdminSystemHealth } from './api'
import { formatLocalTimestamp } from './reportFormatting'

type Section = 'overview' | 'investigations' | 'scam-analytics' | 'url-intelligence' | 'ml-monitoring' | 'system-health'
type DateRange = { from_date: string; to_date: string }
const nav: Array<{ id: Section; label: string; icon: typeof Activity }> = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'investigations', label: 'Investigations', icon: ClipboardList },
  { id: 'scam-analytics', label: 'Scam analytics', icon: BarChart3 },
  { id: 'url-intelligence', label: 'URL intelligence', icon: ExternalLink },
  { id: 'ml-monitoring', label: 'ML monitoring', icon: Waypoints },
  { id: 'system-health', label: 'System health', icon: Database },
]
const chartTooltipStyle = { background: '#101d2e', border: '1px solid #263b55', borderRadius: 9, color: '#edf5ff', fontSize: 11 }
const pieColors = ['#44c9d7', '#8d83ee', '#f4b951', '#58d6a1']

function utcToday(): string { return new Date().toISOString().slice(0, 10) }
function initialRange(): DateRange {
  const today = new Date()
  const start = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - 29))
  return { from_date: start.toISOString().slice(0, 10), to_date: utcToday() }
}
function titleCase(value: string): string { return value.replaceAll('_', ' ').replace(/\b[a-z]/g, letter => letter.toUpperCase()) }

export function AdminDashboardPage({ onLogout }: { onLogout: () => Promise<void> }) {
  const [section, setSection] = useState<Section>('overview')
  const [draftRange, setDraftRange] = useState<DateRange>(initialRange)
  const [range, setRange] = useState<DateRange>(initialRange)
  const [analytics, setAnalytics] = useState<AdminAnalytics | null>(null)
  const [analyticsBusy, setAnalyticsBusy] = useState(true)
  const [analyticsError, setAnalyticsError] = useState('')
  const [health, setHealth] = useState<AdminSystemHealth | null>(null)
  const [healthBusy, setHealthBusy] = useState(false)
  const [healthError, setHealthError] = useState('')
  const [healthRefresh, setHealthRefresh] = useState(0)
  const [searchText, setSearchText] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const [classification, setClassification] = useState<'all' | 'scam' | 'legitimate' | 'uncertain' | 'no_pattern'>('all')
  const [riskLevel, setRiskLevel] = useState('')
  const [sortBy, setSortBy] = useState<'created_at' | 'risk_score' | 'risk_level' | 'category'>('created_at')
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc')
  const [listPage, setListPage] = useState(1)
  const [investigations, setInvestigations] = useState<AdminInvestigationPage | null>(null)
  const [investigationsBusy, setInvestigationsBusy] = useState(false)
  const [investigationsError, setInvestigationsError] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [detail, setDetail] = useState<AdminInvestigationDetail | null>(null)
  const [detailBusy, setDetailBusy] = useState(false)
  const [detailError, setDetailError] = useState('')

  const loadAnalytics = useCallback(async () => {
    setAnalyticsBusy(true)
    setAnalyticsError('')
    try { setAnalytics(await api.adminAnalytics(range)) }
    catch (caught) { setAnalyticsError(caught instanceof Error ? caught.message : 'Admin data could not be loaded.') }
    finally { setAnalyticsBusy(false) }
  }, [range])
  useEffect(() => { void loadAnalytics() }, [loadAnalytics])

  const loadInvestigations = useCallback(async () => {
    setInvestigationsBusy(true)
    setInvestigationsError('')
    try {
      setInvestigations(await api.adminInvestigations({
        q: appliedSearch, classification, risk_level: riskLevel || undefined,
        ...range, sort_by: sortBy, sort_direction: sortDirection, page: listPage, page_size: 10,
      }))
    } catch (caught) { setInvestigationsError(caught instanceof Error ? caught.message : 'Investigation records could not be loaded.') }
    finally { setInvestigationsBusy(false) }
  }, [appliedSearch, classification, riskLevel, range, sortBy, sortDirection, listPage])
  useEffect(() => { if (section === 'investigations') void loadInvestigations() }, [section, loadInvestigations])

  const loadHealth = useCallback(async () => {
    setHealthBusy(true)
    setHealthError('')
    try { setHealth(await api.adminSystemHealth()) }
    catch (caught) { setHealthError(caught instanceof Error ? caught.message : 'System status could not be loaded.') }
    finally { setHealthBusy(false) }
  }, [])
  useEffect(() => { if (section === 'system-health') void loadHealth() }, [section, healthRefresh, loadHealth])

  async function openDetail(id: string) {
    setSelectedId(id)
    setDetail(null)
    setDetailError('')
    setDetailBusy(true)
    try { setDetail(await api.adminInvestigation(id)) }
    catch (caught) { setDetailError(caught instanceof Error ? caught.message : 'Investigation detail could not be loaded.') }
    finally { setDetailBusy(false) }
  }

  function submitRange(event: React.FormEvent) {
    event.preventDefault()
    if (draftRange.from_date > draftRange.to_date) {
      setAnalyticsError('The start date must be on or before the end date.')
      return
    }
    setAnalyticsError('')
    setRange(draftRange)
    setListPage(1)
  }

  const sectionTitle = nav.find(item => item.id === section)?.label ?? 'Overview'
  return <main className="admin-console">
    <header className="admin-console-header">
      <div><span className="eyebrow">SCAMSHIELD · ADMINISTRATION</span><h1>Admin console</h1><p>Read-only views of persisted application activity and service configuration.</p></div>
      <button className="button button-quiet admin-logout" onClick={() => void onLogout()}><LogOut size={15} /> Logout</button>
    </header>
    <nav className="admin-subnav" aria-label="Administrator sections">
      {nav.map(item => { const Icon = item.icon; return <button key={item.id} className={section === item.id ? 'active' : ''} aria-current={section === item.id ? 'page' : undefined} onClick={() => setSection(item.id)}><Icon size={15} /><span>{item.label}</span></button> })}
    </nav>
    <div className="admin-section-heading"><div><span className="eyebrow">{section === 'overview' ? 'LIVE DATABASE AGGREGATES' : 'ADMIN WORKSPACE'}</span><h2>{sectionTitle}</h2></div>
      {section !== 'system-health' && <form className="admin-date-filter" onSubmit={submitRange} aria-label="Date range filter"><label>From<input type="date" value={draftRange.from_date} max={draftRange.to_date} onChange={event => setDraftRange(current => ({ ...current, from_date: event.target.value }))} /></label><label>To<input type="date" value={draftRange.to_date} min={draftRange.from_date} max={utcToday()} onChange={event => setDraftRange(current => ({ ...current, to_date: event.target.value }))} /></label><button className="button button-quiet">Apply</button></form>}
    </div>
    {analyticsError && <div className="error-banner" role="alert"><ShieldAlert size={16} />{analyticsError}</div>}
    {analyticsBusy && <div className="admin-loading" role="status"><span className="spin-dot" /> Loading database aggregates…</div>}
    {!analyticsBusy && section !== 'system-health' && !analytics && !analyticsError && <EmptyState title="No dashboard data" body="The admin analytics response was empty." />}
    {!analyticsBusy && analytics && section === 'overview' && <Overview analytics={analytics} onViewInvestigations={() => setSection('investigations')} />}
    {!analyticsBusy && analytics && section === 'scam-analytics' && <ScamAnalytics analytics={analytics} />}
    {!analyticsBusy && analytics && section === 'url-intelligence' && <UrlIntelligence analytics={analytics} />}
    {!analyticsBusy && analytics && section === 'ml-monitoring' && <MLMonitoring analytics={analytics} />}
    {section === 'investigations' && <InvestigationsSection
      searchText={searchText} setSearchText={setSearchText} applySearch={setAppliedSearch}
      classification={classification} setClassification={value => { setClassification(value); setListPage(1) }}
      riskLevel={riskLevel} setRiskLevel={value => { setRiskLevel(value); setListPage(1) }}
      sortBy={sortBy} setSortBy={value => { setSortBy(value); setListPage(1) }}
      sortDirection={sortDirection} setSortDirection={value => { setSortDirection(value); setListPage(1) }}
      page={listPage} setPage={setListPage} data={investigations} busy={investigationsBusy} error={investigationsError}
      onOpenDetail={openDetail} />}
    {section === 'system-health' && <SystemHealth health={health} busy={healthBusy} error={healthError} refresh={() => setHealthRefresh(value => value + 1)} />}
    {selectedId && <InvestigationDialog detail={detail} busy={detailBusy} error={detailError} close={() => setSelectedId('')} />}
    <footer className="admin-console-footer"><span>Dates and daily counts use UTC.</span><span>Classification counts use explicit stored labels only; missing categories are not treated as legitimate.</span></footer>
  </main>
}

function Overview({ analytics, onViewInvestigations }: { analytics: AdminAnalytics; onViewInvestigations: () => void }) {
  return <>
    <div className="admin-kpi-grid">
      <Metric label="Investigations" value={analytics.total_investigations} note={`${analytics.investigations_today_utc} today · UTC`} />
      <Metric label="Scam detections" value={analytics.total_scam_detections} note={`${analytics.scam_detection_percentage}% of saved investigations have a scam category`} accent="cyan" />
      <Metric label="Legitimate classifications" value={analytics.total_legitimate_classifications} note="Explicit labels only; no low-risk inference" accent="green" />
      <Metric label="Uncertain classifications" value={analytics.total_uncertain_classifications} note="Explicit labels only" accent="amber" />
      <Metric label="Users" value={analytics.total_users} note={`${analytics.user_counts.user ?? 0} users · ${analytics.user_counts.admin ?? 0} admins`} />
      <Metric label="Average processing" value={analytics.average_processing_time_ms === null ? '—' : `${analytics.average_processing_time_ms.toLocaleString()} ms`} note="Mean summed agent time in the selected date range" />
    </div>
    <div className="admin-chart-grid">
      <ChartCard title="Investigation trend" subtitle={`${analytics.date_range.from_date} to ${analytics.date_range.to_date} UTC`}>
        {analytics.investigations_per_day.length ? <ResponsiveContainer width="100%" height="100%"><LineChart data={analytics.investigations_per_day}><CartesianGrid stroke="#20334a" strokeDasharray="4 4" vertical={false} /><XAxis dataKey="date" tick={{ fill: '#8da2b8', fontSize: 9 }} tickLine={false} axisLine={false} minTickGap={18} /><YAxis allowDecimals={false} tick={{ fill: '#8da2b8', fontSize: 10 }} tickLine={false} axisLine={false} width={28} /><Tooltip contentStyle={chartTooltipStyle} /><Line type="monotone" dataKey="count" name="Investigations" stroke="#49cfdf" strokeWidth={2.5} dot={{ r: 2, fill: '#49cfdf' }} /></LineChart></ResponsiveContainer> : <EmptyState title="No activity in this range" body="Choose another date range to see investigation trends." />}
      </ChartCard>
      <ChartCard title="Scam vs legitimate classifications" subtitle="Only explicit stored classifications are counted.">
        <div className="admin-chart-note">A missing category or a low risk score is not a legitimate verdict.</div>
        <ClassificationChart analytics={analytics} />
      </ChartCard>
      <ChartCard title="Detector outcomes" subtitle="A category match is a detector result, not a ground-truth label.">
        <Donut values={[{ name: 'Scam category matched', value: analytics.range_detection_counts.scam_detected ?? 0 }, { name: 'No scam category', value: analytics.range_detection_counts.no_scam_category ?? 0 }]} empty="No investigations in the selected date range." />
      </ChartCard>
      <ChartCard title="Risk distribution" subtitle="Stored deterministic risk levels in the selected range.">
        <HorizontalBars values={analytics.risk_distribution} empty="No risk records in this range." />
      </ChartCard>
    </div>
    <section className="panel admin-recent-panel"><div className="admin-panel-heading"><div><h3>Recent investigation activity</h3><p>Metadata only. Source messages are not shown.</p></div><button className="link-button" onClick={onViewInvestigations}>Manage investigations <ChevronRight size={15} /></button></div>
      {analytics.recent_activity.length ? <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Created (local)</th><th>Input</th><th>Category</th><th>Risk</th><th>Score</th></tr></thead><tbody>{analytics.recent_activity.map(row => <tr key={row.id}><td>{formatLocalTimestamp(row.created_at)}</td><td>{titleCase(row.input_type)}</td><td>{row.category ? titleCase(row.category) : 'No scam pattern'}</td><td><StatusPill value={row.risk_level} /></td><td>{row.risk_score} / 100</td></tr>)}</tbody></table></div> : <EmptyState title="No investigation activity" body="New saved reports will appear here." />}
    </section>
  </>
}

function ScamAnalytics({ analytics }: { analytics: AdminAnalytics }) {
  const categories = useMemo(() => Object.entries(analytics.category_distribution).sort((a, b) => b[1] - a[1]), [analytics.category_distribution])
  return <>
    <div className="admin-kpi-grid compact"><Metric label="Category matches" value={analytics.range_detection_counts.scam_detected ?? 0} note="In selected range" accent="cyan" /><Metric label="No scam category" value={analytics.range_detection_counts.no_scam_category ?? 0} note="Not a legitimate classification" /><Metric label="Feedback records" value={Object.values(analytics.feedback_counts).reduce((sum, value) => sum + value, 0)} note="Feedback is not ground truth" /><Metric label="Detector rate" value={`${analytics.scam_detection_percentage}%`} note="All-time category-match rate" accent="amber" /></div>
    <div className="admin-chart-grid">
      <ChartCard title="Scam category distribution" subtitle="Categories present in stored investigation records.">
        {categories.length ? <ResponsiveContainer width="100%" height="100%"><BarChart data={categories.slice(0, 12).map(([category, count]) => ({ category: titleCase(category), count }))} layout="vertical" margin={{ left: 12, right: 12 }}><CartesianGrid stroke="#20334a" strokeDasharray="4 4" horizontal={false} /><XAxis type="number" allowDecimals={false} tick={{ fill: '#8da2b8', fontSize: 10 }} axisLine={false} tickLine={false} /><YAxis type="category" dataKey="category" width={118} tick={{ fill: '#adbed0', fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={chartTooltipStyle} /><Bar dataKey="count" name="Investigations" fill="#8d83ee" radius={[0, 5, 5, 0]} /></BarChart></ResponsiveContainer> : <EmptyState title="No matched categories" body="The selected date range contains no stored scam category matches." />}
      </ChartCard>
      <ChartCard title="Explicit class records" subtitle="No category or risk score is converted into a label.">
        <ClassificationChart analytics={analytics} />
      </ChartCard>
      <ChartCard title="Risk levels" subtitle="Stored risk levels; score is not a probability.">
        <Donut values={Object.entries(analytics.risk_distribution).map(([name, value]) => ({ name, value }))} empty="No risk records in the selected date range." />
      </ChartCard>
      <ChartCard title="Investigations per day" subtitle="UTC days in the selected range.">
        {analytics.investigations_per_day.length ? <ResponsiveContainer width="100%" height="100%"><BarChart data={analytics.investigations_per_day}><CartesianGrid stroke="#20334a" strokeDasharray="4 4" vertical={false} /><XAxis dataKey="date" tick={{ fill: '#8da2b8', fontSize: 9 }} axisLine={false} tickLine={false} minTickGap={18} /><YAxis allowDecimals={false} tick={{ fill: '#8da2b8', fontSize: 10 }} axisLine={false} tickLine={false} width={28} /><Tooltip contentStyle={chartTooltipStyle} /><Bar dataKey="count" name="Investigations" fill="#49cfdf" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer> : <EmptyState title="No activity in this range" body="Choose another date range to see trends." />}
      </ChartCard>
    </div>
  </>
}

function ClassificationChart({ analytics }: { analytics: AdminAnalytics }) {
  const values = [
    { name: 'Explicit scam', value: analytics.range_detection_counts.explicit_scam ?? 0 },
    { name: 'Explicit legitimate', value: analytics.range_detection_counts.explicit_legitimate ?? 0 },
    { name: 'Explicit uncertain', value: analytics.range_detection_counts.explicit_uncertain ?? 0 },
  ].filter(item => item.value > 0)
  return values.length ? <Donut values={values} empty="No explicit labels recorded." /> : <EmptyState title="No explicit class labels" body="This project stores detector results and experimental ML suggestions, but no ground-truth legitimate or uncertain class labels for live investigations." />
}

function UrlIntelligence({ analytics }: { analytics: AdminAnalytics }) {
  const intel = analytics.url_intelligence
  const providerNames: Record<string, string> = { google_safe_browsing: 'Google Safe Browsing', virustotal: 'VirusTotal' }
  return <>
    <div className="admin-kpi-grid compact"><Metric label="Malicious provider verdicts" value={intel.malicious_results} note="Completed threat-intelligence matches" accent="red" /><Metric label="Heuristic URL findings" value={intel.suspicious_url_findings} note="Structure signals; not provider verification" accent="amber" /><Metric label="No known threat" value={intel.clean_no_known_threat_results} note="Not proof that a URL is safe" accent="green" /><Metric label="Provider failures" value={intel.provider_failures} note="Failed, timed out, or unavailable" /></div>
    <section className="panel admin-section-panel"><div className="admin-panel-heading"><div><h3>Provider results</h3><p>Values are counts of saved provider lookup records in the selected date range.</p></div></div><div className="admin-provider-grid">{Object.entries(intel.providers).map(([provider, counts]) => <article className="admin-provider-card" key={provider}><span className="eyebrow">REPUTATION PROVIDER</span><h3>{providerNames[provider] ?? titleCase(provider)}</h3><div className="admin-provider-counts"><span>Checks<strong>{counts.checks}</strong></span><span>Malicious<strong>{counts.malicious}</strong></span><span>No known threat<strong>{counts.clean_no_known_threat}</strong></span><span>Failed / unavailable<strong>{counts.failures}</strong></span><span>Skipped<strong>{counts.skipped}</strong></span></div></article>)}</div><p className="admin-caveat"><ShieldAlert size={15} />{intel.clean_result_caveat} Skipped and unavailable checks are not clean results.</p></section>
    <section className="panel admin-section-panel"><div className="admin-panel-heading"><div><h3>Lookup status breakdown</h3><p>Shows operational gaps without exposing URLs or diagnostic details.</p></div></div><HorizontalBars values={intel.status_counts} empty="No provider lookup records in this range." /></section>
  </>
}

function MLMonitoring({ analytics }: { analytics: AdminAnalytics }) {
  const ml = analytics.ml_monitoring
  const evaluation = ml.evaluation
  const test = evaluation.test ?? {}
  const cv = evaluation.cross_validation ?? {}
  const matrix = test.confusion_matrix as { labels?: string[]; rows_actual_columns_predicted?: number[][] } | undefined
  return <>
    <section className="panel ml-monitoring-card"><div className="ml-monitoring-title"><div><span className="eyebrow">EXPERIMENTAL MODEL</span><h3>{ml.model_name}</h3><p>Version <strong>{ml.model_version}</strong> · advisory inference only</p></div><StatusPill value="Experimental" /></div><p>{ml.disclaimer}</p><p>Model suggestions are not verification, are not calibrated probabilities, and never change deterministic findings or risk scores.</p></section>
    <div className="admin-kpi-grid compact"><Metric label="Completed predictions" value={ml.prediction_status_counts.completed ?? 0} note="Saved reports in selected date range" accent="cyan" /><Metric label="Scam-like suggestions" value={ml.predicted_class_counts.scam ?? 0} note="Advisory class counts" accent="red" /><Metric label="Legitimate-looking suggestions" value={ml.predicted_class_counts.legitimate ?? 0} note="Not a ground-truth classification" accent="green" /><Metric label="Unavailable / failed" value={(ml.prediction_status_counts.unavailable ?? 0) + (ml.prediction_status_counts.failed ?? 0)} note="No prediction included" /></div>
    <section className="panel admin-section-panel"><div className="admin-panel-heading"><div><h3>Offline evaluation</h3><p>Source: {evaluation.source ?? 'not bundled with this build'} · no live data is sent to the model.</p></div><StatusPill value={evaluation.status} /></div>
      {evaluation.status === 'available' ? <><div className="admin-eval-metrics"><EvalMetric label="Held-out accuracy" value={percent(test.accuracy)} /><EvalMetric label="Scam precision" value={percent(test.precision_scam)} /><EvalMetric label="Scam recall" value={percent(test.recall_scam)} /><EvalMetric label="Scam F1" value={percent(test.f1_scam)} /><EvalMetric label="False positive rate" value={percent(test.false_positive_rate)} /><EvalMetric label="False negative rate" value={percent(test.false_negative_rate)} /><EvalMetric label="Test rows" value={String(test.n ?? '—')} /></div>
        {matrix?.rows_actual_columns_predicted && <p className="admin-matrix">Confusion matrix (actual rows × predicted columns; labels {matrix.labels?.join(', ')}): {matrix.rows_actual_columns_predicted.map(row => `[${row.join(', ')}]`).join(' ')}</p>}
        <h4>5-fold cross-validation</h4><div className="admin-eval-metrics"><EvalMetric label="Accuracy" value={percent(cv.accuracy)} /><EvalMetric label="Precision" value={percent(cv.precision_scam)} /><EvalMetric label="Recall" value={percent(cv.recall_scam)} /><EvalMetric label="F1" value={percent(cv.f1_scam)} /></div>
        <ul className="admin-limitations">{(evaluation.limitations ?? []).map(item => <li key={item}>{item}</li>)}</ul>
      </> : <EmptyState title="Evaluation metrics unavailable" body="This deployment does not include a validated evaluation report." />}
    </section>
  </>
}

function percent(value: unknown): string { return typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : '—' }
function EvalMetric({ label, value }: { label: string; value: string }) { return <div className="admin-eval-metric"><span>{label}</span><strong>{value}</strong></div> }

function SystemHealth({ health, busy, error, refresh }: { health: AdminSystemHealth | null; busy: boolean; error: string; refresh: () => void }) {
  return <>
    <section className="panel admin-health-intro"><div><h3>Service health and provider configuration</h3><p>Backend and database are checked directly. Provider keys are only checked for presence; this view makes no third-party requests.</p></div><button className="button button-quiet" onClick={refresh} disabled={busy}><RefreshCw size={15} /> {busy ? 'Checking…' : 'Refresh checks'}</button></section>
    {error && <div className="error-banner" role="alert"><ShieldAlert size={16} />{error}</div>}
    {busy && !health && <p role="status" className="admin-loading">Checking backend, database, and scanner…</p>}
    {health && <><div className="admin-health-grid">{health.services.map(service => <article className="panel admin-health-card" key={service.id}><div className="admin-health-card-top"><span className="admin-health-icon"><HealthIcon id={service.id} /></span><StatusPill value={service.status} /></div><h3>{service.name}</h3><p>{healthNote(service.id, service.status, service.selected)}</p><small>Verification: {titleCase(service.verification)}</small></article>)}</div><p className="admin-health-footnote">{health.provider_note}</p><p className="admin-health-time">Last checked {formatLocalTimestamp(health.checked_at)}</p></>}
  </>
}

function healthNote(id: string, status: string, selected?: boolean): string {
  if (id === 'backend') return 'This protected API request completed.'
  if (id === 'database') return status === 'operational' ? 'A lightweight database query succeeded.' : 'The database check did not succeed.'
  if (id === 'url_scanner') return status === 'operational' ? 'The scanner health endpoint responded.' : status === 'unavailable' ? 'The scanner health check failed.' : 'Scanner URL is not configured.'
  if (id === 'groq') return selected ? 'Key configuration only; no Groq inference was requested.' : 'Groq is not the selected LLM provider; no request was made.'
  return status === 'configured' ? 'Key is configured; no provider request was made.' : 'No key is configured in this deployment.'
}
function HealthIcon({ id }: { id: string }) {
  if (id === 'database') return <Database size={18} />
  if (id === 'url_scanner') return <DownloadCloud size={18} />
  if (id === 'groq') return <Waypoints size={18} />
  if (id === 'google_safe_browsing' || id === 'virustotal') return <ShieldCheck size={18} />
  return <Activity size={18} />
}

function InvestigationsSection(props: {
  searchText: string; setSearchText: (value: string) => void; applySearch: (value: string) => void
  classification: 'all' | 'scam' | 'legitimate' | 'uncertain' | 'no_pattern'; setClassification: (value: 'all' | 'scam' | 'legitimate' | 'uncertain' | 'no_pattern') => void
  riskLevel: string; setRiskLevel: (value: string) => void
  sortBy: 'created_at' | 'risk_score' | 'risk_level' | 'category'; setSortBy: (value: 'created_at' | 'risk_score' | 'risk_level' | 'category') => void
  sortDirection: 'asc' | 'desc'; setSortDirection: (value: 'asc' | 'desc') => void
  page: number; setPage: (value: number) => void; data: AdminInvestigationPage | null; busy: boolean; error: string
  onOpenDetail: (id: string) => void
}) {
  return <section className="panel admin-investigations-panel"><div className="admin-panel-heading"><div><h3>Saved investigations</h3><p>Read-only metadata view. Message text and account identity are not returned.</p></div><span className="admin-record-total">{props.data?.total ?? 0} records</span></div>
    <form className="admin-investigation-filters" onSubmit={event => { event.preventDefault(); props.setPage(1); props.applySearch(props.searchText.trim()) }}>
      <label className="admin-search"><Search size={15} /><input aria-label="Search investigation metadata" placeholder="Search ID, category, type, or risk" value={props.searchText} onChange={event => props.setSearchText(event.target.value)} /></label>
      <label>Classification<select value={props.classification} onChange={event => props.setClassification(event.target.value as typeof props.classification)}><option value="all">All classifications</option><option value="scam">Scam category detected</option><option value="no_pattern">No scam category</option><option value="legitimate">Explicit legitimate label</option><option value="uncertain">Explicit uncertain label</option></select></label>
      <label>Risk<select value={props.riskLevel} onChange={event => props.setRiskLevel(event.target.value)}><option value="">All risk levels</option>{['Low', 'Moderate', 'Medium', 'High', 'Critical'].map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Sort by<select value={props.sortBy} onChange={event => props.setSortBy(event.target.value as typeof props.sortBy)}><option value="created_at">Created date</option><option value="risk_score">Risk score</option><option value="risk_level">Risk level</option><option value="category">Category</option></select></label>
      <label>Order<select value={props.sortDirection} onChange={event => props.setSortDirection(event.target.value as typeof props.sortDirection)}><option value="desc">Descending</option><option value="asc">Ascending</option></select></label>
      <button className="button button-quiet">Search</button>
    </form>
    {props.error && <div className="error-banner" role="alert"><ShieldAlert size={16} />{props.error}</div>}
    {props.busy ? <p role="status" className="admin-loading">Loading investigation metadata…</p> : props.data?.items.length ? <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Created</th><th>Input</th><th>Classification basis</th><th>Category</th><th>Risk</th><th>Indicators</th><th></th></tr></thead><tbody>{props.data.items.map(row => <tr key={row.id}><td>{formatLocalTimestamp(row.created_at)}</td><td>{titleCase(row.input_type)}</td><td><span>{titleCase(row.classification)}</span><small>{titleCase(row.classification_source)}</small></td><td>{row.category ? titleCase(row.category) : '—'}</td><td><StatusPill value={row.risk_level} /><small>{row.risk_score} / 100</small></td><td>{row.finding_count} findings · {row.url_count} URLs</td><td><button className="admin-detail-button" onClick={() => props.onOpenDetail(row.id)}>Details</button></td></tr>)}</tbody></table></div> : !props.busy && <EmptyState title="No investigations match" body="Try a broader date range or remove some filters." />}
    <div className="admin-pagination"><span>Page {props.page} of {Math.max(props.data?.total_pages ?? 0, 1)} · {props.data?.total ?? 0} records</span><div><button className="button button-quiet" disabled={props.page <= 1 || props.busy} onClick={() => props.setPage(Math.max(1, props.page - 1))}><ChevronLeft size={15} /> Previous</button><button className="button button-quiet" disabled={props.page >= (props.data?.total_pages ?? 0) || props.busy} onClick={() => props.setPage(props.page + 1)}>Next <ChevronRight size={15} /></button></div></div>
  </section>
}

function InvestigationDialog({ detail, busy, error, close }: { detail: AdminInvestigationDetail | null; busy: boolean; error: string; close: () => void }) {
  return <div className="admin-dialog-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) close() }}><section className="panel admin-investigation-dialog" role="dialog" aria-modal="true" aria-labelledby="admin-detail-title"><header><div><span className="eyebrow">READ-ONLY RECORD</span><h2 id="admin-detail-title">Investigation details</h2></div><button className="button button-quiet" onClick={close}>Close</button></header>
    {busy && <p role="status">Loading safe metadata…</p>}{error && <div className="error-banner" role="alert">{error}</div>}
    {detail && <><div className="admin-detail-summary"><span>ID <strong>{detail.id}</strong></span><span>Created <strong>{formatLocalTimestamp(detail.created_at)}</strong></span><span>Input <strong>{titleCase(detail.input_type)}</strong></span><span>Category <strong>{detail.category ? titleCase(detail.category) : 'No scam pattern'}</strong></span><span>Risk <strong>{detail.risk_level} · {detail.risk_score}/100</strong></span><span>URLs <strong>{detail.url_count}</strong></span></div>
      <h3>Finding metadata</h3>{detail.findings.length ? <ul className="admin-detail-list">{detail.findings.map((finding, index) => <li key={`${finding.indicator}-${index}`}><strong>{finding.indicator ?? 'Finding'}</strong><span>{finding.source ?? 'Unknown source'} · {finding.verification_level ?? 'Unspecified'}</span></li>)}</ul> : <p>No findings recorded.</p>}
      <h3>Provider outcomes</h3>{detail.providers.length ? <ul className="admin-detail-list">{detail.providers.map((provider, index) => <li key={`${provider.provider}-${index}`}><strong>{provider.provider}</strong><span>{provider.status}{provider.is_malicious === true ? ' · malicious verdict' : provider.is_malicious === false ? ' · no known threat; not verified safe' : ''}</span></li>)}</ul> : <p>No provider records.</p>}
      <h3>Agent audit</h3>{detail.agents.length ? <ul className="admin-detail-list">{detail.agents.map((agent, index) => <li key={`${agent.name}-${index}`}><strong>{agent.name}</strong><span>{agent.status} · {agent.duration_ms} ms</span></li>)}</ul> : <p>No agent audit records.</p>}
      {detail.ml_prediction && <p className="admin-ml-detail">Experimental ML: {detail.ml_prediction.status} · {detail.ml_prediction.predicted_class ?? 'no class'} · {detail.ml_prediction.model_version ?? 'no model version'}</p>}
      <p className="admin-health-footnote">{detail.privacy_note}</p>
    </>}
  </section></div>
}

function Metric({ label, value, note, accent = '' }: { label: string; value: string | number; note: string; accent?: string }) {
  return <section className={`admin-kpi panel ${accent}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></section>
}
function ChartCard({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return <section className="panel admin-chart-card"><div className="admin-panel-heading"><div><h3>{title}</h3><p>{subtitle}</p></div></div><div className="admin-chart-area">{children}</div></section>
}
function Donut({ values, empty }: { values: Array<{ name: string; value: number }>; empty: string }) {
  const chartValues = values.filter(item => item.value > 0)
  if (!chartValues.length) return <EmptyState title="No chart data" body={empty} />
  return <div className="admin-donut-layout"><div className="admin-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={chartValues} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="82%" paddingAngle={3}>{chartValues.map((entry, index) => <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />)}</Pie><Tooltip contentStyle={chartTooltipStyle} /></PieChart></ResponsiveContainer></div><ul className="admin-legend">{chartValues.map((item, index) => <li key={item.name}><i style={{ background: pieColors[index % pieColors.length] }} /><span>{item.name}</span><strong>{item.value}</strong></li>)}</ul></div>
}
function HorizontalBars({ values, empty }: { values: Record<string, number>; empty: string }) {
  const rows = Object.entries(values).filter(([, count]) => count > 0).sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...rows.map(([, count]) => count))
  return rows.length
    ? <div className="admin-horizontal-bars">{rows.map(([name, count]) => <div className="admin-bar-row" key={name}><span>{titleCase(name)}</span><div><i style={{ width: `${Math.max(2, count / max * 100)}%` }} /></div><strong>{count}</strong></div>)}</div>
    : <EmptyState title="No records" body={empty} />
}
function StatusPill({ value }: { value: string }) { return <span className={`admin-status-pill ${value.toLowerCase().replaceAll(/[^a-z0-9]+/g, '-')}`}>{titleCase(value)}</span> }
function EmptyState({ title, body }: { title: string; body: string }) { return <div className="admin-empty"><span><Siren size={17} /></span><strong>{title}</strong><p>{body}</p></div> }
