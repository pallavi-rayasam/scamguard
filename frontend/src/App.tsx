import { Component, createContext, useContext, useEffect, useMemo, useRef, useState, type ErrorInfo, type ReactNode } from 'react'
import {
  ArrowRight, BookOpen, CheckCircle2, ChevronRight, CircleAlert, ClipboardList, LayoutDashboard,
  LoaderCircle, LockKeyhole, LogOut, Menu, MessageSquareWarning, ScanLine, Search, Settings,
  Shield, ShieldCheck, ShieldAlert, Sparkles, Trash2, TriangleAlert, Download, X,
} from 'lucide-react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type Report, type User } from './api'
import { UrlResults } from './UrlResults'
import { categoryLabel, formatLocalTimestamp } from './reportFormatting'

type Page = 'home' | 'login' | 'dashboard' | 'scanner' | 'history' | 'awareness' | 'settings' | 'report'
type AuthContextType = { user: User | null; setUser: (user: User | null) => void; signOut: () => Promise<void> }
const AuthContext = createContext<AuthContextType | null>(null)
const useAuth = () => {
  const value = useContext(AuthContext)
  if (!value) throw new Error('Auth context missing')
  return value
}

class ErrorBoundary extends Component<{ children: ReactNode }, { error: boolean }> {
  state = { error: false }
  static getDerivedStateFromError() { return { error: true } }
  componentDidCatch(_error: Error, _info: ErrorInfo) { /* Keep the fallback generic; never log user content. */ }
  render() { return this.state.error ? <main className="center-page"><div className="panel"><CircleAlert /><h1>Something went wrong</h1><p>Your investigation content was not included in the error report.</p><button className="button" onClick={() => location.reload()}>Reload</button></div></main> : this.props.children }
}

function readPage(): Page {
  const path = location.hash.replace('#/', '').split('/')[0]
  return (['home', 'login', 'dashboard', 'scanner', 'history', 'awareness', 'settings', 'report'].includes(path) ? path : 'home') as Page
}
function readReportId() { return location.hash.replace('#/', '').split('/')[1] ?? '' }

export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [page, setPage] = useState<Page>(readPage)
  const [reportId, setReportId] = useState(readReportId)

  useEffect(() => {
    const sync = () => { setPage(readPage()); setReportId(readReportId()) }
    addEventListener('hashchange', sync)
    api.me().then(setUser).catch(() => setUser(null)).finally(() => setLoaded(true))
    return () => removeEventListener('hashchange', sync)
  }, [])

  const navigate = (next: Page, id = '') => {
    setReportId(id)
    location.hash = next === 'report' && id ? `/report/${encodeURIComponent(id)}` : `/${next}`
  }
  const signOut = async () => { try { await api.logout() } catch { /* local session is cleared either way */ } setUser(null); navigate('home') }
  const auth = useMemo(() => ({ user, setUser, signOut }), [user])

  if (!loaded) return <main className="center-page"><LoaderCircle className="spin" /></main>
  const needsAuth = ['dashboard', 'scanner', 'history', 'awareness', 'settings', 'report'].includes(page)
  if (needsAuth && !user) return <AuthContext.Provider value={auth}><LoginPage navigate={navigate} /></AuthContext.Provider>
  if (page === 'home' && !user) return <LandingPage navigate={navigate} />
  if (page === 'login' || page === 'home') return <AuthContext.Provider value={auth}><LoginPage navigate={navigate} /></AuthContext.Provider>
  return <AuthContext.Provider value={auth}><ErrorBoundary><Shell page={page} navigate={navigate} reportId={reportId} /></ErrorBoundary></AuthContext.Provider>
}

function LandingPage({ navigate }: { navigate: (page: Page) => void }) {
  return <main className="landing">
    <header className="landing-top"><Brand /><button className="button button-quiet" onClick={() => navigate('login')}>Sign in</button></header>
    <section className="hero"><div className="eyebrow"><span className="status-dot" />Evidence-led protection</div><h1>Pause. Check.<br /><span>Stay in control.</span></h1><p>Investigate suspicious messages, links, and payment requests with clear evidence, transparent risk scores, and calm next steps.</p><div className="hero-actions"><button className="button" onClick={() => navigate('login')}>Open investigation centre <ArrowRight size={17} /></button><span className="privacy-note"><LockKeyhole size={14} /> Advisory only · No payments initiated</span></div></section>
    <section className="feature-row"><Feature icon={<Search />} title="Investigate" body="Check text, links, conversations, and payment requests." /><Feature icon={<ShieldCheck />} title="Understand" body="See which indicators were found and how they were verified." /><Feature icon={<MessageSquareWarning />} title="Act calmly" body="Get practical steps and independent verification guidance." /></section>
    <footer className="landing-footer">Unknown does not mean safe. Scores are indicators, not probabilities.</footer>
  </main>
}

function Feature({ icon, title, body }: { icon: ReactNode; title: string; body: string }) { return <div className="feature-card"><div className="feature-icon">{icon}</div><h3>{title}</h3><p>{body}</p></div> }
function Brand() { return <div className="brand"><div className="brand-icon"><Shield size={20} /></div><span>scamguard<span className="brand-dot">.</span></span></div> }

function LoginPage({ navigate }: { navigate: (page: Page) => void }) {
  const { setUser } = useAuth()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<'email' | 'password', string>>>({})
  const [busy, setBusy] = useState(false)
  const emailRef = useRef<HTMLInputElement>(null)

  function clearFieldError(field: 'email' | 'password') {
    setFieldErrors(current => {
      const next = { ...current }
      delete next[field]
      return next
    })
  }

  function validate(): Partial<Record<'email' | 'password', string>> {
    const issues: Partial<Record<'email' | 'password', string>> = {}
    const normalizedEmail = email.trim()
    const at = normalizedEmail.lastIndexOf('@')
    const domain = at >= 0 ? normalizedEmail.slice(at + 1) : ''
    if (!normalizedEmail) issues.email = 'Email is required.'
    else if (Array.from(normalizedEmail).length > 254) issues.email = 'Email must be at most 254 characters.'
    else if (!emailRef.current?.validity.valid || at <= 0 || !domain.includes('.') || domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) {
      issues.email = 'Enter a valid email address, such as name@example.com.'
    }

    const passwordLength = Array.from(password).length
    if (!passwordLength) issues.password = 'Password is required.'
    else if (passwordLength > 128) issues.password = 'Password must be at most 128 characters.'
    else if (mode === 'register' && passwordLength < 12) issues.password = 'Password must be at least 12 characters.'
    return issues
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setError('')
    const validationErrors = validate()
    setFieldErrors(validationErrors)
    if (Object.keys(validationErrors).length) return

    setBusy(true)
    try {
      const user = mode === 'login'
        ? await api.login(email.trim(), password)
        : await api.register(email.trim(), password)
      setUser(user)
      navigate('dashboard')
    } catch (caught) {
      if (typeof caught === 'object' && caught !== null && 'fieldErrors' in caught) {
        const apiFields = (caught as { fieldErrors?: Partial<Record<'email' | 'password', string>> }).fieldErrors
        setFieldErrors(apiFields ?? {})
      }
      setError(caught instanceof Error ? caught.message : 'Could not complete the request. Please retry.')
    } finally {
      setBusy(false)
    }
  }

  return <main className="center-page"><div className="auth-card"><button className="back-link" onClick={() => navigate('home')}>← Back</button><Brand /><div className="auth-heading"><span className="eyebrow">Investigation workspace</span><h1>{mode === 'login' ? 'Welcome back' : 'Create your account'}</h1><p>Your reports stay private to your account.</p></div>
    <form onSubmit={submit} className="form-stack" noValidate>
      <label>Email<input ref={emailRef} type="email" autoComplete="email" required value={email} onChange={event => { setEmail(event.target.value); clearFieldError('email') }} placeholder="you@example.com" aria-invalid={Boolean(fieldErrors.email)} aria-describedby={fieldErrors.email ? 'email-hint email-error' : 'email-hint'} /></label>
      <small id="email-hint" className="field-hint">Use a valid email address with a dotted domain, up to 254 characters.</small>
      {fieldErrors.email && <small id="email-error" className="field-error" role="alert">{fieldErrors.email}</small>}
      <label>Password<input type="password" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required value={password} onChange={event => { setPassword(event.target.value); clearFieldError('password') }} placeholder={mode === 'register' ? 'At least 12 characters' : 'Your password'} aria-invalid={Boolean(fieldErrors.password)} aria-describedby={fieldErrors.password ? 'password-hint password-error' : 'password-hint'} /></label>
      <small id="password-hint" className="field-hint">{mode === 'register' ? 'Use 12–128 characters.' : 'Use 1–128 characters.'}</small>
      {fieldErrors.password && <small id="password-error" className="field-error" role="alert">{fieldErrors.password}</small>}
      {error && <div className="error-message" role="alert"><CircleAlert size={16} />{error}</div>}
      <button className="button button-full" disabled={busy} aria-busy={busy}>{busy ? <><LoaderCircle className="spin" size={17} />{mode === 'register' ? 'Creating account…' : 'Signing in…'}</> : mode === 'login' ? 'Sign in securely' : 'Create account'}</button>
    </form>
    <p className="switch-mode">{mode === 'login' ? 'New to ScamGuard?' : 'Already have an account?'} <button className="text-button" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); setFieldErrors({}) }}>{mode === 'login' ? 'Create account' : 'Sign in'}</button></p><div className="privacy-box"><LockKeyhole size={15} /><span>Never enter an OTP, UPI PIN, password, or full card number into an investigation.</span></div></div></main>
}

const navItems: Array<{ page: Page; label: string; icon: ReactNode }> = [
  { page: 'dashboard', label: 'Overview', icon: <LayoutDashboard size={18} /> },
  { page: 'scanner', label: 'New investigation', icon: <ScanLine size={18} /> },
  { page: 'history', label: 'Investigation history', icon: <ClipboardList size={18} /> },
  { page: 'awareness', label: 'Awareness centre', icon: <BookOpen size={18} /> },
]

function Shell({ page, navigate, reportId }: { page: Page; navigate: (page: Page, id?: string) => void; reportId: string }) {
  const { user, signOut } = useAuth()
  const [mobileNav, setMobileNav] = useState(false)
  return <div className="app-shell"><aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}><div className="sidebar-head"><Brand /><button className="icon-button mobile-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={18} /></button></div><div className="workspace-label">WORKSPACE</div><nav>{navItems.map(item => <button key={item.page} className={`nav-item ${page === item.page ? 'active' : ''}`} onClick={() => { navigate(item.page); setMobileNav(false) }}>{item.icon}<span>{item.label}</span>{page === item.page && <ChevronRight className="nav-chevron" size={15} />}</button>)}</nav><div className="sidebar-bottom"><div className="safety-tip"><Sparkles size={16} /><div><strong>Safety note</strong><span>We never initiate payments or verify account holders.</span></div></div><button className={`nav-item ${page === 'settings' ? 'active' : ''}`} onClick={() => navigate('settings')}><Settings size={18} /><span>Settings</span></button><div className="user-row"><div className="avatar">{user?.email.slice(0, 1).toUpperCase()}</div><div className="user-meta"><strong>{user?.email}</strong><span>Personal workspace</span></div><button className="icon-button logout-button" onClick={signOut} aria-label="Sign out"><LogOut size={16} /></button></div></div></aside>
    {mobileNav && <button className="scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <main className="main-area"><header className="topbar"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileNav(true)}><Menu size={20} /></button><div className="breadcrumb"><span>Workspace</span><ChevronRight size={14} /><strong>{pageTitle(page)}</strong></div><div className="topbar-right"><span className="secure-pill"><span className="status-dot" />Private session</span></div></header><div className="content-area">{page === 'dashboard' && <DashboardPage navigate={navigate} />}{page === 'scanner' && <ScannerPage navigate={navigate} />}{page === 'history' && <HistoryPage navigate={navigate} />}{page === 'awareness' && <AwarenessPage />}{page === 'settings' && <SettingsPage navigate={navigate} />}{page === 'report' && <ReportPage id={reportId} navigate={navigate} />}</div></main></div>
}
function pageTitle(page: Page) { return ({ dashboard: 'Overview', scanner: 'New investigation', history: 'History', awareness: 'Awareness centre', settings: 'Settings', report: 'Investigation report', home: 'Home', login: 'Sign in' })[page] }

function DashboardPage({ navigate }: { navigate: (page: Page, id?: string) => void }) {
  const [stats, setStats] = useState<{ total_investigations: number; risk_distribution: Record<string, number>; category_distribution: Record<string, number> } | null>(null)
  const [recent, setRecent] = useState<Array<{ id: string; category: string | null; risk_score: number; risk_level: string; created_at: string }>>([])
  const [error, setError] = useState('')
  useEffect(() => { api.stats().then(setStats).catch(e => setError(e.message)); api.history().then(data => setRecent(data.items.slice(0, 5))).catch(e => setError(e.message)) }, [])
  const chartData = Object.entries(stats?.risk_distribution ?? {}).map(([risk, count]) => ({ risk, count }))
  const categoryChartData = Object.entries(stats?.category_distribution ?? {}).map(([category, count]) => ({ category: categoryLabel(category), count }))
  return <><PageHeader eyebrow="YOUR SECURITY SNAPSHOT" title="Good to see you" description="Review recent investigations or start a new check." action={<button className="button" onClick={() => navigate('scanner')}><ScanLine size={17} /> New investigation</button>} />
    {error && <div className="error-banner"><CircleAlert size={17} />{error}</div>}
    <div className="stat-grid"><StatCard icon={<ClipboardList />} label="Investigations" value={stats?.total_investigations ?? '—'} note="From your saved reports" /><StatCard icon={<ShieldAlert />} label="High / critical" value={(stats?.risk_distribution?.High ?? 0) + (stats?.risk_distribution?.Critical ?? 0)} note="Risk indicators found" /><StatCard icon={<ShieldCheck />} label="Model confidence" value="Unavailable" note="No calibrated model yet" /></div>
    <div className="dashboard-grid"><section className="panel chart-panel"><div className="section-head"><div><h2>Risk distribution</h2><p>Based on your investigation records</p></div><span className="live-tag"><span className="status-dot" />Database</span></div>{chartData.length ? <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={chartData} margin={{ top: 16, right: 12, left: -20, bottom: 0 }}><CartesianGrid stroke="#20334a" strokeDasharray="4 4" vertical={false} /><XAxis dataKey="risk" axisLine={false} tickLine={false} tick={{ fill: '#8193a9', fontSize: 12 }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#8193a9', fontSize: 12 }} /><Tooltip contentStyle={{ background: '#101d2e', border: '1px solid #263b55', borderRadius: 10, color: '#edf5ff' }} /><Bar dataKey="count" fill="#34c9d9" radius={[5, 5, 0, 0]} /></BarChart></ResponsiveContainer></div> : <EmptyState title="No chart data yet" body="Submit your first message or link to populate this chart." />}</section>
      <section className="panel recent-panel"><div className="section-head"><div><h2>Recent investigations</h2><p>Your latest saved reports</p></div><button className="link-button" onClick={() => navigate('history')}>View all <ArrowRight size={14} /></button></div>{recent.length ? <div className="recent-list">{recent.map(row => <button className="recent-row" key={row.id} onClick={() => navigate('report', row.id)}><RiskBadge level={row.risk_level} /><span className="recent-title">{categoryLabel(row.category)}</span><span className="recent-time">{new Date(row.created_at).toLocaleDateString()}</span></button>)}</div> : <EmptyState title="Nothing investigated yet" body="Your saved reports will appear here." />}</section></div>
    <section className="panel chart-panel category-chart-panel"><div className="section-head"><div><h2>Scam category distribution</h2><p>Only investigations with a matched scam category are included.</p></div><span className="live-tag"><span className="status-dot" />Database</span></div>{categoryChartData.length ? <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><BarChart data={categoryChartData} margin={{ top: 16, right: 12, left: -20, bottom: 0 }}><CartesianGrid stroke="#20334a" strokeDasharray="4 4" vertical={false} /><XAxis dataKey="category" axisLine={false} tickLine={false} tick={{ fill: '#8193a9', fontSize: 12 }} /><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#8193a9', fontSize: 12 }} /><Tooltip contentStyle={{ background: '#101d2e', border: '1px solid #263b55', borderRadius: 10, color: '#edf5ff' }} /><Bar dataKey="count" fill="#8b83ef" radius={[5, 5, 0, 0]} /></BarChart></ResponsiveContainer></div> : <EmptyState title="No scam categories yet" body="Only matched scam patterns appear in this chart." />}</section>
    <div className="notice-strip"><TriangleAlert size={17} /><p><strong>A risk score is not a probability.</strong> Unknown URLs remain unverified even when no known threat is found.</p><button className="link-button" onClick={() => navigate('awareness')}>Safety guidance <ArrowRight size={14} /></button></div>
  </>
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) { return <div className="page-header"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{action}</div> }
function StatCard({ icon, label, value, note }: { icon: ReactNode; label: string; value: ReactNode; note: string }) { return <div className="stat-card"><div className="stat-top"><div className="stat-icon">{icon}</div><span>{label}</span></div><strong className="stat-value">{value}</strong><span className="stat-note">{note}</span></div> }
function EmptyState({ title, body }: { title: string; body: string }) { return <div className="empty-state"><div className="empty-icon"><ClipboardList size={20} /></div><strong>{title}</strong><p>{body}</p></div> }

function ScannerPage({ navigate }: { navigate: (page: Page, id?: string) => void }) {
  const [mode, setMode] = useState('text')
  const [text, setText] = useState('')
  const [image, setImage] = useState<File | null>(null)
  const [transaction, setTransaction] = useState({ description: '', recipient: '', reason: '', amount: '', relatedChat: '' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (mode === 'payment_request' && !transaction.description.trim()) return
    if (mode === 'image' && !image) return
    if (!['payment_request', 'image'].includes(mode) && !text.trim()) return
    setBusy(true); setError('')
    try {
      let result
      if (mode === 'payment_request') {
        result = await api.transaction({
          description: transaction.description,
          claimed_recipient: transaction.recipient,
          reason: transaction.reason,
          amount: transaction.amount ? Number(transaction.amount) : undefined,
          related_chat: transaction.relatedChat,
        })
      } else if (mode === 'image' && image) {
        result = await api.image(image)
      } else if (mode === 'conversation') {
        const messages = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => {
          const match = line.match(/^([^:]{1,80}):\s*(.+)$/)
          return match ? { sender: match[1].trim(), text: match[2].trim() } : { sender: 'participant', text: line }
        })
        result = await api.conversation(messages)
      } else {
        result = await api.scan(text, mode)
      }
      navigate('report', result.id)
    }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Investigation could not be completed.') }
    finally { setBusy(false) }
  }
  const modes = [{ id:'text', label:'Message or SMS' }, { id:'url', label:'URL' }, { id:'conversation', label:'Conversation' }, { id:'payment_request', label:'Payment request' }, { id:'email', label:'Email text' }, { id:'image', label:'Screenshot' }]
  return <><PageHeader eyebrow="INVESTIGATION CENTRE" title="Check before you act" description="Paste the message, link, or request you want to review. Sensitive values are redacted before saving." />
    <div className="scanner-layout"><section className="panel scanner-panel"><div className="mode-tabs" role="tablist" aria-label="Input type">{modes.map(item => <button role="tab" aria-selected={mode === item.id} className={mode === item.id ? 'mode-tab selected' : 'mode-tab'} key={item.id} onClick={() => setMode(item.id)}>{item.label}</button>)}</div>
      <form onSubmit={submit}>{mode === 'payment_request' ? <div className="transaction-fields"><label>Description<textarea value={transaction.description} onChange={event => setTransaction({ ...transaction, description: event.target.value })} maxLength={2000} required rows={3} placeholder="What are you being asked to pay for?" /></label><div className="transaction-row"><label>Claimed recipient<input value={transaction.recipient} onChange={event => setTransaction({ ...transaction, recipient: event.target.value })} maxLength={160} placeholder="Person or organisation" /></label><label>Amount (INR)<input type="number" min="0" max="100000000" step="0.01" value={transaction.amount} onChange={event => setTransaction({ ...transaction, amount: event.target.value })} placeholder="Optional" /></label></div><label>Reason for payment<input value={transaction.reason} onChange={event => setTransaction({ ...transaction, reason: event.target.value })} maxLength={300} placeholder="e.g. bill, fee, investment" /></label><label>Related conversation<textarea value={transaction.relatedChat} onChange={event => setTransaction({ ...transaction, relatedChat: event.target.value })} maxLength={6000} rows={5} placeholder="Paste related chat if useful" /></label></div> : mode === 'image' ? <div className="transaction-fields"><label htmlFor="investigation-image">Screenshot image<input id="investigation-image" aria-label="Screenshot image" type="file" accept=".jpg,.jpeg,.png,image/jpeg,image/png" onChange={event => setImage(event.currentTarget.files?.[0] ?? null)} /></label><p>JPG, JPEG, or PNG up to 5 MB. Text is extracted for analysis; links shown in the image are never opened.</p>{image && <div className="input-meta"><span>{image.name}</span><span>{(image.size / 1024 / 1024).toFixed(2)} MB</span></div>}</div> : <><label htmlFor="investigation-text">{mode === 'url' ? 'Paste a suspicious URL' : mode === 'conversation' ? 'Paste the conversation in order' : 'Paste suspicious content'}</label><textarea id="investigation-text" value={text} onChange={event => setText(event.target.value)} maxLength={12000} required rows={10} placeholder={mode === 'url' ? 'https://example.in/...' : 'Paste the message or describe what happened…'} /><div className="input-meta"><span>{text.length.toLocaleString()} / 12,000 characters</span><span><LockKeyhole size={13} /> Redacted before saving</span></div></>}
        {error && <div className="error-message"><CircleAlert size={16} />{error}</div>}<div className="form-actions"><p><strong>Never include</strong> an OTP, UPI PIN, password, or full card number.</p><button className="button" disabled={busy || (mode === 'payment_request' ? !transaction.description.trim() : mode === 'image' ? !image : !text.trim())}>{busy ? <><LoaderCircle className="spin" size={17} /> Investigating…</> : <>Run investigation <ArrowRight size={16} /></>}</button></div></form></section>
      <aside className="panel scanner-aside"><div className="aside-icon"><ShieldCheck size={21} /></div><h3>What happens next?</h3><ul><li><CheckCircle2 size={15} />Text is normalized and sensitive values are removed.</li><li><CheckCircle2 size={15} />Deterministic checks look for scam indicators.</li><li><CheckCircle2 size={15} />Configured threat-intel providers may be queried using URL origins only.</li><li><CheckCircle2 size={15} />You receive a risk score with evidence and limitations.</li></ul><div className="aside-warning"><TriangleAlert size={15} /><span>Unknown does not mean safe. This tool never verifies account ownership.</span></div></aside></div>
  </>
}

function RiskBadge({ level }: { level: string }) { return <span className={`risk-badge ${level.toLowerCase()}`}><span />{level}</span> }

function HistoryPage({ navigate }: { navigate: (page: Page, id?: string) => void }) {
  const [items, setItems] = useState<Array<{ id: string; category: string | null; risk_score: number; risk_level: string; created_at: string }>>([])
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [search, setSearch] = useState('')
  const [risk, setRisk] = useState('')
  useEffect(() => { setBusy(true); api.history({ q: search, risk_level: risk }).then(data => { setItems(data.items); setError('') }).catch(e => setError(e.message)).finally(() => setBusy(false)) }, [search, risk])
  async function deleteReport(id: string, event: React.MouseEvent) {
    event.stopPropagation()
    if (!window.confirm('Delete this investigation and its report?')) return
    try { await api.deleteInvestigation(id); setItems(previous => previous.filter(item => item.id !== id)) }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'The report could not be deleted.') }
  }
  return <><PageHeader eyebrow="SAVED REPORTS" title="Investigation history" description="Search, reopen, and review reports saved to your account." action={<button className="button" onClick={() => navigate('scanner')}><ScanLine size={17} /> New investigation</button>} />
    <section className="panel table-panel"><div className="section-head"><div><h2>Your reports</h2><p>Only your account's investigations are shown.</p></div><div className="history-count">{items.length} reports</div></div><form className="history-controls" onSubmit={event => { event.preventDefault(); setSearch(query.trim()) }}><label className="search-field"><Search size={15} /><input aria-label="Search reports" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search redacted content" /></label><select aria-label="Filter by risk" value={risk} onChange={event => setRisk(event.target.value)}><option value="">All risk levels</option><option>Low</option><option>Moderate</option><option>High</option><option>Critical</option></select><button className="button button-quiet">Search</button></form>{error && <div className="error-message"><CircleAlert size={16} />{error}</div>}{busy ? <div className="loading-row"><LoaderCircle className="spin" /> Loading reports…</div> : items.length ? <div className="table-scroll"><table><thead><tr><th>Risk</th><th>Category</th><th>Score</th><th>Date</th><th>Actions</th></tr></thead><tbody>{items.map(item => <tr key={item.id} onClick={() => navigate('report', item.id)}><td><RiskBadge level={item.risk_level} /></td><td>{categoryLabel(item.category)}</td><td>{item.risk_score} / 100</td><td>{formatLocalTimestamp(item.created_at)}</td><td className="history-actions"><button className="icon-button" aria-label={`Delete ${categoryLabel(item.category)} report`} onClick={event => deleteReport(item.id, event)}><Trash2 size={15} /></button><ArrowRight size={15} /></td></tr>)}</tbody></table></div> : <EmptyState title="No reports saved" body="Your investigations will be listed here." />}</section>
  </>
}

function ReportPage({ id, navigate }: { id: string; navigate: (page: Page, id?: string) => void }) {
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState('')
  const [feedback, setFeedback] = useState('')
  const [pdfBusy, setPdfBusy] = useState(false)
  const [pdfError, setPdfError] = useState('')
  useEffect(() => { if (id) api.report(id).then(setReport).catch(e => setError(e.message)); else setError('Open this report from history to view its details.') }, [id])
  async function sendFeedback(rating: string) { if (!id) return; try { await api.feedback(id, rating); setFeedback('Thanks. Your feedback is saved separately from evaluation labels.') } catch (e) { setFeedback(e instanceof Error ? e.message : 'Feedback was not saved.') } }
  async function downloadPdf() {
    setPdfBusy(true); setPdfError('')
    try {
      const blob = await api.reportPdf(id)
      const objectUrl = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = objectUrl
      link.download = 'scamguard-report-' + id + '.pdf'
      document.body.appendChild(link)
      link.click()
      link.remove()
      globalThis.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)
    } catch (caught) {
      setPdfError(caught instanceof Error ? caught.message : 'PDF could not be downloaded.')
    } finally {
      setPdfBusy(false)
    }
  }
  if (error) return <><PageHeader eyebrow="REPORT" title="Report unavailable" description={error} /><button className="button" onClick={() => navigate('history')}>Back to history</button></>
  if (!report) return <div className="loading-row"><LoaderCircle className="spin" /> Loading report…</div>
  return <><PageHeader eyebrow="INVESTIGATION REPORT" title="Evidence and next steps" description={`Created ${formatLocalTimestamp(report.created_at)}`} action={<><button className="button" onClick={downloadPdf} disabled={pdfBusy}><Download size={16} /> {pdfBusy ? 'Preparing PDF…' : 'Download PDF'}</button><button className="button button-quiet" onClick={() => navigate('history')}>Back to history</button></>} />
    {pdfError && <div className="error-message" role="alert"><CircleAlert size={16} />{pdfError}</div>}
    <div className="report-grid"><section className="panel score-panel"><span className="eyebrow">DETERMINISTIC RISK SCORE</span><div className="score-display"><strong>{report.risk_score}</strong><span>/ 100</span></div><RiskBadge level={report.risk_level} /><p>This score is not a probability. Model confidence: <strong>{report.model_confidence.replaceAll('_', ' ')}</strong>.</p><div className="score-meta"><div><span>Evidence strength</span><strong>{report.evidence_strength}</strong></div><div><span>Category</span><strong>{categoryLabel(report.category)}</strong></div></div></section>
      <section className="panel findings-panel"><div className="section-head"><div><h2>Indicators found</h2><p>Each finding shows its verification level.</p></div></div>{report.findings.length ? <div className="finding-list">{report.findings.map((item, index) => <div className="finding-row" key={`${String(item.indicator)}-${index}`}><div className="finding-icon"><TriangleAlert size={16} /></div><div><strong>{String(item.detail)}</strong><span>{String(item.source)} · {String(item.verification_level)}</span></div></div>)}</div> : <EmptyState title="No indicators detected" body="No known threat does not mean the content is safe. Verify independently." />}</section>
    </div>
    {report.transaction_advisory && <section className="panel transaction-advisory"><div className="section-head"><div><h2>Pre-transaction advisory</h2><p>Advisory only · recipient identity not verified · no payment initiated.</p></div></div><p>{report.transaction_advisory.advisory}</p><ul>{report.transaction_advisory.recommendations.map(item => <li key={item}>{item}</li>)}</ul></section>}
    {report.urls.length > 0 && <UrlResults urls={report.urls} urlScans={report.url_scans ?? []} threatIntelResults={report.threat_intel_results ?? []} findings={report.findings} />}
    {report.explanation && <section className="panel explanation-panel"><Sparkles size={18} /><div><h2>AI explanation <span className="verification-tag llm">LLM inferred</span></h2><p>{report.explanation}</p><small>This model explanation is an opinion, not verified evidence.</small></div></section>}
    <div className="report-grid lower-grid"><section className="panel"><div className="section-head"><div><h2>Recommended next steps</h2><p>Advisory guidance for you to verify independently.</p></div></div><ol className="recommendation-list">{report.recommendations.map((item, index) => <li key={index}><span>{index + 1}</span>{item}</li>)}</ol></section><section className="panel"><div className="section-head"><div><h2>Investigation audit</h2><p>Status per stage and tool.</p></div></div><div className="agent-list">{report.agents.map((agent, index) => <div className="agent-row" key={`${String(agent.agent_name)}-${index}`}><div className={`agent-status ${agent.status === 'completed' ? 'done' : ''}`}>{agent.status === 'completed' ? <CheckCircle2 size={15} /> : <CircleAlert size={15} />}</div><span>{String(agent.agent_name)}</span><span className={`status-label ${String(agent.status)}`}>{String(agent.status).replaceAll('_', ' ')}</span></div>)}</div></section></div>
    <section className="panel availability-panel"><div><h2>Data availability</h2><p>Provider statuses are reported; no sample reputation data is substituted.</p></div><pre>{JSON.stringify(report.data_availability, null, 2)}</pre></section>
    <section className="panel limitation-panel"><TriangleAlert size={17} /><div><h2>Limitations</h2><ul>{report.limitations.map(item => <li key={item}>{item}</li>)}</ul></div></section>
    <section className="panel feedback-panel"><div><h2>Was this report helpful?</h2><p>Your feedback is not treated as ground truth for evaluation.</p></div><div className="feedback-actions"><button onClick={() => sendFeedback('correct')}>Correct</button><button onClick={() => sendFeedback('incorrect')}>Incorrect</button><button onClick={() => sendFeedback('uncertain')}>Uncertain</button></div>{feedback && <span className="feedback-message">{feedback}</span>}</section>
  </>
}

function AwarenessPage() {
  const [items, setItems] = useState<Array<{ title: string; body: string }> | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { api.awareness().then(data => setItems(data.items)).catch(e => setError(e.message)) }, [])
  return <><PageHeader eyebrow="STAY INFORMED" title="Awareness centre" description="Practical ways to verify requests and reduce risk." />{error && <div className="error-message"><CircleAlert size={16} />{error}</div>}<div className="awareness-grid">{items?.map((item, index) => <section className="panel awareness-card" key={item.title}><div className="awareness-number">0{index + 1}</div><h2>{item.title}</h2><p>{item.body}</p></section>)}</div><section className="official-card"><div className="official-icon"><ShieldAlert /></div><div><span className="eyebrow">IF MONEY HAS BEEN LOST IN INDIA</span><h2>Contact your bank and report it quickly</h2><p>Call 1930 or visit cybercrime.gov.in. Use the official contact details you find independently.</p></div><a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">Open portal <ArrowRight size={15} /></a></section></>
}

function SettingsPage({ navigate }: { navigate: (page: Page) => void }) {
  const { signOut } = useAuth()
  const [warning, setWarning] = useState(false)
  const [message, setMessage] = useState('')
  async function deleteData() { try { await api.deleteData(); setMessage('Your account data was deleted.'); setWarning(false); await signOut(); navigate('home') } catch (e) { setMessage(e instanceof Error ? e.message : 'Deletion failed.') } }
  return <><PageHeader eyebrow="ACCOUNT & PRIVACY" title="Settings" description="Manage session and saved investigation data." /><section className="panel settings-card"><div className="settings-item"><div><h2>Sign out</h2><p>End your current private session on this device.</p></div><button className="button button-quiet" onClick={signOut}><LogOut size={16} /> Sign out</button></div><div className="settings-item danger-zone"><div><h2>Delete all account data</h2><p>Permanently delete your account, investigations, and feedback.</p></div><button className="button button-danger" onClick={() => setWarning(true)}><Trash2 size={16} /> Delete data</button></div>{warning && <div className="confirm-box"><div><strong>This action cannot be undone.</strong><p>Your account and saved records will be removed.</p></div><button className="button button-danger" onClick={deleteData}>Confirm deletion</button><button className="button button-quiet" onClick={() => setWarning(false)}>Cancel</button></div>}{message && <div className="feedback-message">{message}</div>}</section><section className="panel privacy-detail"><LockKeyhole size={18} /><div><h2>Privacy notice</h2><p>Messages are redacted before storage. URL paths and query strings are removed; when a threat-intel key is configured, only the URL origin is sent to that provider. OpenAI receives only redacted content and the deterministic report summary when its key is configured.</p></div></section></>
}
