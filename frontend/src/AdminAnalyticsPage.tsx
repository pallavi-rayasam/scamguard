import { useEffect, useState } from 'react'
import { CircleAlert } from 'lucide-react'
import { api, type AdminAnalytics } from './api'

export function AdminAnalyticsPage() {
  const [analytics, setAnalytics] = useState<AdminAnalytics | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    api.adminAnalytics()
      .then(data => { if (active) setAnalytics(data) })
      .catch(caught => { if (active) setError(caught instanceof Error ? caught.message : 'Could not load admin analytics.') })
    return () => { active = false }
  }, [])

  if (error) {
    const denied = error.toLowerCase().includes('administrator')
    return <>
      <header className="page-header"><div><span className="eyebrow">ADMINISTRATION</span><h1>{denied ? 'Administrator access required' : 'Analytics unavailable'}</h1><p>{denied ? 'This database dashboard is available to administrator accounts.' : 'The database analytics could not be loaded.'}</p></div></header>
      <div className="error-banner" role="alert"><CircleAlert size={17} />{error}</div>
    </>
  }

  if (!analytics) {
    return <><header className="page-header"><div><span className="eyebrow">ADMINISTRATION</span><h1>Admin analytics</h1><p>Loading database aggregates…</p></div></header><p role="status">Loading admin analytics</p></>
  }

  const feedbackTotal = Object.values(analytics.feedback_counts).reduce((sum, count) => sum + count, 0)
  const providerFailureTotal = Object.values(analytics.provider_failure_counts).reduce((sum, count) => sum + count, 0)
  const agentFailureTotal = Object.values(analytics.agent_failure_counts).reduce((sum, count) => sum + count, 0)

  return <>
    <header className="page-header"><div><span className="eyebrow">ADMINISTRATION</span><h1>Admin analytics</h1><p>Live aggregates from saved users, investigations, provider checks, agent runs, and feedback.</p></div></header>
    <div className="admin-metrics" aria-label="Key admin metrics">
      <Metric label="Users" value={analytics.total_users} note={`${analytics.user_counts.user ?? 0} user · ${analytics.user_counts.admin ?? 0} admin`} />
      <Metric label="Investigations" value={analytics.total_investigations} note="Stored report records" />
      <Metric label="Provider failures" value={providerFailureTotal} note="Failed, timed out, or unavailable" />
      <Metric label="Agent failures" value={agentFailureTotal} note="Failed or timed out runs" />
      <Metric label="Average processing time" value={analytics.average_processing_time_ms === null ? '—' : `${analytics.average_processing_time_ms.toLocaleString()} ms`} note="Mean summed agent duration per investigation with recorded runs" />
      <Metric label="Feedback" value={feedbackTotal} note="Submitted feedback records" />
    </div>
    <div className="admin-data-grid">
      <RecordsPanel title="Investigations per day" values={Object.fromEntries(analytics.investigations_per_day.map(item => [item.date, item.count]))} empty="No investigation records yet." />
      <RecordsPanel title="Category distribution" values={analytics.category_distribution} empty="No matched scam categories yet." />
      <RecordsPanel title="Risk distribution" values={analytics.risk_distribution} empty="No risk records yet." />
      <RecordsPanel title="Provider failures" values={analytics.provider_failure_counts} details={analytics.provider_failure_statuses} empty="No provider failures recorded." />
      <RecordsPanel title="Agent failures" values={analytics.agent_failure_counts} details={analytics.agent_failure_statuses} empty="No agent failures recorded." />
      <RecordsPanel title="Feedback counts" values={analytics.feedback_counts} empty="No feedback submitted yet." />
    </div>
  </>
}

function Metric({ label, value, note }: { label: string; value: string | number; note: string }) {
  return <section className="admin-metric panel"><span>{label}</span><strong>{value}</strong><small>{note}</small></section>
}

function RecordsPanel({ title, values, details, empty }: {
  title: string
  values: Record<string, number>
  details?: Record<string, Record<string, number>>
  empty: string
}) {
  const rows = Object.entries(values).sort(([left], [right]) => left.localeCompare(right))
  return <section className="admin-panel panel">
    <h2>{title}</h2>
    {rows.length ? <ul>{rows.map(([name, count]) => <li key={name}><span>{name.replaceAll('_', ' ')}</span><strong>{count}</strong>{details?.[name] && <small>{Object.entries(details[name]).map(([status, statusCount]) => `${status}: ${statusCount}`).join(' · ')}</small>}</li>)}</ul> : <p>{empty}</p>}
  </section>
}
