export type ThreatIntelResult = {
  provider: string
  status: string
  is_malicious?: boolean | null
  reason?: string | null
  detail?: string | null
}

export type UrlScanResult = {
  origin?: string | null
  status?: string | null
  reason?: string | null
  findings?: Array<Record<string, unknown>>
  fetch?: { status?: string | null; reason?: string | null }
}

type UrlResultsProps = {
  urls: string[]
  urlScans: UrlScanResult[]
  threatIntelResults: ThreatIntelResult[]
  findings: Array<Record<string, unknown>>
}

const PROVIDERS: Record<string, string> = {
  google_safe_browsing: 'Google Safe Browsing',
  virustotal: 'VirusTotal',
}
const PROVIDER_ORDER = Object.keys(PROVIDERS)

function statusFor(results: ThreatIntelResult[]): 'checked' | 'unavailable' | 'rate-limited' {
  if (results.some(item => item.status === 'completed' && item.is_malicious === true)) return 'checked'
  if (results.some(item => item.status === 'rate_limited' || /rate.?limited/i.test(item.reason ?? ''))) return 'rate-limited'
  if (results.length > 0 && results.every(item => item.status === 'completed')) return 'checked'
  return 'unavailable'
}

function verificationFor(results: ThreatIntelResult[], status: string): { label: string; level: string } {
  if (results.some(item => item.status === 'completed' && item.is_malicious === true)) return { label: 'verified threat report', level: 'verified' }
  if (status === 'checked') return { label: 'provider response; safety not verified', level: 'not-verified' }
  return { label: 'not verified', level: 'not-verified' }
}

function ProviderRow({ provider, results }: { provider: string; results: ThreatIntelResult[] }) {
  const status = statusFor(results)
  const verification = verificationFor(results, status)
  const flagged = results.some(item => item.status === 'completed' && item.is_malicious === true)
  const hasCompleted = results.some(item => item.status === 'completed')
  const message = flagged
    ? 'A provider reported a known threat for this URL.'
    : hasCompleted
      ? 'no known threat found; not verified safe'
      : status === 'rate-limited'
        ? 'Provider rate limit reached; no reputation conclusion is available.'
        : 'Provider unavailable; no reputation conclusion is available.'
  return <article className="url-provider-row">
    <div className="url-provider-heading"><strong>{PROVIDERS[provider] ?? provider}</strong><span className={`url-provider-status ${status}`}>{status}</span><span className={`verification-tag ${verification.level}`}>{verification.label}</span>{flagged && <span className="url-flagged">flagged</span>}</div>
    <p>{message}</p>
  </article>
}

function badgeFor(level: string): { label: string; className: string } {
  if (level === 'verified') return { label: 'verified', className: 'verified' }
  if (level === 'llm_inferred') return { label: 'LLM inferred', className: 'llm' }
  if (level === 'heuristic') return { label: 'heuristic', className: 'heuristic' }
  return { label: 'not verified', className: 'not-verified' }
}

export function UrlResults({ urls, urlScans, threatIntelResults, findings }: UrlResultsProps) {
  if (!urls.length) return null
  const providerNames = [...new Set([...PROVIDER_ORDER, ...threatIntelResults.map(item => item.provider)])]
  const urlFindingSources = new Set(['url_domain_heuristic', 'url_structure_check', 'url_scanner', 'trusted_domain_comparison'])
  const allFindings = [
    ...urlScans.flatMap(scan => scan.findings ?? []),
    ...findings.filter(item => urlFindingSources.has(String(item.source ?? ''))),
  ]
  const uniqueFindings = [...new Map(allFindings.map(item => [`${String(item.indicator ?? '')}|${String(item.detail ?? '')}`, item])).values()]
  return <section className="panel url-results-panel" aria-labelledby="url-results-title">
    <div className="section-head"><div><h2 id="url-results-title">URL investigation</h2><p>Provider checks and URL signals are shown separately; a clean lookup does not establish safety.</p></div></div>
    <div className="url-provider-list">{providerNames.map(provider => <ProviderRow key={provider} provider={provider} results={threatIntelResults.filter(item => item.provider === provider)} />)}</div>
    <div className="url-origin-list"><h3>URLs checked</h3>{urls.map((url, index) => {
      const scan = urlScans.find(item => item.origin === url) ?? urlScans[index]
      const scanStatus = scan?.status === 'completed' ? 'checked' : scan?.status === 'blocked' ? 'blocked' : scan ? 'unavailable' : 'unavailable'
      return <div className="url-origin-row" key={`${url}-${index}`}><code>{url}</code><span className={`url-provider-status ${scanStatus}`}>{scanStatus}</span></div>
    })}</div>
    {uniqueFindings.length > 0 && <div className="url-signal-list"><h3>URL signals</h3>{uniqueFindings.map((item, index) => {
      const badge = badgeFor(String(item.verification_level ?? 'heuristic'))
      return <div className="url-signal-row" key={`${String(item.indicator)}-${index}`}><strong>{String(item.detail ?? item.indicator ?? 'URL signal')}</strong><span className={`verification-tag ${badge.className}`}>{badge.label}</span></div>
    })}</div>}
  </section>
}
