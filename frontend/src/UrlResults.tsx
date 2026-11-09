export type ThreatIntelResult = {
  provider: string
  status: string
  is_malicious?: boolean | null
  reason?: string | null
  detail?: string | null
  failure_category?: string | null
  http_status?: number | null
  diagnostic?: { category?: string; http_status?: number; exception_type?: string; retry_count?: number }
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
  threatIntelAvailability?: Record<string, unknown>
  findings: Array<Record<string, unknown>>
}

const PROVIDERS: Record<string, string> = {
  google_safe_browsing: 'Google Safe Browsing',
  virustotal: 'VirusTotal',
}
const PROVIDER_ORDER = Object.keys(PROVIDERS)

const LOOKUP_NOT_ATTEMPTED_REASONS = new Set([
  'target_not_publicly_validated', 'non_public_address', 'redirect_target_not_public',
  'invalid_hostname', 'ambiguous_numeric_address', 'scanner_analysis_result_missing',
  'dns_resolution_failed', 'scanner_unavailable', 'scanner_timed_out',
  'scanner_rate_limited', 'scanner_origin_mismatch',
])

function statusFor(results: ThreatIntelResult[], availability?: string): 'checked' | 'unavailable' | 'rate-limited' | 'not-checked' {
  if (results.some(item => item.status === 'completed' && item.is_malicious === true)) return 'checked'
  if (results.some(item => item.status === 'rate_limited' || /rate.?limited/i.test(item.reason ?? ''))) return 'rate-limited'
  if (results.length > 0 && results.every(item => item.status === 'completed')) return 'checked'
  if (results.length === 0 && (availability === 'skipped' || availability === 'not_queried')) return 'not-checked'
  if (results.length > 0 && results.every(item => item.status !== 'completed' && LOOKUP_NOT_ATTEMPTED_REASONS.has(item.reason ?? ''))) return 'not-checked'
  return 'unavailable'
}

function verificationFor(results: ThreatIntelResult[], status: string): { label: string; level: string } {
  if (results.some(item => item.status === 'completed' && item.is_malicious === true)) return { label: 'verified threat report', level: 'verified' }
  if (status === 'checked') return { label: 'provider response; safety not verified', level: 'not-verified' }
  if (status === 'not-checked') return { label: 'not checked', level: 'not-verified' }
  return { label: 'not verified', level: 'not-verified' }
}

const FAILURE_MESSAGES: Record<string, string> = {
  not_configured: 'Provider API key is not configured in the URL scanner.',
  authentication_failed: 'Provider rejected its credentials; check the scanner key configuration.',
  quota_exhausted: 'Provider quota is exhausted; no reputation conclusion is available.',
  rate_limited: 'Provider rate limit reached; no reputation conclusion is available.',
  timed_out: 'Provider request timed out; no reputation conclusion is available.',
  provider_outage: 'Provider service is temporarily unavailable.',
  upstream_error: 'Provider service is temporarily unavailable.',
  invalid_response: 'Provider returned an invalid response; no reputation conclusion is available.',
  provider_rejected_request: 'Provider rejected the lookup request; no reputation conclusion is available.',
  request_failed: 'Provider request failed; no reputation conclusion is available.',
  scanner_timed_out: 'The URL scanner timed out before a reputation result was available.',
  scanner_unavailable: 'The URL scanner is unavailable; no reputation conclusion is available.',
  scanner_rate_limited: 'The URL scanner rate limit was reached; no reputation conclusion is available.',
  scanner_provider_result_missing: 'The URL scanner did not return this provider result.',
  scanner_provider_result_ambiguous: 'The URL scanner returned an ambiguous provider result.',
  target_not_publicly_validated: 'The URL target did not pass public-address validation; provider lookup was not attempted.',
  non_public_address: 'The URL target was blocked by SSRF safety checks; provider lookup was not attempted.',
  redirect_target_not_public: 'A redirect target did not pass public-address validation; provider lookup was not attempted.',
  invalid_hostname: 'The URL hostname could not be safely validated; provider lookup was not attempted.',
  ambiguous_numeric_address: 'The URL uses an ambiguous numeric address and was blocked before provider lookup.',
  scanner_analysis_result_missing: 'The scanner could not validate the URL before provider lookup.',
  dns_resolution_failed: 'The hostname did not resolve to a validated public address; provider lookups were not attempted.',
  dns_failure: 'The provider hostname could not be resolved; no reputation result is available.',
  tls_failure: 'The secure provider connection failed TLS verification; no reputation result is available.',
  network_failure: 'The provider could not be reached; no reputation result is available.',
  malformed_response: 'The provider returned a malformed response; no reputation conclusion is available.',
  invalid_scanner_response: 'The URL scanner returned an invalid provider response.',
}

function ProviderRow({ provider, results, availability }: { provider: string; results: ThreatIntelResult[]; availability?: string }) {
  const status = statusFor(results, availability)
  const verification = verificationFor(results, status)
  const flagged = results.some(item => item.status === 'completed' && item.is_malicious === true)
  const completed = results.filter(item => item.status === 'completed')
  const hasNoReport = completed.some(item => item.reason === 'no_report' || item.is_malicious === null)
  const hasCompleted = completed.length > 0
  const failureReason = results.find(item => item.status !== 'completed')?.reason ?? ''
  const message = flagged
    ? 'A provider reported a known threat for this URL.'
    : hasNoReport
      ? 'No provider report is available; not verified safe.'
      : hasCompleted
        ? 'no known threat found; not verified safe'
        : status === 'not-checked'
          ? FAILURE_MESSAGES[failureReason] ?? 'Reputation lookup was skipped for this input; the URL was not checked.'
          : FAILURE_MESSAGES[failureReason] ?? 'Provider unavailable; no reputation conclusion is available.'
  return <article className="url-provider-row">
    <div className="url-provider-heading"><strong>{PROVIDERS[provider] ?? provider}</strong><span className={`url-provider-status ${status}`}>{status === 'not-checked' ? 'not checked' : status}</span><span className={`verification-tag ${verification.level}`}>{verification.label}</span>{flagged && <span className="url-flagged">flagged</span>}</div>
    <p>{message}</p>
  </article>
}

function badgeFor(level: string): { label: string; className: string } {
  if (level === 'verified') return { label: 'verified', className: 'verified' }
  if (level === 'llm_inferred') return { label: 'LLM inferred', className: 'llm' }
  if (level === 'heuristic') return { label: 'heuristic', className: 'heuristic' }
  return { label: 'not verified', className: 'not-verified' }
}

export function UrlResults({ urls, urlScans, threatIntelResults, threatIntelAvailability = {}, findings }: UrlResultsProps) {
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
    <div className="url-provider-list">{providerNames.map(provider => <ProviderRow key={provider} provider={provider} results={threatIntelResults.filter(item => item.provider === provider)} availability={String(threatIntelAvailability[provider] ?? threatIntelAvailability.providers ?? '')} />)}</div>
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
