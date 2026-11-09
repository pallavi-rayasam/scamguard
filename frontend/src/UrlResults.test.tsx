import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { UrlResults, type ThreatIntelResult } from './UrlResults'

afterEach(cleanup)

const urlScans = [{
  origin: 'https://example.test', status: 'completed',
  findings: [{ indicator: 'url_http_not_https', detail: 'The URL uses HTTP without transport encryption.', verification_level: 'heuristic' }],
}]

function renderResults(results: ThreatIntelResult[], availability: Record<string, unknown> = {}) {
  return render(<UrlResults urls={['https://example.test']} urlScans={urlScans} threatIntelResults={results} threatIntelAvailability={availability} findings={[]} />)
}

const unavailable = (provider: string, reason = 'request_failed'): ThreatIntelResult => ({ provider, status: 'unavailable', is_malicious: null, reason })
const clean = (provider: string): ThreatIntelResult => ({ provider, status: 'completed', is_malicious: false, detail: 'No known threat found; not verified safe.' })

describe('URL investigation results', () => {
  it('shows both providers unavailable when all provider checks fail', () => {
    renderResults([unavailable('google_safe_browsing'), unavailable('virustotal')])
    expect(screen.getAllByText('unavailable')).toHaveLength(2)
    expect(screen.getAllByText('not verified')).toHaveLength(2)
    expect(screen.getAllByText(/no reputation conclusion is available/i)).toHaveLength(2)
  })

  it('shows a successful provider as checked and preserves one provider failure', () => {
    const { container } = renderResults([clean('google_safe_browsing'), unavailable('virustotal')])
    expect(Array.from(container.querySelectorAll('.url-provider-row .url-provider-status')).map(item => item.textContent)).toEqual(['checked', 'unavailable'])
    expect(screen.getByText('no known threat found; not verified safe')).toBeTruthy()
  })

  it('shows intentionally skipped provider checks as not checked, not unavailable', () => {
    const { container } = renderResults([], { providers: 'skipped' })
    expect(container.querySelectorAll('.url-provider-status.not-checked')).toHaveLength(2)
    expect(screen.getAllByText('not checked')).toHaveLength(4)
    expect(screen.getAllByText(/lookup was skipped for this input/i)).toHaveLength(2)
  })

  it('shows DNS validation failures as not checked because provider requests were skipped', () => {
    const { container } = renderResults([
      { provider: 'google_safe_browsing', status: 'skipped', is_malicious: null, reason: 'dns_resolution_failed' },
      { provider: 'virustotal', status: 'skipped', is_malicious: null, reason: 'dns_resolution_failed' },
    ])
    expect(container.querySelectorAll('.url-provider-status.not-checked')).toHaveLength(2)
    expect(screen.getAllByText(/provider lookups were not attempted/i)).toHaveLength(2)
  })

  it.each([
    ['not_configured', 'Provider API key is not configured in the URL scanner.'],
    ['authentication_failed', 'Provider rejected its credentials; check the scanner key configuration.'],
    ['quota_exhausted', 'Provider quota is exhausted; no reputation conclusion is available.'],
    ['timed_out', 'Provider request timed out; no reputation conclusion is available.'],
    ['provider_outage', 'Provider service is temporarily unavailable.'],
  ])('explains provider failure reason %s', (reason, message) => {
    renderResults([unavailable('google_safe_browsing', reason)])
    expect(screen.getByText(message)).toBeTruthy()
  })

  it('shows SSRF-blocked targets as not checked rather than provider outages', () => {
    const { container } = renderResults([
      unavailable('google_safe_browsing', 'non_public_address'),
      unavailable('virustotal', 'non_public_address'),
    ])
    expect(container.querySelectorAll('.url-provider-status.not-checked')).toHaveLength(2)
    expect(screen.getAllByText(/blocked by SSRF safety checks/i)).toHaveLength(2)
  })

  it('marks a reported threat as flagged and verified', () => {
    renderResults([{ provider: 'google_safe_browsing', status: 'completed', is_malicious: true }, unavailable('virustotal')])
    expect(screen.getByText('flagged')).toBeTruthy()
    expect(screen.getByText('verified threat report')).toBeTruthy()
    expect(screen.getByText(/reported a known threat/i)).toBeTruthy()
  })

  it('uses the required wording for clean provider responses and shows heuristic badges', () => {
    const { container } = renderResults([clean('google_safe_browsing'), clean('virustotal')])
    expect(Array.from(container.querySelectorAll('.url-provider-row .url-provider-status')).map(item => item.textContent)).toEqual(['checked', 'checked'])
    expect(screen.getAllByText('no known threat found; not verified safe')).toHaveLength(2)
    expect(screen.getByText('heuristic')).toBeTruthy()
    expect(screen.getByText('The URL uses HTTP without transport encryption.')).toBeTruthy()
  })

  it('maps provider rate-limit reasons to the rate-limited status', () => {
    renderResults([unavailable('google_safe_browsing', 'rate_limited'), clean('virustotal')])
    expect(screen.getByText('rate-limited')).toBeTruthy()
  })
})
