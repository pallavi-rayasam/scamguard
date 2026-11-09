import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from './App'

const { mockMe, mockLogin, mockRegister, mockImage, mockReport, mockReportPdf, mockAdminAnalytics, mockAdminInvestigations, mockAdminInvestigation, mockAdminSystemHealth, mockLogout } = vi.hoisted(() => ({
  mockMe: vi.fn(),
  mockLogin: vi.fn(),
  mockRegister: vi.fn(),
  mockImage: vi.fn(),
  mockReport: vi.fn(),
  mockReportPdf: vi.fn(),
  mockAdminAnalytics: vi.fn(),
  mockAdminInvestigations: vi.fn(),
  mockAdminInvestigation: vi.fn(),
  mockAdminSystemHealth: vi.fn(),
  mockLogout: vi.fn(),
}))
vi.mock('./api', () => ({ api: { me: mockMe, login: mockLogin, register: mockRegister, image: mockImage, report: mockReport, reportPdf: mockReportPdf, adminAnalytics: mockAdminAnalytics, adminInvestigations: mockAdminInvestigations, adminInvestigation: mockAdminInvestigation, adminSystemHealth: mockAdminSystemHealth, logout: mockLogout } }))

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

beforeEach(() => {
  location.hash = '#/home'
  vi.clearAllMocks()
  mockMe.mockRejectedValue(new Error('Not signed in'))
  mockLogout.mockResolvedValue(undefined)
  mockAdminInvestigations.mockResolvedValue({ items: [], page: 1, page_size: 10, total: 0, total_pages: 0, date_range: { from_date: '2026-11-01', to_date: '2026-11-09' }, privacy_note: 'No message text.' })
  mockAdminInvestigation.mockResolvedValue({ id: 'investigation-id', input_type: 'text', category: null, risk_score: 0, risk_level: 'Low', created_at: '2026-11-09T10:00:00Z', findings: [], providers: [], agents: [], ml_prediction: null, recommendation_count: 0, url_count: 0, privacy_note: 'No source message.' })
  mockAdminSystemHealth.mockResolvedValue({ services: [
    { id: 'backend', name: 'FastAPI backend', status: 'operational', verification: 'request_served' },
    { id: 'database', name: 'PostgreSQL database', status: 'operational', verification: 'select_1' },
    { id: 'url_scanner', name: 'URL scanner', status: 'unavailable', verification: 'health_endpoint' },
    { id: 'groq', name: 'Groq LLM provider', status: 'configured', verification: 'not_probed', selected: true },
    { id: 'google_safe_browsing', name: 'Google Safe Browsing', status: 'configured', verification: 'not_probed' },
    { id: 'virustotal', name: 'VirusTotal', status: 'not_configured', verification: 'not_probed' },
  ], provider_note: 'No third-party provider calls were made.', checked_at: '2026-11-09T10:00:00Z' })
})

async function openRegistration() {
  location.hash = '#/login'
  render(<App />)
  await screen.findByRole('heading', { name: /welcome back/i })
  fireEvent.click(screen.getByRole('button', { name: 'Create account' }))
  await screen.findByRole('heading', { name: /create your account/i })
}

function fillValidRegistration(password = 'long-enough-password') {
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'member@example.com' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } })
}

describe('authentication UI', () => {
  it('explains the product and advisory boundary on the landing page', async () => {
    render(<App />)
    expect(await screen.findByRole('heading', { name: /pause\. check\./i })).toBeTruthy()
    expect(screen.getByText(/no payments initiated/i)).toBeTruthy()
  })

  it('shows browser/backend email mismatch validation under the email field', async () => {
    await openRegistration()
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'member@localhost' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'long-enough-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create account' }))
    expect(await screen.findByText(/valid email address, such as name@example.com/i)).toBeTruthy()
    expect(mockRegister).not.toHaveBeenCalled()
  })

  it('renders API field errors under the field and as readable summary text', async () => {
    const failure = Object.assign(new Error('password: must be at least 12 characters'), { fieldErrors: { password: 'must be at least 12 characters' } })
    mockRegister.mockRejectedValue(failure)
    await openRegistration()
    fillValidRegistration()
    fireEvent.click(screen.getByRole('button', { name: 'Create account' }))
    expect(await screen.findByText('must be at least 12 characters', { selector: 'small' })).toBeTruthy()
    expect(screen.getByText('password: must be at least 12 characters')).toBeTruthy()
  })

  it('resets the loading state in finally after a request timeout', async () => {
    mockRegister.mockRejectedValue(new Error('Request timed out after 15 seconds. Please try again.'))
    await openRegistration()
    fillValidRegistration()
    fireEvent.click(screen.getByRole('button', { name: 'Create account' }))
    expect(await screen.findByText(/request timed out after 15 seconds/i)).toBeTruthy()
    const submit = screen.getByRole('button', { name: 'Create account' })
    expect(submit.hasAttribute('disabled')).toBe(false)
    expect(submit.getAttribute('aria-busy')).toBe('false')
  })

  it('shows the database outage message returned by the API', async () => {
    mockRegister.mockRejectedValue(new Error('Database unavailable'))
    await openRegistration()
    fillValidRegistration()
    fireEvent.click(screen.getByRole('button', { name: 'Create account' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Database unavailable')
    expect(screen.getByRole('button', { name: 'Create account' }).hasAttribute('disabled')).toBe(false)
  })
})


describe('screenshot upload UI', () => {
  it('accepts JPEG/PNG screenshots and submits the selected image', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockImage.mockResolvedValue({ id: 'image-report' })
    location.hash = '#/scanner'
    render(<App />)
    await screen.findByRole('heading', { name: 'Check before you act' })
    fireEvent.click(screen.getByRole('tab', { name: 'Screenshot' }))
    const input = await screen.findByLabelText('Screenshot image') as HTMLInputElement
    expect(input.accept).toBe('.jpg,.jpeg,.png,image/jpeg,image/png')
    const file = new File(['image-bytes'], 'notice.png', { type: 'image/png' })
    fireEvent.change(input, { target: { files: [file] } })
    expect(await screen.findByText('notice.png')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Run investigation' }))
    await waitFor(() => expect(mockImage).toHaveBeenCalledWith(file))
    await waitFor(() => expect(location.hash).toBe('#/report/image-report'))
  })
})


describe('report PDF download', () => {
  it('downloads a report PDF from the owner report page', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockReport.mockResolvedValue({
      id: 'report-id', category: null, risk_score: 0, risk_level: 'Low', score_is_probability: false,
      model_confidence: 'not_available', evidence_strength: 'Weak', findings: [], evidence: [], agents: [],
      urls: [], threat_intel_results: [], url_scans: [], data_availability: {}, recommendations: [],
      explanation: '', limitations: [], created_at: '2026-01-02T14:14:00Z',
    })
    mockReportPdf.mockResolvedValue(new Blob(['%PDF-1.4'], { type: 'application/pdf' }))
    const NativeURL = URL
    class DownloadURL extends NativeURL {
      static createObjectURL = vi.fn(() => 'blob:pdf')
      static revokeObjectURL = vi.fn()
    }
    vi.stubGlobal('URL', DownloadURL)
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    location.hash = '#/report/report-id'
    render(<App />)
    await screen.findByRole('heading', { name: 'Evidence and next steps' })
    fireEvent.click(screen.getByRole('button', { name: 'Download PDF' }))
    await waitFor(() => expect(mockReportPdf).toHaveBeenCalledWith('report-id'))
    expect(screen.getByRole('button', { name: 'Download PDF' }).hasAttribute('disabled')).toBe(false)
  })

  it('shows a useful download error and exposes a working print action', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockReport.mockResolvedValue({
      id: 'report-id', category: null, risk_score: 0, risk_level: 'Low', score_is_probability: false,
      model_confidence: 'not_available', evidence_strength: 'Weak', findings: [], evidence: [], agents: [],
      urls: [], threat_intel_results: [], url_scans: [], data_availability: {}, recommendations: [],
      explanation: '', limitations: [], created_at: '2026-01-02T14:14:00Z',
    })
    mockReportPdf.mockRejectedValue(new Error('The server response was not a valid PDF. Please try again.'))
    const print = vi.spyOn(window, 'print').mockImplementation(() => {})
    location.hash = '#/report/report-id'
    render(<App />)
    await screen.findByRole('heading', { name: 'Evidence and next steps' })

    fireEvent.click(screen.getByRole('button', { name: 'Download PDF' }))
    expect((await screen.findByRole('alert')).textContent).toContain('The server response was not a valid PDF.')
    expect(screen.getByRole('button', { name: 'Download PDF' }).hasAttribute('disabled')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Print Report' }))
    expect(print).toHaveBeenCalledOnce()
  })

  it('explains the UTC fallback without blocking the report when browser zone detection is unavailable', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockReport.mockResolvedValue({
      id: 'report-id', category: null, risk_score: 0, risk_level: 'Low', score_is_probability: false,
      model_confidence: 'not_available', evidence_strength: 'Weak', findings: [], evidence: [], agents: [],
      urls: [], threat_intel_results: [], url_scans: [], data_availability: {}, recommendations: [],
      explanation: '', limitations: [], created_at: '2026-01-02T14:14:00Z',
    })
    const NativeDateTimeFormat = Intl.DateTimeFormat
    vi.spyOn(Intl, 'DateTimeFormat').mockImplementation((function (locales?: Intl.LocalesArgument, options?: Intl.DateTimeFormatOptions) {
      if (!options?.timeZone) throw new RangeError('timezone detection unavailable')
      return new NativeDateTimeFormat(locales, options)
    }) as typeof Intl.DateTimeFormat)
    location.hash = '#/report/report-id'
    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Evidence and next steps' })).toBeTruthy()
    expect(screen.getByRole('status').textContent).toContain('timestamps are displayed in UTC')
    expect(screen.getByText(/Created .* UTC/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Download PDF' }).hasAttribute('disabled')).toBe(false)
  })

  it('prevents duplicate PDF downloads while one request is in flight', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockReport.mockResolvedValue({
      id: 'report-id', category: null, risk_score: 0, risk_level: 'Low', score_is_probability: false,
      model_confidence: 'not_available', evidence_strength: 'Weak', findings: [], evidence: [], agents: [],
      urls: [], threat_intel_results: [], url_scans: [], data_availability: {}, recommendations: [],
      explanation: '', limitations: [], created_at: '2026-01-02T14:14:00Z',
    })
    let resolveDownload!: (blob: Blob) => void
    mockReportPdf.mockReturnValue(new Promise(resolve => { resolveDownload = resolve }))
    const NativeURL = URL
    class DownloadURL extends NativeURL {
      static createObjectURL = vi.fn(() => 'blob:pdf')
      static revokeObjectURL = vi.fn()
    }
    vi.stubGlobal('URL', DownloadURL)
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    location.hash = '#/report/report-id'
    render(<App />)
    await screen.findByRole('heading', { name: 'Evidence and next steps' })
    const button = screen.getByRole('button', { name: 'Download PDF' })
    fireEvent.click(button)
    fireEvent.click(button)

    expect(mockReportPdf).toHaveBeenCalledTimes(1)
    resolveDownload(new Blob(['%PDF-1.4'], { type: 'application/pdf' }))
    await waitFor(() => expect(button.hasAttribute('disabled')).toBe(false))
  })
})


describe('report explanation source', () => {
  it('shows the deterministic fallback clearly when Groq is unavailable', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockReport.mockResolvedValue({
      id: 'report-id', category: null, risk_score: 0, risk_level: 'Low', score_is_probability: false,
      model_confidence: 'not_available', evidence_strength: 'Weak', findings: [], evidence: [],
      urls: [], threat_intel_results: [], url_scans: [], data_availability: { llm: 'timed_out' },
      agents: [{ agent_name: 'LLMExplanation', status: 'failed', failure_category: 'response_truncated' }],
      recommendations: [], explanation: 'No verified deterministic findings were available to summarize.',
      explanation_source: 'deterministic_fallback', limitations: [], created_at: '2026-01-02T14:14:00Z',
    })
    location.hash = '#/report/report-id'
    render(<App />)
    await screen.findByRole('heading', { name: 'Evidence and next steps' })

    expect(screen.getByRole('heading', { name: /deterministic explanation/i })).toBeTruthy()
    expect(screen.getByText('Deterministic fallback')).toBeTruthy()
    expect(screen.getByText('No verified deterministic findings were available to summarize.')).toBeTruthy()
    expect(screen.getByText(/no llm response was used/i)).toBeTruthy()
    expect(screen.getByText('failed')).toBeTruthy()
    expect(screen.getByText('response truncated')).toBeTruthy()
    expect(screen.queryByText('LLM inferred')).toBeNull()
  })
})

describe('experimental ML suggestion', () => {
  it('keeps a model failure visible and separate from the deterministic report', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockReport.mockResolvedValue({
      id: 'report-id', category: null, risk_score: 18, risk_level: 'Low', score_is_probability: false,
      model_confidence: 'not_available', evidence_strength: 'Limited', findings: [], evidence: [], agents: [],
      urls: [], threat_intel_results: [], url_scans: [], data_availability: {}, recommendations: [],
      explanation: '', limitations: [], created_at: '2026-01-02T14:14:00Z',
      ml_prediction: { status: 'unavailable', predicted_class: null, calibrated_probability: null, calibration_status: 'not_justified', model_version: 'message-text-v1' },
    })
    location.hash = '#/report/report-id'
    render(<App />)
    await screen.findByRole('heading', { name: 'Evidence and next steps' })

    const card = screen.getByRole('region', { name: 'Experimental ML Suggestion' })
    expect(card.className).toContain('ml-suggestion-panel')
    expect(screen.getByRole('heading', { name: 'Model suggestion unavailable' })).toBeTruthy()
    expect(screen.getByText('This isolated advisory does not change the deterministic score, findings, verification, or recommendations.')).toBeTruthy()
    expect(screen.getByText('Status: unavailable').className).toContain('ml-status-badge unavailable')
    expect(screen.getByText(/calibration is not justified; no probability is shown/i)).toBeTruthy()
    expect(screen.getByText('18')).toBeTruthy()
  })

  it('labels completed model output as a suggestion and does not show a probability', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockReport.mockResolvedValue({
      id: 'report-id', category: null, risk_score: 0, risk_level: 'Low', score_is_probability: false,
      model_confidence: 'not_available', evidence_strength: 'Weak', findings: [], evidence: [], agents: [],
      urls: [], threat_intel_results: [], url_scans: [], data_availability: {}, recommendations: [],
      explanation: '', limitations: [], created_at: '2026-01-02T14:14:00Z',
      ml_prediction: { status: 'completed', predicted_class: 'scam', calibrated_probability: null, calibration_status: 'not_justified', model_version: 'message-text-v1' },
    })
    location.hash = '#/report/report-id'
    render(<App />)
    await screen.findByRole('heading', { name: 'Evidence and next steps' })

    expect(screen.getByRole('heading', { name: 'Model suggestion: scam-like' })).toBeTruthy()
    expect(screen.getByText('Status: completed').className).toContain('ml-status-badge completed')
    expect(screen.getByText(/no probability is shown/i)).toBeTruthy()
    expect(screen.queryByText(/\d+%/)).toBeNull()
  })
})

describe('admin analytics dashboard', () => {
  it('shows database aggregates and section navigation to an administrator', async () => {
    mockMe.mockResolvedValue({ id: 'admin-id', email: 'admin@example.com', role: 'admin' })
    mockAdminAnalytics.mockResolvedValue({
      total_users: 3,
      user_counts: { user: 2, admin: 1 },
      total_investigations: 4,
      total_scam_detections: 2,
      total_legitimate_classifications: 0,
      total_uncertain_classifications: 0,
      classification_counts_are_explicit_only: true,
      scam_detection_percentage: 50,
      investigations_today_utc: 0,
      date_range: { from_date: '2026-11-01', to_date: '2026-11-09' },
      investigations_in_range: 4,
      range_detection_counts: { scam_detected: 2, no_scam_category: 2, explicit_scam: 0, explicit_legitimate: 0, explicit_uncertain: 0 },
      recent_activity: [],
      investigations_per_day: [{ date: '2026-11-07', count: 4 }],
      category_distribution: { upi_fraud: 2 },
      risk_distribution: { High: 1, Low: 3 },
      provider_failure_counts: { virustotal: 1 },
      provider_failure_statuses: { virustotal: { unavailable: 1 } },
      agent_failure_counts: { url: 1 },
      agent_failure_statuses: { url: { failed: 1 } },
      average_processing_time_ms: 1350,
      feedback_counts: { correct: 2 },
      url_intelligence: { malicious_results: 1, suspicious_url_findings: 0, clean_no_known_threat_results: 1, provider_failures: 1, skipped_lookups: 0, status_counts: { completed: 2, unavailable: 1 }, providers: { google_safe_browsing: { checks: 1, malicious: 1, clean_no_known_threat: 0, failures: 0, skipped: 0 }, virustotal: { checks: 2, malicious: 0, clean_no_known_threat: 1, failures: 1, skipped: 0 } }, clean_result_caveat: 'No known threat found; not verified safe.' },
      ml_monitoring: { model_name: 'TF-IDF + Logistic Regression', model_version: 'message-text-v1', experimental: true, prediction_status_counts: { completed: 0, skipped: 0, unavailable: 0, failed: 0 }, predicted_class_counts: { scam: 0, legitimate: 0 }, evaluation: { status: 'available', source: 'evaluation-report-v2.json', test: { n: 6, accuracy: 1, precision_scam: 1, recall_scam: 1, f1_scam: 1, false_positive_rate: 0, false_negative_rate: 0, confusion_matrix: { labels: ['legitimate', 'scam'], rows_actual_columns_predicted: [[3, 0], [0, 3]] } }, cross_validation: { accuracy: 0.9, precision_scam: 0.9, recall_scam: 0.9, f1_scam: 0.9 }, limitations: ['The held-out test set has only six records; these descriptive metrics do not establish generalization.'] }, disclaimer: 'This isolated advisory does not change the deterministic score, findings, verification, or recommendations.' },
    })
    location.hash = '#/admin'

    render(<App />)

    await screen.findByRole('heading', { name: 'Admin console' })
    expect(await screen.findByText('1,350 ms')).toBeTruthy()
    expect(screen.getByText('Investigation trend')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Admin console/ })).toBeTruthy()
    expect(mockAdminAnalytics).toHaveBeenCalledOnce()
    fireEvent.click(screen.getByRole('button', { name: /URL intelligence/ }))
    expect(await screen.findByRole('heading', { name: 'Provider results' })).toBeTruthy()
    expect(screen.getByText(/No known threat found; not verified safe/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /ML monitoring/ }))
    expect(await screen.findByRole('heading', { name: 'Offline evaluation' })).toBeTruthy()
    expect(screen.getByText(/only six records/i)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /System health/ }))
    expect(await screen.findByText('Google Safe Browsing')).toBeTruthy()
    expect(screen.getByText(/no third-party provider calls were made/i)).toBeTruthy()
  })

  it('hides admin navigation and shows the server denial for a regular user', async () => {
    mockMe.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    mockAdminAnalytics.mockRejectedValue(new Error('Administrator access required'))
    location.hash = '#/admin'

    render(<App />)

    expect(await screen.findByRole('heading', { name: 'Administrator access required' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Admin console/ })).toBeNull()
    expect(screen.getByText(/this signed-in account does not have an administrator role/i)).toBeTruthy()
  })

  it('offers a dedicated administrator login entry and rejects a regular account', async () => {
    mockLogin.mockResolvedValue({ id: 'user-id', email: 'member@example.com', role: 'user' })
    location.hash = '#/admin-login'
    render(<App />)
    await screen.findByRole('heading', { name: 'Administrator sign in' })
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'member@example.com' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in to admin console' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/administrator access required/i)
    expect(mockLogout).toHaveBeenCalledOnce()
    expect(screen.getByRole('heading', { name: 'Administrator sign in' })).toBeTruthy()
  })

  it('loads paginated investigation metadata and opens a privacy-minimized detail', async () => {
    mockMe.mockResolvedValue({ id: 'admin-id', email: 'admin@example.com', role: 'admin' })
    mockAdminAnalytics.mockResolvedValue({
      total_users: 1, user_counts: { user: 0, admin: 1 }, total_investigations: 0, total_scam_detections: 0,
      total_legitimate_classifications: 0, total_uncertain_classifications: 0, classification_counts_are_explicit_only: true,
      scam_detection_percentage: 0, investigations_today_utc: 0, date_range: { from_date: '2026-11-01', to_date: '2026-11-09' },
      investigations_in_range: 0, range_detection_counts: {}, recent_activity: [], investigations_per_day: [], category_distribution: {}, risk_distribution: {},
      provider_failure_counts: {}, provider_failure_statuses: {}, agent_failure_counts: {}, agent_failure_statuses: {}, average_processing_time_ms: null,
      feedback_counts: {}, url_intelligence: { malicious_results: 0, suspicious_url_findings: 0, clean_no_known_threat_results: 0, provider_failures: 0, skipped_lookups: 0, status_counts: {}, providers: {}, clean_result_caveat: 'No known threat found; not verified safe.' },
      ml_monitoring: { model_name: 'TF-IDF + Logistic Regression', model_version: 'message-text-v1', experimental: true, prediction_status_counts: {}, predicted_class_counts: {}, evaluation: { status: 'unavailable' }, disclaimer: 'This isolated advisory does not change the deterministic score, findings, verification, or recommendations.' },
    })
    mockAdminInvestigations.mockResolvedValue({ items: [{ id: 'investigation-id', input_type: 'text', category: 'upi_fraud', risk_score: 80, risk_level: 'High', created_at: '2026-11-09T10:00:00Z', classification: 'scam_detected', classification_source: 'deterministic_category_match', finding_count: 2, url_count: 1 }], page: 1, page_size: 10, total: 1, total_pages: 1, date_range: { from_date: '2026-11-01', to_date: '2026-11-09' }, privacy_note: 'No message text.' })
    location.hash = '#/admin'
    render(<App />)
    await screen.findByRole('heading', { name: 'Admin console' })
    fireEvent.click(screen.getByRole('button', { name: /Investigations/ }))
    expect(await screen.findByText(/upi fraud/i)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Details' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Finding metadata' })).toBeTruthy()
    expect(screen.queryByText(/PRIVATE_EVIDENCE_TEXT|PRIVATE_QUERY|PRIVATE_PROVIDER_DETAIL/)).toBeNull()
    expect(mockAdminInvestigation).toHaveBeenCalledWith('investigation-id')
  })

  it('shows admin API failures and completes logout', async () => {
    mockMe.mockResolvedValue({ id: 'admin-id', email: 'admin@example.com', role: 'admin' })
    mockAdminAnalytics.mockRejectedValue(new Error('Analytics service unavailable'))
    mockAdminInvestigations.mockRejectedValue(new Error('Investigation list unavailable'))
    location.hash = '#/admin'
    render(<App />)

    expect((await screen.findByRole('alert')).textContent).toContain('Analytics service unavailable')
    fireEvent.click(screen.getByRole('button', { name: /Investigations/ }))
    expect(await screen.findByText(/Investigation list unavailable/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Logout' }))
    expect(await screen.findByRole('heading', { name: /pause. check./i })).toBeTruthy()
    expect(mockLogout).toHaveBeenCalledOnce()
  })
})
