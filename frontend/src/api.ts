const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000/api'
let csrfToken = ''

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers = new Headers(options.headers)
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) {
    if (!csrfToken) {
      const token = await fetch(`${API_BASE}/auth/csrf`, { credentials: 'include' })
      if (!token.ok) throw new Error('Could not establish a secure session. Please retry.')
      csrfToken = (await token.json()).csrf_token as string
    }
    headers.set('X-CSRF-Token', csrfToken)
  }
  const response = await fetch(`${API_BASE}${path}`, { ...options, method, headers, credentials: 'include' })
  if (response.status === 204) return undefined as T
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail ?? 'Request failed. Please try again.')
  return data as T
}

export type User = { id: string; email: string; role: string }
export type Investigation = { id: string; category: string; risk_score: number; risk_level: string; created_at: string }
export type Report = {
  id: string; category: string; risk_score: number; risk_level: string; score_is_probability: boolean
  model_confidence: string; evidence_strength: string; findings: Array<Record<string, unknown>>
  evidence: Array<Record<string, unknown>>; agents: Array<Record<string, unknown>>; urls: string[]
  threat_intel_results: Array<{ provider: string; status: string; is_malicious?: boolean | null; reason?: string | null; detail?: string | null }>;
  url_scans: Array<{ origin?: string; status?: string; reason?: string; findings?: Array<Record<string, unknown>>; fetch?: { status?: string; reason?: string } }>; data_availability: Record<string, unknown>
  recommendations: string[]; explanation: string; limitations: string[]; created_at: string
  transaction_advisory?: { advisory_only: boolean; advisory: string; recipient_identity_check: string; claimed_recipient_provided: boolean; amount_provided: boolean; payment_initiated: boolean; risk_score: number; risk_level: string; recommendations: string[] } | null
}

export const api = {
  me: () => request<User>('/auth/me'),
  login: (email: string, password: string) => request<User>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  register: (email: string, password: string) => request<User>('/auth/register', { method: 'POST', body: JSON.stringify({ email, password }) }),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  scan: (text: string, input_type: string) => request<Report>('/investigations/text', { method: 'POST', body: JSON.stringify({ text, input_type }) }),
  conversation: (messages: Array<{ sender: string; text: string }>) => request<Report>("/investigations/conversation", { method: 'POST', body: JSON.stringify({ messages }) }),
  transaction: (payload: { description: string; claimed_recipient: string; reason: string; amount?: number; related_chat: string }) => request<Report>("/investigations/transaction", { method: 'POST', body: JSON.stringify(payload) }),
  history: (filters: { q?: string; risk_level?: string } = {}) => {
    const query = new URLSearchParams()
    if (filters.q) query.set('q', filters.q)
    if (filters.risk_level) query.set('risk_level', filters.risk_level)
    return request<{ items: Investigation[] }>(`/investigations${query.size ? `?${query}` : ''}`)
  },
  report: (id: string) => request<Report>(`/investigations/${id}/report`),
  stats: () => request<{ total_investigations: number; risk_distribution: Record<string, number> }>('/dashboard/statistics'),
  categories: () => request<Array<{ code: string; name: string; language: string }>>('/scam-categories'),
  awareness: () => request<{ language: string; items: Array<{ title: string; body: string }> }>('/scam-awareness'),
  feedback: (investigation_id: string, rating: string) => request('/feedback', { method: 'POST', body: JSON.stringify({ investigation_id, rating }) }),
  deleteData: () => request<void>('/me/data', { method: 'DELETE' }),
  deleteInvestigation: (id: string) => request<void>(`/investigations/${id}`, { method: 'DELETE' }),
}
