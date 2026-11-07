const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000/api'
let csrfToken = ''

export const REQUEST_TIMEOUT_MS = 15_000

type ApiFieldErrors = Record<string, string>
type ValidationIssue = { loc?: unknown; type?: unknown; msg?: unknown; ctx?: unknown }

export class ApiError extends Error {
  constructor(message: string, readonly fieldErrors: ApiFieldErrors = {}) {
    super(message)
    this.name = 'ApiError'
  }
}

function validationField(issue: ValidationIssue): string {
  if (!Array.isArray(issue.loc)) return 'request'
  const parts = issue.loc.filter((part): part is string => typeof part === 'string' && part !== 'body' && part !== 'query')
  return parts[0] ?? 'request'
}

function validationMessage(field: string, issue: ValidationIssue): string {
  const type = String(issue.type ?? '')
  const context = typeof issue.ctx === 'object' && issue.ctx !== null ? issue.ctx as Record<string, unknown> : {}
  if (type === 'string_too_short' && typeof context.min_length === 'number') return `must be at least ${context.min_length} characters`
  if (type === 'string_too_long' && typeof context.max_length === 'number') return `must be at most ${context.max_length} characters`
  if (type === 'missing') return 'is required'
  if (field === 'email' && type.includes('value_error')) return 'must be a valid email address'
  const message = typeof issue.msg === 'string' ? issue.msg : 'is invalid'
  return message.replace(/^value error,\s*/i, '').replace(/^field required$/i, 'is required')
}

function apiError(detail: unknown, status: number): ApiError {
  if (typeof detail === 'string' && detail.trim()) return new ApiError(detail)
  if (Array.isArray(detail)) {
    const fields: ApiFieldErrors = {}
    for (const rawIssue of detail) {
      if (typeof rawIssue !== 'object' || rawIssue === null) continue
      const issue = rawIssue as ValidationIssue
      const field = validationField(issue)
      const message = validationMessage(field, issue)
      fields[field] = fields[field] ? `${fields[field]}; ${message}` : message
    }
    const readable = Object.entries(fields).map(([field, message]) => `${field}: ${message}`).join('; ')
    if (readable) return new ApiError(readable, fields)
  }
  return new ApiError(`Request failed (HTTP ${status}).`)
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const controller = new AbortController()
  const timeout = globalThis.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const method = options.method ?? 'GET'
    const headers = new Headers(options.headers)
    const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData
    if (options.body && !isFormData && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) {
      if (!csrfToken) {
        const token = await fetch(`${API_BASE}/auth/csrf`, { credentials: 'include', signal: controller.signal })
        if (!token.ok) throw new Error('Could not establish a secure session. Please retry.')
        csrfToken = (await token.json()).csrf_token as string
      }
      headers.set('X-CSRF-Token', csrfToken)
    }
    const response = await fetch(`${API_BASE}${path}`, { ...options, method, headers, credentials: 'include', signal: controller.signal })
    if (response.status === 204) return undefined as T
    const data = await response.json().catch(caught => {
      if (controller.signal.aborted) throw caught
      return {}
    })
    if (!response.ok) throw apiError(data.detail, response.status)
    return data as T
  } catch (caught) {
    if (controller.signal.aborted) throw new Error('Request timed out after 15 seconds. Please try again.')
    throw caught
  } finally {
    globalThis.clearTimeout(timeout)
  }
}

export type User = { id: string; email: string; role: string }
export type Investigation = { id: string; category: string | null; risk_score: number; risk_level: string; created_at: string }
export type Report = {
  id: string; category: string | null; risk_score: number; risk_level: string; score_is_probability: boolean
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
  image: (file: File) => {
    const body = new FormData()
    body.append('file', file, file.name)
    return request<Report>('/investigations/image', { method: 'POST', body })
  },
  conversation: (messages: Array<{ sender: string; text: string }>) => request<Report>("/investigations/conversation", { method: 'POST', body: JSON.stringify({ messages }) }),
  transaction: (payload: { description: string; claimed_recipient: string; reason: string; amount?: number; related_chat: string }) => request<Report>("/investigations/transaction", { method: 'POST', body: JSON.stringify(payload) }),
  history: (filters: { q?: string; risk_level?: string } = {}) => {
    const query = new URLSearchParams()
    if (filters.q) query.set('q', filters.q)
    if (filters.risk_level) query.set('risk_level', filters.risk_level)
    return request<{ items: Investigation[] }>(`/investigations${query.size ? `?${query}` : ''}`)
  },
  report: (id: string) => request<Report>(`/investigations/${id}/report`),
  stats: () => request<{ total_investigations: number; risk_distribution: Record<string, number>; category_distribution: Record<string, number> }>('/dashboard/statistics'),
  categories: () => request<Array<{ code: string; name: string; language: string }>>('/scam-categories'),
  awareness: () => request<{ language: string; items: Array<{ title: string; body: string }> }>('/scam-awareness'),
  feedback: (investigation_id: string, rating: string) => request('/feedback', { method: 'POST', body: JSON.stringify({ investigation_id, rating }) }),
  deleteData: () => request<void>('/me/data', { method: 'DELETE' }),
  deleteInvestigation: (id: string) => request<void>(`/investigations/${id}`, { method: 'DELETE' }),
}
