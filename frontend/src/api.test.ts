import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

beforeEach(() => { vi.resetModules() })

describe('auth API errors and timeout', () => {
  it('formats FastAPI email validation details without echoing submitted values', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'csrf-test' }))
      .mockResolvedValueOnce(jsonResponse({ detail: [{ loc: ['body', 'email'], type: 'value_error', msg: 'value is not a valid email address' }] }, 422))
    vi.stubGlobal('fetch', fetchMock)
    const { api, ApiError } = await import('./api')
    const email = 'member@localhost'
    const password = 'long-enough-password'
    await expect(api.register(email, password)).rejects.toMatchObject({
      name: 'ApiError',
      message: 'email: must be a valid email address',
      fieldErrors: { email: 'must be a valid email address' },
    })
    expect(fetchMock.mock.calls[1][0]).toContain('/auth/register')
    expect(JSON.parse(fetchMock.mock.calls[1][1].body as string)).toEqual({ email, password })
    expect(ApiError).toBeDefined()
  })

  it('turns password min-length validation into readable field text', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'csrf-test' }))
      .mockResolvedValueOnce(jsonResponse({ detail: [{ loc: ['body', 'password'], type: 'string_too_short', msg: 'String should have at least 12 characters', ctx: { min_length: 12 } }] }, 422))
    vi.stubGlobal('fetch', fetchMock)
    const { api } = await import('./api')
    await expect(api.register('member@example.com', 'short-pass')).rejects.toMatchObject({
      message: 'password: must be at least 12 characters',
      fieldErrors: { password: 'must be at least 12 characters' },
    })
  })

  it('uploads a screenshot as multipart without overriding the browser boundary', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'csrf-test' }))
      .mockResolvedValueOnce(jsonResponse({ id: 'report-id' }, 201))
    vi.stubGlobal('fetch', fetchMock)
    const { api } = await import('./api')
    const file = new File(['png-data'], 'notice.png', { type: 'image/png' })
    await api.image(file)
    const [, options] = fetchMock.mock.calls[1]
    expect(fetchMock.mock.calls[1][0]).toContain('/investigations/image')
    expect(options.body).toBeInstanceOf(FormData)
    expect(options.body.get('file')).toBeInstanceOf(File)
    expect((options.headers as Headers).has('Content-Type')).toBe(false)
  })

  it('downloads a PDF blob with the browser time zone in the request', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('%PDF-1.4', {
      status: 200,
      headers: { 'Content-Type': 'application/pdf' },
    }))
    vi.stubGlobal('fetch', fetchMock)
    const { api } = await import('./api')
    const blob = await api.reportPdf('report-id')
    expect(blob).toBeInstanceOf(Blob)
    expect(fetchMock.mock.calls[0][0]).toContain('/investigations/report-id/report.pdf?time_zone=')
    expect((fetchMock.mock.calls[0][1] as RequestInit).credentials).toBe('include')
  })

  it('preserves the database unavailable detail for the auth UI', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'csrf-test' }))
      .mockResolvedValueOnce(jsonResponse({ detail: 'Database unavailable' }, 503))
    vi.stubGlobal('fetch', fetchMock)
    const { api } = await import('./api')
    await expect(api.register('member@example.com', 'long-enough-password'))
      .rejects.toMatchObject({ name: 'ApiError', message: 'Database unavailable' })
  })

  it('aborts an API request after exactly 15 seconds', async () => {
    vi.useFakeTimers()
    let mainSignal: AbortSignal | undefined
    const fetchMock = vi.fn().mockImplementation((input: string, options: RequestInit = {}) => {
      if (input.endsWith('/auth/csrf')) return Promise.resolve(jsonResponse({ csrf_token: 'csrf-test' }))
      mainSignal = options.signal as AbortSignal
      return new Promise((_resolve, reject) => {
        mainSignal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
      })
    })
    vi.stubGlobal('fetch', fetchMock)
    const { api, REQUEST_TIMEOUT_MS } = await import('./api')
    const request = api.register('member@example.com', 'long-enough-password').catch(error => error)
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(REQUEST_TIMEOUT_MS).toBe(15_000)
    await vi.advanceTimersByTimeAsync(14_999)
    expect(mainSignal?.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    await expect(request).resolves.toMatchObject({ message: 'Request timed out after 15 seconds. Please try again.' })
  })
})
