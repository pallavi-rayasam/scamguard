import { afterEach, describe, expect, it, vi } from 'vitest'
import { categoryLabel, formatLocalTimestamp, getBrowserTimeZone } from './reportFormatting'

afterEach(() => vi.restoreAllMocks())

describe('report formatting', () => {
  it('labels missing scam categories explicitly', () => {
    expect(categoryLabel(null)).toBe('No scam pattern detected')
    expect(categoryLabel('fake_kyc')).toBe('Fake Kyc')
  })

  it('converts a UTC timestamp into the browser-selected local zone', () => {
    expect(formatLocalTimestamp('2026-11-07T14:14:00+00:00', {
      timeZone: 'Asia/Kolkata',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    })).toBe('19:44')
  })

  it.each([
    ['Asia/Kolkata', '19:44'],
    ['UTC', '14:14'],
    ['America/New_York', '09:14'],
  ])('formats an instant in the valid %s IANA time zone', (timeZone, expected) => {
    expect(formatLocalTimestamp('2026-11-07T14:14:00Z', {
      timeZone,
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    })).toBe(expected)
  })

  it.each([undefined, '', 'not-a-timestamp'])('labels a missing or malformed timestamp as unavailable (%s)', value => {
    expect(formatLocalTimestamp(value)).toBe('Timestamp unavailable')
  })

  it('falls back to UTC when browser time zone detection throws, without changing the source timestamp', () => {
    const original = '2026-11-07T14:14:00+00:00'
    const NativeDateTimeFormat = Intl.DateTimeFormat
    vi.spyOn(Intl, 'DateTimeFormat').mockImplementation((function (locales?: Intl.LocalesArgument, options?: Intl.DateTimeFormatOptions) {
      if (!options?.timeZone) throw new RangeError('timezone detection unavailable')
      return new NativeDateTimeFormat(locales, options)
    }) as typeof Intl.DateTimeFormat)

    expect(getBrowserTimeZone()).toEqual({ timeZone: 'UTC', usedFallback: true })
    expect(formatLocalTimestamp(original, { hour: '2-digit', minute: '2-digit', hour12: false })).toMatch(/14:14.*UTC/)
    expect(original).toBe('2026-11-07T14:14:00+00:00')
  })

  it('falls back to UTC for an invalid explicit time zone instead of failing', () => {
    expect(formatLocalTimestamp('2026-11-07T14:14:00Z', {
      timeZone: 'Unknown/Zone', hour: '2-digit', minute: '2-digit', hour12: false,
    })).toMatch(/14:14.*UTC/)
  })
})
