import { describe, expect, it } from 'vitest'
import { categoryLabel, formatLocalTimestamp } from './reportFormatting'

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
})
