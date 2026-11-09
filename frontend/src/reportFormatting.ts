export function categoryLabel(category: string | null | undefined): string {
  if (!category) return 'No scam pattern detected'
  return category.replaceAll('_', ' ').replace(/\b[a-z]/g, letter => letter.toUpperCase())
}

export type BrowserTimeZone = { timeZone: string; usedFallback: boolean }

export function getBrowserTimeZone(): BrowserTimeZone {
  try {
    const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone
    if (typeof timeZone !== 'string' || !timeZone.trim()) throw new RangeError('Browser time zone is unavailable')
    new Intl.DateTimeFormat('en-US', { timeZone }).format(new Date(0))
    return { timeZone, usedFallback: false }
  } catch {
    return { timeZone: 'UTC', usedFallback: true }
  }
}

export function formatLocalTimestamp(
  value: string | null | undefined,
  options?: Intl.DateTimeFormatOptions,
): string {
  if (typeof value !== 'string' || !value.trim()) return 'Timestamp unavailable'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Timestamp unavailable'

  const { timeZone: requestedTimeZone, ...formatOptions } = options ?? {}
  let timeZone = requestedTimeZone
  let usedFallback = false
  if (!timeZone) {
    const browserZone = getBrowserTimeZone()
    timeZone = browserZone.timeZone
    usedFallback = browserZone.usedFallback
  }

  try {
    const formatted = new Intl.DateTimeFormat(undefined, { ...formatOptions, timeZone }).format(date)
    return usedFallback ? `${formatted} UTC` : formatted
  } catch {
    const formatted = new Intl.DateTimeFormat(undefined, { ...formatOptions, timeZone: 'UTC' }).format(date)
    return `${formatted} UTC`
  }
}
