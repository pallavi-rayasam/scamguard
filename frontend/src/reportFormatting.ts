export function categoryLabel(category: string | null | undefined): string {
  if (!category) return 'No scam pattern detected'
  return category.replaceAll('_', ' ').replace(/\b[a-z]/g, letter => letter.toUpperCase())
}

export function formatLocalTimestamp(value: string, options?: Intl.DateTimeFormatOptions): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString(undefined, options)
}
