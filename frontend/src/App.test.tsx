import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from './App'

vi.mock('./api', () => ({ api: { me: vi.fn().mockRejectedValue(new Error('Not signed in')) } }))

describe('landing page', () => {
  beforeEach(() => { location.hash = '#/home' })

  it('explains the product and advisory boundary', async () => {
    render(<App />)
    expect(await screen.findByRole('heading', { name: /pause\. check\./i })).toBeTruthy()
    expect(screen.getByText(/no payments initiated/i)).toBeTruthy()
  })
})
