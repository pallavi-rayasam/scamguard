import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import App from './App'

const { mockMe, mockLogin, mockRegister } = vi.hoisted(() => ({
  mockMe: vi.fn(),
  mockLogin: vi.fn(),
  mockRegister: vi.fn(),
}))
vi.mock('./api', () => ({ api: { me: mockMe, login: mockLogin, register: mockRegister } }))

afterEach(cleanup)

beforeEach(() => {
  location.hash = '#/home'
  vi.clearAllMocks()
  mockMe.mockRejectedValue(new Error('Not signed in'))
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
})
