import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { TailnetDirectLink } from './TailnetDirectLink'

vi.mock('../utils/clipboard', () => ({ copyToClipboard: vi.fn(async () => false) }))

describe('TailnetDirectLink', () => {
  it('describes Tailscale rules rather than promising invite-only access', () => {
    render(<TailnetDirectLink direct={{ state: 'active', urls: ['https://crew.example.ts.net/'] } as never} />)
    expect(screen.getByTestId('tailnet-direct-link')).toHaveTextContent('By default, anyone allowed by Tailscale access rules')
    expect(screen.getByTestId('tailnet-direct-link')).toHaveTextContent('With local authorization on')
  })

  it('a refused copy shows the shared error notice', async () => {
    render(<TailnetDirectLink direct={{ state: 'active', urls: ['https://crew.example.ts.net/'] } as never} />)
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    const notice = await screen.findByTestId('direct-link-copy-error')
    expect(notice).toHaveAttribute('role', 'alert')
    expect(screen.getByRole('button', { name: /Ask the agent/ })).toBeInTheDocument()
  })
})
