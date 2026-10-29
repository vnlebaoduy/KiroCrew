/** A creator filter keeps the search field on screen and follows catalog changes. */
import { describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider, QueryObserver } from '@tanstack/react-query'
import { Provider } from 'react-redux'
import { MemoryRouter } from 'react-router-dom'

import ChatSidebar from '../pages/ChatSidebar'
import { ThemeProvider } from '../hooks/useTheme'
import { createTestStore } from './helpers'
import type { RootState } from '../store'
import type { ChatSlot, HistorySession } from '../types'
import { triggerRefresh } from '../store/dashboardSlice'
import { sharedCrewKeys } from '../hooks/sharedCrew/sharedCrewSocket'

const SLOT = 'chat-1'

vi.mock('../pages/chat-sidebar/CreatorFilter', async importOriginal => ({
  ...(await importOriginal<typeof import('../pages/chat-sidebar/CreatorFilter')>()),
  useSharedCrewListView: () => ({ filterAvailable: true, filter: 'mine', setFilter: vi.fn() }),
  CreatorFilteredSessions: () => <div data-testid="creator-filtered-sessions" />,
}))

function mount() {
  const slots = [{ key: SLOT, title: 'A session', running: false, tags: [], created: '', last_ts: '' }] as unknown as ChatSlot[]
  const store = createTestStore({
    dashboard: {
      status: {}, connected: false, slots, approvalMode: 'normal',
      channelTrusted: false, refreshTrigger: 0, unreadSlots: [], updateProgress: null,
      subagentRunning: {}, subagentDetails: {}, subagentText: {},
      sessionDefaultColor: null, sessionColorsMode: 'tint', sessionColorsPalette: 'horizon',
      sessionColorsIntensity: 'clear',
    } as RootState['dashboard'],
    chat: { activeSlot: SLOT } as RootState['chat'],
  })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const tree = (localSlots = slots, history: HistorySession[] = []) => (
    <QueryClientProvider client={qc}>
      <Provider store={store}>
        <ThemeProvider>
          <MemoryRouter>
            <ChatSidebar
              slots={localSlots} activeSlot={SLOT} unreadSlots={[]}
              history={history} historyHasMore={false} defaultAgent="" installedAgents={[]}
            />
          </MemoryRouter>
        </ThemeProvider>
      </Provider>
    </QueryClientProvider>
  )
  return { ...render(tree()), tree, slots, qc, store }
}

describe('sidebar creator filter', () => {
  it('keeps the search field beside the filtered list', () => {
    mount()
    expect(screen.getByTestId('creator-filtered-sessions')).toBeInTheDocument()
    expect(screen.getByTestId('list-dock')).toBeInTheDocument()
    expect(screen.getByTestId('search-field-glass')).toBeInTheDocument()
  })

  it.each(['slots', 'history', 'refresh'] as const)('refreshes active and cached creator pages on %s changes', async change => {
    const { qc, store, tree, slots, rerender } = mount()
    const key = [...sharedCrewKeys.sessions('mine', ''), '']
    const other = [...sharedCrewKeys.sessions('unattributed', 'search'), 'page-2']
    qc.setQueryData(sharedCrewKeys.people, { people: [] })
    qc.setQueryData(key, { items: ['old'] })
    qc.setQueryData(other, { items: ['cached'] })
    const read = vi.fn().mockResolvedValue({ items: ['new'] })
    const observer = new QueryObserver(qc, { queryKey: key, queryFn: read, staleTime: Infinity })
    const unsubscribe = observer.subscribe(() => {})
    try {
      expect(read).not.toHaveBeenCalled()
      act(() => {
        if (change === 'slots') rerender(tree([...slots, { ...slots[0], key: 'chat-2' }]))
        else if (change === 'history') rerender(tree(slots, [{ key: 'persisted' } as HistorySession]))
        else store.dispatch(triggerRefresh())
      })
      await waitFor(() => expect(qc.getQueryData(key)).toEqual({ items: ['new'] }))
      expect(read).toHaveBeenCalledTimes(1)
      expect(qc.getQueryState(other)?.isInvalidated).toBe(true)
      expect(qc.getQueryState(sharedCrewKeys.people)?.isInvalidated).toBe(true)
    } finally {
      unsubscribe()
      qc.clear()
    }
  })
})
