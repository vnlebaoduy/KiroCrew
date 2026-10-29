/**
 * The drag a desktop trackpad swipe plays on a side panel anchored to the
 * window's RIGHT edge: the offset under the fingers, and the release.
 *
 * Shared by every page that hosts the swipe (the Mates page, the chat page),
 * so a panel follows the fingers and settles by one rule wherever it is. The
 * run itself (where it starts, where the fingers lift) is `useTrackpadSwipe`'s;
 * this is what a page does with the run's summed `deltaX`.
 *
 * The offset is the panel's distance from its resting place, px: 0 is fully
 * open, `travel` fully out. The release is the phone's rule from
 * `useDrawerSwipe`, so a trackpad and a finger settle a panel the same way.
 */
import { COMMIT_DRAG_SHARE, COMMIT_VELOCITY, VELOCITY_MIN_SPAN_MS } from './useDrawerSwipe'

/** The release speed is read over the fingers' last this-many ms. */
export const TRACKPAD_VELOCITY_WINDOW_MS = 60

export interface TrackpadPanelDrag {
  on: boolean
  /** The state a release falls back to: where the drag started (or, grabbed
   *  mid-settle, the state that settle was heading for). */
  startedOpen: boolean
  /** How far the panel travels from open to out, px: its own width. */
  travel: number
  /** The offset the fingers' sum is measured from. */
  base: number
  /** (offset, event time) per move, newest last. */
  samples: { x: number; t: number }[]
}

export function idleTrackpadDrag(): TrackpadPanelDrag {
  return { on: false, startedOpen: false, travel: 0, base: 0, samples: [] }
}

/** The offset for the run's summed `deltaX` at `at`, recorded for the release
 *  speed. Fingers moving left report a positive `deltaX`, which pulls the panel
 *  in. */
export function moveTrackpadDrag(d: TrackpadPanelDrag, sumX: number, at: number): number {
  const x = Math.min(d.travel, Math.max(0, d.base - sumX))
  d.samples.push({ x, t: at })
  if (d.samples.length > 32) d.samples.splice(0, d.samples.length - 32)
  return x
}

/**
 * Where the panel goes once the fingers are off, and the speed it leaves with
 * (px/ms, positive moving out).
 *
 * `how` is the reader's: `momentum` when the tail was recognised, so the
 * fingers left at the speed of their last moves; `gap` when no event came for
 * the idle window, so they had stopped before they left. A flick decides; else
 * moving past the share decides by its direction; else the panel goes back to
 * `startedOpen`.
 */
export function releaseTrackpadDrag(
  d: TrackpadPanelDrag, x: number, how: 'momentum' | 'gap', at: number,
): { open: boolean; velocity: number } {
  const last = d.samples[d.samples.length - 1]
  const liftAt = how === 'momentum' && last ? last.t : at
  let first: { x: number; t: number } | undefined
  for (let i = 0; i < d.samples.length; i++) {
    if (liftAt - d.samples[i].t <= TRACKPAD_VELOCITY_WINDOW_MS) {
      first = d.samples[i]
      if (liftAt - first.t < VELOCITY_MIN_SPAN_MS && i > 0) first = d.samples[i - 1]
      break
    }
  }
  const span = first && last ? last.t - first.t : 0
  const velocity = first && last && span > 0 ? (last.x - first.x) / span : 0
  // A smaller offset is open (the panel is anchored right).
  const dragged = Math.abs(x - d.base) / Math.max(1, d.travel)
  let open: boolean
  if (-velocity > COMMIT_VELOCITY) open = true
  else if (velocity > COMMIT_VELOCITY) open = false
  else if (dragged > COMMIT_DRAG_SHARE) open = x < d.base
  else open = d.startedOpen
  return { open, velocity }
}
