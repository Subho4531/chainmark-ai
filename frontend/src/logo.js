/**
 * Brand mark resolution ladder.
 *
 * `public/logo/mark-<n>.png` is generated at every width below by
 * `make-logo-crisp.ps1` (Lanczos3 + unsharp on premultiplied alpha, fully
 * transparent). Each placement declares the CSS box it paints and `markSrcSet`
 * returns the nearest asset at or above 1x, 2x and 3x of that box, so the
 * browser always lands on a file that is either exactly the device pixel count
 * or a hair larger — never a large bitmap squeezed down through a cheap
 * resampler, which is what used to smear the 1px concentric strokes.
 *
 * The 24/26/27/28/30/32/38 entries and their x2/x3 partners (48…114) exist
 * because those are the real on-screen boxes: nav 27/32, footer 28/30,
 * dashboard 26, scan hub 24/38. Add a placement, add its width here **and**
 * to the generator's `$sizes` list.
 */
export const MARK_WIDTHS = [
  16, 20,
  24, 26, 27, 28, 30, 32, 38, 40,
  48, 52, 54, 56, 60, 64,
  72, 76, 78, 81, 84, 90, 96,
  114, 128, 160, 192, 256, 384, 512,
]

const DPR_STEPS = [1, 2, 3]

/** Smallest generated width that covers `target` device pixels (never upscales). */
function atLeast(target) {
  for (const width of MARK_WIDTHS) {
    if (width >= target) return width
  }
  return MARK_WIDTHS[MARK_WIDTHS.length - 1]
}

function asset(width) {
  return `/logo/mark-${width}.png`
}

/**
 * `srcSet` string for one mark that paints at the given CSS width(s).
 * Pass every width the element takes across breakpoints, e.g.
 * `markSrcSet(27, 32)` for a nav mark that shrinks at ≤900px.
 */
export function markSrcSet(...displayWidths) {
  const widths = new Set()
  for (const px of displayWidths) {
    for (const dpr of DPR_STEPS) {
      widths.add(atLeast(px * dpr))
    }
  }
  return [...widths]
    .sort((a, b) => a - b)
    .map((width) => `${asset(width)} ${width}w`)
    .join(', ')
}

/** 1x fallback used by browsers that ignore `srcSet`. */
export function markSrc(displayPx) {
  return asset(atLeast(displayPx))
}
