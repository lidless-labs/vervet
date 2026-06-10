/**
 * useDefaultVariant — Persist a preferred variant in localStorage.
 * 
 * When a default is set, the variant picker auto-redirects on load.
 * Users can change or clear the default from any variant's settings.
 * 
 * Usage:
 *   const { defaultVariant, setDefaultVariant, clearDefault } = useDefaultVariant('vervet')
 */
import { useState, useCallback } from 'react'

const STORAGE_PREFIX = 'variant-default-'

export function useDefaultVariant(appId: string) {
  const key = STORAGE_PREFIX + appId

  const [defaultVariant, setDefaultVariantState] = useState<number | null>(() => {
    try {
      const stored = localStorage.getItem(key)
      if (stored) {
        const num = parseInt(stored, 10)
        return num >= 1 && num <= 5 ? num : null
      }
    } catch {}
    return null
  })

  const setDefaultVariant = useCallback((variant: number | null) => {
    const safe = variant !== null && variant >= 1 && variant <= 5 ? variant : null
    try {
      if (safe === null) {
        localStorage.removeItem(key)
      } else {
        localStorage.setItem(key, String(safe))
      }
    } catch {}
    setDefaultVariantState(safe)
  }, [key])

  const clearDefault = useCallback(() => {
    setDefaultVariant(null)
  }, [setDefaultVariant])

  return { defaultVariant, setDefaultVariant, clearDefault }
}
