/**
 * Content script — runs on every github.com page.
 * Detects repo pages and injects the 🔐 Scan button into the GitHub header.
 */

(function () {
  'use strict'

  // Parse owner/repo from the current URL
  const match = location.pathname.match(/^\/([^/]+)\/([^/]+)/)
  if (!match) return

  const [, owner, repo] = match
  // Exclude non-repo paths (settings, orgs, topics, etc.)
  const EXCLUDED = new Set(['settings', 'orgs', 'topics', 'marketplace', 'explore', 'notifications'])
  if (EXCLUDED.has(owner)) return

  const fullRepo = `${owner}/${repo}`

  // Avoid injecting twice on soft navigations
  if (document.getElementById('vuln-patcher-btn')) return

  // ── Build the button ────────────────────────────────────────────────────────

  const btn = document.createElement('button')
  btn.id = 'vuln-patcher-btn'
  btn.title = 'Vuln Auto-Patcher — click to scan this repo'
  btn.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0a5 5 0 0 1 5 5v1h.5A1.5 1.5 0 0 1 15 7.5v6A1.5 1.5 0 0 1 13.5 15h-11A1.5 1.5 0 0 1 1 13.5v-6A1.5 1.5 0 0 1 2.5 6H3V5a5 5 0 0 1 5-5zm0 1.5A3.5 3.5 0 0 0 4.5 5v1h7V5A3.5 3.5 0 0 0 8 1.5zm0 8a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/>
    </svg>
    <span>Scan</span>
  `

  // Style — matches GitHub's secondary button look
  Object.assign(btn.style, {
    display:        'inline-flex',
    alignItems:     'center',
    gap:            '4px',
    padding:        '4px 12px',
    fontSize:       '14px',
    fontWeight:     '500',
    lineHeight:     '20px',
    color:          '#24292f',
    backgroundColor: '#f6f8fa',
    border:         '1px solid rgba(31,35,40,0.15)',
    borderRadius:   '6px',
    cursor:         'pointer',
    marginLeft:     '8px',
    verticalAlign:  'middle',
    fontFamily:     '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  })

  btn.addEventListener('mouseenter', () => {
    btn.style.backgroundColor = '#f3f4f6'
    btn.style.borderColor = 'rgba(31,35,40,0.3)'
  })
  btn.addEventListener('mouseleave', () => {
    btn.style.backgroundColor = '#f6f8fa'
    btn.style.borderColor = 'rgba(31,35,40,0.15)'
  })

  // Clicking the button just stores the repo and opens the popup via the extension action
  btn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'set_active_repo', repo: fullRepo })
    // Open the popup programmatically — user may need to click the toolbar icon
    // We show a small tooltip instead since extensions can't open their own popup
    showTooltip(btn, 'Click the 🔐 toolbar icon to scan')
  })

  // ── Inject into GitHub header ───────────────────────────────────────────────

  function inject() {
    if (document.getElementById('vuln-patcher-btn')) return

    // Try several possible injection points across different GitHub layouts
    const candidates = [
      // Repo action bar (main repo view)
      () => document.querySelector('ul[aria-label="Repository actions"]'),
      // Older GitHub header nav
      () => document.querySelector('.pagehead-actions'),
      // Generic — any nav with repo context
      () => document.querySelector('[data-turbo-frame="repo-content"] nav'),
    ]

    for (const find of candidates) {
      const target = find()
      if (target) {
        const li = document.createElement('li')
        li.appendChild(btn)
        target.appendChild(li)
        return
      }
    }

    // Final fallback: inject after the repo title
    const repoHeader = document.querySelector('[itemprop="name"]')?.closest('h1')
    if (repoHeader) {
      repoHeader.insertAdjacentElement('afterend', btn)
    }
  }

  // GitHub uses Turbo/soft navigation — re-inject on page transitions
  inject()
  const observer = new MutationObserver(() => {
    if (!document.getElementById('vuln-patcher-btn')) inject()
  })
  observer.observe(document.body, { childList: true, subtree: true })

  // ── Tooltip helper ──────────────────────────────────────────────────────────

  function showTooltip(anchor, text) {
    const existing = document.getElementById('vuln-patcher-tooltip')
    if (existing) existing.remove()

    const tip = document.createElement('div')
    tip.id = 'vuln-patcher-tooltip'
    tip.textContent = text
    Object.assign(tip.style, {
      position:      'fixed',
      background:    '#24292f',
      color:         '#fff',
      padding:       '6px 10px',
      borderRadius:  '6px',
      fontSize:      '12px',
      zIndex:        '99999',
      pointerEvents: 'none',
      whiteSpace:    'nowrap',
    })
    document.body.appendChild(tip)

    const rect = anchor.getBoundingClientRect()
    tip.style.top  = (rect.bottom + 6) + 'px'
    tip.style.left = rect.left + 'px'

    setTimeout(() => tip.remove(), 3000)
  }
})()
