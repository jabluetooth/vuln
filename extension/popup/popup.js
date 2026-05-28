'use strict'

// ── State ──────────────────────────────────────────────────────────────────────

let currentRepo  = null  // "owner/repo" of the active GitHub tab
let workflowRepo = null  // "owner/repo" of the central scanner repo

// ── Boot ───────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  await init()
})

async function init() {
  bindSettingsToggle()
  bindSettingsForm()
  bindScanForm()
  bindRangeLabel()

  // Detect current repo from active tab URL
  currentRepo = await detectRepo()
  document.getElementById('repo-name').textContent = currentRepo || 'Not on a repo page'

  // Check if credentials are configured
  const stored = await chrome.storage.sync.get(['github_pat', 'workflow_repo'])
  workflowRepo = stored.workflow_repo?.trim() || null

  if (!stored.github_pat || !workflowRepo) {
    showView('setup')
    return
  }

  updateViaPill()
  showView('scan')

  if (currentRepo) {
    await loadScanSettings()
    await refreshStatus()
  }
}

// ── View management ────────────────────────────────────────────────────────────

function showView(name) {
  document.querySelectorAll('.view').forEach(el => el.classList.add('hidden'))
  document.getElementById(`view-${name}`)?.classList.remove('hidden')
}

// ── Repo detection ─────────────────────────────────────────────────────────────

async function detectRepo() {
  // Check if service worker stored a repo from content.js click
  const { active_repo } = await chrome.storage.local.get('active_repo')
  if (active_repo) return active_repo

  // Fall back to current tab URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab?.url) return null
    const match = new URL(tab.url).pathname.match(/^\/([^/]+)\/([^/]+)/)
    if (match) return `${match[1]}/${match[2]}`
  } catch { /* tabs permission not granted yet */ }
  return null
}

// ── Via pill ───────────────────────────────────────────────────────────────────

function updateViaPill() {
  const pill = document.getElementById('via-pill')
  const display = document.getElementById('workflow-repo-display')
  if (workflowRepo && currentRepo && currentRepo !== workflowRepo) {
    display.textContent = workflowRepo
    pill.classList.remove('hidden')
  } else {
    pill.classList.add('hidden')
  }
}

// ── Settings toggle ────────────────────────────────────────────────────────────

function bindSettingsToggle() {
  document.getElementById('btn-settings').addEventListener('click', async () => {
    const current = document.getElementById('view-settings-edit')
    if (!current.classList.contains('hidden')) {
      showView('scan')
      return
    }
    // Pre-fill from storage
    const stored = await chrome.storage.sync.get([
      'github_pat', 'workflow_repo', 'worker_url', 'extension_token',
    ])
    document.getElementById('edit-pat').value           = stored.github_pat      || ''
    document.getElementById('edit-workflow-repo').value = stored.workflow_repo   || ''
    document.getElementById('edit-worker').value        = stored.worker_url      || ''
    document.getElementById('edit-ext-token').value     = stored.extension_token || ''
    document.getElementById('settings-msg').className   = 'hidden'
    showView('settings-edit')
  })

  document.getElementById('btn-settings-cancel').addEventListener('click', () => {
    showView('scan')
  })
}

// ── Settings forms ─────────────────────────────────────────────────────────────

function bindSettingsForm() {
  // First-time setup form
  document.getElementById('btn-save-settings').addEventListener('click', async () => {
    const pat          = document.getElementById('input-pat').value.trim()
    const wfRepo       = document.getElementById('input-workflow-repo').value.trim()
    const worker       = document.getElementById('input-worker').value.trim()
    const token        = document.getElementById('input-ext-token').value.trim()
    const errEl        = document.getElementById('setup-error')

    if (!pat) {
      showError(errEl, 'GitHub PAT is required.')
      return
    }
    if (!wfRepo) {
      showError(errEl, 'Central Scanner Repo is required (e.g. jabluetooth/vuln).')
      return
    }
    if (!wfRepo.includes('/')) {
      showError(errEl, 'Central Scanner Repo must be in "owner/repo" format.')
      return
    }

    await chrome.storage.sync.set({
      github_pat:      pat,
      workflow_repo:   wfRepo,
      worker_url:      worker,
      extension_token: token,
    })

    workflowRepo = wfRepo
    errEl.classList.add('hidden')
    updateViaPill()
    showView('scan')
    await refreshStatus()
  })

  // Edit settings form
  document.getElementById('btn-settings-save').addEventListener('click', async () => {
    const pat    = document.getElementById('edit-pat').value.trim()
    const wfRepo = document.getElementById('edit-workflow-repo').value.trim()
    const worker = document.getElementById('edit-worker').value.trim()
    const token  = document.getElementById('edit-ext-token').value.trim()
    const msgEl  = document.getElementById('settings-msg')

    if (!pat) {
      msgEl.textContent = 'GitHub PAT is required.'
      msgEl.className   = 'error'
      return
    }
    if (!wfRepo) {
      msgEl.textContent = 'Central Scanner Repo is required.'
      msgEl.className   = 'error'
      return
    }
    if (!wfRepo.includes('/')) {
      msgEl.textContent = 'Central Scanner Repo must be in "owner/repo" format.'
      msgEl.className   = 'error'
      return
    }

    await chrome.storage.sync.set({
      github_pat:      pat,
      workflow_repo:   wfRepo,
      worker_url:      worker,
      extension_token: token,
    })

    workflowRepo = wfRepo
    updateViaPill()
    msgEl.textContent = 'Saved!'
    msgEl.className   = 'success'
    setTimeout(() => showView('scan'), 800)
  })
}

// ── Scan settings persistence ──────────────────────────────────────────────────

async function loadScanSettings() {
  const { default_settings } = await chrome.storage.sync.get('default_settings')
  if (!default_settings) return

  const { min_severity, cvss_threshold, package_denylist, cve_denylist, dry_run } = default_settings
  if (min_severity)     document.getElementById('sel-severity').value    = min_severity
  if (cvss_threshold)   document.getElementById('range-cvss').value      = cvss_threshold
  if (package_denylist) document.getElementById('input-pkg-deny').value  = package_denylist
  if (cve_denylist)     document.getElementById('input-cve-deny').value  = cve_denylist
  if (dry_run)          document.getElementById('chk-dryrun').checked    = dry_run
  updateCvssLabel()
}

function collectSettings() {
  return {
    min_severity:     document.getElementById('sel-severity').value,
    cvss_threshold:   parseFloat(document.getElementById('range-cvss').value),
    package_denylist: document.getElementById('input-pkg-deny').value.trim(),
    cve_denylist:     document.getElementById('input-cve-deny').value.trim(),
    dry_run:          document.getElementById('chk-dryrun').checked,
  }
}

// ── CVSS label ─────────────────────────────────────────────────────────────────

function bindRangeLabel() {
  document.getElementById('range-cvss').addEventListener('input', updateCvssLabel)
}

function updateCvssLabel() {
  const val = parseFloat(document.getElementById('range-cvss').value)
  document.getElementById('cvss-value').textContent = val === 0 ? '0 (off)' : val.toFixed(1)
}

// ── Scan button ────────────────────────────────────────────────────────────────

function bindScanForm() {
  document.getElementById('btn-scan').addEventListener('click', async () => {
    if (!currentRepo) {
      setStatus('error', '⚠️', 'No repo detected', 'Navigate to a GitHub repository first.')
      return
    }
    if (!workflowRepo) {
      setStatus('error', '⚠️', 'Not configured', 'Open Settings and set your Central Scanner Repo.')
      return
    }

    const settings = collectSettings()
    // Save settings as defaults for next time
    await chrome.storage.sync.set({ default_settings: settings })

    setStatus('running', '⏳', 'Triggering workflow…', `Dispatching to ${workflowRepo}…`)
    document.getElementById('btn-scan').disabled = true

    try {
      const response = await sendToServiceWorker({
        action:      'start_scan',
        target_repo: currentRepo,
        settings,
      })
      if (response.success) {
        setStatus(
          'running', '⏳', 'Workflow running',
          `Run #${response.run_id} on ${workflowRepo} · checking every 15s…`,
        )
      } else {
        setStatus('error', '❌', 'Failed to start scan', response.error)
        document.getElementById('btn-scan').disabled = false
      }
    } catch (err) {
      setStatus('error', '❌', 'Error', err.message)
      document.getElementById('btn-scan').disabled = false
    }
  })

  // Service worker pushes scan_complete back to popup
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === 'scan_complete' && msg.repo === currentRepo) {
      onScanComplete(msg.result)
    }
  })
}

// ── Status helpers ─────────────────────────────────────────────────────────────

function setStatus(type, icon, title, detail) {
  const banner = document.getElementById('status-banner')
  banner.className = `status-banner ${type}`
  banner.classList.remove('hidden')
  document.getElementById('status-icon').textContent   = icon
  document.getElementById('status-title').textContent  = title
  document.getElementById('status-detail').textContent = detail
}

async function refreshStatus() {
  if (!currentRepo) return

  const status = await sendToServiceWorker({ action: 'get_status', repo: currentRepo })
  if (!status) return

  if (status.status === 'running') {
    setStatus('running', '⏳', 'Scan in progress', `Run #${status.run_id} · checking every 15s…`)
    document.getElementById('btn-scan').disabled = true
  } else if (status.status === 'complete') {
    onScanComplete(status)
  }
}

function onScanComplete(result) {
  document.getElementById('btn-scan').disabled = false

  if (result.conclusion === 'failure') {
    setStatus('error', '❌', 'Workflow failed', 'Check the Actions log for details.')
  } else {
    setStatus('success', '✅', 'Scan complete', `${result.patches_opened} fix(es) found.`)
  }

  renderResults(result)
}

// ── Results rendering ──────────────────────────────────────────────────────────

function renderResults(result) {
  const section = document.getElementById('results-section')
  section.classList.remove('hidden')

  // Run link
  document.getElementById('results-run-link').href = result.run_url || '#'
  document.getElementById('results-label').textContent =
    result.last_scan_at ? `Last scan ${formatDate(result.last_scan_at)}` : 'Results'

  const findings = result.findings || []

  document.getElementById('no-findings').classList.toggle('hidden', findings.length > 0)
  const table = document.getElementById('findings-table')
  table.classList.toggle('hidden', findings.length === 0)

  if (findings.length > 0) {
    const tbody = document.getElementById('findings-body')
    tbody.innerHTML = ''
    for (const f of findings) {
      const tr = document.createElement('tr')
      tr.innerHTML = `
        <td><strong>${esc(f.package)}</strong></td>
        <td>${esc(f.old_version)} → ${esc(f.new_version)}</td>
        <td class="${sevClass(f.worst_severity)}">${esc(f.worst_severity)}</td>
        <td>${f.pr_url
          ? `<a href="${esc(f.pr_url)}" target="_blank">#${f.pr_number}</a>`
          : '<em>dry run</em>'}</td>
      `
      tbody.appendChild(tr)
    }
  }

  document.getElementById('results-meta-text').textContent =
    result.packages_scanned ? `${result.packages_scanned} packages scanned` : ''
}

// ── Utilities ──────────────────────────────────────────────────────────────────

function sendToServiceWorker(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message))
      } else {
        resolve(response || {})
      }
    })
  })
}

function showError(el, msg) {
  el.textContent = msg
  el.classList.remove('hidden')
}

function sevClass(sev) {
  const map = { CRITICAL: 'sev-critical', HIGH: 'sev-high', MODERATE: 'sev-moderate', LOW: 'sev-low' }
  return map[sev?.toUpperCase()] || ''
}

function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
  } catch { return iso }
}
