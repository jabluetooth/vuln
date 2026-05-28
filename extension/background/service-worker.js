'use strict'

/**
 * Service worker — runs persistently in the background.
 *
 * Responsibilities:
 *   - Trigger GitHub Actions workflow_dispatch
 *   - Resolve the new run_id via GitHub API
 *   - Poll for completion (via Cloudflare Worker or GitHub API)
 *   - Cache results and fire browser notifications
 *   - Relay scan status back to the popup
 */

const ALARM_NAME       = 'poll_scan_result'
const POLL_MINUTES     = 0.25              // every 15 seconds
const MAX_POLL_ALARMS  = 80               // give up after ~20 minutes
const WORKFLOW_FILE    = 'vuln_scan.yml'
const GH_API           = 'https://api.github.com'

// ── Message handler ────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.action) {

    case 'set_active_repo':
      chrome.storage.local.set({ active_repo: msg.repo })
      sendResponse({})
      break

    case 'start_scan':
      startScan(msg.repo, msg.settings)
        .then(r  => sendResponse({ success: true,  run_id: r }))
        .catch(e => sendResponse({ success: false, error:  e.message }))
      return true   // keep the channel open for async response

    case 'get_status':
      getStatus(msg.repo)
        .then(s => sendResponse(s))
      return true

    case 'get_settings':
      chrome.storage.sync.get(['github_pat', 'worker_url', 'extension_token'])
        .then(s => sendResponse(s))
      return true

    default:
      sendResponse({})
  }
})

// ── Alarm handler ──────────────────────────────────────────────────────────────

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== ALARM_NAME) return

  const { pending_scan } = await chrome.storage.local.get('pending_scan')
  if (!pending_scan) { await chrome.alarms.clear(ALARM_NAME); return }

  const { runId, repo, workerUrl, extensionToken, pollCount } = pending_scan

  // Give up after MAX_POLL_ALARMS
  if ((pollCount || 0) >= MAX_POLL_ALARMS) {
    await chrome.storage.local.remove('pending_scan')
    await chrome.alarms.clear(ALARM_NAME)
    await notify('⏱️ Scan timed out', `${repo}: workflow did not finish within 20 minutes.`)
    return
  }

  // Increment poll counter
  await chrome.storage.local.set({
    pending_scan: { ...pending_scan, pollCount: (pollCount || 0) + 1 },
  })

  // Try Worker first, fall back to GitHub API
  const result = workerUrl
    ? await pollWorker(runId, workerUrl, extensionToken)
    : await pollGitHub(runId, repo)

  if (result) {
    await finalizeScan(repo, runId, result)
  }
})

// ── Core: start scan ───────────────────────────────────────────────────────────

async function startScan(repo, settings) {
  const creds = await chrome.storage.sync.get(['github_pat', 'worker_url', 'extension_token'])
  const { github_pat, worker_url, extension_token } = creds

  if (!github_pat) throw new Error('GitHub PAT not configured. Open Settings and add your PAT.')

  // 1. Dispatch workflow
  const dispatchedAt = new Date().toISOString()
  const dispatchRes  = await ghFetch(`/repos/${repo}/actions/workflows/${WORKFLOW_FILE}/dispatches`, github_pat, {
    method: 'POST',
    body: JSON.stringify({
      ref: 'main',
      inputs: {
        min_severity:     settings.min_severity     || 'MODERATE',
        cvss_threshold:   String(settings.cvss_threshold ?? 0),
        package_denylist: settings.package_denylist || '',
        cve_denylist:     settings.cve_denylist     || '',
        dry_run:          settings.dry_run ? 'true' : 'false',
      },
    }),
  })

  if (!dispatchRes.ok) {
    const txt = await dispatchRes.text()
    throw new Error(`Dispatch failed (${dispatchRes.status}): ${txt}`)
  }

  // 2. Find the newly created run_id (GitHub returns 204, no body)
  const runId = await waitForRunId(repo, github_pat, dispatchedAt)
  if (!runId) throw new Error('Could not find the new workflow run. It may still appear in GitHub Actions.')

  // 3. Save pending scan so the alarm can pick it up
  await chrome.storage.local.set({
    pending_scan: {
      runId:          String(runId),
      repo,
      workerUrl:      worker_url  || '',
      extensionToken: extension_token || '',
      pollCount:      0,
    },
  })

  // 4. Start the polling alarm
  await chrome.alarms.create(ALARM_NAME, { periodInMinutes: POLL_MINUTES })

  return runId
}

// ── Run ID discovery ───────────────────────────────────────────────────────────

async function waitForRunId(repo, token, after, maxAttempts = 20) {
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(3000)
    const res = await ghFetch(
      `/repos/${repo}/actions/runs?event=workflow_dispatch&per_page=10`,
      token,
    )
    if (!res.ok) continue

    const { workflow_runs } = await res.json()
    // Find the most recent run created at or after our dispatch timestamp
    const run = workflow_runs.find(r => r.created_at >= after)
    if (run) return run.id
  }
  return null
}

// ── Polling: via Cloudflare Worker ─────────────────────────────────────────────

async function pollWorker(runId, workerUrl, extensionToken) {
  try {
    const res = await fetch(`${workerUrl}/result/${runId}`, {
      headers: extensionToken ? { Authorization: `Bearer ${extensionToken}` } : {},
    })
    if (res.status === 202) return null   // still pending
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

// ── Polling: directly via GitHub API (no Worker) ───────────────────────────────

async function pollGitHub(runId, repo) {
  const { github_pat } = await chrome.storage.sync.get('github_pat')
  if (!github_pat) return null

  const res = await ghFetch(`/repos/${repo}/actions/runs/${runId}`, github_pat)
  if (!res.ok) return null

  const run = await res.json()
  if (run.status !== 'completed') return null

  // Build a minimal result object matching Worker format
  return {
    run_id:       String(runId),
    repo,
    conclusion:   run.conclusion,
    completed_at: run.updated_at,
    run_url:      run.html_url,
    scan_report:  null,   // can't download artifact without Worker
  }
}

// ── Finalize ───────────────────────────────────────────────────────────────────

async function finalizeScan(repo, runId, result) {
  const scanData = {
    status:          'complete',
    conclusion:      result.conclusion,
    run_id:          String(runId),
    run_url:         result.run_url,
    last_scan_at:    result.completed_at || new Date().toISOString(),
    patches_opened:  result.scan_report?.patches_opened   ?? 0,
    packages_scanned: result.scan_report?.packages_scanned ?? 0,
    findings:        result.scan_report?.findings         ?? [],
  }

  // Persist result under repo key
  const { scans } = await chrome.storage.local.get('scans')
  await chrome.storage.local.set({
    scans: { ...(scans || {}), [repo]: scanData },
    pending_scan: null,
    active_repo: repo,
  })

  await chrome.alarms.clear(ALARM_NAME)

  // Browser notification
  const count = scanData.patches_opened
  const msg = result.scan_report
    ? (count > 0
        ? `${count} vulnerability fix(es) opened as PRs`
        : 'No vulnerabilities found above threshold')
    : 'Workflow complete — open the extension for details'
  await notify(`🔐 ${repo}`, msg)

  // Push result to popup if it's open
  chrome.runtime.sendMessage({ action: 'scan_complete', repo, result: scanData }).catch(() => {})
}

// ── Status query ───────────────────────────────────────────────────────────────

async function getStatus(repo) {
  const { pending_scan, scans } = await chrome.storage.local.get(['pending_scan', 'scans'])

  if (pending_scan?.repo === repo) {
    return { status: 'running', run_id: pending_scan.runId }
  }

  const cached = (scans || {})[repo]
  if (cached) return cached

  return { status: 'idle' }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function ghFetch(path, token, options = {}) {
  return fetch(`${GH_API}${path}`, {
    ...options,
    headers: {
      Authorization:   `Bearer ${token}`,
      Accept:          'application/vnd.github+json',
      'Content-Type':  'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(options.headers || {}),
    },
  })
}

function notify(title, message) {
  return chrome.notifications.create({
    type:     'basic',
    iconUrl:  'icons/icon-48.png',
    title,
    message,
  })
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}
