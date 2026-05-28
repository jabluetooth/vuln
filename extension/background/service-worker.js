'use strict'

/**
 * Service worker — always dispatches to the CENTRAL scanner repo
 * (jabluetooth/vuln), passing the viewed repo as target_repo input.
 *
 * This means the extension works on any GitHub repo — the user browses
 * to any repo, clicks Scan, and the central workflow handles everything.
 */

const ALARM_NAME      = 'poll_scan_result'
const POLL_MINUTES    = 0.25            // every 15 seconds
const MAX_POLL_ALARMS = 80             // give up after ~20 minutes
const WORKFLOW_FILE   = 'vuln_scan.yml'
const GH_API          = 'https://api.github.com'

// ── Message handler ────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.action) {

    case 'set_active_repo':
      chrome.storage.local.set({ active_repo: msg.repo })
      sendResponse({})
      break

    case 'start_scan':
      startScan(msg.target_repo, msg.settings)
        .then(r  => sendResponse({ success: true,  run_id: r }))
        .catch(e => sendResponse({ success: false, error:  e.message }))
      return true

    case 'get_status':
      getStatus(msg.repo)
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

  const { runId, target_repo, workflow_repo, workerUrl, extensionToken, pollCount } = pending_scan

  if ((pollCount || 0) >= MAX_POLL_ALARMS) {
    await chrome.storage.local.remove('pending_scan')
    await chrome.alarms.clear(ALARM_NAME)
    await notify('⏱️ Scan timed out', `${target_repo}: workflow did not finish within 20 minutes.`)
    return
  }

  await chrome.storage.local.set({
    pending_scan: { ...pending_scan, pollCount: (pollCount || 0) + 1 },
  })

  const result = workerUrl
    ? await pollWorker(runId, workerUrl, extensionToken)
    : await pollGitHub(runId, workflow_repo)

  if (result) {
    await finalizeScan(target_repo, runId, result)
  }
})

// ── Core: start scan ───────────────────────────────────────────────────────────

async function startScan(target_repo, settings) {
  const creds = await chrome.storage.sync.get([
    'github_pat', 'workflow_repo', 'worker_url', 'extension_token',
  ])
  const { github_pat, worker_url, extension_token } = creds

  // The central repo that runs the scanner workflow
  const workflow_repo = creds.workflow_repo?.trim() || ''
  if (!workflow_repo) {
    throw new Error('Workflow repo not configured. Open Settings and set your central scanner repo (e.g. jabluetooth/vuln).')
  }
  if (!github_pat) {
    throw new Error('GitHub PAT not configured. Open Settings and add your PAT.')
  }

  await setStatus(target_repo, { status: 'triggering', message: 'Triggering workflow…' })

  const dispatchedAt = new Date().toISOString()

  // Always dispatch to the CENTRAL scanner repo, passing target as input
  const dispatchRes = await ghFetch(
    `/repos/${workflow_repo}/actions/workflows/${WORKFLOW_FILE}/dispatches`,
    github_pat,
    {
      method: 'POST',
      body: JSON.stringify({
        ref: 'main',
        inputs: {
          target_repo:      target_repo === workflow_repo ? '' : target_repo,
          min_severity:     settings.min_severity     || 'MODERATE',
          cvss_threshold:   String(settings.cvss_threshold ?? 0),
          package_denylist: settings.package_denylist || '',
          cve_denylist:     settings.cve_denylist     || '',
          dry_run:          settings.dry_run ? 'true' : 'false',
        },
      }),
    },
  )

  if (!dispatchRes.ok) {
    const txt = await dispatchRes.text()
    throw new Error(`Dispatch failed (${dispatchRes.status}): ${txt}`)
  }

  await setStatus(target_repo, { status: 'waiting', message: 'Waiting for run to start…' })

  // Find the new run_id on the WORKFLOW repo (not the target repo)
  const runId = await waitForRunId(workflow_repo, github_pat, dispatchedAt)
  if (!runId) throw new Error('Could not find the new workflow run ID. Check GitHub Actions.')

  await setStatus(target_repo, { status: 'running', message: `Run #${runId} in progress…` })

  await chrome.storage.local.set({
    pending_scan: {
      runId:          String(runId),
      target_repo,
      workflow_repo,
      workerUrl:      worker_url     || '',
      extensionToken: extension_token || '',
      pollCount:      0,
    },
  })

  await chrome.alarms.create(ALARM_NAME, { periodInMinutes: POLL_MINUTES })

  return runId
}

// ── Run ID discovery ───────────────────────────────────────────────────────────

async function waitForRunId(workflow_repo, token, after, maxAttempts = 20) {
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(3000)
    const res = await ghFetch(
      `/repos/${workflow_repo}/actions/runs?event=workflow_dispatch&per_page=10`,
      token,
    )
    if (!res.ok) continue
    const { workflow_runs } = await res.json()
    const run = workflow_runs.find(r => r.created_at >= after)
    if (run) return run.id
  }
  return null
}

// ── Polling ────────────────────────────────────────────────────────────────────

async function pollWorker(runId, workerUrl, extensionToken) {
  try {
    const res = await fetch(`${workerUrl}/result/${runId}`, {
      headers: extensionToken ? { Authorization: `Bearer ${extensionToken}` } : {},
    })
    if (res.status === 202) return null
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

async function pollGitHub(runId, workflow_repo) {
  const { github_pat } = await chrome.storage.sync.get('github_pat')
  if (!github_pat) return null
  const res = await ghFetch(`/repos/${workflow_repo}/actions/runs/${runId}`, github_pat)
  if (!res.ok) return null
  const run = await res.json()
  if (run.status !== 'completed') return null
  return {
    run_id:       String(runId),
    conclusion:   run.conclusion,
    completed_at: run.updated_at,
    run_url:      run.html_url,
    scan_report:  null,
  }
}

// ── Finalize ───────────────────────────────────────────────────────────────────

async function finalizeScan(target_repo, runId, result) {
  const scanData = {
    status:           'complete',
    conclusion:       result.conclusion,
    run_id:           String(runId),
    run_url:          result.run_url,
    last_scan_at:     result.completed_at || new Date().toISOString(),
    patches_opened:   result.scan_report?.patches_opened    ?? 0,
    packages_scanned: result.scan_report?.packages_scanned  ?? 0,
    findings:         result.scan_report?.findings          ?? [],
  }

  const { scans } = await chrome.storage.local.get('scans')
  await chrome.storage.local.set({
    scans:        { ...(scans || {}), [target_repo]: scanData },
    pending_scan: null,
    active_repo:  target_repo,
  })

  await chrome.alarms.clear(ALARM_NAME)

  const count = scanData.patches_opened
  const msg = result.scan_report
    ? (count > 0
        ? `${count} vulnerability fix(es) opened as PRs`
        : 'No vulnerabilities found above threshold')
    : 'Workflow complete — open the extension for details'
  await notify(`🔐 ${target_repo}`, msg)

  chrome.runtime.sendMessage({
    action: 'scan_complete', repo: target_repo, result: scanData,
  }).catch(() => {})
}

// ── Status ─────────────────────────────────────────────────────────────────────

async function getStatus(repo) {
  const { pending_scan, scans } = await chrome.storage.local.get(['pending_scan', 'scans'])
  if (pending_scan?.target_repo === repo) {
    return { status: 'running', run_id: pending_scan.runId }
  }
  const cached = (scans || {})[repo]
  if (cached) return cached
  return { status: 'idle' }
}

async function setStatus(repo, statusData) {
  const { scan_status } = await chrome.storage.local.get('scan_status')
  await chrome.storage.local.set({
    scan_status: { ...(scan_status || {}), [repo]: statusData },
  })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function ghFetch(path, token, options = {}) {
  return fetch(`${GH_API}${path}`, {
    ...options,
    headers: {
      Authorization:          `Bearer ${token}`,
      Accept:                 'application/vnd.github+json',
      'Content-Type':         'application/json',
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
