/**
 * Vuln Auto-Patcher — Cloudflare Worker Relay
 *
 * Routes:
 *   POST /webhook         ← GitHub workflow_run webhook
 *   GET  /result/:run_id  ← extension polls for result
 *   GET  /health          ← sanity check
 *
 * Secrets (set via: wrangler secret put <NAME>):
 *   WEBHOOK_SECRET    HMAC secret shared with GitHub webhook
 *   GITHUB_PAT        read-only PAT for downloading artifacts
 *   EXTENSION_TOKEN   Bearer token the extension sends
 *
 * KV binding: SCAN_RESULTS
 *   key:   run:<run_id>
 *   value: JSON result object
 *   TTL:   24 hours
 */

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS })
    }

    // ── POST /webhook ──────────────────────────────────────────────────────────
    if (request.method === 'POST' && url.pathname === '/webhook') {
      return handleWebhook(request, env)
    }

    // ── GET /result/:run_id ────────────────────────────────────────────────────
    const resultMatch = url.pathname.match(/^\/result\/(\d+)$/)
    if (request.method === 'GET' && resultMatch) {
      if (!verifyExtensionToken(request, env)) {
        return new Response('Unauthorized', { status: 401 })
      }
      return handleResult(resultMatch[1], env)
    }

    // ── GET /health ────────────────────────────────────────────────────────────
    if (request.method === 'GET' && url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      })
    }

    return new Response('Not found', { status: 404 })
  },
}

// ── Webhook handler ────────────────────────────────────────────────────────────

async function handleWebhook(request, env) {
  const body = await request.text()

  // Verify GitHub HMAC signature
  const sig = request.headers.get('X-Hub-Signature-256') || ''
  if (!sig || !(await verifyGitHubSig(body, sig, env.WEBHOOK_SECRET))) {
    return new Response('Invalid signature', { status: 401 })
  }

  // Only care about workflow_run events
  const githubEvent = request.headers.get('X-GitHub-Event')
  if (githubEvent !== 'workflow_run') {
    return new Response('Ignored', { status: 200 })
  }

  const payload = JSON.parse(body)
  const { action, workflow_run: run } = payload

  // Only process when the run finishes
  if (action !== 'completed') {
    return new Response('Not completed', { status: 200 })
  }

  // Only process our workflow
  if (run.name !== 'Vulnerability Auto-Patcher') {
    return new Response('Not our workflow', { status: 200 })
  }

  const runId = String(run.id)
  const repo  = run.repository?.full_name || ''

  // Download scan_report.json artifact (only on success)
  let scanReport = null
  if (run.conclusion === 'success') {
    scanReport = await downloadScanReport(runId, repo, env.GITHUB_PAT)
  }

  // Store result in KV with 24h TTL
  const result = {
    run_id:       runId,
    repo,
    conclusion:   run.conclusion,
    completed_at: run.updated_at,
    run_url:      run.html_url,
    scan_report:  scanReport,
  }
  await env.SCAN_RESULTS.put(`run:${runId}`, JSON.stringify(result), {
    expirationTtl: 86400,
  })

  return new Response('OK', { status: 200 })
}

// ── Result handler ─────────────────────────────────────────────────────────────

async function handleResult(runId, env) {
  const raw = await env.SCAN_RESULTS.get(`run:${runId}`)

  if (!raw) {
    // Run not finished yet
    return new Response(JSON.stringify({ status: 'pending' }), {
      status: 202,
      headers: { 'Content-Type': 'application/json', ...CORS },
    })
  }

  return new Response(raw, {
    status: 200,
    headers: { 'Content-Type': 'application/json', ...CORS },
  })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function verifyExtensionToken(request, env) {
  const auth = request.headers.get('Authorization') || ''
  return auth === `Bearer ${env.EXTENSION_TOKEN}`
}

async function verifyGitHubSig(body, signature, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body))
  const expected =
    'sha256=' +
    Array.from(new Uint8Array(mac))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')

  // Constant-time comparison — prevents timing attacks
  if (expected.length !== signature.length) return false
  let diff = 0
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i)
  }
  return diff === 0
}

async function downloadScanReport(runId, repo, githubPat) {
  try {
    // 1. List artifacts for this run
    const artifactsRes = await fetch(
      `https://api.github.com/repos/${repo}/actions/runs/${runId}/artifacts`,
      {
        headers: {
          Authorization:  `Bearer ${githubPat}`,
          Accept:         'application/vnd.github+json',
          'User-Agent':   'vuln-patcher-worker/1.0',
        },
      },
    )
    if (!artifactsRes.ok) return null

    const { artifacts } = await artifactsRes.json()
    const artifact = artifacts.find(a => a.name.startsWith('scan-report-'))
    if (!artifact) return null

    // 2. Download ZIP (GitHub redirects to a signed S3 URL)
    const zipRes = await fetch(artifact.archive_download_url, {
      headers: {
        Authorization: `Bearer ${githubPat}`,
        'User-Agent':  'vuln-patcher-worker/1.0',
      },
      redirect: 'follow',
    })
    if (!zipRes.ok) return null

    // 3. Extract scan_report.json from the ZIP
    const zipBuffer = await zipRes.arrayBuffer()
    return await extractJsonFromZip(zipBuffer, 'scan_report.json')
  } catch {
    return null
  }
}

/**
 * Extract and parse a single JSON file from a ZIP archive.
 * Handles both stored (method 0) and deflated (method 8) files.
 */
async function extractJsonFromZip(buffer, targetFile) {
  const bytes = new Uint8Array(buffer)
  const view  = new DataView(buffer)

  // Find the End of Central Directory (EOCD) record
  let eocd = -1
  for (let i = bytes.length - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break }
  }
  if (eocd === -1) return null

  const cdOffset = view.getUint32(eocd + 16, true)
  const cdCount  = view.getUint16(eocd + 10, true)

  let offset = cdOffset
  for (let i = 0; i < cdCount; i++) {
    if (view.getUint32(offset, true) !== 0x02014b50) break

    const fnLen      = view.getUint16(offset + 28, true)
    const extraLen   = view.getUint16(offset + 30, true)
    const commentLen = view.getUint16(offset + 32, true)
    const localOff   = view.getUint32(offset + 42, true)
    const compSize   = view.getUint32(offset + 20, true)
    const uncompSize = view.getUint32(offset + 24, true)
    const method     = view.getUint16(offset + 10, true)
    const filename   = new TextDecoder().decode(bytes.slice(offset + 46, offset + 46 + fnLen))

    if (filename === targetFile) {
      // Read past the Local File Header
      const localFnLen    = view.getUint16(localOff + 26, true)
      const localExtraLen = view.getUint16(localOff + 28, true)
      const dataStart     = localOff + 30 + localFnLen + localExtraLen
      const compressedBytes = bytes.slice(dataStart, dataStart + compSize)

      let fileBytes
      if (method === 0) {
        // Stored — no compression
        fileBytes = compressedBytes
      } else if (method === 8) {
        // Deflated — use DecompressionStream (available in Workers runtime)
        const ds     = new DecompressionStream('deflate-raw')
        const writer = ds.writable.getWriter()
        const reader = ds.readable.getReader()

        writer.write(compressedBytes)
        writer.close()

        const chunks = []
        let totalLen = 0
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          chunks.push(value)
          totalLen += value.length
        }
        fileBytes = new Uint8Array(totalLen)
        let pos = 0
        for (const chunk of chunks) { fileBytes.set(chunk, pos); pos += chunk.length }
      } else {
        return null  // unsupported compression method
      }

      return JSON.parse(new TextDecoder().decode(fileBytes))
    }

    offset += 46 + fnLen + extraLen + commentLen
  }
  return null
}
