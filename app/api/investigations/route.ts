import { NextResponse } from 'next/server'
import { z } from 'zod'

const phases = ['passive', 'active', 'discovery', 'vulnerabilities'] as const
const investigationSchema = z.object({ query: z.string().trim().min(2).max(240), profile: z.enum(['quick', 'passive', 'ctf', 'full']).default('quick'), modules: z.array(z.string().trim().min(1).max(80)).min(1).max(30) })

function hostnameFromTarget(target: string) {
  return new URL(target.includes('://') ? target : `https://${target}`).hostname
}

async function getHttpMetadata(hostname: string) {
  const started = Date.now()
  try {
    const response = await fetch(`https://${hostname}`, { redirect: 'manual', signal: AbortSignal.timeout(7000), headers: { 'user-agent': 'DOOMSDAY-Public-Research/1.0' } })
    return { module: 'http-metadata', phase: 'passive', status: 'complete', title: `${response.status} ${response.statusText || 'HTTP response'}`, detail: `HTTPS responded in ${Date.now() - started}ms with ${response.headers.get('content-type') || 'unknown content type'}. Server: ${response.headers.get('server') || 'not disclosed'}.`, metadata: { status: response.status, location: response.headers.get('location'), contentType: response.headers.get('content-type') } }
  } catch (error) { return { module: 'http-metadata', phase: 'passive', status: 'error', title: 'HTTPS request failed', detail: error instanceof Error ? error.message : 'Request failed.' } }
}

async function getDnsMetadata(hostname: string) {
  try {
    const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`, { signal: AbortSignal.timeout(7000) })
    const data = await response.json()
    const answers = Array.isArray(data.Answer) ? data.Answer.map((answer: { data?: string }) => answer.data).filter(Boolean) : []
    return { module: 'dns-a-record', phase: 'discovery', status: 'complete', title: `${answers.length} A record${answers.length === 1 ? '' : 's'}`, detail: answers.length ? answers.join(', ') : 'No A records returned by the resolver.', metadata: { answers } }
  } catch (error) { return { module: 'dns-a-record', phase: 'discovery', status: 'error', title: 'DNS lookup failed', detail: error instanceof Error ? error.message : 'Resolver request failed.' } }
}

async function getCtMetadata(hostname: string) {
  try {
    const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${hostname}`)}&output=json`, { signal: AbortSignal.timeout(9000), headers: { accept: 'application/json' } })
    const body = await response.text()
    let data: unknown = []
    try { data = JSON.parse(body) } catch { return { module: 'certificate-transparency', phase: 'passive', status: 'warning', title: 'CT lookup unavailable', detail: 'The certificate transparency service returned a non-JSON response.' } }
    const names = [...new Set((Array.isArray(data) ? data : []).flatMap((entry: { name_value?: string }) => (entry.name_value || '').split('\\n')).filter(Boolean))].slice(0, 20)
    return { module: 'certificate-transparency', phase: 'passive', status: 'complete', title: `${names.length} certificate names`, detail: names.length ? names.join(', ') : 'No certificate names returned.', metadata: { names } }
  } catch (error) { return { module: 'certificate-transparency', phase: 'passive', status: 'error', title: 'CT lookup unavailable', detail: error instanceof Error ? error.message : 'Certificate transparency request failed.' } }
}

export async function POST(request: Request) {
  const parsed = investigationSchema.safeParse(await request.json().catch(() => null))
  if (!parsed.success) return NextResponse.json({ error: 'Provide a target and at least one module.' }, { status: 400 })
  let hostname: string
  try { hostname = hostnameFromTarget(parsed.data.query) } catch { return NextResponse.json({ error: 'Use a valid domain or URL.' }, { status: 400 }) }
  const requested = new Set(parsed.data.modules)
  const liveFindings = await Promise.all([
    requested.has('http-metadata') ? getHttpMetadata(hostname) : null,
    requested.has('dns-a-record') ? getDnsMetadata(hostname) : null,
    requested.has('certificate-transparency') ? getCtMetadata(hostname) : null,
  ].filter(Boolean))
  const unsupported = parsed.data.modules.filter((module) => !['http-metadata', 'dns-a-record', 'certificate-transparency'].includes(module)).map((module, index) => ({ module, phase: phases[index % phases.length], status: 'warning', title: `${module} requires an authorized worker`, detail: 'This public scanner does not execute active probing or exploitation. Connect an approved worker before running this module.' }))
  const findings = [...liveFindings, ...unsupported]
  const now = new Date().toISOString()
  return NextResponse.json({ id: crypto.randomUUID(), query: parsed.data.query, hostname, profile: parsed.data.profile, status: 'completed', createdAt: now, completedAt: now, findings, summary: `${findings.length} modules processed for ${hostname}.` })
}

export async function GET() { return NextResponse.json({ investigations: [] }) }
