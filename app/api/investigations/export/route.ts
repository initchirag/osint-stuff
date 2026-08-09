import { NextResponse } from 'next/server'
import { z } from 'zod'

const exportSchema = z.object({ query: z.string().max(240).optional(), evidence: z.array(z.record(z.string(), z.unknown())).max(500).default([]) })

export async function POST(request: Request) {
  const parsed = exportSchema.safeParse(await request.json().catch(() => null))
  if (!parsed.success) return NextResponse.json({ error: 'Invalid export payload.' }, { status: 400 })
  const payload = { format: 'json', generatedAt: new Date().toISOString(), query: parsed.data.query ?? '', evidence: parsed.data.evidence }
  return new NextResponse(JSON.stringify(payload, null, 2), { headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="doomsday-investigation.json"', 'Cache-Control': 'no-store' } })
}
