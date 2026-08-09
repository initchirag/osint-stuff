import { NextResponse } from 'next/server'

export async function GET() {
  return NextResponse.json({
    providers: [
      { id: 'web-search', name: 'Web search', status: 'ready', access: 'public' },
      { id: 'domain-intelligence', name: 'Domain intelligence', status: 'ready', access: 'public' },
      { id: 'breach-monitor', name: 'Breach monitor', status: 'restricted', access: 'authorized' },
      { id: 'social-signals', name: 'Social signals', status: 'degraded', access: 'public' },
    ],
  })
}
