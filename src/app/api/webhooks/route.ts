import { Webhook } from 'svix'
import { headers } from 'next/headers'
import type { WebhookEvent } from '@clerk/nextjs/server'
import { NextResponse } from 'next/server'

export async function POST(req: Request) {
  const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET

  if (!WEBHOOK_SECRET) {
    return NextResponse.json(
      { error: 'CLERK_WEBHOOK_SECRET not configured' },
      { status: 500 }
    )
  }

  // Get headers - need to await the headers() call
  const headerList = await headers()
  const svixHeaders = {
    'svix-id': headerList.get('svix-id'),
    'svix-timestamp': headerList.get('svix-timestamp'),
    'svix-signature': headerList.get('svix-signature')
  }

  // Check headers exist
  if (!svixHeaders['svix-id'] || !svixHeaders['svix-timestamp'] || !svixHeaders['svix-signature']) {
    return NextResponse.json(
      { error: 'Missing required Svix headers' },
      { status: 400 }
    )
  }

  // Get request body
  const payload = await req.json()
  
  // Verify webhook
  const wh = new Webhook(WEBHOOK_SECRET)
  let evt: WebhookEvent

  try {
    evt = wh.verify(JSON.stringify(payload), svixHeaders) as WebhookEvent
  } catch (err) {
    console.error('Error verifying webhook:', err)
    return NextResponse.json(
      { error: 'Invalid webhook signature' },
      { status: 401 }
    )
  }

  // Handle the event
  console.log(`Clerk webhook received: ${evt.type} (ID: ${evt.data.id})`)

  return NextResponse.json(
    { success: true, event: evt.type },
    { status: 200 }
  )
}