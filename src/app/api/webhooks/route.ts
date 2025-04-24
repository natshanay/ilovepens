import { verifyWebhook } from '@clerk/nextjs/webhooks'

export async function POST(req ) {
  try {
    const evt = await verifyWebhook(req)

    // Do something with payload
    // For this guide, log payload to console
    const { id } = evt.data
    const eventType = evt.type
    
    
    if (evt.type === 'user.created') {
        console.log('userId:', evt.data.id)
      }
    if (evt.type === 'user.updated') {
        console.log('userId:', evt.data.id)
      }
    if (evt.type === 'user.deleted') {
        console.log('userId:', evt.data.id)
      }

    return new Response('Webhook received', { status: 200 })
  } catch (err) {
    console.error('Error verifying webhook:', err)
    return new Response('Error verifying webhook', { status: 400 })
  }
}