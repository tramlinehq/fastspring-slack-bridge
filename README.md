# Fastspring Slack Bridge

A lightweight Go service that receives Fastspring webhook events and sends notifications to Slack. Designed for deployment on Google Cloud Run.

## Supported Events

### Orders
| Event | Description |
|-------|-------------|
| `order.completed` | Order/payment completed |
| `order.canceled` | Order canceled |
| `order.failed` | Order failed |
| `order.payment.pending` | Payment processed but not yet received |
| `order.approval.pending` | Invoice order awaiting approval |

### Subscriptions
| Event | Description |
|-------|-------------|
| `subscription.activated` | New subscription created |
| `subscription.deactivated` | Subscription deactivated |
| `subscription.canceled` | Subscription canceled |
| `subscription.uncanceled` | Subscription reactivated |
| `subscription.updated` | Subscription modified |
| `subscription.paused` | Subscription paused |
| `subscription.resumed` | Subscription resumed |
| `subscription.charge.completed` | Recurring payment received |
| `subscription.charge.failed` | Recurring payment failed |
| `subscription.trial.reminder` | Trial ending soon |
| `subscription.payment.reminder` | Upcoming payment reminder |
| `subscription.payment.overdue` | Payment overdue |

### Other
| Event | Description |
|-------|-------------|
| `return.created` | Refund processed |
| `invoice.reminder.email` | Invoice reminder sent |
| `quote.created` | Quote created |
| `quote.updated` | Quote updated |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SLACK_WEBHOOK_URL` | Yes | Slack incoming webhook URL |
| `FASTSPRING_HMAC_SECRET` | No | HMAC secret for signature verification |
| `PORT` | No | Server port (default: 8080) |

## Local Development

```bash
# Run locally
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export FASTSPRING_HMAC_SECRET="your-secret"
go run main.go

# Test the endpoint
curl -X POST http://localhost:8080/webhooks/fastspring \
  -H "Content-Type: application/json" \
  -d '{"events":[{"id":"test","type":"order.completed","live":false,"data":{"reference":"TEST-123","totalDisplay":"$99.00","customer":{"first":"John","last":"Doe","email":"john@example.com","company":"Acme"},"items":[]}}]}'
```

## Deploy to Cloud Run

```bash
gcloud run deploy fastspring-slack-bridge \
  --source . \
  --region europe-west3 \
  --allow-unauthenticated \
  --set-env-vars "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...,FASTSPRING_HMAC_SECRET=your-secret"
```

## Configure Fastspring

1. Go to **Developer Tools → Webhooks → Configuration** in Fastspring dashboard
2. Click **Add Webhook**
3. Enter your Cloud Run URL: `https://fastspring-slack-bridge-xxxxx.run.app/webhooks/fastspring`
4. Set HMAC SHA256 secret (same as `FASTSPRING_HMAC_SECRET`)
5. Select events (all supported events listed above)
6. Save

## Create Slack Webhook

1. Go to https://api.slack.com/apps
2. Create a new app or use existing
3. Enable **Incoming Webhooks**
4. Add a new webhook to your workspace
5. Choose the channel for notifications
6. Copy the webhook URL
