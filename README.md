# Fastspring Webhooks

A lightweight Go service that receives Fastspring webhook events and sends notifications to Slack. Designed for deployment on Google Cloud Run.

## Supported Events

| Event | Description |
|-------|-------------|
| `order.completed` | New order/payment completed |
| `subscription.charge.completed` | Recurring subscription payment |
| `subscription.activated` | New subscription created |
| `order.payment.pending` | Payment processed but not yet received |

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

### Option 1: Using gcloud directly

```bash
# Build and deploy
gcloud run deploy fastspring-webhooks \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...,FASTSPRING_HMAC_SECRET=your-secret"
```

### Option 2: Using Cloud Build

```bash
gcloud builds submit \
  --config cloudbuild.yaml \
  --substitutions _SLACK_WEBHOOK_URL="https://hooks.slack.com/services/...",_FASTSPRING_HMAC_SECRET="your-secret",_REGION="us-central1"
```

## Configure Fastspring

1. Go to **Developer Tools → Webhooks → Configuration** in Fastspring dashboard
2. Click **Add Webhook**
3. Enter your Cloud Run URL: `https://fastspring-webhooks-xxxxx.run.app/webhooks/fastspring`
4. Set HMAC SHA256 secret (same as `FASTSPRING_HMAC_SECRET`)
5. Select events:
   - `order.completed`
   - `subscription.charge.completed`
   - `subscription.activated`
   - `order.payment.pending`
6. Save

## Create Slack Webhook

1. Go to https://api.slack.com/apps
2. Create a new app or use existing
3. Enable **Incoming Webhooks**
4. Add a new webhook to your workspace
5. Choose the channel for notifications
6. Copy the webhook URL
