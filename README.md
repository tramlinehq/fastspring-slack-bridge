# Fastspring Slack Bridge

A lightweight Go service that receives Fastspring webhook events and sends notifications to Slack. Also provides a weekly payment digest. Designed for deployment on Google Cloud Run.

## Features

- **Real-time webhooks**: Receive Fastspring events and post to Slack instantly
- **Weekly digest**: Summarize payments per customer with subscription history and open quotes

## Supported Webhook Events

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

## Weekly Digest

The `/digest` endpoint generates a weekly payment summary including:

- All subscriptions grouped by customer
- Last 5 payment cycles per subscription (with invoice links)
- Deduplication of pending/completed entries for the same date
- Open and awaiting-payment quotes

The digest posts to Slack as a threaded message: header with quotes as the parent, each customer as a reply.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SLACK_WEBHOOK_URL` | Yes | Slack incoming webhook URL (for real-time webhooks) |
| `SLACK_BOT_TOKEN` | For digest | Slack Bot token for threaded digest messages |
| `SLACK_CHANNEL_ID` | For digest | Slack channel ID for digest (e.g., `C01234ABCDE`) |
| `FASTSPRING_HMAC_SECRET` | No | HMAC secret for webhook signature verification |
| `FASTSPRING_API_USERNAME` | For digest | Fastspring API username |
| `FASTSPRING_API_PASSWORD` | For digest | Fastspring API password |
| `PORT` | No | Server port (default: 8080) |

## Setup

### 1. Slack Incoming Webhook (for real-time events)

1. Go to https://api.slack.com/apps
2. Create a new app or use existing
3. Enable **Incoming Webhooks**
4. Add a new webhook to your workspace
5. Choose the channel for notifications
6. Copy the webhook URL

### 2. Slack Bot Token (for digest threading)

1. Go to https://api.slack.com/apps and select your app
2. Go to **OAuth & Permissions**
3. Under **Scopes → Bot Token Scopes**, add:
   - `chat:write` - Post messages
4. Install/reinstall the app to your workspace
5. Copy the **Bot User OAuth Token** (starts with `xoxb-`)
6. Invite the bot to your channel: `/invite @YourBotName`

### 3. Get Slack Channel ID

1. Open Slack in a browser
2. Navigate to the channel
3. The URL will be: `https://app.slack.com/client/TXXXXX/C01234ABCDE`
4. The channel ID is the last part (e.g., `C01234ABCDE`)

### 4. Fastspring API Credentials

1. Go to **Developer Tools → APIs** in Fastspring dashboard
2. Create new API credentials
3. Note the username and password

### 5. Configure Fastspring Webhooks

1. Go to **Developer Tools → Webhooks → Configuration** in Fastspring dashboard
2. Click **Add Webhook**
3. Enter your Cloud Run URL: `https://fastspring-slack-bridge-xxxxx.run.app/webhooks/fastspring`
4. Set HMAC SHA256 secret (same as `FASTSPRING_HMAC_SECRET`)
5. Select events (all supported events listed above)
6. Save

## Local Development

```bash
# Run locally
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export FASTSPRING_HMAC_SECRET="your-secret"
export FASTSPRING_API_USERNAME="your-api-username"
export FASTSPRING_API_PASSWORD="your-api-password"
export SLACK_BOT_TOKEN="xoxb-your-bot-token"
export SLACK_CHANNEL_ID="C01234ABCDE"
go run main.go

# Test webhook endpoint
curl -X POST http://localhost:8080/webhooks/fastspring \
  -H "Content-Type: application/json" \
  -d '{"events":[{"id":"test","type":"order.completed","live":false,"data":{"reference":"TEST-123","totalDisplay":"$99.00","customer":{"first":"John","last":"Doe","email":"john@example.com","company":"Acme"},"items":[]}}]}'

# Test digest endpoint
curl http://localhost:8080/digest
```

## Deploy to Cloud Run

```bash
gcloud run deploy fastspring-slack-bridge \
  --source . \
  --region europe-west3 \
  --allow-unauthenticated \
  --set-env-vars "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/..."
```

For production with secrets, use Google Secret Manager:

```bash
# Create secrets
echo -n "your-webhook-url" | gcloud secrets create fastspring-slack-webhook --data-file=-
echo -n "your-hmac-secret" | gcloud secrets create fastspring-hmac-secret --data-file=-
echo -n "your-api-username" | gcloud secrets create fastspring-api-username --data-file=-
echo -n "your-api-password" | gcloud secrets create fastspring-api-password --data-file=-
echo -n "xoxb-your-bot-token" | gcloud secrets create slack-bot-token --data-file=-
echo -n "C01234ABCDE" | gcloud secrets create slack-channel-id --data-file=-

# Deploy with secrets
gcloud run deploy fastspring-slack-bridge \
  --source . \
  --region europe-west3 \
  --allow-unauthenticated \
  --set-secrets "SLACK_WEBHOOK_URL=fastspring-slack-webhook:latest,FASTSPRING_HMAC_SECRET=fastspring-hmac-secret:latest,FASTSPRING_API_USERNAME=fastspring-api-username:latest,FASTSPRING_API_PASSWORD=fastspring-api-password:latest,SLACK_BOT_TOKEN=slack-bot-token:latest,SLACK_CHANNEL_ID=slack-channel-id:latest"
```

## Schedule Weekly Digest

Use Cloud Scheduler to trigger the digest weekly:

```bash
gcloud scheduler jobs create http fastspring-weekly-digest \
  --location=europe-west3 \
  --schedule="0 14 * * 4" \
  --time-zone="Europe/Berlin" \
  --uri="https://your-service-url.run.app/digest" \
  --http-method=GET
```

This runs every Thursday at 14:00 Berlin time.

To trigger manually:

```bash
gcloud scheduler jobs run fastspring-weekly-digest --location=europe-west3
```
