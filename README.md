# FINALX Gmail Auto

An event-driven Gmail security assistant that analyzes newly received messages, assigns an explainable risk score, and applies Gmail labels to suspicious or high-risk email.

## Features

- Gmail Push Notifications through Google Cloud Pub/Sub.
- Gmail History API processing for newly added inbox messages.
- Parsing of sender headers, Reply-To, SPF, DKIM, DMARC, links, and attachments.
- Multilingual SetFit classification: `legitimate`, `suspicious`, or `threat`.
- Explainable scoring from ML, URL structure, attachments, sender authentication, reputation, rules, and optional threat-intelligence APIs.
- Gmail labels for high-risk, medium-risk, and primary reason.
- MongoDB state, scan events, sender reputation, feedback, threat cache, and retry queue.
- FastAPI endpoints and a built-in dashboard.
- Human feedback review and approved training-data workflow.
- Optional Discord notifications and Gmail Add-on example.

## Architecture

```text
Gmail inbox
    │
    ▼
Gmail Watch ──► Cloud Pub/Sub ──► POST /api/gmail/push
                                      │
                                      ▼
                                Gmail History API
                                      │
                                      ▼
                              Message parser and analyzer
                              ├─ SetFit classifier
                              ├─ sender authentication
                              ├─ URL and attachment checks
                              ├─ optional threat intelligence
                              └─ rules fallback
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                    Gmail labels               MongoDB
                                            dashboard/events
```

## Requirements

- Python 3.11+
- MongoDB
- Google Cloud project with Gmail API and Pub/Sub enabled
- Gmail OAuth desktop client

The SetFit model and runtime data are intentionally not committed.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set at least:

```env
MONGODB_URI=mongodb://127.0.0.1:27017/
MONGODB_DATABASE=finalx_gmail_auto
```

For Gmail Push, also set:

```env
GMAIL_WATCH_TOPIC_NAME=projects/YOUR_PROJECT/topics/YOUR_TOPIC
```

Download the OAuth desktop-client JSON from Google Cloud Console, place it in the repository root as `credentials.json`, and authorize:

```bash
./run.sh auth
./run.sh watch
```

## Model

Train the local multilingual SetFit model:

```bash
./run.sh train-setfit
```

The generated model is stored under `data/models/` and excluded from Git.

## Run

```bash
./run.sh api
```

Open:

```text
http://127.0.0.1:8008/dashboard
```

For a public deployment, expose the API through HTTPS and configure the Pub/Sub push subscription to:

```text
https://YOUR_PUBLIC_DOMAIN/api/gmail/push
```

## Test

```bash
./run.sh test
./run.sh evaluate
./run.sh evaluate-setfit
```

The repository includes unit tests, regression email templates, and a held-out challenge fixture. Test results should not be interpreted as a production-world accuracy guarantee.

## Demo

Preview the test messages without writing to Gmail:

```bash
./record_demo.sh --fast --dry-run
```

Run the guided Gmail demo:

```bash
FINALX_PUBLIC_URL=https://YOUR_PUBLIC_DOMAIN ./record_demo.sh
```

## Optional integrations

External threat-intelligence keys, Gemini, Discord, and the Gmail Add-on are optional. Leave their environment variables empty to disable those integrations.

## Security notes

- Never commit `.env`, OAuth credentials, `token.json`, API keys, MongoDB data, logs, or trained models.
- Protect public management APIs with `API_TOKEN`.
- For production, validate Pub/Sub OIDC tokens instead of relying only on a query-string push token.
- Use a durable queue/worker before acknowledging Pub/Sub messages in production.
- Review the privacy impact before sending email URLs or text to third-party services.

