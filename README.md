# Inbox Sentry

Inbox Sentry is a small email threat triage project. It looks for phishing signals in a message, explains the evidence behind its risk score, and can label high-risk mail in Gmail.

The analyzer can also run on pasted text, so you can try the core project without connecting a mailbox or sharing email credentials.

## Try it locally

Requires Python 3.11 or newer.

```bash
git clone https://github.com/XiaYue1013/inbox-sentry.git
cd inbox-sentry
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

For a quick, offline-friendly walkthrough, turn off optional model and threat-intelligence lookups in `.env`:

```env
ENABLE_EXTERNAL_THREAT_LOOKUPS=false
ENABLE_SETFIT_CLASSIFIER=false
ENABLE_LLM_INTENT_CLASSIFIER=false
```

Analyze a sample without contacting Gmail:

```bash
./run.sh analyze-text "Your account will be suspended today. Verify your password at http://example.test/login"
```

The command prints a JSON report with the risk level, score, explanation, indicators, and recommended next steps. Analysis is local in this mode; no Gmail account or API keys are required.

## What it does

- Checks message text and URLs for phishing patterns, impersonation, suspicious reply-to addresses, failed sender authentication, and risky attachments.
- Combines explainable rules with optional multilingual SetFit classification and external threat-intelligence lookups.
- Returns evidence and recommendations alongside a risk score, so a reviewer can see why a message was flagged.
- Can monitor Gmail and apply a label to high-risk messages. Gmail integration is opt-in and requires OAuth setup.
- Includes a FastAPI dashboard, feedback review flow, MongoDB-backed history, and optional Discord notifications.

## Connect Gmail (optional)

Create a Google Cloud OAuth desktop client with the Gmail API enabled, save its client file as `credentials.json`, then run:

```bash
./run.sh auth
./run.sh dry-run
```

`dry-run` analyzes messages without changing Gmail labels. After reviewing the results and configuring the desired monitoring mode, `./run.sh scan` applies the high-risk label. Push monitoring additionally needs a Google Cloud Pub/Sub topic and a reachable webhook.

## Configuration

Copy `.env.example` to `.env`. The local text analyzer works without credentials. Optional integrations are disabled or skipped when their credentials are absent. SetFit model files are generated locally and are not included in this repository.

Useful commands:

| Command | Purpose |
| --- | --- |
| `./run.sh analyze-text "..."` | Analyze text without Gmail |
| `./run.sh dry-run` | Preview Gmail scan results without applying labels |
| `./run.sh scan` | Scan Gmail and label high-risk messages |
| `./run.sh api` | Start the local API and dashboard at `http://127.0.0.1:8008` |
| `./run.sh test` | Run the project test suite |

## Project map

```text
app/analysis/    Risk scoring, URL checks, threat intelligence, classifiers
app/gmail/       Gmail authorization, message parsing, scanning, and labels
app/main.py      FastAPI endpoints and dashboard integration
gmail_addon/     Optional Google Apps Script sidebar template
tests/           Unit and integration tests
```

This is a learning and portfolio project, not a guaranteed phishing detector. Treat its results as triage signals and review suspicious messages before taking action.
