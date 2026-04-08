# SporlyWorks License Server

A lightweight Python license key validation server for the SporlyWorks Chrome Extension suite.

## Deploy to Railway

1. Push this folder to a GitHub repo
2. Connect the repo to Railway.app
3. Set environment variables:
   - `STRIPE_WEBHOOK_SECRET` = your Stripe webhook signing secret
   - `PORT` = 8080 (Railway sets this automatically)

## Endpoints

- `GET /health` — Health check
- `GET /validate?key=XXXX-XXXX-XXXX-XXXX` — Validate a license key
- `POST /webhook` — Stripe webhook endpoint (configure in Stripe Dashboard)

## How It Works

1. User purchases via Stripe → Stripe fires `checkout.session.completed` webhook
2. Server generates a unique license key and stores it
3. Extension popup validates the key against this API
4. If user cancels subscription → Stripe fires `customer.subscription.deleted`
5. Server revokes the key
