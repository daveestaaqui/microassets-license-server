import os
import json
import hmac
import hashlib
import secrets
import time
import stripe
from flask import Flask, request, jsonify, abort, redirect
from functools import wraps

# ============================================
# OmniSuite License Key Validation Server
# v5.0 — Production Hardened Edition
# ============================================

app = Flask(__name__)

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", secrets.token_hex(16))
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production")

# Use Railway persistent volume if available, else local
LICENSE_DB_FILE = os.environ.get("LICENSE_DB_PATH", "/app/data/licenses.json")

# Allowed CORS origins
ALLOWED_ORIGINS = [
    "https://sporlyworks.com",
    "https://www.sporlyworks.com",
    "chrome-extension://",  # All Chrome extensions
]

# Rate limiting: track IPs for brute-force protection
rate_limit_store = {}  # ip -> { "count": int, "reset_at": float }
RATE_LIMIT_MAX = 30    # max requests per window
RATE_LIMIT_WINDOW = 60 # seconds

def check_rate_limit(ip):
    """Returns True if the request should be blocked."""
    now = time.time()
    entry = rate_limit_store.get(ip)
    if entry is None or now > entry["reset_at"]:
        rate_limit_store[ip] = {"count": 1, "reset_at": now + RATE_LIMIT_WINDOW}
        return False
    entry["count"] += 1
    return entry["count"] > RATE_LIMIT_MAX

def load_licenses():
    if os.path.exists(LICENSE_DB_FILE):
        with open(LICENSE_DB_FILE) as f:
            return json.load(f)
    return {}

def save_licenses(db):
    with open(LICENSE_DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def generate_license_key():
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return '-'.join(parts)

@app.route('/health')
def health():
    db = load_licenses()
    active = sum(1 for v in db.values() if v.get('status') == 'active')
    return jsonify({"status": "ok", "active_licenses": active, "version": "5.0"})

@app.route('/')
def index():
    return jsonify({"service": "OmniSuite License Server", "version": "5.0"})

@app.route('/metrics')
def metrics():
    """Protected metrics endpoint for monitoring dashboards."""
    auth = request.headers.get('X-Admin-Key', '')
    if not hmac.compare_digest(auth, ADMIN_SECRET):
        abort(403)
    
    db = load_licenses()
    active = sum(1 for v in db.values() if v.get('status') == 'active')
    revoked = sum(1 for v in db.values() if v.get('status') == 'revoked')
    products = {}
    for v in db.values():
        p = v.get('product', 'unknown')
        products[p] = products.get(p, 0) + 1
    
    return jsonify({
        "total_keys": len(db),
        "active": active,
        "revoked": revoked,
        "products": products,
        "rate_limit_entries": len(rate_limit_store),
        "db_path": LICENSE_DB_FILE,
        "environment": ENVIRONMENT
    })

@app.route('/validate')
def validate():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip):
        return jsonify({"valid": False, "error": "Rate limited. Try again later."}), 429
    
    key = request.args.get('key', '').strip().upper()
    
    # Input validation 
    if not key or len(key) > 30:
        return jsonify({"valid": False, "error": "Invalid key format"}), 400
    
    db = load_licenses()
    
    if key in db and db[key].get('status') == 'active':
        return jsonify({"valid": True, "product": db[key]['product']})
    else:
        return jsonify({"valid": False, "error": "Invalid or expired license key"}), 403

@app.route('/poll')
def poll():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip):
        return jsonify({"ready": False}), 429
    
    uuid_str = request.args.get('uuid', '').strip()
    
    # Input validation: UUIDs are 36 chars max
    if not uuid_str or len(uuid_str) > 50:
        return jsonify({"ready": False})
         
    db = load_licenses()
    for key, data in db.items():
        if data.get('client_ref') == uuid_str and data.get('status') == 'active':
            return jsonify({"ready": True, "key": key, "product": data.get('product')})
            
    return jsonify({"ready": False})

@app.route('/webhook', methods=['POST'])
def webhook():
    # ================================================
    # CRITICAL: Verify Stripe Webhook Signature
    # Without this, anyone can forge fake checkout
    # events and generate unlimited free license keys.
    # ================================================
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature', '')
    
    if not STRIPE_WEBHOOK_SECRET:
        print("⚠️ WARNING: STRIPE_WEBHOOK_SECRET not set! Rejecting all webhooks.")
        abort(500)
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        print("❌ Invalid payload")
        abort(400)
    except stripe.error.SignatureVerificationError:
        print("❌ REJECTED: Invalid Stripe signature — possible forgery attempt!")
        abort(403)
    
    event_type = event.get('type', '')
    db = load_licenses()
    
    if event_type == 'checkout.session.completed':
        obj = event.get('data', {}).get('object', {})
        customer_email = obj.get('customer_details', {}).get('email', 
                         obj.get('customer_email', 'unknown'))
        
        # client_reference_id carries the auto-unlock UUID
        client_ref = obj.get('client_reference_id')
        product_name = obj.get('metadata', {}).get('product', 'microassets-master-suite')
        
        key = generate_license_key()
        db[key] = {
            "email": customer_email,
            "product": product_name,
            "status": "active",
            "created": obj.get('created', 0),
            "client_ref": client_ref
        }
        save_licenses(db)
        print(f"✅ New license (Auto-Unlock): {key} for {customer_email} [UUID: {client_ref}]")
        return jsonify({"received": True})
        
    elif event_type == 'customer.subscription.deleted':
        obj = event.get('data', {}).get('object', {})
        customer_email = obj.get('customer_email', '')
        revoked = 0
        for k, data in db.items():
            if data.get('email') == customer_email:
                data['status'] = 'revoked'
                revoked += 1
        save_licenses(db)
        return jsonify({"revoked": revoked})
    
    return jsonify({"ignored": True})

@app.before_request
def enforce_https():
    """Redirect HTTP → HTTPS in production (Railway sets X-Forwarded-Proto)."""
    if ENVIRONMENT == 'production':
        proto = request.headers.get('X-Forwarded-Proto', 'https')
        if proto == 'http':
            return redirect(request.url.replace('http://', 'https://', 1), code=301)

@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin', '')
    # Allow sporlyworks.com and Chrome extensions
    if any(origin.startswith(allowed) for allowed in ALLOWED_ORIGINS):
        response.headers['Access-Control-Allow-Origin'] = origin
    elif not origin:
        # Server-to-server requests (no Origin header) — allow for webhooks
        response.headers['Access-Control-Allow-Origin'] = 'https://sporlyworks.com'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Admin-Key'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    # Ensure data directory exists
    os.makedirs(os.path.dirname(LICENSE_DB_FILE) or '.', exist_ok=True)
    print(f"🔐 OmniSuite License Server v5.0 (Production) on port {port}")
    print(f"   DB: {LICENSE_DB_FILE}")
    print(f"   Env: {ENVIRONMENT}")
    app.run(host='0.0.0.0', port=port)
