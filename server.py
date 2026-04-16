import os
import json
import hmac
import hashlib
import secrets
import time
import tempfile
import shutil
import re
import uuid
import stripe
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, abort, redirect
from functools import wraps

# ============================================
# OmniSuite License Key Validation Server
# v6.0 — Hardened Production Edition
# ============================================
# Changes from v5.0:
#   - Atomic file writes (temp + rename) prevent corruption
#   - Persistent rate limiting (survives restarts)
#   - Auto-backup before every license DB write
#   - Security headers (HSTS, X-XSS-Protection, etc.)
#   - Request ID tracking for audit trail
#   - License key format enforcement
#   - Stale rate-limit entry cleanup
# ============================================

app = Flask(__name__)

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production")

# SECURITY: Require ADMIN_SECRET in production — never auto-generate
if not ADMIN_SECRET:
    if ENVIRONMENT == "production":
        print("⚠️ CRITICAL: ADMIN_SECRET not set in production! /metrics endpoint will be disabled.")
    else:
        ADMIN_SECRET = secrets.token_hex(16)
        print(f"⚠️ DEV MODE: Generated ephemeral ADMIN_SECRET: {ADMIN_SECRET}")

# Use Railway persistent volume if available, else local
LICENSE_DB_FILE = os.environ.get("LICENSE_DB_PATH", "/app/data/licenses.json")
USERS_DB_FILE = os.environ.get("USERS_DB_PATH", "/app/data/users.json")
BACKUP_DIR = os.path.join(os.path.dirname(LICENSE_DB_FILE), "backups")
RATE_LIMIT_FILE = os.path.join(os.path.dirname(LICENSE_DB_FILE), "rate_limits.json")
JWT_SECRET = os.environ.get("OMNISUITE_SECRET", "super-secret-default-jwts")

# Allowed CORS origins
ALLOWED_ORIGINS = [
    "https://sporlyworks.com",
    "https://www.sporlyworks.com",
    "chrome-extension://",  # All Chrome extensions
]

# Rate limiting configuration
RATE_LIMIT_MAX = 30    # max requests per window
RATE_LIMIT_WINDOW = 60 # seconds
MAX_RATE_LIMIT_ENTRIES = 10000  # Prevent memory exhaustion

# License key format: XXXX-XXXX-XXXX-XXXX (hex pairs)
LICENSE_KEY_PATTERN = re.compile(r'^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$')


# ============================================
# Atomic File I/O Utilities
# ============================================

def atomic_write_json(filepath, data, indent=2):
    """
    Atomically write JSON data to a file using temp-file-then-rename.
    This ensures the file is never in a partial/corrupt state, even
    if the process crashes mid-write or the disk fills up.
    """
    dir_path = os.path.dirname(filepath) or '.'
    os.makedirs(dir_path, exist_ok=True)
    
    try:
        # Write to temp file in the same directory (same filesystem for atomic rename)
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix='.tmp', prefix='.atomic_')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=indent)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            
            # Atomic rename (on POSIX systems, rename is atomic)
            os.replace(tmp_path, filepath)
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as e:
        print(f"❌ Atomic write failed for {filepath}: {e}")
        raise


def create_backup(filepath, max_backups=5):
    """Create a timestamped backup of a file, maintaining a rolling window."""
    if not os.path.exists(filepath):
        return
    
    os.makedirs(BACKUP_DIR, exist_ok=True)
    basename = os.path.basename(filepath)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"{basename}.{timestamp}.bak")
    
    try:
        shutil.copy2(filepath, backup_path)
    except Exception as e:
        print(f"⚠️ Backup failed: {e}")
        return
    
    # Prune old backups
    existing = sorted([
        f for f in os.listdir(BACKUP_DIR)
        if f.startswith(f"{basename}.") and f.endswith(".bak")
    ])
    while len(existing) > max_backups:
        old = existing.pop(0)
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except OSError:
            pass


# ============================================
# Persistent Rate Limiting
# ============================================

def _load_rate_limits():
    """Load rate limits from persistent file."""
    if os.path.exists(RATE_LIMIT_FILE):
        try:
            with open(RATE_LIMIT_FILE) as f:
                data = json.load(f)
            # Prune expired entries
            now = time.time()
            data = {ip: entry for ip, entry in data.items() if now <= entry.get("reset_at", 0)}
            return data
        except (json.JSONDecodeError, Exception):
            return {}
    return {}

def _save_rate_limits(data):
    """Save rate limits persistently (best-effort, non-blocking)."""
    try:
        # Limit entries to prevent unbounded growth
        if len(data) > MAX_RATE_LIMIT_ENTRIES:
            # Keep only the newest entries
            sorted_entries = sorted(data.items(), key=lambda x: x[1].get("reset_at", 0), reverse=True)
            data = dict(sorted_entries[:MAX_RATE_LIMIT_ENTRIES // 2])
        atomic_write_json(RATE_LIMIT_FILE, data, indent=None)
    except Exception:
        pass  # Rate limit persistence is best-effort

# In-memory cache with periodic persistence
_rate_limit_cache = None
_rate_limit_dirty = False
_last_persist_time = 0

def check_rate_limit(ip):
    """Returns True if the request should be blocked. Persists across restarts."""
    global _rate_limit_cache, _rate_limit_dirty, _last_persist_time
    
    if _rate_limit_cache is None:
        _rate_limit_cache = _load_rate_limits()
    
    now = time.time()
    entry = _rate_limit_cache.get(ip)
    
    if entry is None or now > entry["reset_at"]:
        _rate_limit_cache[ip] = {"count": 1, "reset_at": now + RATE_LIMIT_WINDOW}
        _rate_limit_dirty = True
    else:
        entry["count"] += 1
        _rate_limit_dirty = True
        if entry["count"] > RATE_LIMIT_MAX:
            # Persist immediately on rate limit trigger (for forensics)
            _save_rate_limits(_rate_limit_cache)
            _rate_limit_dirty = False
            _last_persist_time = now
            return True
    
    # Periodic persistence every 30 seconds
    if _rate_limit_dirty and (now - _last_persist_time) > 30:
        _save_rate_limits(_rate_limit_cache)
        _rate_limit_dirty = False
        _last_persist_time = now
    
    return False


# ============================================
# License Database Operations
# ============================================

def load_licenses():
    """Load license database with corruption recovery."""
    if os.path.exists(LICENSE_DB_FILE):
        try:
            with open(LICENSE_DB_FILE) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("License DB is not a dict")
            return data
        except (json.JSONDecodeError, ValueError) as e:
            print(f"❌ CRITICAL: License DB corrupted: {e}")
            # Attempt auto-recovery from backup
            return _recover_from_backup()
    return {}


def _recover_from_backup():
    """Attempt to restore license DB from most recent backup."""
    if not os.path.isdir(BACKUP_DIR):
        print("❌ No backup directory found. Starting with empty license DB.")
        return {}
    
    basename = os.path.basename(LICENSE_DB_FILE)
    backups = sorted([
        f for f in os.listdir(BACKUP_DIR)
        if f.startswith(f"{basename}.") and f.endswith(".bak")
    ], reverse=True)
    
    for backup_name in backups:
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        try:
            with open(backup_path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                print(f"✅ RECOVERED license DB from backup: {backup_name}")
                # Write recovered data back to primary
                atomic_write_json(LICENSE_DB_FILE, data)
                return data
        except Exception:
            continue
    
    print("❌ All backups corrupted or missing. Starting with empty license DB.")
    return {}


def save_licenses(db):
    """Save license database with automatic backup and atomic write."""
    create_backup(LICENSE_DB_FILE)
    atomic_write_json(LICENSE_DB_FILE, db)


def generate_license_key():
    """Generate a cryptographically random license key."""
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    return '-'.join(parts)


def validate_license_key_format(key):
    """Validate that a license key matches the expected format."""
    return bool(LICENSE_KEY_PATTERN.match(key))


# ============================================
# User Database Operations
# ============================================

def load_users():
    """Load users database."""
    if os.path.exists(USERS_DB_FILE):
        try:
            with open(USERS_DB_FILE) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Users DB is not a dict")
            return data
        except (json.JSONDecodeError, ValueError) as e:
            print(f"❌ CRITICAL: Users DB corrupted: {e}")
            return {}
    return {}

def save_users(db):
    """Save users database with atomic write."""
    create_backup(USERS_DB_FILE)
    atomic_write_json(USERS_DB_FILE, db)

def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        users = load_users()
        user_id = data.get("user_id")
        if user_id in users:
            return users[user_id], user_id
    except jwt.ExpiredSignatureError:
        pass
    except jwt.InvalidTokenError:
        pass
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'OPTIONS':
            return '', 200
        user_tuple = get_current_user()
        if not user_tuple:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function


# ============================================
# Request ID Middleware
# ============================================

@app.before_request
def inject_request_id():
    """Assign a unique request ID for audit trailing."""
    request.request_id = str(uuid.uuid4())[:8]


# ============================================
# Routes
# ============================================

@app.route('/health')
def health():
    db = load_licenses()
    active = sum(1 for v in db.values() if v.get('status') == 'active')
    
    # Check DB file integrity
    db_healthy = os.path.exists(LICENSE_DB_FILE) and os.path.getsize(LICENSE_DB_FILE) > 0
    
    return jsonify({
        "status": "ok" if db_healthy else "degraded",
        "active_licenses": active,
        "version": "6.0",
        "db_healthy": db_healthy,
        "request_id": request.request_id
    })


@app.route('/')
def index():
    return jsonify({"service": "OmniSuite License Server", "version": "6.0"})


@app.route('/metrics')
def metrics():
    """Protected metrics endpoint for monitoring dashboards."""
    if not ADMIN_SECRET:
        abort(503)  # Disabled if no admin secret configured
    
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
        
    users_db = load_users()
    total_users = len(users_db)
    pro_users = sum(1 for u in users_db.values() if u.get('tier') == 'Pro Suite')
    free_users = total_users - pro_users
    
    conversion_rate = round((pro_users / total_users * 100), 2) if total_users > 0 else 0
    estimated_mrr = pro_users * 49
    
    # Backup health
    backup_count = 0
    if os.path.isdir(BACKUP_DIR):
        backup_count = len([f for f in os.listdir(BACKUP_DIR) if f.endswith('.bak')])
    
    return jsonify({
        "total_keys": len(db),
        "active": active,
        "revoked": revoked,
        "products": products,
        "total_users": total_users,
        "pro_users": pro_users,
        "free_users": free_users,
        "conversion_rate": conversion_rate,
        "estimated_mrr": estimated_mrr,
        "backup_count": backup_count,
        "db_path": LICENSE_DB_FILE,
        "db_size_bytes": os.path.getsize(LICENSE_DB_FILE) if os.path.exists(LICENSE_DB_FILE) else 0,
        "environment": ENVIRONMENT,
        "request_id": request.request_id
    })


@app.route('/validate')
def validate():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip):
        return jsonify({"valid": False, "error": "Rate limited. Try again later."}), 429
    
    key = request.args.get('key', '').strip().upper()
    
    # Input validation — strict format check
    if not key or len(key) > 30 or not validate_license_key_format(key):
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
    
    # Input validation: UUIDs are 36 chars max, alphanumeric + hyphens only
    if not uuid_str or len(uuid_str) > 50:
        return jsonify({"ready": False})
    
    # Sanitize: allow only alphanumeric, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9\-_]+$', uuid_str):
        return jsonify({"ready": False}), 400
    
    db = load_licenses()
    for key, data in db.items():
        if data.get('client_ref') == uuid_str and data.get('status') == 'active':
            return jsonify({"ready": True, "key": key, "product": data.get('product')})
            
    return jsonify({"ready": False})


# ============================================
# Auth & Monetization Endpoints
# ============================================

@app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password or len(password) < 6:
        return jsonify({"error": "Invalid email or password (min 6 chars)"}), 400
        
    users = load_users()
    for uid, u in users.items():
        if u.get('email') == email:
            return jsonify({"error": "Email already registered"}), 409
            
    user_id = str(uuid.uuid4())
    users[user_id] = {
        "email": email,
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
        "tier": "Free",
        "created_at": time.time()
    }
    save_users(users)
    
    token = jwt.encode({
        "user_id": user_id,
        "exp": time.time() + 7 * 24 * 3600
    }, JWT_SECRET, algorithm="HS256")
    
    return jsonify({"token": token, "user_id": user_id, "tier": "Free"}), 201


@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    users = load_users()
    for uid, u in users.items():
        if u.get('email') == email:
            if check_password_hash(u.get('password_hash'), password):
                token = jwt.encode({
                    "user_id": uid,
                    "exp": time.time() + 7 * 24 * 3600
                }, JWT_SECRET, algorithm="HS256")
                return jsonify({"token": token, "user_id": uid, "tier": u.get('tier', 'Free')})
            break
            
    return jsonify({"error": "Invalid credentials"}), 401


@app.route('/api/user/me', methods=['GET', 'OPTIONS'])
@login_required
def user_me():
    user, uid = get_current_user()
    return jsonify({
        "email": user.get('email'),
        "tier": user.get('tier', 'Free'),
        "stripe_customer_id": user.get('stripe_customer_id'),
        "created_at": user.get('created_at')
    })


@app.route('/api/checkout/create-session', methods=['POST', 'OPTIONS'])
@login_required
def create_checkout_session():
    user, uid = get_current_user()
    if user.get('tier') == 'Pro Suite':
        # Even if Pro, we may allow billing view/update, but redirecting to Stripe billing portal
        return jsonify({"error": "Already subscribed to Pro Suite"}), 400
        
    data = request.get_json(silent=True) or {}
    plan_type = data.get('plan', 'monthly') # or 'annual'
    
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not stripe.api_key:
        return jsonify({"error": "Stripe is not configured on the server"}), 500
        
    try:
        # We would lookup the price ID based on plan_type and actual setup
        price_id = os.environ.get(f"STRIPE_PRICE_{plan_type.upper()}", "price_mock")
        domain_url = request.headers.get("Origin", "https://sporlyworks.com")
        
        checkout_session = stripe.checkout.Session.create(
            success_url=domain_url + "/dashboard.html?session_id={CHECKOUT_SESSION_ID}&success=true",
            cancel_url=domain_url + "/pricing.html",
            payment_method_types=["card"],
            mode="subscription",
            client_reference_id=uid,
            customer_email=user.get('email'),
            line_items=[{"price": price_id, "quantity": 1}],
            metadata={"product": "Pro Suite"}
        )
        return jsonify({"checkoutUrl": checkout_session.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        print(f"❌ Invalid payload [req:{request.request_id}]")
        abort(400)
    except stripe.error.SignatureVerificationError:
        print(f"❌ REJECTED: Invalid Stripe signature — possible forgery attempt! [req:{request.request_id}]")
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
            "created_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_ref": client_ref,
            "stripe_session_id": obj.get('id', ''),
            "request_id": request.request_id
        }
        save_licenses(db)
        
        # Upgrade User Tier
        if client_ref:
            users = load_users()
            if client_ref in users:
                users[client_ref]['tier'] = 'Pro Suite'
                users[client_ref]['stripe_customer_id'] = obj.get('customer')
                save_users(users)
                print(f"✅ Upgraded user tier to Pro Suite for user {client_ref}")
                
        print(f"✅ New license (Auto-Unlock): {key} for {customer_email} [UUID: {client_ref}] [req:{request.request_id}]")
        return jsonify({"received": True})
        
    elif event_type == 'customer.subscription.deleted':
        obj = event.get('data', {}).get('object', {})
        customer_email = obj.get('customer_email', '')
        revoked = 0
        for k, data in db.items():
            if data.get('email') == customer_email:
                data['status'] = 'revoked'
                data['revoked_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                revoked += 1
        save_licenses(db)
        
        # Downgrade User Tier
        customer_id = obj.get('customer', '')
        if customer_id or customer_email:
            users = load_users()
            for uid, u in users.items():
                if u.get('stripe_customer_id') == customer_id or u.get('email') == customer_email:
                    u['tier'] = 'Free'
            save_users(users)
            
        print(f"🔒 Revoked {revoked} licenses for {customer_email} [req:{request.request_id}]")
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
def add_security_headers(response):
    """Add comprehensive security headers and CORS."""
    origin = request.headers.get('Origin', '')
    
    # CORS: Allow sporlyworks.com and Chrome extensions
    if any(origin.startswith(allowed) for allowed in ALLOWED_ORIGINS) or origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
        response.headers['Access-Control-Allow-Origin'] = origin
    elif not origin:
        # Server-to-server requests (no Origin header) — allow for webhooks
        response.headers['Access-Control-Allow-Origin'] = 'https://sporlyworks.com'
    
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Admin-Key, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    
    if ENVIRONMENT == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Cache control — never cache authenticated endpoints
    if request.path in ('/validate', '/poll', '/webhook', '/metrics') or request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    
    # Request ID for tracing
    response.headers['X-Request-ID'] = getattr(request, 'request_id', 'unknown')
    
    return response


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    # Ensure data directory exists
    os.makedirs(os.path.dirname(LICENSE_DB_FILE) or '.', exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    print(f"🔐 OmniSuite License Server v6.0 (Production Hardened) on port {port}")
    print(f"   DB: {LICENSE_DB_FILE}")
    print(f"   Backups: {BACKUP_DIR}")
    print(f"   Env: {ENVIRONMENT}")
    print(f"   Admin: {'✅ Configured' if ADMIN_SECRET else '❌ DISABLED'}")
    app.run(host='0.0.0.0', port=port)
