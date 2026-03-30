import os
import json
import secrets
from flask import Flask, request, jsonify

# ============================================
# MicroAssets License Key Validation Server
# ============================================

app = Flask(__name__)

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_PLACEHOLDER")
LICENSE_DB_FILE = "licenses.json"

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
    return jsonify({"status": "ok", "licenses": len(db)})

@app.route('/')
def index():
    return jsonify({"service": "MicroAssets License Server", "version": "2.0"})

@app.route('/validate')
def validate():
    key = request.args.get('key', '').strip().upper()
    db = load_licenses()
    
    if key in db and db[key].get('status') == 'active':
        return jsonify({"valid": True, "product": db[key]['product']})
    else:
        return jsonify({"valid": False, "error": "Invalid or expired license key"}), 403

@app.route('/webhook', methods=['POST'])
def webhook():
    body = request.get_json(force=True)
    event_type = body.get('type', '')
    db = load_licenses()
    
    if event_type == 'checkout.session.completed':
        obj = body.get('data', {}).get('object', {})
        customer_email = obj.get('customer_details', {}).get('email', 
                         obj.get('customer_email', 'unknown'))
        
        # Get product from metadata, line items, or client_reference_id
        product_name = obj.get('client_reference_id', 
                       obj.get('metadata', {}).get('product', 'unknown'))
        
        key = generate_license_key()
        db[key] = {
            "email": customer_email,
            "product": product_name,
            "status": "active",
            "created": obj.get('created', 0)
        }
        save_licenses(db)
        print(f"✅ New license: {key} for {customer_email} ({product_name})")
        return jsonify({"license_key": key})
        
    elif event_type == 'customer.subscription.deleted':
        obj = body.get('data', {}).get('object', {})
        customer_email = obj.get('customer_email', '')
        revoked = 0
        for k, data in db.items():
            if data.get('email') == customer_email:
                data['status'] = 'revoked'
                revoked += 1
        save_licenses(db)
        return jsonify({"revoked": revoked})
    
    return jsonify({"ignored": True})

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    print(f"🔐 MicroAssets License Server on port {port}")
    app.run(host='0.0.0.0', port=port)
