import os
import json
import hmac
import hashlib
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer

# ============================================
# MicroAssets License Key Validation Server
# Deploy on Railway.app (Hobby Mode, $5/mo)
# ============================================

# In production, use env vars:
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

class LicenseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Validate a license key: GET /validate?key=XXXX-XXXX-XXXX-XXXX"""
        if self.path.startswith('/validate'):
            params = dict(p.split('=') for p in self.path.split('?')[1].split('&'))
            key = params.get('key', '')
            db = load_licenses()
            
            if key in db and db[key]['status'] == 'active':
                self._respond(200, {"valid": True, "product": db[key]['product']})
            else:
                self._respond(403, {"valid": False, "error": "Invalid or expired license key"})
        elif self.path == '/health':
            self._respond(200, {"status": "ok", "licenses": len(load_licenses())})
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self):
        """Handle Stripe webhook: POST /webhook"""
        if self.path == '/webhook':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            
            # In production, verify Stripe signature
            # sig = self.headers.get('Stripe-Signature', '')
            
            try:
                event = json.loads(body)
                event_type = event.get('type', '')
                
                db = load_licenses()
                
                if event_type == 'checkout.session.completed':
                    customer_email = event['data']['object'].get('customer_email', 'unknown')
                    product_name = event['data']['object'].get('metadata', {}).get('product', 'unknown')
                    
                    key = generate_license_key()
                    db[key] = {
                        "email": customer_email,
                        "product": product_name,
                        "status": "active",
                        "created": event['data']['object'].get('created', 0)
                    }
                    save_licenses(db)
                    print(f"✅ New license generated: {key} for {customer_email}")
                    self._respond(200, {"license_key": key})
                    
                elif event_type == 'customer.subscription.deleted':
                    customer_email = event['data']['object'].get('customer_email', '')
                    # Revoke all keys for this customer
                    revoked = 0
                    for key, data in db.items():
                        if data.get('email') == customer_email:
                            data['status'] = 'revoked'
                            revoked += 1
                    save_licenses(db)
                    print(f"🔒 Revoked {revoked} licenses for {customer_email}")
                    self._respond(200, {"revoked": revoked})
                    
                else:
                    self._respond(200, {"ignored": True})
                    
            except Exception as e:
                self._respond(400, {"error": str(e)})
        else:
            self._respond(404, {"error": "Not found"})

    def _respond(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    server = HTTPServer(('0.0.0.0', port), LicenseHandler)
    print(f"🔐 MicroAssets License Server running on port {port}")
    print(f"   Health: http://localhost:{port}/health")
    print(f"   Validate: http://localhost:{port}/validate?key=XXXX-XXXX-XXXX-XXXX")
    print(f"   Webhook: POST http://localhost:{port}/webhook")
    server.serve_forever()
