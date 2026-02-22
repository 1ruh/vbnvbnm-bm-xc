from flask import Flask, request, jsonify
import json
import os
import secrets
import string
from datetime import datetime, timedelta

app = Flask(__name__)
KEYS_FILE = "keys.json"

# Set your admin password via Render Environment Variables as ADMIN_PASSWORD
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=4)

def generate_key_string():
    alphabet = string.ascii_uppercase + string.digits
    return '-'.join(''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(6))

@app.route('/validate', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('key')
    hwid = data.get('hwid')
    
    keys = load_keys()
    
    if key not in keys:
        return jsonify({"success": False, "message": "Invalid key"})
        
    key_data = keys[key]
    
    if key_data.get('status') == 'banned':
        return jsonify({"success": False, "message": "This key has been banned"})

    if key_data['status'] == 'unused':
        key_data['status'] = 'active'
        key_data['hwid'] = hwid
        key_data['activation_date'] = datetime.now().isoformat()
        save_keys(keys)
        return jsonify({"success": True, "message": f"Key activated! Type: {key_data['type']}"})

    if key_data['status'] == 'active':
        if key_data['hwid'] != hwid:
            return jsonify({"success": False, "message": "HWID mismatch. Contact support."})

        if key_data['type'] != 'lifetime':
            activation_date = datetime.fromisoformat(key_data['activation_date'])
            days_allowed = 7 if key_data['type'] == '7d' else 30
            expiration_date = activation_date + timedelta(days=days_allowed)
            
            if datetime.now() > expiration_date:
                key_data['status'] = 'expired'
                save_keys(keys)
                return jsonify({"success": False, "message": "Key has expired"})

        return jsonify({"success": True, "message": "Login successful"})

    return jsonify({"success": False, "message": "Key is no longer valid"})

# ── ADMIN ENDPOINTS ──────────────────────────────────────────

@app.route('/admin/genkey', methods=['POST'])
def admin_genkey():
    data = request.json or {}
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    key_type = data.get('type', 'lifetime')  # 7d, 30d, lifetime
    if key_type not in ('7d', '30d', 'lifetime'):
        return jsonify({"success": False, "message": "Invalid type. Use 7d, 30d or lifetime"}), 400

    count = int(data.get('count', 1))
    note = data.get('note', '')
    keys = load_keys()
    generated = []

    for _ in range(count):
        new_key = generate_key_string()
        keys[new_key] = {
            "type": key_type,
            "note": note,
            "hwid": None,
            "status": "unused",
            "activation_date": None
        }
        generated.append(new_key)

    save_keys(keys)
    return jsonify({"success": True, "keys": generated})

@app.route('/admin/listkeys', methods=['POST'])
def admin_listkeys():
    data = request.json or {}
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    keys = load_keys()
    return jsonify({"success": True, "keys": keys})

@app.route('/admin/bankey', methods=['POST'])
def admin_bankey():
    data = request.json or {}
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    key = data.get('key')
    keys = load_keys()
    if key not in keys:
        return jsonify({"success": False, "message": "Key not found"}), 404

    keys[key]['status'] = 'banned'
    save_keys(keys)
    return jsonify({"success": True, "message": f"Key {key} has been banned"})

if __name__ == "__main__":
    app.run(port=5000)
