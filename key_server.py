from flask import Flask, request, jsonify
import os
import secrets
import string
import json
from datetime import datetime, timedelta
import redis

app = Flask(__name__)

# Render automatically sets REDIS_URL when you link a Redis instance
REDIS_URL     = os.environ.get("REDIS_URL", "redis://localhost:6379")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin9001")

r = redis.from_url(REDIS_URL, decode_responses=True)

def get_key(key: str):
    data = r.get(f"key:{key}")
    return json.loads(data) if data else None

def set_key(key: str, data: dict):
    r.set(f"key:{key}", json.dumps(data))

def generate_key_string():
    alphabet = string.ascii_uppercase + string.digits
    return '-'.join(''.join(secrets.choice(alphabet) for _ in range(4)) for _ in range(6))

# ── ROUTES ────────────────────────────────────────────────────

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "online"})

@app.route('/validate', methods=['POST'])
def validate_key():
    data = request.json or {}
    key  = data.get('key',  '').strip()
    hwid = data.get('hwid', '').strip()

    if not key or not hwid:
        return jsonify({"success": False, "message": "Invalid request"})

    entry = get_key(key)
    if not entry:
        return jsonify({"success": False, "message": "Invalid key"})

    if entry.get('status') == 'banned':
        return jsonify({"success": False, "message": "This key has been banned"})

    # First-time activation
    if entry['status'] == 'unused':
        entry.update({
            "status": "active",
            "hwid": hwid,
            "activation_date": datetime.utcnow().isoformat()
        })
        set_key(key, entry)
        return jsonify({
            "success": True, 
            "message": f"Key activated! Type: {entry['type']}",
            "spoof_type": entry.get('spoof_type', 'temp')
        })

    # Already active
    if entry['status'] == 'active':
        if entry.get('hwid') != hwid:
            return jsonify({"success": False, "message": "HWID mismatch. Contact support."})

        if entry['type'] != 'lifetime':
            activation_date = datetime.fromisoformat(entry['activation_date'])
            days_allowed = 7 if entry['type'] == '7d' else 30
            if datetime.utcnow() > activation_date + timedelta(days=days_allowed):
                entry['status'] = 'expired'
                set_key(key, entry)
                return jsonify({"success": False, "message": "Key has expired"})

        return jsonify({
            "success": True, 
            "message": "Login successful",
            "spoof_type": entry.get('spoof_type', 'temp')
        })

    return jsonify({"success": False, "message": "Key is no longer valid"})

# ── ADMIN ENDPOINTS ───────────────────────────────────────────

@app.route('/admin/genkey', methods=['POST'])
def admin_genkey():
    data = request.json or {}
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    key_type = data.get('type', 'lifetime')
    if key_type not in ('7d', '30d', 'lifetime'):
        return jsonify({"success": False, "message": "Invalid type. Use 7d, 30d or lifetime"}), 400

    spoof_type = data.get('spoof_type', 'temp')
    if spoof_type not in ('temp', 'perm', 'both'):
        return jsonify({"success": False, "message": "Invalid spoof_type. Use temp, perm, or both"}), 400

    count     = int(data.get('count', 1))
    note      = data.get('note', '')
    generated = []

    for _ in range(count):
        new_key = generate_key_string()
        set_key(new_key, {
            "type": key_type,
            "spoof_type": spoof_type,
            "note": note,
            "hwid": None,
            "status": "unused",
            "activation_date": None,
            "created_at": datetime.utcnow().isoformat()
        })
        generated.append(new_key)

    return jsonify({"success": True, "keys": generated})

@app.route('/admin/listkeys', methods=['POST'])
def admin_listkeys():
    data = request.json or {}
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    all_keys = r.keys("key:*")
    result = {}
    for k in all_keys:
        clean = k.replace("key:", "", 1)
        result[clean] = json.loads(r.get(k))
    return jsonify({"success": True, "keys": result})

@app.route('/admin/bankey', methods=['POST'])
def admin_bankey():
    data = request.json or {}
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    key = data.get('key', '').strip()
    entry = get_key(key)
    if not entry:
        return jsonify({"success": False, "message": "Key not found"}), 404

    entry['status'] = 'banned'
    set_key(key, entry)
    return jsonify({"success": True, "message": f"Key {key} has been banned"})

@app.route('/admin/resetkey', methods=['POST'])
def admin_resetkey():
    data = request.json or {}
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    key = data.get('key', '').strip()
    entry = get_key(key)
    if not entry:
        return jsonify({"success": False, "message": "Key not found"}), 404

    entry.update({"status": "unused", "hwid": None, "activation_date": None})
    set_key(key, entry)
    return jsonify({"success": True, "message": f"Key {key} HWID reset"})

if __name__ == "__main__":
    app.run(port=5000)
