from flask import Flask, request, jsonify
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)
KEYS_FILE = "keys.json"

def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=4)

@app.route('/validate', methods=['POST'])
def validate_key():
    data = request.json
    key = data.get('key')
    hwid = data.get('hwid')
    
    keys = load_keys()
    
    if key not in keys:
        return jsonify({"success": False, "message": "Invalid key"})
        
    key_data = keys[key]
    
    # Check if key is banned
    if key_data.get('status') == 'banned':
        return jsonify({"success": False, "message": "This key has been banned"})

    # Handle first-time activation
    if key_data['status'] == 'unused':
        key_data['status'] = 'active'
        key_data['hwid'] = hwid
        key_data['activation_date'] = datetime.now().isoformat()
        save_keys(keys)
        return jsonify({"success": True, "message": f"Key activated! Type: {key_data['type']}"})

    # Validate active key
    if key_data['status'] == 'active':
        # HWID Lock Check
        if key_data['hwid'] != hwid:
            return jsonify({"success": False, "message": "HWID mismatch. Contact support."})

        # Expiration Check
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

if __name__ == "__main__":
    app.run(port=5000)
