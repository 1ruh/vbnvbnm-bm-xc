from flask import Flask, request, jsonify
import json
import os

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
    
    if key in keys:
        key_data = keys[key]
        if key_data['status'] == 'unused':
            key_data['status'] = 'active'
            key_data['hwid'] = hwid
            save_keys(keys)
            return jsonify({"success": True, "message": "Key activated successfully"})
        elif key_data['status'] == 'active':
            if key_data['hwid'] == hwid:
                return jsonify({"success": True, "message": "Login successful"})
            else:
                return jsonify({"success": False, "message": "HWID mismatch"})
        else:
            return jsonify({"success": False, "message": "Key is banned or expired"})
    
    return jsonify({"success": False, "message": "Invalid key"})

if __name__ == "__main__":
    app.run(port=5000)
