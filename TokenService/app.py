
import base64
from dotenv import load_dotenv
import os
from flask_cors import CORS
import requests
from google.cloud import secretmanager
from flask import json, jsonify, request,Flask
load_dotenv()


app=Flask(__name__)
CORS(app)

app.config["DEBUG"] = os.environ.get("FLASK_DEBUG")


def get_secret():
  
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/1049306790691/secrets/spotify_secrets/versions/latest"
    response = client.access_secret_version(request={"name": name})
    secret_data = response.payload.data.decode("UTF-8")
    return json.loads(secret_data) 

@app.route('/refresh_token', methods=['POST'])
def refresh_token():
    refresh_token = request.json.get('refresh_token')
  
    secrets = get_secret()
    CLIENT_ID = secrets['client_id']
    CLIENT_SECRET = secrets['client_secret']
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID
    }

    auth_credentials = f"{CLIENT_ID}:{CLIENT_SECRET}"
    auth_header = base64.b64encode(auth_credentials.encode()).decode('utf-8')
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {auth_header}'
    }

    response = requests.post('https://accounts.spotify.com/api/token', headers=headers, data=data)
    if response.ok:
        tokens = response.json()
        return jsonify(tokens), 200
    else:
        return jsonify({'error': 'Failed to retrieve tokens', 'details': response.json()}), response.status_code




@app.route('/exchange_code', methods=['POST'])
def exchange_code():
    code = request.json.get('code')
    secrets = get_secret()
    CLIENT_ID = secrets['client_id']
    CLIENT_SECRET = secrets['client_secret']
    redirect_uri = "http://www.music_buddy_app2/callback"
    data = {
        'code' : code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }

    auth_credentials = f"{CLIENT_ID}:{CLIENT_SECRET}"
    auth_header = base64.b64encode(auth_credentials.encode()).decode('utf-8')
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {auth_header}'
    }

    response = requests.post('https://accounts.spotify.com/api/token', headers=headers, data=data)
    if response.ok:
        tokens = response.json()
        return jsonify(tokens), 200
    else:
        return jsonify({'error': 'Failed to retrieve tokens', 'details': response.json()}), response.status_code


if __name__ == '__main__':
    app.run(debug=True)
    


