from flask import Flask, request, jsonify, redirect, url_for
from flask_cors import CORS
import requests
import csv
from io import StringIO

import google.oauth2.credentials
import google_auth_oauthlib.flow

app = Flask(__name__)
CORS(app)

def fetch_csv_and_convert_to_list(url):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        csv_file = StringIO()
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                csv_file.write(chunk.decode('utf-8'))

        csv_file.seek(0)
        csv_reader = csv.reader(csv_file)
        rows = [row for row in csv_reader]
        csv_file.close()
        return rows
    
    except requests.exceptions.RequestException as e:
        splitat = 4
        left, right = str(e)[:splitat], str(e)[splitat:]
        return {"status":"error", "code": int(left), "message": right}

      

@app.route('/fetch_csv', methods=['POST'])
def fetch_csv():
    data = request.get_json()
    if 'csv_url' in data:
        csv_url = data['csv_url']
        result_rows = fetch_csv_and_convert_to_list(csv_url)
        if "status" in result_rows and result_rows["status"] == "error":
          return jsonify(result_rows), result_rows["code"]
        return jsonify(result_rows)

    return jsonify({'error': 'Missing csv_url parameter'}), 400

  
  
@app.route('/fetch_airtable', methods=['POST'])
def fetch_airtable():
    data = request.get_json()

    payload=f'code={data["code"]}&client_id={data["client_id"]}&redirect_uri={data["redirect_uri"]}&grant_type=authorization_code&code_verifier={data["code_verifier"]}'
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = requests.request("POST", "https://airtable.com/oauth2/v1/token", headers=headers, data=payload)
    return response.text

@app.route('/fetch_airtable_refresh_token', methods=['POST'])
def fetch_airtable_refresh_token():
    data = request.get_json()
    
    payload=f'grant_type={data["grant_type"]}&refresh_token={data["refresh_token"]}&client_id={data["client_id"]}'
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    }

    response = requests.request("POST", "https://airtable.com/oauth2/v1/token", headers=headers, data=payload)
    return response.text

@app.route('/fetch_youtube_access_token', methods=['GET'])
def fetch_youtube_access_token():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=["https://www.googleapis.com/auth/youtube.readonly", "https://www.googleapis.com/auth/yt-analytics-monetary.readonly","https://www.googleapis.com/auth/yt-analytics.readonly"]
    )
    #flow.redirect_uri = "http://localhost:3000/dashboard/integration/youtube"
    flow.redirect_uri = url_for('youtube_oauth_callback', _external=True)
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
    )

    return redirect(authorization_url)

@app.route('/youtube_oauth_callback', methods=['GET'])
def youtube_oauth_callback():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=["https://www.googleapis.com/auth/youtube.readonly", "https://www.googleapis.com/auth/yt-analytics-monetary.readonly","https://www.googleapis.com/auth/yt-analytics.readonly"]
    )
    flow.redirect_uri = "http://localhost:3000/dashboard/integration/youtube"

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    print(credentials)

    return "ok"
