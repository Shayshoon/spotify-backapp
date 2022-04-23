import base64
from secrets import token_urlsafe
from urllib.parse import urlencode

import requests
from cofiguration import env
from flask import Flask, redirect, request

config = env()

REDIRECT_URI = f'http://localhost:{config.PORT}/callback/'
STATE_COOKIE_KEY = 'spotify_auth_state'
AUTHORIZATION_SCOPE = 'user-read-private user-library-read'

app = Flask(__name__)


@app.route("/")
def home():
    state = token_urlsafe()
    redirect_url = f'''{config.SPOTIFY_ACCOUNTS_SERVICE_URL}/authorize?{urlencode({
        "response_type": "code",
        "client_id": config.CLIENT_ID,
        "scope": AUTHORIZATION_SCOPE,
        "redirect_uri": REDIRECT_URI,
        "state": state
    })}'''

    res = redirect(redirect_url)
    res.set_cookie(STATE_COOKIE_KEY, state)

    return res


# your application requests refresh and access tokens
# after checking the state parameter
@app.route("/callback/")
def callback_route():
    query_params = request.args

    code = query_params.get('code')
    state = query_params.get('state')
    stored_state = request.cookies.get(
        STATE_COOKIE_KEY) if request.cookies != None else None

    if state == None or state != stored_state:
        return redirect(f"/#?{urlencode({'error': 'state_mismatch'})}")
    else:
        token = 'Basic ' + str(
            base64.b64encode(
                (f"{config.CLIENT_ID}:{config.CLIENT_SECRET}".encode('utf-8')
                 )), 'utf-8')

        spotify_response = requests.post(
            f"{config.SPOTIFY_ACCOUNTS_SERVICE_URL}/api/token",
            headers={'Authorization': token},
            data={
                'code': code,
                'redirect_uri': REDIRECT_URI,
                'grant_type': 'authorization_code'
            },
            json=True)

        if not spotify_response.ok:
            res = redirect(
                f"/bad_login?{urlencode({'error': 'invalid_token'})}")
            res.delete_cookie(STATE_COOKIE_KEY)

            return res
        else:
            access_token, refresh_token = spotify_response.json(
            )['access_token'], spotify_response.json()['refresh_token']

            res = redirect('/my-tracks')
            res.set_cookie('access_token', access_token)
            res.set_cookie('refresh_token', refresh_token)
            res.delete_cookie(STATE_COOKIE_KEY)

            return res


@app.route("/my-tracks")
def get_tracks_route():
    access_token = request.cookies.get('access_token')

    spotify_response = requests.get(
        url=f"{config.SPOTIFY_API_URL}/v1/me/tracks?limit=50",
        headers={'Authorization': 'Bearer ' + access_token},
    )

    print(str(f"{config.SPOTIFY_API_URL}/v1/me/tracks"))

    return spotify_response.json()
