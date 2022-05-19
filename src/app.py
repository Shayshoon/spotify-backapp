import base64
from secrets import token_urlsafe
from urllib.parse import urlencode
import pandas as pd

import requests
from cofiguration import env
from flask import Flask, jsonify, make_response, redirect, request
from markupsafe import escape

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

            res = redirect('/home')
            res.set_cookie('access_token', access_token)
            res.set_cookie('refresh_token', refresh_token)
            res.delete_cookie(STATE_COOKIE_KEY)

            return res


@app.route("/home")
def home_route():
    return "<h1>HOME</h1>"


@app.route("/refresh_token")
def refresh_token_route():
    # requesting access token from refresh token
    refresh_token = request.cookies.get('refresh_token')
    print(refresh_token)
    token = 'Basic ' + str(
        base64.b64encode(
            (f"{config.CLIENT_ID}:{config.CLIENT_SECRET}".encode('utf-8'))),
        'utf-8')

    spotify_response = requests.post(
        f'{config.SPOTIFY_ACCOUNTS_SERVICE_URL}/api/token',
        headers={'Authorization': token},
        data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        })

    if spotify_response.ok:
        response_json = spotify_response.json()
        access_token = response_json['access_token']

        res = jsonify(access_token=access_token)
        res.set_cookie('access_token', access_token)

        return res
    else:
        res = make_response()
        res.status_code = spotify_response.status_code
        res.set_data(spotify_response.text)

        return res


@app.route("/playlists")
def get_playlists_route():
    access_token = request.cookies.get('access_token')

    return fetch_all(fetch_spotify_playlists, access_token)


@app.route("/playlists/<playlist_id>")
def get_playlist_route(playlist_id):
    access_token = request.cookies.get('access_token')

    return fetch_playlist(escape(playlist_id), access_token)


@app.route("/tracks")
def get_tracks_route():
    access_token = request.cookies.get('access_token')
    query_params = request.args
    type = query_params.get('type')
    delimiter = query_params.get('delimiter')

    return fetch_all(fetch_spotify_tracks, access_token, type)


@app.route("/albums")
def get_albums_route():
    access_token = request.cookies.get('access_token')

    return fetch_all(fetch_spotify_albums, access_token)


def parse_tracks_to_csv(json_tracks):
    dt = pd.DataFrame({
        'spotify_id': [],
        'name': [],
        'album_name': [],
        'artist': [],
        'isrc': [],
        'spotify_link': [],
        'spotify_preview_link': []
    })

    for track in json_tracks:
        track_object = track['track']
        dt.append({
            'spotify_id': [track_object['id']],
            'name': [track_object['name']],
            'album_name': [track_object['album']['name']],
            'artist': [track_object['artists'][0]['name']],
            'isrc': [track_object['external_ids']['isrc']],
            'spotify_link': [track_object['external_urls']['spotify']],
            'spotify_preview_link': [track_object['preview_url']]
        })

    return dt.to_csv(sep=',')


def fetch_all(fetch_item, access_token, type='json'):
    MAX_LIMIT = 50

    all_items = []
    counter = 1

    curr_response = fetch_item(MAX_LIMIT, 0, access_token)

    while len(curr_response['items']) > 0:
        all_items.extend(curr_response['items'])
        print(f'fetched {len(all_items)} items from spotify')

        curr_response = fetch_item(MAX_LIMIT, MAX_LIMIT * counter,
                                   access_token)

        counter += 1

    if type == 'json' or type == None:
        return jsonify(all_items)
    elif type == 'csv':
        output = make_response(parse_tracks_to_csv(all_items))
        output.headers[
            "Content-Disposition"] = "attachment; filename=export.csv"
        output.headers["Content-type"] = "text/csv"

        return output


def fetch_spotify_item(url, access_token):
    response = requests.get(
        url=url,
        headers={'Authorization': 'Bearer ' + access_token},
    )

    print(f'got status code {response.status_code} from spotify')
    return response.json()


def fetch_spotify_albums(limit, offset, access_token):
    return fetch_spotify_item(
        f"{config.SPOTIFY_API_URL}/v1/me/albums?limit={limit}&offset={offset}",
        access_token)


def fetch_spotify_tracks(limit, offset, access_token):
    return fetch_spotify_item(
        f"{config.SPOTIFY_API_URL}/v1/me/tracks?limit={limit}&offset={offset}",
        access_token)


def fetch_spotify_playlists(limit, offset, access_token):
    return fetch_spotify_item(
        f"{config.SPOTIFY_API_URL}/v1/me/playlists?limit={limit}&offset={offset}",
        access_token)


def fetch_playlist(playlist_id, access_token):
    return fetch_spotify_item(
        f"{config.SPOTIFY_API_URL}/v1/playlists/{playlist_id}", access_token)
