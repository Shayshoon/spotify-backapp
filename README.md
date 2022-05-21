# Spotify Backapp

## Description

This project is meant to backup all of you spotify library.

## How to run

1. Setup environment variables specified bellow.
2. Install dependencies specified in `requirements.txt`.
3. Start development server using `flask run`.

## Environment variables

| Name | Description | Default value |
|--------------|-----------|------------|
| FLASK_RUN_PORT | The port specified for Flask server | `8080` |
| FLASK_APP | Path to the flask server module | `src/app` |
| CLIENT_ID | Spotify client id | `None` |
| CLIENT_SECRET | Spotify client secret | `None` |
| SPOTIFY_ACCOUNTS_SERVICE_URL | URL of Spotify accounts API | `https://accounts.spotify.com` |
| SPOTIFY_API_URL | URL of Spotify API | `https://api.spotify.com` |
