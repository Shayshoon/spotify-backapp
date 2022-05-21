from os import environ
from dotenv import load_dotenv

load_dotenv()

class config:
    
    def __init__(self):
        self.PORT = environ['FLASK_RUN_PORT'] or 8080
        self.CLIENT_ID = environ['CLIENT_ID']
        self.CLIENT_SECRET = environ['CLIENT_SECRET']
        self.SPOTIFY_API_URL = environ['SPOTIFY_API_URL'] or 'https://api.spotify.com'
        self.SPOTIFY_ACCOUNTS_SERVICE_URL = environ['SPOTIFY_ACCOUNTS_SERVICE_URL'] or 'https://accounts.spotify.com'

def env():
    return config()