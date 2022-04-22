/**
* This is an example of a basic node.js script that performs
* the Authorization Code oAuth2 flow to authenticate against
* the Spotify Accounts.
*
* For more information, read
* https://developer.spotify.com/web-api/authorization-guide/#authorization_code_flow
*/

var express = require('express'); // Express web server framework
var request = require('request'); // "Request" library
var cors = require('cors');
var querystring = require('querystring');
var cookieParser = require('cookie-parser');
const dotenv = require('dotenv')

dotenv.config()

const PORT = process.env.PORT;
const CLIENT_ID = process.env.CLIENT_ID; // Your client id
const CLIENT_SECRET = process.env.CLIENT_SECRET; // Your secret
const SPOTIFY_ACCOUNTS_SERVICE_URL = process.env.SPOTIFY_ACCOUNTS_SERVICE_URL;
const SPOTIFY_API_URL = process.env.SPOTIFY_API_URL;


var redirect_uri = `http://localhost:${PORT}/callback`; // Your redirect uri

/**
 * Generates a random string containing numbers and letters
 * @param  {number} length The length of the string
 * @return {string} The generated string
 */
var generateRandomString = function (length) {
  var text = '';
  var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  for (var i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
};

var stateKey = 'spotify_auth_state';

var app = express();

app.use(express.static(__dirname + '/public'))
  .use(cors())
  .use(cookieParser());

app.get('/', function (req, res) {

  var state = generateRandomString(16);
  res.cookie(stateKey, state);

  // your application requests authorization
  var scope = 'user-read-private user-library-read';
  res.redirect(`${SPOTIFY_ACCOUNTS_SERVICE_URL}/authorize?` +
    querystring.stringify({
      response_type: 'code',
      client_id: CLIENT_ID,
      scope: scope,
      redirect_uri: redirect_uri,
      state: state
    }));
});

app.get('/callback', function (req, res) {

  // your application requests refresh and access tokens
  // after checking the state parameter

  var code = req.query.code || null;
  var state = req.query.state || null;
  var storedState = req.cookies ? req.cookies[stateKey] : null;

  if (state === null || state !== storedState) {
    res.redirect('/#' +
      querystring.stringify({
        error: 'state_mismatch'
      }));
  } else {
    res.clearCookie(stateKey);
    var authOptions = {
      url: `${SPOTIFY_ACCOUNTS_SERVICE_URL}/api/token`,
      form: {
        code: code,
        redirect_uri: redirect_uri,
        grant_type: 'authorization_code'
      },
      headers: {
        'Authorization': 'Basic ' + (new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64'))
      },
      json: true
    };

    const spotifyResponse = request.post(authOptions, function (error, response, body) {
      if (!error && response.statusCode === 200) {

        var access_token = body.access_token,
          refresh_token = body.refresh_token;

        // we can also pass the token to the browser to make requests from there
        res.cookie('access_token', access_token);
        res.cookie('refresh_token', refresh_token)
        res.redirect('/my-tracks');
      } else {
        res.redirect(`bad_login?${querystring.stringify({
          error: 'invalid_token'
        })}`);
      }
    });

    console.log(spotifyResponse.access_token)
  }
});

app.get('/my-tracks', (req, res) => {
  const access_token = req.cookies.access_token,
    refresh_token = req.cookies.refresh_token;

  const options = {
    url: `${SPOTIFY_API_URL}/v1/me/tracks`,
    headers: { 'Authorization': 'Bearer ' + access_token },
    json: true
  };

  // use the access token to access the Spotify Web API
  request.get(options, function (error, response, body) {
    res.send(body)
  });
});

app.get('/my-albums', (req, res) => {
  const access_token = req.cookies.access_token,
    refresh_token = req.cookies.refresh_token;

  const options = {
    url: `${SPOTIFY_API_URL}/v1/me/albums`,
    headers: { 'Authorization': 'Bearer ' + access_token },
    json: true
  };

  // use the access token to access the Spotify Web API
  request.get(options, function (error, response, body) {
    res.send(body)
  });
});

app.get('/refresh_token', function (req, res) {

  // requesting access token from refresh token
  var refresh_token = req.query.refresh_token;
  var authOptions = {
    url: `${SPOTIFY_ACCOUNTS_SERVICE_URL}/api/token`,
    headers: { 'Authorization': 'Basic ' + (new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64')) },
    form: {
      grant_type: 'refresh_token',
      refresh_token: refresh_token
    },
    json: true
  };

  request.post(authOptions, function (error, response, body) {
    if (!error && response.statusCode === 200) {
      var access_token = body.access_token;
      res.send({
        'access_token': access_token
      });
    }
  });
});

console.log(`Listening on ${PORT}`);
app.listen(PORT);