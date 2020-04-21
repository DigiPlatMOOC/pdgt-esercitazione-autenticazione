const express = require("express");
const app = express();

const cookieparser = require("cookie-parser");
app.use(cookieparser());

const sha256 = require("js-sha256");

const logins = new Map();
logins.set('lorenz', { salt: '123456', hash: 'aca2d6bd777ac00e4581911a87dcc8a11b5faf11e08f584513e380a01693ef38' });

const cookies = new Map();

function attemptLogin(username, password) {
  if(!logins.has(username)) {
    return false;
  }
  
  const user = logins.get(username);
  
  const compound = user.salt + password;
  const h = sha256.create();
  h.update(compound);
  
  console.log("Verifying " + user.hash + " == " + h.hex());
  
  return h.hex() == user.hash;
}

function attemptAuth(req) {
  console.log("Authentication header: " + req.headers.authorization);
  // req.cookies.auth
  console.log("Cookies: " + JSON.stringify(req.cookies));
  
  if(req.cookies.auth) {
    if(cookies.has(req.cookies.auth)) {
      const username = cookies.get(req.cookies.auth);
      console.log("Utente " + username + " loggato via cookie");
      return true;
    }
  }
  
  if(!req.headers.authorization) {
    return false;
  }
  if(!req.headers.authorization.startsWith('Basic ')) {
    return false;
  }
  
  // Basic bG9yZW56OnBhc3N3b3Jk
  const auth = req.headers.authorization.substr(6);
  const decoded = new Buffer(auth, 'base64').toString();
  const [login, password] = decoded.split(':');
  
  console.log("Login: " + login + ", password: " + password);
  
  return attemptLogin(login, password);
}

app.get('/secret', (req, resp) => {
  if(attemptAuth(req)) {
    resp.status(200).send("File segretissimo").end();
  }
  else {
    resp.set('WWW-Authenticate', 'Basic realm="Cose segrete"')
      .sendStatus(401)
      .end();
  }
});

app.get('/hash', (req, resp) => {
  const input = req.query.input;
  
  const h = sha256.create();
  h.update(input);
  
  resp.type('text/plain')
    .status(200)
    .send(h.hex())
    .end();
});

app.post('/login', (req, resp) => {
  const username = req.query.username;
  const password = req.query.password;
  if(!attemptLogin(username, password)) {
    resp.sendStatus(403).end();
    return;
  }
  
  const now = new Date().toString();
  const h = sha256.create();
  h.update(now + username);
  const sessionId = h.hex();
  
  console.log("New session: " + sessionId);
  
  cookies.set(sessionId, username);
  
  resp.cookie('auth', sessionId); // Set-Cookie: auth=123XYZ...
  
  resp.status(200).send("Sei autenticato!").end();
});

// listen for requests :)
const listener = app.listen(process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
