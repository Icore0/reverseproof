// The "protected" client code: a baked-in secret that is used to call an API.
const SECRET = 'sk_live_JSEXPERIMENT_SECRET_12345678';
function callApi() {
  return fetch('https://api.example.invalid/v1/score', { headers: { authorization: 'Bearer ' + SECRET } });
}
callApi().then((r) => r.text()).then((t) => console.log('done', t));
