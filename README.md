![GitHub package.json version](https://img.shields.io/github/package-json/v/thzero/library_server_auth_providers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# library_server_auth_providers

Sign-in proof checks for [@thzero/library_server](https://github.com/thzero/library_server) auth servers. Each service takes the proof a client got from a sign-in provider, checks it with that provider, and answers who signed in. The auth server then finds or creates the user and issues its own token; nothing here knows about users or tokens.

| Service | Proof | Answers |
| --- | --- | --- |
| `discord/index.js` (`DiscordOAuthService`) | the OAuth2 authorization code Discord returned to the client | `{ externalType: 'discord', externalId, name }` |
| `eos/index.js` (`EosIdTokenService`) | an EOS Connect ID token | `{ puid, externalType, externalId, platform }` |
| `firebase/index.js` (`FirebaseIdTokenService`) | a Firebase Auth ID token (Google and the other Firebase providers) | `{ externalType: 'firebase', externalId, provider }` |
| `steam/index.js` (`SteamOpenIdService`) | the `openid.*` fields Steam's OpenID 2.0 sign-in returned to the client | `{ externalType: 'steam', externalId }` (the SteamID64) |

Every service has one method, `verify(correlationId, proof)`, and answers a library response: `success` with `results`, or an error with a message saying why the proof was refused.

The pairing client library is [@thzero/library_client_auth_providers](https://github.com/thzero/library_client_auth_providers), which gets these proofs in the browser.

## Requirements

### NodeJs

[NodeJs](https://nodejs.org) version 22+

### Installation

[![NPM](https://nodei.co/npm/@thzero/library_server_auth_providers.png?compact=true)](https://npmjs.org/package/@thzero/library_server_auth_providers)

## Usage

Inject the services the server needs, and call them from its auth service:

```js
import steamOpenIdService from '@thzero/library_server_auth_providers/steam/index.js';

this._injectService(Constants.InjectorKeys.SERVICE_AUTH_STEAM, new steamOpenIdService());

const response = await this._serviceSteam.verify(correlationId, request.params);
if (this._hasFailed(response))
	return response;
const { externalType, externalId } = response.results;
```

## Configuration

Each service reads its own section of the server's config.

### Discord

```json
"discord": {
	"clientId": "<application id>",
	"clientSecret": "<client secret>",
	"redirectUrl": "https://example.com/auth/discord"
}
```

`redirectUrl` must be the client page Discord returns to, exactly as registered under the application's OAuth2 redirects. The code is exchanged with the client secret, which never leaves the server, and must have been granted the `identify` scope.

### EOS

```json
"eos": {
	"clientId": "<EOS client id>",
	"deploymentId": "<optional: only tokens for this deployment>",
	"issuerPrefix": "https://api.epicgames.dev",
	"jwksUrl": "https://api.epicgames.dev/auth/v1/oauth/jwks"
}
```

### Firebase

```json
"firebase": {
	"projectId": "<Firebase project id>"
}
```

The token is checked against Google's published certificates, the way Firebase documents for checking ID tokens without its admin SDK: RS256, the project as audience and issuer, expiry, and the times it was issued and signed in. No service account is needed.

### Steam

```json
"steam": {
	"returnUrl": "https://example.com/auth/steam"
}
```

`returnUrl` must be the client page Steam returns to, the `openid.return_to` the client sent. The answer is checked field by field, then with Steam itself (`check_authentication`). Answers older than five minutes, or already used, are refused; used answers are remembered in memory, so the replay check covers one server instance.

## Tests

```
npm test
```

The tests stand in for the providers' endpoints, so they run offline.

## License

[MIT](license.md)
