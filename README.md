# Scenic Slider Captcha Demo

This project is a deployable Go web demo for a slider captcha.

Current rendering model:

- The server chooses a random scene image and random slot position.
- The answer stays on the server only.
- The server sets a short-lived attempt cookie for each new challenge.
- The browser computes a JS proof with Web Crypto before submit.
- The server returns two raster images for each challenge:
  - `panel.png`: the background image with a visible slot
  - `piece.png`: the draggable puzzle piece cut from the same source image
- The frontend uses canvas for display and interaction.
- The frontend sends the final slider position plus drag trace back to the server.
- The server verifies both alignment and behavior.

## Project Layout

```text
human-verify-web/
|-- cmd/server/main.go
|-- internal/captcha/service.go
|-- static/
|   |-- index.html
|   |-- styles.css
|   |-- app.js
|   `-- assets/
|       |-- 1.jpg
|       |-- 2.jpg
|       `-- 3.jpg
`-- go.mod
```

## Endpoints

### `GET /api/captcha/new`

Returns a new challenge:

- `token`
- `panelUrl`
- `pieceUrl`
- `proofNonce`
- `powDifficulty`
- `width`
- `height`
- `pieceSize`
- `pieceY`
- `sliderMax`
- `expiresInMs`

The response does not expose the correct `targetX`.
It does expose a per-challenge `proofNonce` used for client-side proof generation.

### `GET /api/captcha/panel/{token}.png`

Returns a raster background image with the slot already rendered.

### `GET /api/captcha/piece/{token}.png`

Returns a raster puzzle piece cut from the same source image.

### `POST /api/captcha/verify`

Request example:

```json
{
  "token": "challenge-token",
  "sliderX": 148.25,
  "durationMs": 1320,
  "trace": [
    { "x": 0, "y": 0, "t": 0 },
    { "x": 12.6, "y": 1.4, "t": 96 },
    { "x": 47.2, "y": 3.1, "t": 248 }
  ]
}
```

Response:

- `success`
- `score`
- `message`

## Verification Logic

The server checks:

- final horizontal alignment against the hidden target
- attempt cookie presence and match
- JS proof validity
- `navigator.webdriver`
- browser-side signal completeness
- drag duration
- minimum trace point count
- X-direction monotonicity
- excessive backtracking
- trace span vs final displacement
- total traveled distance vs displacement
- abnormal Y movement
- speed variance

The challenge is single-use and stored in memory with a 2 minute TTL.

## Attempt Cookie And JS Proof

For each challenge:

- the server sets cookie `hv_attempt`
- the response includes `proofNonce`
- the response includes `powDifficulty`
- the browser collects a small set of client signals
- the browser first solves a small PoW challenge
- the browser then computes a SHA-256 proof from:
  - challenge token
  - proof nonce
  - signed attempt cookie
  - per-drag random salt
  - PoW counter and digest
  - slider position
  - duration
  - trace digest
  - browser signals

The proof is sent with `/api/captcha/verify` and is recomputed on the server.
The attempt cookie is HMAC-signed on the server to prevent client-side forgery.

## Frontend Behavior

The frontend:

- loads `panel.png` and `piece.png`
- draws both with canvas
- moves the piece canvas according to slider position
- records drag trace points
- submits the trace when the pointer is released

## Assets

The current sample uses raster scene images in `static/assets`.

Supported source formats for the current server-side raster pipeline:

- `.png`
- `.jpg`
- `.jpeg`

Keep images near the `320x180` ratio for best results.

## Deployment

No database is required.

Environment variables:

- `ADDR`: listen address, default `:8080`
- `STATIC_DIR`: static directory, default `./static`
- `ATTEMPT_COOKIE_SECRET`: optional stable secret for signed attempt cookies
- `POW_DIFFICULTY`: leading zero hex count for PoW, default `3`

## Limits

This is an engineering demo, not a hardened production captcha.

Current limits:

- behavior scoring is heuristic, not ML-based
- sessions are stored in memory
- multi-instance deployment needs a shared session layer
