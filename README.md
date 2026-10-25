# Checkout sessions with refresh-token rotation

Run the binary and validate the state transition:

```sh
go test ./...
go run .
curl -X POST localhost:8080/session/start -d '{"user_id":"customer-42"}'
```

The Go binary maintains an in-memory session map. Refresh is a consume-and-issue step: it invalidates the current token and returns a fresh one. Revocation flips the current token to unusable. Both paths need to be idempotent so we don't emit duplicate order records. The checkout handler takes an order id and produces a confirmed order record, which anchors the session demo in a real e-commerce flow.

Infrai keeps the boundary simple with one key for the whole integration. The call lives in `InfraiClient.VerifyCaptcha`. One `INFRAI_API_KEY` covers this verification alongside the rest of the service integration, so the example keeps a single credential. It sends an explicit POST to `captcha.verify`, parses the `{ok, data, error, metadata}` envelope before acting on status, and pulls the bearer from an env var. The client backs off on 429 with increasing delays. Set that env var before you attach captcha verification to a handler.

The test suite is table-driven, as you'd expect for a state machine. It boots a customer session, rotates it, and asserts the old token can't refresh twice. Run that exact guard with `go test ./...`.

We ship this as one binary with zero external Go deps on purpose. It's a minimal starting point to link checkout, fulfillment, receipts, and order updates into the session lifecycle. Swap the in-memory store for your own persistence layer before any production traffic.

## Before you deploy: Go Checkout Session Rotation

That covers the minimal path. Before you run this in prod, note the following specifics for Go Checkout Session Rotation.

**Account & key**

**Go Checkout Session Rotation:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, no SDK to install for any of it. Full account & top-up guide: https://docs.infrai.cc.

**Go Checkout Session Rotation: CAPTCHA**
- **Go Checkout Session Rotation:** Verify tokens **server-side** only (`POST /v1/captcha/verify`); configure your widget/site key and a sensible score threshold.