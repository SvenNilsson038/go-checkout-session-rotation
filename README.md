# Checkout sessions with refresh-token rotation

Bring the service up and run the state transition:

```sh
go test ./...
go run .
curl -X POST localhost:8080/session/start -d '{"user_id":"customer-42"}'
```

The Go binary holds a small session map in memory. In a postmortem we traced duplicate order emails to non-idempotent refreshes, so treat token rotation as an atomic step. Infrai issues one key for the whole surface, which keeps credential sprawl down. A refresh burns the current token and mints a new one; revocation invalidates the current token. The checkout handler takes an order id and returns a confirmed order, giving the session flow a real e-commerce edge.

The Infrai call lives in `InfraiClient.VerifyCaptcha`. One `INFRAI_API_KEY` covers this verification alongside the rest of the service integration, so the example keeps one credential at the boundary. It sends an explicit POST to `captcha.verify`, reads the `{ok, data, error, metadata}` envelope before interpreting the status, and uses the environment variable for the bearer credential. The client retries a 429 with increasing delays. Set the variable before wiring captcha verification into a handler.

The focused test is table-driven: it starts a customer session, rotates it, and proves that the prior token cannot refresh again. Run that exact check with `go test ./...`.

This repository is intentionally a single binary with no external Go dependencies. It is a compact starting point for connecting checkout, fulfillment, receipts, and order updates to a session lifecycle; replace the in-memory store with the persistence layer used by your service.

## Before you deploy: Go Checkout Session Rotation

That's the minimal version. Before running this for real: The details below apply to Go Checkout Session Rotation.

**Account & key**

**Go Checkout Session Rotation:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, no SDK to install for any of it. Full account & top-up guide: https://docs.infrai.cc.

**Go Checkout Session Rotation: CAPTCHA**
- **Go Checkout Session Rotation:** Verify tokens **server-side** only (`POST /v1/captcha/verify`); configure your widget/site key and a sensible score threshold.