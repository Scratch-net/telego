# Next release — draft

This draft covers the WEB changes under evaluation. The release number and publication date are not set.

- A client `CLOSE` now cancels a pending WebSocket lane immediately. The bridge releases its socket, timer, queued data, and lane reservation.
- Established bridges can recover within the page after a carrier failure or server restart. Each attempt has a 15-second total limit.
- Recovery closes retired streams and discards their queued data. Telegram opens replacements without a second `WELCOME`.
- An online or visible-page event can start recovery after 30 seconds without stream activity.
- The optional `web-proxy.base-path` serves WEB under a path on the existing HTTPS port. Generated links use the path-bound capability format.
- The `generate` command accepts `--web-base-path` with `--web-host`.
- Requests with recognized WEB credentials cannot reach the ordinary website through an incorrect path.

Existing root links retain their credential format. Path links require a Telegram client with WEB base-path support.
A base-path change requires new links and a service restart.

Carrier selection stays explicit. Recovery uses the configured carrier and returns control to Telegram if the attempt fails.
Recovery does not move active MTProto streams or replay data across sessions.
Detailed browser reports remain disabled unless the log level is `debug` or `trace`.

The [WEB guide](../web-proxy.md#serve-web-under-a-path) describes the path configuration and Nginx requirements.
