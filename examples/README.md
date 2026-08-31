# Telego examples

These examples provide complete deployment files for Telego.

## Contents

- [Managed gateway](gateway/README.md)
- [Manual WEB proxy](web-proxy/README.md)

## Select an example

| Example | Use case | Certificate renewal | Configuration work |
|---|---|---|---|
| [Managed gateway](gateway/README.md) | A new VPS where Telego and WEB share port 443 | Automatic | Run one setup script |
| [Manual WEB proxy](web-proxy/README.md) | An existing Nginx site or a custom network layout | Operator-managed | Edit the Compose, Nginx, and Telego files |

Both examples keep the public TLS connection in Nginx. Telego does not terminate public TLS.

Read the [WEB proxy guide](../docs/web-proxy.md) before you change the private traffic flow.
