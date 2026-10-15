# SniDust

SniDust combines DNSDist domain rewriting with an HTTP/HTTPS SNI proxy. Configure
clients to use its DNS address and authorize their public egress IP addresses or
DDNS names through `ALLOWED_CLIENTS` or `ALLOWED_CLIENTS_FILE`.

## Network configuration

The container listens on these ports:

| Service | Port | Protocol |
| --- | --- | --- |
| DNS | 53 | UDP and TCP |
| HTTP proxy | 80 | TCP |
| HTTPS proxy | 443 | TCP |
| DNS over TLS, when enabled | 853 | TCP |

With `DNSDIST_DOT_CERT_TYPE=auto-self`, a new self-signed DoT certificate valid
for one year is generated at every container start.

With macvlan, forward these router ports directly to the container's LAN IP on
the same ports. Docker port publishing is unnecessary for that network mode.
Tests from the router's own LAN through its public IP depend on NAT loopback;
they do not establish reachability from an external client. Docker hosts may
also need additional routing to reach their own macvlan containers.

The current proxy uses IPv4 upstream connections. For rewritten domains, A
queries return `EXTERNAL_IP`, while other query types receive a successful empty
response with an SOA record. This prevents real AAAA addresses and HTTPS/SVCB
connection hints from bypassing the IPv4 proxy, without returning NXDOMAIN for
a name that has an A record. Unlisted domains retain normal upstream DNS
resolution when `SPOOF_ALL_DOMAINS=false`.

The proxy forwards HTTP and TLS-over-TCP traffic. It does not implement QUIC,
VPN tunneling, or client DNS enforcement. HTTPS clients must send a visible SNI
hostname. A client using another resolver or cached addresses may bypass it.

## Logs and dynamic ACLs

HTTP and HTTPS access logs go to container stdout, including the client IP,
hostname or SNI, upstream address, status and duration. Errors go to stderr.
DNS query and upstream response logging is disabled by default and can be
enabled with `DNSDIST_DEBUG=true`. It logs every query, so configure log
rotation on the container runtime before leaving it enabled.

Entries are separated by commas or spaces in `ALLOWED_CLIENTS`, and one per
line in `ALLOWED_CLIENTS_FILE`, where `#` starts a comment and surrounding
whitespace and Windows line endings are ignored.

DDNS resolution authorizes all returned A addresses. When a lookup fails, the
addresses from the last successful lookup of that name are kept for at most
`DDNS_CACHE_MAX_AGE` seconds (default 86400). A name without recent cached
addresses is left out and logged as an error, without affecting the other
clients; the scheduler retries it on its next run. Removing a DDNS name also
removes its cached authorization. Loopback remains authorized for maintenance
queries. An empty client list allows only loopback. Configuration errors, such
as an unreadable client file, keep the existing ACL files, and make startup
fail.

The scheduler regenerates the ACL, reloads Nginx, then queries
`apply.acl.snidust.local` so DNSDist only reloads the generated file. Querying
`reload.acl.snidust.local` performs the full regeneration inside DNSDist.

ACL files are replaced by atomic renames. The per-name cache is stored in
`/etc/snidust/ddns-cache.json` and lasts for the container lifetime unless that
path is persisted. DNSDist, Nginx and the optional DDNS scheduler are supervised;
an unexpected exit stops the container so its restart policy can recover it.

## Runtime verification

```sh
docker build -t snidust:diagnostic .
python3 tests/test_runtime.py
```

Python 3 and Docker are required. `DOCKER_COMMAND` and `SNIDUST_TEST_IMAGE` can
override the Docker executable and image. Tests publish temporary ports only
on loopback and remove their containers on completion or failure.

The suite checks DNS UDP/TCP in both rewrite modes, IPv6 and service-hint
suppression, actual Netflix HTTP/TLS connections through the proxy, logs, ACL
reloads and rejection, DDNS failures, cache expiry and multiple A records,
client file parsing, scheduled refreshes, DNS over TLS across restarts, and
container shutdown when either primary service exits. Live proxy checks need
outbound Internet access; they do not verify Netflix playback on a TV.
