# sing-box patches

Downstream changes to sing-box, kept as patches rather than a vendored fork so
they can be rebased onto later releases instead of re-derived by hand.

**Pinned upstream:** `v1.13.18` (SagerNet/sing-box)

## Why these exist

A panel adds and removes users continuously. Stock sing-box can only be told
its user set once, when an inbound is constructed, so every user change meant
restarting the process and dropping every live connection. That made sing-box
and a subscription panel fundamentally incompatible.

The capability was already present — every protocol service supports having its
credential table replaced at runtime. What was missing was a way to ask for it
from outside, and a stats service that would count a user it had not been told
about at startup.

## `0001-runtime-users.patch`

Three changes, verified end to end against a live tunnel:

- **`protocol/hysteria2/inbound.go`** — exported `UpdateUsers`. The service's
  credentials and `userNameList` swap under one write lock, because that list
  is indexed by the user id the service returns; updating them separately bills
  traffic arriving mid-swap to the wrong user. Name lookup is bounds-checked —
  the id can come from a connection authenticated against a longer list, and
  indexing past the end panics the process.

- **`experimental/clashapi/inbound_users.go`** — `PUT /inbounds/{tag}/users`,
  behind the existing clash_api secret. Generic rather than per-protocol: the
  remaining six protocols are a case in one switch, not another route. The body
  matches the inbound's own `users` block.

- **`experimental/v2rayapi/stats.go`** — `"*"` in the stats `users` list means
  count everyone. Naming users individually cannot work here: that list is read
  once at startup, so a user created later passes traffic attributed to nobody,
  which defeats the point of adding them without a restart. This mirrors how
  xray gates user stats — a switch, not an allowlist.

### Known gap

Removing a user does not close their established sessions. New connections are
refused; existing ones run until the client closes them. For TCP protocols that
window is short, but a Hysteria2 QUIC session can stay open for hours — so an
expired or over-quota user keeps service until they disconnect.

## Building

```sh
git clone --depth 1 --branch v1.13.18 https://github.com/SagerNet/sing-box.git
cd sing-box
git am < ../singbox/0001-runtime-users.patch
go build -tags with_quic,with_clash_api,with_v2ray_api,with_utls,with_gvisor -o sing-box ./cmd/sing-box
```

`with_v2ray_api` is not in sing-box's default tag set and is required — without
it there are no per-user counters at all.

## Moving to a newer sing-box

```sh
git checkout -b rebase vX.Y.Z
git am -3 < singbox/0001-runtime-users.patch
```

If it conflicts, the three files above are the only ones touched. Re-verify by
adding a user through the endpoint after startup and confirming their traffic
appears under `user>>>NAME>>>traffic>>>downlink` — that is the assertion that
failed before the patch and is the one worth keeping.
