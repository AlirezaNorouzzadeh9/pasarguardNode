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

Applied in order with `git am`. Each is a real commit, so a later sing-box
release is a rebase rather than a re-derivation.

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

## `0002-all-protocols.patch`

The endpoint was generic from the start; only its dispatch knew hysteria2. This
gives vless, vmess, trojan, tuic and hysteria the same exported `UpdateUsers`
and widens the dispatch to all of them.

It claimed shadowsocks already worked, because shadowsocks does have an
`UpdateUsers` upstream. It was never tested, and it did not work: see 0003.

Each carries the hazard hysteria2 did: the inbound keeps its own copy of the
user list and resolves a connecting client's name by indexing it with the id the
service returns. Swapping those separately bills traffic arriving mid-swap to
whoever now sits at that index — seen in testing, where one user's download was
recorded against a stranger. Both halves swap under one write lock, and the
lookup is bounds-checked.

tuic differs from the rest in three ways that only the compiler surfaced: its
service field is named `server`, its UpdateUsers takes `[][16]byte` rather than
`[]uuid.UUID`, and it rejects an empty uuid before parsing.

## `0003-shadowsocks-users.patch`

0002 assumed that an upstream `UpdateUsers` was enough. Shadowsocks has one, but
its signature is `UpdateUsers(users []string, uPSKs []string)` — two parallel
slices rather than a list of user structs — so none of the dispatch's
single-argument interface cases could match it, and every push to a shadowsocks
inbound was refused with "inbound does not support updating users".

That refusal is not confined to shadowsocks: the node fails its initial user
push, stops sing-box, and every other protocol on the core goes down with it.
One inbound nobody could use took out four that worked.

It also had the hazard the others were fixed for — the service is given the new
passwords, then the name list is replaced separately and without a lock, and the
lookup into it is unbounded. Both are fixed here alongside the dispatch case.

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
git am < ../singbox/0002-all-protocols.patch
git am < ../singbox/0003-shadowsocks-users.patch
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
