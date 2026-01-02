# Broadcastr
[![Made for Nostr](https://img.shields.io/badge/Nostr-enabled-purple?logo=nostr&logoColor=white)](https://github.com/nostr-protocol)
[![Crates.io](https://img.shields.io/crates/v/broadcastr)](https://crates.io/crates/broadcastr)
[![Crates.io](https://img.shields.io/crates/d/broadcastr)](https://crates.io/crates/broadcastr)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-%23db61a2.svg?&logo=github&logoColor=white&labelColor=181717&style=flat-square)](#Support)

Vendor lock-free stateless alternative to [blastr](https://github.com/MutinyWallet/blastr) with additional features:
- spam filtering ([spam.nostr.band](https://spam.nostr.band) and [azzamo.net](https://azzamo.net/introducing-the-azzamo-ban-api))
- events filtering
    - kind
    - author/mention
    - [PoW](https://github.com/nostr-protocol/nips/blob/master/13.md)
- [gossip](https://github.com/frnandu/yana/blob/master/GOSSIP.md)
- tor/onion relays
- minimizes the risk of being rate-limited by the relay
    - it checks whether event is already published on a certain relay
- relays ignore list

## Install

### From crates.io
```bash
cargo install --locked broadcastr
```

### From git
```bash
cargo install --locked --force --git https://github.com/codonaft/broadcastr
```

## Run
```
broadcastr --listen ws://localhost:8080 --relays https://codonaft.com/relays.json
```

<details>
<summary><b>💡 Usage 👁️</b></summary>
<p>

```
Usage: broadcastr --listen <listen> --relays <relays> [--blocked-relays <blocked-relays>] [--tor-proxy <tor-proxy>] [--proxy <proxy>] [--min-pow <min-pow>] [--allowed-pubkeys <allowed-pubkeys>] [--disable-mentions] [--max-events-per-min <max-events-per-min>] [--allowed-kinds <allowed-kinds>] [--disable-gossip] [--disable-spam-nostr-band] [--disable-azzamo] [--update-interval <update-interval>] [--max-backoff-interval <max-backoff-interval>] [--connection-timeout <connection-timeout>] [--request-timeout <request-timeout>] [--log-level <log-level>] [--tcp-backlog <tcp-backlog>] [--max-msg-size <max-msg-size>] [--max-frame-size <max-frame-size>]

Broadcast Nostr events to other relays

Options:
  --listen          the listener ws URI (e.g. "ws://localhost:8080")
  --relays          relays or relay-list URIs (comma-separated, e.g.
                    "https://codonaft.com/relays.json,file:///path/to/relays-in-array.json,ws://1.2.3.4:5678")
  --blocked-relays  same, but for ignored relays; put public URL to your
                    broadcastr here to avoid loops
  --tor-proxy       connect to tor onion relays using socks5 proxy (e.g.
                    "127.0.0.1:9050")
  --proxy           connect to all relays using socks5 proxy
  --min-pow         pow difficulty limit (NIP-13)
  --allowed-pubkeys authors or mentioned authors (comma-separated
                    hex/bech32/NIP-21 allow-list)
  --disable-mentions
                    disallow mentions (of the allowed authors) by others
                    (default is false)
  --max-events-per-min
                    max events by author per minute (default is 5)
  --allowed-kinds   limit event kinds with (comma-separated allow-list, e.g
                    "0,1,3,5,6,7,4550,34550")
  --disable-gossip  don't discover additional relays from user profiles
  --disable-spam-nostr-band
                    don't use spam.nostr.band for spam filtering
  --disable-azzamo  don't use azzamo.net for spam filtering
  --update-interval relays and spam-lists update interval (default is 15m)
  --max-backoff-interval
                    max update backoff interval (default is 5m)
  --connection-timeout
                    connection timeout (default is 15s)
  --request-timeout request timeout (default is 10s)
  --log-level       log level (default is info)
  --tcp-backlog     max incoming connections per listener IP address
  --max-msg-size    event message size
  --max-frame-size  ws frame size
  -h, --help        display usage information
```

</p>
</details>

## TODO
- [x] make it compatible with ordinary clients (besides `nak`)
  - [x] support delivery of multiple events over the same connection
  - [x] response with `vary` header
- [x] support azzamo ban api
- [ ] limit concurrent connections per IP?
- [ ] deduplicate concurrently sent events
- [x] NIP-11
- [ ] improve RAM usage
- [ ] add metrics

## Support
I'm currently investing [all my time](https://codonaft.com/why) in FOSS projects.

If you found this repo useful and you want to support me, please
- ⭐ star
- ⚡ [zap](https://zapper.nostrapps.org/zap?id=npub1alptdev5srcw2hxg03567p4k6xs3lgj7f6545suc0rzp0xw98svse7rg94&amount=5000)
- 🌚 something [else](https://codonaft.com/sponsor)

Your support keeps me going ❤️ (◕‿◕)

## License
MIT/Apache-2.0
