# Broadcastr
Vendor lock-free stateless alternative to [blastr](https://github.com/MutinyWallet/blastr) with additional features:
- [spam](https://spam.nostr.band) filtering
- events filtering (kind, author/mention, [PoW](https://github.com/nostr-protocol/nips/blob/master/13.md))
- gossip
- tor relays

<details>
<summary><b>💡 Usage 👁️</b></summary>
<p>

```
Usage: broadcastr --listen <listen> --relay-sources <relay-sources> [--blocked-relays <blocked-relays>] [--tor-proxy <tor-proxy>] [--proxy <proxy>] [--min-pow <min-pow>] [--allowed-pubkeys <allowed-pubkeys>] [--max-events-per-min <max-events-per-min>] [--allowed-kinds <allowed-kinds>] [--disable-gossip] [--disable-spam-nostr-band] [--update-interval <update-interval>] [--max-backoff-interval <max-backoff-interval>] [--connection-timeout <connection-timeout>] [--request-timeout <request-timeout>] [--tcp-backlog <tcp-backlog>] [--max-msg-size <max-msg-size>] [--max-frame-size <max-frame-size>]

Broadcast nostr events to other relays

Options:
  --listen          the listener ws address (e.g. "ws://localhost:8080")
  --relay-sources   API endpoints/files with relay list (comma-separated, e.g.
                    "https://api.nostr.watch/v1/online,file:///path/to/relays-in-array.json")
  --blocked-relays  relays ignore-list (comma-separated, e.g.
                    "wss://nostr.mutinywallet.com,ws://1.2.3.4:9000"); put
                    public URL to your broadcastr here to avoid loops
  --tor-proxy       connect to tor onion relays using socks5 proxy (e.g.
                    "127.0.0.1:9050")
  --proxy           connect to all relays using socks5 proxy
  --min-pow         pow difficulty limit (NIP-13)
  --allowed-pubkeys authors or mentioned authors (comma-separated
                    hex/bech32/NIP-21 allow-list)
  --max-events-per-min
                    max events by author per minute (default is 5)
  --allowed-kinds   limit event kinds with (comma-separated allow-list, e.g
                    "0,1,3,5,6,7,4550,34550")
  --disable-gossip  don't discover additional relays from user profiles
  --disable-spam-nostr-band
                    don't use spam.nostr.band for spam filtering
  --update-interval relays and spam-lists update interval (default is 15m)
  --max-backoff-interval
                    max update backoff interval (default is 5m)
  --connection-timeout
                    connection timeout (default is 15s)
  --request-timeout request timeout (default is 10s)
  --tcp-backlog     max incoming connections per listener IP address
  --max-msg-size    event message size
  --max-frame-size  ws frame size
  -h, --help        display usage information
```

</p>
</details>

## Installation

### From crates.io
```
cargo install --locked broadcastr
```

### From git
```
cargo install --locked --force --git https://github.com/codonaft/broadcastr
```

## Support
I'm currently investing [all my time](https://codonaft.com/why) in FOSS projects.

If you found this repo useful and you want to support me, please
- ⭐ it
- check ⚡ [here](https://codonaft.com/sponsor)

Your support keeps me going ❤️ (◕‿◕)

## License
MIT/Apache-2.0
