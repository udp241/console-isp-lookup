<div align="center">

<img src="res/isp-256.png" width="116" alt="isp" />

# isp

**IP / ISP lookup for the Windows console.**
One small exe, no libcurl, no runtime, nothing to install.

![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0a0a12?style=flat-square)
![C99](https://img.shields.io/badge/C-99-00bfa5?style=flat-square&logo=c)
![Release](https://img.shields.io/github/v/release/udp241/console-isp-lookup?style=flat-square&color=00bfa5)

[**Download**](https://github.com/udp241/console-isp-lookup/releases/latest) · [Discord](https://discord.gg/icmp) · [Telegram](https://t.me/ncahq)

</div>

---

## Usage

```
isp [--no-color] [target ...]
```

`target` can be an IP (v4 or v6), a hostname, or a pasted URL. Ports, paths and `user@` bits get stripped, so `https://example.com:8443/login` works as-is. Use `me` for your own public IP.

Run it with no target for an interactive prompt. Leave the prompt blank to look up your own IP, type `exit` to quit.

```
isp 8.8.8.8
isp google.com cloudflare.com
isp me
isp
```

```
  -- Network --
  IP          : 8.8.8.8
  Reverse DNS : dns.google
  ASN         : AS15169
  AS Name     : GOOGLE
  ISP         : Google LLC
  Org         : Google Public DNS

  -- Location --
  Country     : United States (US)
  Region      : Virginia
  City        : Ashburn
  Postal      : 20149
  Lat / Lon   : 39.03, -77.5
  Timezone    : America/New_York
  Currency    : USD

  -- Flags --
  Proxy / VPN : no
  Hosting     : yes
  Mobile      : no

  [!] suspicious: this IP looks like a datacenter/hosting provider

  source: ip-api.com
```

## How it works

- Looks the address up on **ip-api.com** first. If that's down or rate limited it falls back to **ipapi.co**, then **ipinfo.io**. No API keys needed for any of them.
- Hostnames are resolved locally first. Private, loopback and reserved addresses are caught before anything is sent.
- If your DNS blocks the lookup API (Pi-hole, an adblock hosts file), it resolves `ip-api.com` over DNS-over-HTTPS through `1.1.1.1` instead. Only that one hostname is affected. The rest of your system keeps its normal DNS.
- The proxy, hosting and mobile flags only come from ip-api.com, so they're left out when a fallback answered.
- Run from Win+R with a target (`isp 8.8.8.8`), it waits for a key before closing so you can read the result.
- Set `NO_COLOR` or pass `--no-color` for plain output. Colours also switch off when output is redirected to a file.

The free ip-api.com tier allows 45 requests a minute. Past that you'll see it fall through to the next provider.

## Build

**MinGW:**
```
windres isp.rc -O coff -o isp.res
gcc lookup.c isp.res -o isp.exe -O2 -s -static -lwinhttp -lws2_32
```

**Visual Studio** (from the *x64 Native Tools Command Prompt*):
```
rc isp.rc
cl /O2 lookup.c isp.res /Fe:isp.exe
```

**CMake:**
```
cmake -B build
cmake --build build --config Release
```

Drop `isp.exe` somewhere on your `PATH` and it's available from Win+R and any terminal.

---

<div align="center">

Part of the **Rhino** tool family

[discord.gg/icmp](https://discord.gg/icmp) · [t.me/ncahq](https://t.me/ncahq) · Discord: **@wljt**

</div>
