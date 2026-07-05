# Connecting as a user

Someone runs a Postern server and gave you access to it. This page shows how to sign in, download your connection, and get online. Everything here happens on your own computer — no server knowledge needed.

## Get access

There is no signup form. The person running the server (your *operator*) creates your account using your email address. You need two things from them:

- The portal address — a web link such as `https://postern.example.com`.
- Confirmation that your email is registered.

## Sign in

1. Open the portal address in your browser.
1. Enter your email address.
1. A 6-digit code arrives in your inbox. It is valid for a few minutes.
1. Type the code into the page.

There is no password. The emailed code is the entire login, every time.

## Download your connection

After signing in, you land on your dashboard. It lists the connections your operator made for you — each has a short label like "laptop" or "phone".

Click a connection to download its configuration: a small file named `postern-<label>.json`. This file contains your personal keys. Keep it private, like a password.

## Set up a client

The file works with **sslocal**, the client program from the [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust/releases) project. Two pieces of software are needed:

1. **sslocal** — download a release for your operating system from the [shadowsocks-rust releases page](https://github.com/shadowsocks/shadowsocks-rust/releases).
1. **A plugin** — a small helper program that sslocal launches automatically.

```{note}
Your operator chose one of two plugins for each connection. Ask them which one yours uses:

- **v2ray-plugin** — works with the standard [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin) binary, which also ships inside many Shadowsocks client bundles.
- **galoshes** — download the galoshes binary from [bindreams/hole releases](https://github.com/bindreams/hole/releases). Unlike v2ray-plugin, galoshes also carries UDP traffic, which some apps and games need.
```

Put the plugin program somewhere your system searches for programs (on `PATH`), or simply in the same folder as sslocal.

## Run it

Start the tunnel by pointing sslocal at your downloaded file:

```bash
sslocal -c postern-<label>.json
```

This opens a SOCKS5 proxy — a local doorway that forwards your traffic through the tunnel — at 127.0.0.1:1080 on your own computer. Nothing else changes on its own: you now tell your browser or operating system to use that doorway. Search your OS's or browser's proxy settings for "SOCKS5", then enter host `127.0.0.1` and port `1080`.

```{tip}
Keep the sslocal window open while you browse. Closing it closes the tunnel, and your traffic goes back to the regular route.
```

## Troubleshooting

- **No code email.** Check your spam folder. Wait a minute or two — email can be slow — before requesting a new code. If nothing arrives, ask your operator to check.
- **Connection fails to start or stalls.** Confirm the plugin program is installed, named exactly `v2ray-plugin` or `galoshes`, and sits on `PATH` or next to sslocal.
- **Still stuck.** Send your operator the error message from the sslocal window. They can check things from the server side.

```{seealso}
Running the server yourself? Start with [Getting started](getting-started.md) and the [admin CLI reference](operations/cli.md).
```
