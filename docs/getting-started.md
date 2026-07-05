# Getting started

This page takes you from an empty server to a verified working tunnel: install the stack, create a user, log in, and pass traffic through end-to-end.

## What you need

- **A Linux host with Docker Engine and Docker Compose v2.** Postern runs as a single-host Compose stack.

- **A public domain you control**, with DNS pointing at the host (`postern.example.com` throughout these docs).

- **A free Docker Hub account with a Personal Access Token.** The base images come from [Docker Hardened Images](https://docs.docker.com/dhi/) (`dhi.io`); the catalog is free, but pulls require authentication. Before the first build:

  ```bash
  docker login dhi.io   # Docker Hub username + PAT
  ```

- **An email delivery path.** Users log in with one-time codes sent by email, so every deployment needs outbound SMTP.

  ```{tip}
  A third-party SMTP relay (Resend, SES, Mailgun, Postmark, …) is the fastest start. The built-in MTA (the default) keeps login metadata away from third parties but has extra prerequisites: port 25 outbound (many cloud providers block it), reverse DNS (PTR), and more DNS records. See [email delivery](deployment/email.md).
  ```

- **TLS certificates at `/etc/letsencrypt/live/<domain>/`** on the host, bind-mounted into nginx. The quickest way to provision them:

  ```bash
  certbot certonly --standalone \
      -d postern.example.com \
      -d mail.postern.example.com \
      -d mta-sts.postern.example.com
  ```

  The `mail.` and `mta-sts.` SANs are required by the built-in MTA; drop them if you use a relay. Alternatively, Postern can obtain and renew a wildcard certificate itself — see [certificates](deployment/certificates.md).

## Install

1. Clone the repository:

   ```bash
   git clone https://github.com/bindreams/postern
   cd postern
   ```

1. Create your environment file from the annotated template [example.env](https://github.com/bindreams/postern/blob/main/example.env):

   ```bash
   cp example.env .env
   ```

1. Generate a `SECRET_KEY` and paste it into `.env` — the portal refuses to start with the placeholder value:

   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

1. Set `DOMAIN` in `.env`, then configure email:

   - **Third-party relay:** comment out `COMPOSE_PROFILES=with-mta` and set `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` to your provider's values.
   - **Built-in MTA (default):** set `MTA_ADMIN_EMAIL` to an external mailbox you read, and work through the prerequisites in [email delivery](deployment/email.md).

1. Build the per-connection tunnel image. Compose does not build this one — the reconciler spawns it at runtime, so it must exist first:

   ```bash
   docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .
   ```

1. Build and start the rest of the stack:

   ```bash
   docker compose up -d --build
   ```

## Create the first user and connection

There is no self-serve signup — you create users and connections with the `postern` CLI inside the portal container:

```bash
docker compose exec portal postern user add "Alice" alice@example.com
docker compose exec portal postern connection add alice@example.com "laptop"
```

`connection add` triggers an immediate reconcile, so the tunnel container appears within a few seconds. Full command reference: [CLI](operations/cli.md).

## Log in and download the config

Browse to `https://postern.example.com/`, enter the user's email address, and submit the 6-digit code from the login email. On the dashboard, click the connection to download its client config — `postern-laptop.json` for the example above.

```{important}
Login requires HTTPS. Session cookies are marked secure, so the flow cannot complete over plain `http://`.
```

## Verify the tunnel end-to-end

On the user's machine, run `sslocal` (the shadowsocks-rust client) with the downloaded config; it opens a SOCKS5 proxy on `127.0.0.1:1080`:

```bash
sslocal -c postern-laptop.json
```

From another terminal, send a request through the proxy:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

It should print your server's public IP — traffic is flowing through the tunnel. Client setup details, including the plugin binary (`v2ray-plugin` or `galoshes`) that `sslocal` needs alongside it, are in [connecting](connecting.md).

## Where to next

- [Deployment](deployment/index.md) — topology options: certificate auto-renewal, CDN edge, local gateway.
- [Operations](operations/index.md) — day-2 administration: managing users, the reconciler, logs, updates, backup.
- [Security](security.md) — the threat model of what you just deployed.
