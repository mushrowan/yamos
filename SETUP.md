# setting up yamos

this guide assumes you already have:

- a couchdb instance running somewhere with obsidian-livesync synced up to it
  - [the livesync repo](https://github.com/vrtmrz/obsidian-livesync) has a guide
    on this
- for sse mode: some way to expose the server to the internet (public url,
  tailscale funnel, cloudflare tunnel, whatever)

## installing from release

TODO: i haven't actually put this on cargo or anything like that yet because i'm
lazy. for now, build from source

## building the thing

```bash
# build the thing - obviously you'll need rust+cargo installed
cargo build --release

# make a little directory for it
mkdir -p /opt/yamos

# copy the stuff over
cp target/release/yamos /opt/yamos
cp .env.example /opt/yamos/.env

# fill in your stuff here! for how to do it, see next section.
# replace vi with nano if you're a pleb
# replace vi with helix if you're a psychopath
vi /opt/yamos/.env

cd /opt/yamos

# run the thingy!
./yamos

# or if you want stdio mode for claude desktop:
./yamos --transport stdio
```

the tools in a chat, and then configure a service or whatever your preferred
method of daemonising is to run it persistently!

## configuration options

you can configure everything either through command line flags or environment
variables (i just stick everything in a `.env` file personally):

| cli flag             | env variable       | what it does                                      | default value              |
| -------------------- | ------------------ | ------------------------------------------------- | -------------------------- |
| `--transport`        | `MCP_TRANSPORT`    | transport mode: `sse` or `stdio`                  | `sse`                      |
| `--host`             | `MCP_HOST`         | host to bind to (sse mode)                        | `localhost`                |
| `--port`             | `MCP_PORT`         | port to listen on (sse mode)                      | `3000`                     |
| `--couchdb-url`      | `COUCHDB_URL`      | your couchdb url                                  | `http://localhost:5984`    |
| `--couchdb-database` | `COUCHDB_DATABASE` | database name                                     | `obsidian`                 |
| `--couchdb-user`     | `COUCHDB_USER`     | couchdb username                                  | required                   |
| `--couchdb-password` | `COUCHDB_PASSWORD` | couchdb password                                  | required                   |
| `--public-url`       | `PUBLIC_URL`       | tells the client where to find various endpoints  | none (but probably needed) |
| `--base-path`        | `BASE_PATH`        | tells the server that we are hosting at a subpath | none                       |

### oauth-specific options

| cli flag                            | env variable                      | what it does                                       | default value        |
| ----------------------------------- | --------------------------------- | -------------------------------------------------- | -------------------- |
| `--oauth-enabled`                   | `OAUTH_ENABLED`                   | enable oauth 2.0 authentication                    | `false`              |
| `--oauth-jwt-secret`                | `OAUTH_JWT_SECRET`                | jwt signing secret                                 | required if oauth on |
| `--oauth-client-id`                 | `OAUTH_CLIENT_ID`                 | oauth client id                                    | required if oauth on |
| `--oauth-client-secret`             | `OAUTH_CLIENT_SECRET`             | oauth client secret                                | required if oauth on |
| `--oauth-token-expiration`          | `OAUTH_TOKEN_EXPIRATION`          | access token lifetime in seconds (0=never)         | `3600` (1 hour)      |
| `--oauth-refresh-token-expiration`  | `OAUTH_REFRESH_TOKEN_EXPIRATION`  | refresh token lifetime in seconds                  | `2592000` (30 days)  |
| `--oauth-strict-rotation`           | `OAUTH_STRICT_ROTATION`           | invalidate token family on refresh token reuse     | `false`              |
| `--auth-token`                      | `MCP_AUTH_TOKEN`                  | legacy static bearer token                         | none                 |

#### refresh tokens

yamos supports oauth refresh tokens with automatic rotation. when you
authenticate, you get both an access token (short-lived, default 1 hour) and a
refresh token (long-lived, default 30 days). when the access token expires,
clients can use the refresh token to get a new access token without
re-authenticating.

**token rotation:** each time a refresh token is used, a new refresh token is
issued and the old one is invalidated. this limits the damage if a refresh token
is stolen.

**reuse detection:** if someone tries to use an old refresh token after it's
been rotated, yamos detects this as potential token theft. by default, it logs a
warning and rejects the request. if `OAUTH_STRICT_ROTATION=true`, it also
invalidates all tokens in that session, forcing re-authentication.

**grace period:** there's a 30-second grace period after rotation where the old
token still works. this handles race conditions if a network request retries.

## authentication

yamos supports two authentication modes for sse mode:

### oauth 2.0 (recommended!)

oauth 2.0 with jwt tokens - the preferred option, the only option for some ai
providers (claude)

**setup:**

1. generate your secrets:

```bash
# jwt secret (used to sign tokens)
openssl rand -hex 64

# client secret
openssl rand -hex 32
```

2. add to your `.env`:

```bash
OAUTH_ENABLED=true
OAUTH_JWT_SECRET=your-generated-jwt-secret
OAUTH_CLIENT_ID=mcp-client # not particularly important, set it to whatever
OAUTH_CLIENT_SECRET=your-generated-client-secret
OAUTH_TOKEN_EXPIRATION=3600  # 1 hour access token
OAUTH_REFRESH_TOKEN_EXPIRATION=2592000  # 30 days refresh token
```

see `.env.example` for a more comprehensive example

### bearer token

you can do this, but i'm not gonna bother documenting it because it's pretty
self explanatory - and you probably shouldnt be using it

## exposing it to the internet (sse mode)

claude's servers need to be able to reach your mcp server, so you gotta expose
it somehow. here are some options:

- **public ip + reverse proxy**: like caddy or nginx
- **cloudflare tunnel**: super easy, no ports to open
- **tailscale funnel**: similar to cloudflare tunnel and it rhymes with it too

## EXAMPLE: connecting to claude.ai

head over to claude.ai, go to settings → connectors → add custom connector

- **name**: whatever you want the connector to be called
- **url**: https://whatever.your.url.is.yippee.tld
- _advanced settings_:
  - oauth client id: your-oauth-client-id
  - **oauth client secret**: your-oauth-client-secret

when you hit "connect" you'll be prompted with an oauth authorization screen!

## using with claude desktop (stdio mode)

if you want to use this with claude desktop on your computer, just add it to
your claude desktop config file at
`~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "obsidian": {
      "command": "/path/to/yamos",
      "args": ["--transport", "stdio"],
      "env": {
        "COUCHDB_URL": "https://your-server.com/couchdb",
        "COUCHDB_DATABASE": "obsidian",
        "COUCHDB_USER": "admin",
        "COUCHDB_PASSWORD": "your-password"
      }
    }
  }
}
```

note: you don't need an auth token for stdio mode since it's running locally as
a subprocess!

another note: i dont really use this functionality. it's probably buggy as it
hasnt been tested much (soz)

## "i use nix btw"

if you use nix, the setup is a lot simpler. because nix is better than anything
else :)

the flake.nix in this repo exposes a module you can add as your own flake input:

```nix
# flake.nix
{
  inputs = {
    yamos = {
      url = "github:mushrowan/yamos";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
}
```

at some point in your config you can then import the module and configure it.
here's my configuration at the time of writing (using sops.nix for the secrets,
but you can do it however you want):

```nix
{ config, lib, yamos, ... }:
{
  imports = [ yamos.nixosModules.default ];

  sops.secrets = {
    yamos-oauth-jwt-secret = {};
    yamos-oauth-client-secret = {};
    couchdb-admin-pass = {};
  };
  sops.templates."yamos.env" = {
    content = ''
      COUCHDB_PASSWORD=${config.sops.placeholder.couchdb-admin-pass}
      OAUTH_JWT_SECRET=${config.sops.placeholder.yamos-oauth-jwt-secret}
      OAUTH_CLIENT_SECRET=${config.sops.placeholder.yamos-oauth-client-secret}
    '';
    owner = config.services.yamos.user;
    group = config.services.yamos.group;
  };

  services.yamos = {
    enable = true;
    settings = {
      # config such as COUCHDB_URL will be automatically grabbed from the
      # services.couchdb configuration if you have it. else, provide it here.
      PUBLIC_URL = "my cool public url";
    };
    environmentFile = config.sops.templates."yamos.env".path;
  };
}
```

## troubleshooting

### "connection refused" errors

- check couchdb is running
- verify credentials in `.env` or cli args
- check database exists: `curl http://couchdb-uri/obsidian`

### "note not found" errors

- verify the note path matches exactly (case-sensitive)
- check the note exists in couchdb
- if all else fails, there may be some data corruption on the database. the
  obsidian livesync plugin is pretty good at dealing with this though, go into
  the plugin settings doctor tab and rebuild the database from local.

### sse mode not working

- check the server is listening: `ss -tlnp | grep 3000`
- verify firewall allows the port
- check logs for binding errors
- ensure no other service is using the port

### oauth "missing or invalid authorization header"

this is the error you'll see when oauth isn't working. check:

- is `OAUTH_ENABLED=true` set?
- are all required env vars set? (`OAUTH_JWT_SECRET`, `OAUTH_CLIENT_ID`,
  `OAUTH_CLIENT_SECRET`)
- is `PUBLIC_URL` set correctly? (needs to be the externally-reachable url)
- can claude.ai reach your server? (check firewall, reverse proxy)
- try hitting `/.well-known/oauth-protected-resource` directly to verify

### stdio mode hangs

- check for errors in stderr logs
- verify claude desktop config is correct
- ensure environment variables are set
- try with `RUST_LOG=debug` for verbose logging
