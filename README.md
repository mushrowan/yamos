# yamos - yet another mcp obsidian server

![yamos helping haiku to append to a note](assets/append.gif)

you want your little ai agent dude to look at your obsidian vault. your musings.
your Ponderings. but other mcp servers only work locally, and your little ai
friend can't access them remotely! woe is you! you cannot tell your little ai
buddy pal to add milk to your shopping list from your phone while you are
walking through croydon at 2am drunk on a monday morning!!

fear not little one. you had the question, i have the answer (if you use
obsidian livesync with couchdb backend)

**introducing yamos**: set up an obsidian livesync server with couchdb as the
storage backend, set up yamos (usually on the same host) with your couchdb
credentials, and then configure an mcp connector on your little ai guy. ta-daaa,
you can now get our ai overlords to interact with your notes from anywhere!!!!

tested with claude. ymmv with other ais. if it doesn't work with other ais then
file an issue pl0x, if you are well-behaved maybe i will fix it

### disclaimer

i'm a devops girlie, not a programmer by trade. this code might suck. it might
also nuke your obsidian vault. it might also be insecure in some way i havent
considered. i have tried my best while writing this, but at the end of the day
please accept that **_you are using it at your own risk._**

if your vault has been nuked by this, feel free to raise an issue, but **_i will
not help you get your vault back. back your stuff up regularly to some place
where claude can't get to it. you have been warned._**

(shoutout to restic. if you wanna back your stuff up, you cant get much better
than that)

## features

### mcp commands

- **list_notes** - list all notes in your vault, optionally filtered by path
  prefix
- **read_note** - read the content of any note
- **write_note** - create or update notes
- **append_to_note** - append content to existing notes (perfect for todos!)
- **delete_note** - remove notes from your vault

### modes

- **sse mode** (default): run as a web service for **claude.ai** - talk to
  claude on your phone while walking around and add stuff to your todos!
- stdio mode: run as a subprocess for **claude desktop**, to talk to whatever
  your local obsidian client is talking to
  - there are other obsidian mcp servers which were purpose-built for this - if
    you'll be doing this exclusively i'd recommend using one of those instead.

## what you'll need

so before you get started, here's what you gotta have set up:

- a couchdb instance running somewhere with obsidian-livesync all configured
- obsidian on your various devices with the livesync plugin doing its thing
- for sse mode: some way to expose the server to the internet (public url,
  tailscale funnel, cloudflare tunnel, whatever)

## getting started

```bash
# build the thing
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

test, make sure you can talk to the server from your ai guy, test a couple of
the tools in a chat, and then configure a service or whatever your preferred
method of daemonising is to run it persistently!

## configuration options

you can configure everything either through command line flags or environment
variables (i just stick everything in a `.env` file personally):

| cli flag             | env variable       | what it does                                     | default value              |
| -------------------- | ------------------ | ------------------------------------------------ | -------------------------- |
| `--transport`        | `MCP_TRANSPORT`    | transport mode: `sse` or `stdio`                 | `sse`                      |
| `--host`             | `MCP_HOST`         | host to bind to (sse mode)                       | `localhost`                |
| `--port`             | `MCP_PORT`         | port to listen on (sse mode)                     | `3000`                     |
| `--auth-token`       | `MCP_AUTH_TOKEN`   | auth token for sse mode (recommended)            | none (but you want one)    |
| `--couchdb-url`      | `COUCHDB_URL`      | your couchdb url                                 | `http://localhost:5984`    |
| `--couchdb-database` | `COUCHDB_DATABASE` | database name                                    | `obsidian`                 |
| `--couchdb-user`     | `COUCHDB_USER`     | couchdb username                                 | required                   |
| `--couchdb-password` | `COUCHDB_PASSWORD` | couchdb password                                 | required                   |
| `--public-url`       | `PUBLIC_URL`       | tells the client where to find various endpoints | none (but probably needed) |

## authentication

yamos supports two authentication modes for sse:

### oauth 2.0 (recommended!)

oauth 2.0 with jwt tokens - this is what you want for production use! it's more
secure than static tokens and works great with claude.ai.

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
OAUTH_TOKEN_EXPIRATION=3600  # 1 hour, or 0 for no expiration
```

see .env.example for a more comprehensive example

### legacy bearer token ("deprecated" - not that anyone had a chance to start using it)

simple static bearer token - easier to set up but less secure. only use this if
your ai of choice doesn't support oauth (who doesn't support oauth. it's current
year current month current day. get with the program)

```bash
OAUTH_ENABLED=false
MCP_AUTH_TOKEN=your-static-token-here
```

**note:** if you set `OAUTH_ENABLED=false` (or don't set it at all), it'll use
this mode. but seriously, use oauth if you can

### step 2: expose it to the internet

claude's servers need to be able to reach your mcp server, so you gotta expose
it somehow. here are some options:

- **public ip + reverse proxy**: like caddy or nginx
- **cloudflare tunnel**: super easy, no ports to open
- **tailscale funnel**: similar to cloudflare tunnel and it rhymes with it too

here's an example caddy config if you're going that route:

```caddy
mcp.yourdomain.com {
    reverse_proxy :3000
}
```

### step 3: connect it to claude.ai

head over to claude.ai, go to settings → connectors → add custom connector

- **name**: <whatever you want the connector to be called>
- **url**: <https://whatever.your.url.is.yippee.tld>
- _advanced settings_:
  - oauth client id: <your-oauth-client-id>
  - **oauth client secret**: <your-oauth-client-secret>

and that's it!! now you can be walking down the street, open claude on your
phone and be like "hey add milk to my shopping list" and boom, it's in your
obsidian vault!

## using it with claude desktop (stdio mode)

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

## ERM HOW DOES THE THING DO THE DO?

okay so here's the deal with how everything fits together: (if you dont care
about the specifics and just want your little computer friend to look at your
obsidian stuff, you can ignore this section)

1. the server connects to your couchdb instance (that's where obsidian-livesync
   stores all your vault data)
2. notes are stored using livesync's chunked format - content gets split into
   ~32 byte chunks stored as separate "leaf" documents
3. when you tell claude to modify a note through this mcp server, it writes the
   chunks to couchdb, and then livesync picks up the changes and syncs them to
   all your devices automatically
4. same thing in reverse - when you edit a note on any device, it syncs to
   couchdb, and then claude can see the changes

### the document format

livesync uses chunked storage. the main document references chunks:

```json
{
  "_id": "todo.md",
  "path": "todo.md",
  "children": ["h:abc123", "h:def456", "h:ghi789"],
  "ctime": 1640000000000,
  "mtime": 1640000000000,
  "size": 1234,
  "type": "plain",
  "eden": {}
}
```

each chunk is a separate document:

```json
{
  "_id": "h:abc123",
  "data": "raw string content here",
  "type": "leaf"
}
```

## http endpoints (sse mode)

**mcp endpoints:**

- `POST /` - streamable http endpoint for mcp protocol
  - from the spec docs, i couldn't really figure out whether this was expected
    to be / or /mcp or /sse. if anyone else can figure it out please let me know
  - i considered just making this endpoint the fallback, but that feels a little
    odd. but who knows, maybe that's normal

**oauth endpoints:**

- `GET /.well-known/oauth-protected-resource` - resource metadata (RFC 9728)
- `GET /.well-known/oauth-authorization-server` - auth server metadata
  (RFC 8414)
- `GET /authorize` - authorization endpoint (shows consent page)
- `POST /token` - token endpoint
- `POST /register` - dynamic client registration (RFC 7591)

## current limitations - ping me if you're desperate for me to unlimitationify it

- can't handle encrypted vaults
- no support for attachments or binary files like images
- dynamic client registration doesn't persist - credentials are generated but
  not stored anywhere, so they won't survive a server restart
- no rate limiting on auth endpoints (probably fine for personal use)

## she hack on my thing til i contribute

i use nix (btw) you should use nix it's real good if you dont use nix just do
your usual rust cargo stuff like usual

```bash
# jump into the dev shell
nix develop

# run with debug logging to see what's going on
RUST_LOG=debug cargo run -- --transport sse

# run tests (if i ever write any lol)
cargo test
```

## questions that i imagine would be frequently asked if anybody ever talked to me

### why is static bearer auth implemented

i didnt bother to check whether claude supported it before i implemented it and
then i discovered that claude doesnt supported it and then i repeatedly slammed
my head into the desk and implemented oauth

### your code sucks

yeah cry about it

### help me set up livesync

no. perish

### why rust

i am transgender

### what are these nix files

i am transgender

### why is this whole readme lowercase

i am transgender

### why are you gay

i am transgender

### why

i am transgender

### ai is evil and uses lots of water

if you eat meat i'm here to remind you that animal agriculture uses far more

### i want to support you

send me nice messages and tell me i'm pretty and tell me i have swag

## license

mit - go cray! preferably morally good cray though. like crayfish cray

uhhh change da world! my final message: goodbye
