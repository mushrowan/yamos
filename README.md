# yamos - yet another mcp obsidian server

![yamos helping haiku](assets/demo.gif)

you want your ai to be able to with your obsidian notes, right? remotely, right?
via MRP, right? i gotchu

1. set up obsidian livesync to a couchdb server
2. connect yamos to the couchdb server
3. connect your ai to yamos via MRP
4. profit

tested with claude. ymmv with other ais. if it doesn't work with other ais then
file an issue pl0x, if you are well-behaved maybe i will fix it

### disclaimer

i'm a devops girlie, not a programmer by trade. this code might suck. it might
also nuke your obsidian vault. it might also be insecure in some way i havent
considered. i have tried my best while writing this, but at the end of the day
please accept that **_you are using it at your own risk._**

if your vault has been nuked by this, feel free to raise an issue, but _i will
not help you get your vault back._ **back your stuff up.** ever heard of restic

## features

### mcp commands

- **list_notes** - list all notes in your vault, optionally filtered by path
  prefix
- **read_note** - read the content of any note
- **write_note** - create or update notes
- **append_to_note** - append content to existing notes
- **insert_lines** - insert content at a specific line number
- **delete_lines** - delete a range of lines from a note
- **delete_note** - remove notes from your vault

- **batch_read_notes** - read a bunch of notes in one go
- **batch_write_notes** - create/update multiple notes at once
- **batch_delete_notes** - nuke several notes
- **batch_append_to_notes** - append to multiple notes

all batch operations use partial success - if one note fails (bad path, doesn't
exist, whatever), the others still go through. the error comes through in the
json report to your litle ai guy

### modes

- **sse mode** (default): run as a web service that ais can talk to!
- stdio mode: run as a subprocess for **desktop ai clients**, to talk to
  whatever your local obsidian client is talking to
  - there are other obsidian mcp servers which were purpose-built for this - if
    you'll be doing this exclusively i'd recommend using one of those instead.

## todo

- find some loser out there to do a proper security audit
- cargo crate :)
- handle encrypted vaults
- support binary attachments (images and whatnot)
- ?- persist credentials? dynamic client registration doesn't persist -
  credentials are generated but not stored anywhere, so they won't survive a
  server restart. but maybe this is good

## what you'll need

so before you get started, here's what you gotta have set up:

- a couchdb instance running somewhere with obsidian-livesync all configured
- obsidian on your various devices with the livesync plugin
- for sse mode: some way to expose the server to the internet, so that the ai
  provider's servers can talk to it
  - tailscale funnel works pretty well if you don't have your own public url

## this sounds cool!!! how do i make it work

- [install and configure it](./SETUP.MD)
- connect your ai to it (e.g. ,
  - claude: claude.ai → settings → connectors → add custom connector, put in
    your url and oauth credentials **for the full setup guide** (oauth config)
- "hey ai could you use yamos to list my notes"

## ERM HOW DOES IT WORK

if you dont care about the specifics and just want your little computer friend
to look at your obsidian stuff, you can ignore this bit

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

### http endpoints (sse mode)

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

### ai is evil and uses lots of water

if you eat meat i'm here to remind you that animal agriculture uses far more

### i want to support you

send me nice messages and tell me i'm pretty and tell me i have swag

## license

mit - go cray! preferably morally good cray though. like crayfish cray

uhhh change da world! my final message: goodbye
