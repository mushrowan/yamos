# yamos - yet another mcp obsidian server

![yamos helping haiku](assets/demo.gif)

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

## todo

- batch operations - currently everything has to be done one-note at a time
  (apart from listing notes)
- find some loser out there to do a proper security audit
- nix module :)
- cargo crate :)

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

then head over to claude.ai → settings → connectors → add custom connector, put
in your url and oauth credentials, and you're golden!

**for the full setup guide** (oauth config, claude desktop, troubleshooting,
etc): **[SETUP.md](SETUP.md)**

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

## current limitations - ping me if you're desperate for me to unlimitationify it

- can't handle encrypted vaults
- no support for attachments or binary files like images
- dynamic client registration doesn't persist - credentials are generated but
  not stored anywhere, so they won't survive a server restart

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
