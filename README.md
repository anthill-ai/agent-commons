# agent-commons

agent-commons is a coordinator that lets many people's AI agents build one
project together, with each person's reputation as the stake. Everyone runs
agents. Agents propose work, write specs, implement, and review each other.
Trust does not come from any single agent being good. It comes from
independence: every change is reviewed by agents of randomly drawn owners who
are socially distant from the author in the project's trust tree, run other
model families, and have their own reputation at stake. Verdicts that matter
are mechanical: a bug counts only when a test reproduces it. Humans stop doing
routine review. They become the court of appeal and the kernel sign-off for the
few files that decide how reputation is computed and how changes are judged.

A commons can be linked to an Anthill community (`init --anthill-community`):
then Anthill is the identity. Members join as their Anthill user, with
Anthill's signed word that their key is theirs (or that an agent is theirs:
a member can connect an agent from the community's Agents page on Anthill
without holding an owner key at all), and reviewers are drawn by
distance in the community's Anthill tree, which the coordinator pins in the
ledger whenever it changes ([`src/anthill.ts`](src/anthill.ts), and
"Linked to Anthill" below). Every draw stays verifiable from the ledger alone,
because the pinned trees are in it.

Unlinked, identity is the commons' own: the ledger's `ownerKey` entries. Each one
names the owner who vouched for the newcomer (its inviter) or none, and those
invites form the trust tree that reviewer selection and bounties measure
distance in ([`src/members.ts`](src/members.ts)). Nothing outside the ledger
decides who is a member or who is close to whom, so anyone holding the ledger
can recompute every reviewer draw. Reputation is per-project commons
reputation (`OwnerState.reputationDelta`, the sum of settlements): it backs
stakes (on top of `rules.stake.allowance`) and sets PR slots.

The commons works on any git repository. Each target project declares its own
kernel (ring 0) paths in its `.commons/rules.json`
([protocol §4](docs/protocol.md#4-rings)); the built-in rules know only what is
kernel in every repository (the commons config, CI, build and deploy files).

## Status

Early. Phase 1 is 3–10 trusted people: the admin admits each one with an
`ownerKey` entry (`commons owner add`; those entries are the allowlist), and
the group runs the `phase1` rules preset. Reputation is commons reputation
only. No money moves, and none is planned for Phase 1. In Phase 1 a human
approves every merge to `dev` with a ledger entry (`commons approve`), an
operator confirms or dismisses every reproduced finding (`commons finding
confirm|dismiss`), and `main` moves when a snapshot passes the promotion rule
under the preset (see
[protocol §5.11](docs/protocol.md#511-promotion-rule--main)). Use the
`phase1` preset: owners admitted with no inviter are all at distance 2 from
each other, so under the default rules (`minTreeDistance` 2) nobody is
eligible to review ([§5.6](docs/protocol.md#56-reviewer-assignment)).
The checklist for a first Phase 1 week is in [HANDOFF.md](HANDOFF.md).

Before a group exists, one person can test the whole loop alone with the
`solo` preset (`init --preset solo`, or `COMMONS_PRESET=solo` for `commons
host`): their own agents of two model families review each other (never the
author, never the author's family), promotion needs no kernel sign-off, and
merges need no `commons approve` unless a reviewer flags a defect. The
ledger's rules say `mode: "solo"`, and `GET /api/head` and every playground
page say "solo test: your own agents review each other": it is not
independent review. An admin leaves it with one command, `commons rules set
--preset phase1 --admin-key admin.json --kernel-signer <id> ...`
([protocol §1.2](docs/protocol.md#12-solo-one-person-testing-alone)).

| Part | State |
| --- | --- |
| `crypto`, `rules`, `ledger`, `members` (the trust tree) | Written, tested |
| `findings` (reproduction harness) | Written, tested |
| `gates/*` (rings, airlock, size, specSeparation) | Written, tested |
| `selection`, `review`, `plants`, `risk` | Written, tested |
| `incentives`, `promotion`, `metrics` | Written, tested |
| `coordinator` (planner and executor), `server` (HTTP API for agents) | Written, tested |
| `github` (diff → branch and PR bridge) | Written, tested; not yet wired into `serve` / `coordinator run-once`, which merge in the coordinator's own clone (`--repo`: dev and main move there; the operator pushes them) |
| `client`, `agent-kit/` | Written, tested. The participant side of the API |
| `playground` (read-only site) | Written, tested |
| `cli.ts` (`commons` command) | Written, tested |
| Checking who a new owner is | Not built. The admin-key holder checks by hand and signs `owner add` |
| Honeytoken placement and detection | Not built. Only the ledger entry and the penalty exist |
| Appeals to humans | Not built. No entry kind records an appeal or its outcome |

The documents in `docs/` describe the protocol; where they and the code
disagree, the code wins. Known gaps are listed in
[protocol §9](docs/protocol.md#9-not-built).

## Quickstart

You can run the tests, build a local ledger with the CLI, and serve the
playground and the coordinator API from it. Node 22 or later. No runtime
dependencies beyond Node's standard library.

```bash
npm install
npm test                                       # every suite in test/
node --import tsx --test test/ledger.test.ts   # one suite
```

`npm run check` runs the type check and every suite. No environment variables
are needed; the only skipped tests are the Linux-only sandbox tests.

### Phase 1: three people

One person holds the admin and coordinator keys; each of the three holds an
owner key and runs an agent. Here everything is in one directory for brevity;
in real use each owner keeps their owner key to themselves
([docs/running-an-agent.md](docs/running-an-agent.md)).

```bash
mkdir -p keys
for k in admin coord alice bob carol alice-agent bob-agent carol-agent; do
  npm run -s commons -- keygen --out keys/$k.json
done

# The target project's rules: the generic defaults plus its own kernel. Here
# src/** is ring 0 (needs a task, a claim and a kernel signoff); a project
# usually commits this file as .commons/rules.json.
node --import tsx -e 'import("./src/rules.ts").then(({ defaultRules }) => {
  const r = defaultRules(); r.rings.unshift({ glob: "src/**", ring: 0 });
  console.log(JSON.stringify(r, null, 2)); })' > rules.json

# The Phase 1 preset on top: minTreeDistance 1, 2 reviewers, other model
# family required, 1 kernel signoff, a 7-day vesting tail. Name two kernel
# signers: a signer may not sign off a snapshot holding its own ring-0 work,
# and with one signer the first src/** change of theirs would freeze main.
npm run commons -- init --project demo --admin-key keys/admin.json --coordinator-key keys/coord.json \
  --rules rules.json --preset phase1 --kernel-signer alice --kernel-signer bob
# The admin's owner entries are the allowlist. With no --inviter every owner
# hangs under the commons root, so every pair is at distance 2 and the draw
# is uniform among the non-authors; --inviter alice would put the newcomer
# under alice (distance 1 from her: she can neither review its work nor win
# a bounty on it).
for o in alice bob carol; do
  npm run commons -- owner add --key keys/admin.json --owner $o --owner-key keys/$o.json
done
npm run commons -- agent register --key keys/alice.json --owner alice --agent-key keys/alice-agent.json --model-family claude --harness claude-code
npm run commons -- agent register --key keys/bob.json --owner bob --agent-key keys/bob-agent.json --model-family gpt --harness codex
npm run commons -- agent register --key keys/carol.json --owner carol --agent-key keys/carol-agent.json --model-family gemini --harness gemini-cli

# The coordinator's clone of the target, with a dev branch: every base must
# be on dev, and merges land there (the operator pushes dev and main).
git clone <target repository URL> ../target
git -C ../target branch dev origin/main

# alice's agent submits a change made on top of dev (here: a docs file,
# ring 1, so it needs no task; a src/** change is ring 0 and needs a task and
# a claim).
git -C ../target checkout -q -b fix-1 dev && echo "notes" > ../target/NOTES.md
git -C ../target add NOTES.md && git -C ../target commit -qm "add notes"
npm run commons -- submit --key keys/alice-agent.json --id fix-1 --repo ../target --base dev --head fix-1
# The coordinator binds the patch, gates it and draws reviewers over the
# ledger's member tree (bob's and carol's agents): run it until it says
# "nothing to do".
npm run commons -- coordinator run-once --key keys/coord.json --repo ../target
npm run commons -- review commit --key keys/bob-agent.json --submission fix-1 --probability 0.1 --summary "looks fine"
# ... carol commits too; reveals wait until both assigned reviewers committed
# (or 12 hours passed), so one early reveal cannot shut a seat out.
npm run commons -- review reveal --key keys/bob-agent.json --submission fix-1
# Then a human approves the merge (a ledger entry), and the next pass merges
# fix-1 onto dev in the coordinator's clone.
npm run commons -- approve --key keys/admin.json --submission fix-1   # the admin, or a kernel signer who is not the author's owner
# --snapshot-every N makes a snapshot once N merges are outside one: without
# it nothing is ever snapshotted, so nothing is promoted and main never moves.
npm run commons -- coordinator run-once --key keys/coord.json --repo ../target --snapshot-every 1
npm run commons -- serve   # the playground on :8080
```

Everyone starts with `rules.stake.allowance` points of stake (370 in the
Phase 1 preset: the largest claim, 320, plus headroom for reviews and
findings) and one open PR slot (slots grow with commons reputation). Phase 1
recall bounds are wide: ten plants, all caught, are the least that passes the
preset's recall and critical-bound checks; one miss fails them until there are
twelve seeds.

### Linked to Anthill

The commons of an Anthill community (here `builders`). Anthill signs the
community's tree and vouches for members' keys with its own key
(anthill-backend `src/commonsLink.ts`); the ledger records that key at `init`.

```bash
# the coordinator's operator: a ledger linked to the community
npm run commons -- init --project builders --admin-key admin.json --coordinator-key coord.json \
  --preset phase1 --anthill-community builders --anthill-url https://<anthill backend>
# serve, pinning Anthill's tree whenever it changed, every pass
npm run commons -- serve --key coord.json --coordinator --loop-seconds 30 --anthill-url https://<anthill backend>

# a member: sign in on the Anthill site, copy the session (localStorage
# anthill.session), and have Anthill vouch for your owner key
npm run commons -- keygen --out owner.json
npm run commons -- anthill join --anthill-url https://<anthill backend> --community builders \
  --session <token> --owner-key owner.json --url http://<coordinator API>
```

Members who work from a browser and a sandboxed agent need no owner key: on
the community's Agents page on Anthill they copy a prompt into their agent,
the agent makes its own key and pairs with a one-time code (`commons-agent
pair`, [agent-kit/README.md](agent-kit/README.md#joining-from-anthill)), the
member approves the fingerprint on the website, and Anthill signs an agent
attestation that the coordinator relays (`POST /api/anthill/agent`, an
`anthillAgent` entry). That admits the member as an owner with no key of
their own, if they were not one yet; revoking on the website relays an
`anthillAgentRevoked` entry. `GET /api/agents?owner=<id>` lists a member's
agents. Anthill can already vouch for any member's owner key, so this adds
no trust; a member who later wants an owner key gets one with `anthill join`.
Anthill signs an agent attestation for each relay, and the ledger takes one
only within 10 minutes before its entry and 5 minutes after it (Anthill's
clock may run ahead): keep Anthill's and the coordinator's clocks within 5
minutes of each other. Nothing in an attestation names the ledger, so this
window is what keeps an old one (they are public in the ledger) out of a
ledger re-created for the community; after a re-creation, agents pair again.

Owner ids are Anthill user ids. An owner who is not in the latest pinned
tree (they left the community, or joined it after the last pin) gets no review
seat and no distance-based reward; their own work gets reviewers once a pin
includes them. `anthill sync` pins by hand, `anthill admit` appends an
attestation without a running coordinator, and `anthill tree` shows what
Anthill would sign now. Reputation stays commons reputation: Anthill's is not
read.

### Hosting a coordinator for an Anthill community

A hosted coordinator serves its API and the playground on one port, and
keeps everything in one data directory: the ledger, the keys, the patches
and its clone of the target repository. `commons host` does all of it: on
its first start (no ledger yet) it sets itself up, then serves.

```bash
commons host --data <dir> --host <address> --port <port> \
  --anthill-url <Anthill backend URL> --community builders \
  --target-repo https://github.com/org/repo --kernel-signer 0x... --kernel-signer 0x...
```

Each setting is also read from the environment (a flag wins):

| Variable | Flag | |
| --- | --- | --- |
| `ANTHILL_URL` | `--anthill-url` | required: the Anthill backend's own URL (the API, e.g. `https://api.anthill.example`, not the website) |
| `COMMONS_TARGET_REPO` | `--target-repo` | required for setup: the public https URL of the repository to build. Checked strictly: https only, no `user:token@`, no query or fragment (it is logged and shown to every agent) |
| `COMMONS_KERNEL_SIGNERS` | `--kernel-signer` | required for setup (not with preset `solo`): Anthill user ids (`0x` and 40 hex digits), comma-separated in the variable. At least one; name two (below) |
| `ANTHILL_COMMUNITY` | `--community` | default `builders` |
| `COMMONS_PROJECT` | `--project` | the genesis project id; default the community |
| `COMMONS_PRESET` | `--preset` | setup only: `phase1` (default), `solo` (one person testing with their own agents, below) or `none` |
| `COMMONS_RULES_PRESET` | `--rules-preset` | over an existing ledger, once per value: switch its rules to `phase1` or `solo` unless they already are it (an admin-signed `rulesChange` with `<data>/keys/admin.json`; with `COMMONS_KERNEL_SIGNERS` set, those become the kernel signers). `<data>/rules-preset.json` records the value applied, so later starts with the same value do nothing and never revert a rule change an admin made since (they log it); change the value to apply a preset again. Leaving solo is refused while solo-reviewed work is merged but not on main, or an open submission waits on a seat only the author's own agent could fill: the start then serves under the rules as they are, logs what is stranded, and tries again next start |
| `COMMONS_RULES_FORCE` | `--rules-force` | `1`: switch with `COMMONS_RULES_PRESET` even so (`rules set --force`; main then freezes until solo is re-entered and that work promoted) |
| `COMMONS_SNAPSHOT_EVERY` | `--snapshot-every` | merged submissions that trigger a snapshot, `0` never; default `1` on a solo ledger (nobody else would snapshot it, so nothing would be promoted), never otherwise. Tasks the operator approves go in `<data>/approved-tasks.json` (a JSON array of task bodies; absent is none), which every coordinator pass re-reads |
| `COMMONS_BASE_PATH` | `--base-path` | serve under a path behind a reverse proxy, e.g. `/commons/builders` |
| `COMMONS_PUBLIC_URL` | `--public-url` | the public URL, for the `COMMONS_SITES` line; default `RENDER_EXTERNAL_URL` plus the base path |
| `COMMONS_FOLLOW_UPSTREAM` | `--follow-upstream` | `1` (default): every coordinator pass fetches the target's `main` from its origin and brings it into `dev` (a fast-forward, else a merge commit; a conflict leaves `dev` alone and is logged once), so commits pushed to the target after setup are valid bases. `0`: `dev` moves only by merges |
| `COMMONS_PUSH_UPSTREAM` | `--push-upstream` | `1`: after every coordinator pass, push the clone's `dev` and `main` to the target on GitHub when they changed (below, "Pushing to GitHub"). Default off: nothing leaves the clone |
| `COMMONS_GITHUB_TOKEN` | none | the token `COMMONS_PUSH_UPSTREAM` pushes with. Only ever read from the environment: no flag, never logged, never in a URL or a command line |
| `COMMONS_EMBEDDED` | `--embedded` | `1`: run by a parent that proxies it and lists its site itself (Anthill's backend, one child per community): setup prints no `COMMONS_SITES` line |

Setup, in order, each step safe to repeat after a crash at any point
(`src/host.ts`):

1. Asks Anthill for its signing key and the community's tree, and checks
   the tree's signature: the genesis is permanent, so a mistyped backend or
   community fails here.
2. Clones the target into `<data>/target` with a `dev` branch from
   `origin/main` (or the remote's default branch). The clone is made in
   `target.partial` and renamed once `dev` exists, so a clone cut off midway
   is detected and made again.
3. Makes the coordinator and admin keys in `<data>/keys` (0700, the files
   0600), unless they exist: a key is never overwritten.
4. Takes the genesis rules from the target's `.commons/rules.json` on `dev`
   if it has one, or the generic defaults (the log says which). Without one
   the target's own kernel (auth, state, contracts) is ring 1, judged like
   any other code: commit one to the target before the first start (see
   the local example below; this repository's own is
   [`.commons/rules.json`](.commons/rules.json)).
5. Runs `init` linked to the community, with the preset and the kernel
   signers, writing the genesis to a temporary file that becomes the ledger
   only when whole. The ledger is never overwritten, and its existence is
   what says setup is done.

**Where agents get dev.** Merges land on `dev` in `<data>/target`, and
promotions move `main` there; by default neither is pushed to the target's
GitHub repository (the coordinator holds no credentials; "Pushing to
GitHub" below turns that on). Both are served
read-only over git's smart HTTP protocol at `<public URL>/api/git` (only
`refs/heads/dev` and `refs/heads/main` are listed; a push is refused), and
`commons-agent fetch-dev` fetches them into `refs/remotes/commons/*`. The
role files tell agents to base their work there: a spec writer's merged
acceptance tests are on that dev, and reach GitHub only through the mirror
or someone pushing them.

**Pushing to GitHub** (`COMMONS_PUSH_UPSTREAM=1`, with
`COMMONS_GITHUB_TOKEN`; `src/mirror.ts`). At the end of every coordinator
pass, `dev` and `main` in the clone are pushed to the same names on the
target (the clone's `origin`, which must be `https://github.com/<owner>/<repo>`)
when they differ from what GitHub was last seen to hold (`git ls-remote`
at the first pass, then each push that succeeded). It is a plain push,
never forced: a push GitHub refuses (its branch moved, branch protection,
the token) is logged once per branch, commit and reason, retried every
pass, and never fails the pass or stops the coordinator. When the owner
pushes to GitHub's `main` meanwhile, `main` is refused until the next pass
brings that `main` into `dev` (`COMMONS_FOLLOW_UPSTREAM`) and the next
promotion moves `main` to a commit that holds it; then it goes up as a
fast-forward. The mirror's own pushes are already on `dev`, so following
upstream finds nothing new in them. A missing token or a target that is not
a GitHub https URL is reported by `--check` and at the start, and the
coordinator serves on without pushing.

**Members' forks** (`src/forks.ts`; protocol §5.4). An agent may push its
submission's head commit to its owner's fork on `agents/<keyId>/<id>` and
register it (`commons-agent submit --fork`). When the clone's origin is on
GitHub the API takes such registrations; the coordinator fetches the branch
anonymously, with a hardened and size- and time-limited git, checks it is
exactly the submitted change, and later merges that commit itself. With the
mirror on and a token that also has Pull requests write, it opens a pull
request from the fork's branch to `dev` after the push, and comments when the
submission merges (GitHub marks the pull request merged once `dev` holds the
commit) or closes it when it can no longer merge. Without that permission it
says so once and goes on.

- The token: a fine-grained personal access token (of a bot account,
  ideally) for the one repository, with **Contents: read and write** and
  nothing else (add **Pull requests: read and write** for pull requests
  from members' forks, below): no Workflows (GitHub then refuses a push that changes
  `.github/workflows/`, so such a merged change reaches GitHub only when a
  person pushes it; until then that branch's push is refused and logged),
  no Administration, no other repository. Set it in the service's
  environment as a secret (on Render, in the dashboard), never in a file
  in the repository.
- Branch protection on `main` and `dev` must let that account push (a
  bypass or an allow-list entry for it), or every push is refused and
  logged; it is never forced, so protection that refuses force pushes
  costs nothing.
- How it reaches git: through the environment only (`GIT_CONFIG_COUNT`,
  `GIT_CONFIG_KEY_n`, `GIT_CONFIG_VALUE_n`: an `Authorization` header scoped
  by `http.https://github.com/.extraheader`, redirects off and TLS
  verification on for github.com, credential helpers off, the system and
  global git config not read, no prompts, tracing and `GIT_SSL_NO_VERIFY`
  dropped), never in a URL, an argument list or a log line. A target URL
  that carries credentials or a query is reported as such, never echoed.
- The blast radius: the coordinator now holds a write credential. Anyone who
  controls its process or reads its environment (the Render dashboard and
  shell, a compromised dependency of this code) can push anything the token
  may push to that repository, up to what branch protection allows; reading
  and rotating it are the operator's to guard. It reaches nothing else: not
  other repositories, not workflows, not settings.
- Phase 1 still runs no repository code: the mirror only pushes commits that
  are already in the clone, with hooks off; what is pushed is what the
  ledger merged and promoted.

The port answers 503 while it works, and a step that may succeed later (the
network, Anthill, the git host) is retried with backoff. Then the log prints
the public URL and the exact value for `COMMONS_SITES` on the anthill-backend
service:

```json
{"builders":{"coordinator":"https://<this service>.onrender.com","site":"https://<this service>.onrender.com","repo":"https://github.com/org/repo"}}
```

(If `COMMONS_SITES` already holds other communities, add this key to its
object.) The key is the community id. Without `repo`, the instructions
Anthill gives agents (agent.md) tell every agent to ask its owner where the
target repository is. The first pass pins the community's tree.

**Kernel signers.** They sign off ring-0 changes, and none of those (CI,
`*.yml`, `tsconfig*` are ring 0 by default) is ever promoted while the list
is empty. Name two. A signer may not sign off a snapshot holding their own
ring-0 work, so with a single signer, once a ring-0 change of theirs (or of
an agent of theirs) merges to `dev`, no snapshot holding it can be signed
off and main stops moving, until an admin-signed `rulesChange` (`commons
rules set --kernel-signer`) or a new ledger adds a second signer. The log warns at
setup when there is only one; until a second exists, that signer should
keep their own work out of ring 0. Signing off takes an owner key, so
signers must be members who join with `anthill join`; owners admitted only
through the Agents page have no key and cannot sign off.

**Testing alone** (`COMMONS_PRESET=solo`, no `COMMONS_KERNEL_SIGNERS`
needed): the genesis takes the `solo` preset on top of the target's rules,
so the operator's own agents, paired through the Agents page with two model
families, review each other and the loop runs end to end with nobody else:
the coordinator snapshots after every merge (`COMMONS_SNAPSHOT_EVERY`) and
promotes once the soak passes (one hour under solo, not Phase 1's day).
Each agent's submissions are assigned to your other agent (the other model
family): that is expected in solo, and `commons-agent head` prints
`mode: "solo"` and the notice to say so. Pair both agents before the first
submission: an agent paired after a submission is never drawn for it, and a
solo submission no reviewer can reach (that, or a seated agent that did not
commit within `review.commitHours`, 12) is closed with a failed `review`
gate so it frees its slot, and is resubmitted. So is a flagged one: a revealed
review at p ≥ 0.5 needs a `mergeApproval`, which your own owner may not sign
and nobody without the admin key can, so a flagged solo submission no one
approves within an hour is closed the same way. Tasks come from
`<data>/approved-tasks.json` (written with the Render shell) or `commons task`.
Solo rules are frozen in the ledger like any rules: a ledger set up by an
older commons keeps that version's solo preset (a 24-hour soak, before the
hour), and the start logs `note: this ledger's solo rules are an older solo
preset (...)`. Set `COMMONS_RULES_PRESET=solo` once and restart to apply
today's.
To leave solo (the group arrives, or the test is over), set
`COMMONS_RULES_PRESET=phase1` and `COMMONS_KERNEL_SIGNERS`, and restart: the
start appends the `rulesChange` before serving (it stops with an error if
`<data>/keys/admin.json` is gone). With a shell, `npm run commons -- rules
set --data /var/data --preset phase1 --kernel-signer 0x... --kernel-signer
0x...` does the same while the service runs. Promote first: Phase 1 counts
no review by the author's own agents, nobody can add a review to merged work
or attest a snapshot whose commit phase ended, and every later snapshot
holds that work, so solo-reviewed work merged but not on main would freeze
main for good (until solo is re-entered and it is promoted). Both paths
refuse to leave solo while such work exists, or while an open submission
waits on a seat only the author's own agent could fill (it must be
resubmitted), and list it; `--force` (`COMMONS_RULES_FORCE=1`) leaves anyway.
Leaving solo also returns every owner to the starter submit credit (never
into debt for solo-era submissions) and one base PR slot.

**The admin key** stays on the disk (`<data>/keys/admin.json`) by default.
An Anthill-linked ledger rarely needs it (Anthill admits owners), so you can
move it off later: copy the file somewhere safe (a password manager), check
that its `publicKey` is in the genesis's `admins` (the ledger's first line;
the setup log printed its key id), and delete it from the disk (`rm
/var/data/keys/admin.json` in the Render shell). Anything an admin signs
later (`owner add`, say) is then signed on your machine and appended
through the shell or the API. Disk snapshots keep it until they
expire.

#### On Render, from the dashboard only

[`render.yaml`](render.yaml) is a Render blueprint: one web service with a
disk at `/var/data`, whose start command
([`scripts/render-start.sh`](scripts/render-start.sh)) runs `commons host
--data /var/data --host 0.0.0.0 --port $PORT --trusted-proxy 10.0.0.0/8
--hold-on-failure`.

1. Create the service from the blueprint on the branch that holds
   `render.yaml` (`main`).
2. When the dashboard asks for the `sync: false` values, set:
   - `ANTHILL_URL`: the Anthill backend's URL;
   - `COMMONS_TARGET_REPO`: e.g. `https://github.com/kelemeno/agent-commons`;
   - `COMMONS_KERNEL_SIGNERS`: e.g. `0x...,0x...`.

   `ANTHILL_COMMUNITY` (`builders`) and `COMMONS_PRESET` (`phase1`) come
   with the blueprint.
3. Deploy. The log shows the setup, then the `COMMONS_SITES` value: paste
   it into the anthill-backend service's `COMMONS_SITES` (a `sync: false`
   variable, in its dashboard).

With a setting missing or invalid, the service keeps a 503 holder up and the
log names exactly which variables are missing or what is wrong with them.
Changing a variable restarts the service, which then sets itself up.

The Render shell is the alternative: without the settings, set up by hand,
in this order (the holder exits once the ledger, the key and the clone's
`dev` branch all exist, and Render restarts the service into `commons
host`, which ends the shell session):

```bash
cd /opt/render/project/src
git clone <target repository URL> /var/data/target
git -C /var/data/target branch dev origin/main
npx tsx src/cli.ts keygen --out /var/data/keys/coord.json
npx tsx src/cli.ts keygen --out /var/data/keys/admin.json   # or keep the admin key on your own machine and pass its public key
npx tsx src/cli.ts init --ledger /var/data/commons-ledger.jsonl --project builders \
  --admin-key /var/data/keys/admin.json --coordinator-key /var/data/keys/coord.json \
  --rules /var/data/target/.commons/rules.json --preset phase1 \
  --kernel-signer <Anthill user id> --kernel-signer <Anthill user id> \
  --anthill-community builders --anthill-url "$ANTHILL_URL"
```

(If the restart cut off something you were still running, finish it in a
new shell; an interrupted clone: `rm -rf /var/data/target` and clone again.)

#### As a child process of another service

A parent (the Anthill backend, say) can run `commons host` itself, with its
own data directory, on `127.0.0.1` and a port of its own, and proxy
`https://<parent>/commons/<community>/...` to it with the full path:

```bash
commons host --data "$DATA_DIR/commons/builders" --host 127.0.0.1 --port 5101 \
  --base-path /commons/builders --trusted-proxy loopback \
  --public-url https://<parent>/commons/builders \
  --anthill-url <the parent's own URL> --target-repo <URL> --kernel-signer 0x...
```

The API then answers at `<base path>/api/...` (agents use
`https://<parent>/commons/builders` as the coordinator URL), the playground
at `<base path>/` with every link and asset under it, the bare base path
redirects to it with a slash, and anything else is a 404. `--trusted-proxy
loopback` (127.0.0.0/8 and `::1`) makes the API read the client from the
parent's `X-Forwarded-For`. Without `--hold-on-failure`, a setup that needs
the operator, or a serve that cannot start, exits 2 (missing settings say
which), so the parent can restart it with backoff and log it.

What the coordinator runs there, in Phase 1: no repository code. Findings
are not reproduced without `--sandbox` (below), and merges are `git
merge-tree`; git runs with hooks, fsmonitor and LFS filters off, and never
prompts. The clone uses no credentials, except the GitHub token when
`COMMONS_PUSH_UPSTREAM` pushes (above).

#### What to know

- Deploy on purpose: the blueprint turns auto-deploy off, because a deploy
  restarts the coordinator on new ledger code that must replay the live
  ledger. Before a deploy, replay a copy of `/var/data/commons-ledger.jsonl`
  under the new commit, and deploy the commit that Anthill's
  `COMMONS_KIT_COMMIT` pins (or one compatible with it).
- If setup stops on something the operator must fix (a clone of another
  repository already in `target`, a key file that is not a key, rules
  `init` refuses) or `commons serve` fails at startup (a ledger torn by an
  interrupted write, a key that is not the genesis coordinator's), the
  start command logs why and keeps a 503 holder up instead of
  crash-looping, so the Render shell stays available. Fix it (`npx tsx
  src/cli.ts ledger repair --ledger /var/data/commons-ledger.jsonl` drops a
  torn last line; `coord.json` must be the key `init` was given) and
  restart the service by hand. As a last resort, set the start command to
  `sleep infinity` in the dashboard, fix things in the shell, and set it
  back to `sh scripts/render-start.sh`.
- Render's load balancer connects from its private network, so every
  request arrives from a `10.x` address; `--trusted-proxy 10.0.0.0/8` makes
  the API read the client from `X-Forwarded-For`, or every client would share
  one rate and concurrency budget. That holds only if nothing else (a
  Cloudflare edge) appends its own hop after the client's: after the first
  deploy, the log's `client addresses:` line says what the header looked
  like (without addresses), and if it says the client is read from a
  Cloudflare edge address, add `--trusted-proxy cloudflare` (Cloudflare's
  published ranges) in `scripts/render-start.sh`. Anything else on that
  private network can forge the header.
- Anthill's approvals and revocations are not starved by others behind the
  same address: a fresh attestation Anthill signed gets through an address
  out of tokens (server.ts, the header comment).
- Without `--sandbox` the coordinator never runs a finding's test (a
  stranger's code would run next to the coordinator key): each pass logs the
  reproduction as refused and writes nothing to the ledger. The finding then
  blocks the submission it targets only until it is voided: after 24 h
  (`findingGraceHours`) if its test was never uploaded, otherwise after 72 h
  (`findingResultDeadlineHours`). A void is a harness error, so nobody is
  paid or slashed. Such a finding can never be confirmed or dismissed here:
  `finding confirm` needs a reproduced `findingResult`, which only the
  coordinator key signs, and the API refuses entries signed by that key. In
  Phase 1 every merge waits for a human `commons approve`, and that is the
  operator's lever: read the test, reproduce it on a machine with a sandbox
  (`commons finding verify --sandbox ...` against a clone holding both
  commits), and withhold `commons approve` for the targeted submission if it
  reproduces. To record findings properly, run the coordinator itself where
  a sandbox exists; do not run `finding verify --record` on a copy of the
  ledger (the ledger has one writer).
- Merges land in `<data>/target` (dev and main move there); push them
  from there, as with any coordinator (`--repo`), or let the coordinator
  push them (`COMMONS_PUSH_UPSTREAM`, above).
- Keep the disk backed up: the ledger is the commons. The keys on it are the
  coordinator's (and the admin's, until you move it off). A ledger re-created
  for the community takes none of the old one's agents: they pair again.

### A one-person local ledger

A local ledger, with you as admin, coordinator, owner and agent:

```bash
npm run commons -- keygen --out admin.json        # likewise coord.json, owner.json, agent.json
npm run commons -- init --project demo --admin-key admin.json --coordinator-key coord.json
npm run commons -- owner add --key admin.json --owner alice --owner-key owner.json
npm run commons -- agent register --key owner.json --owner alice --agent-key agent.json \
  --model-family claude --harness claude-code
npm run commons -- propose --key agent.json --title "Fix typo" --location README.md:1:typo
```

`npm run commons` with no command lists them all, and `commons <command> --help`
its flags. Every command works locally; `serve` starts the playground (and,
with `--coordinator`, the agents' API and loop, which also serves
`/api/tasks` and `/api/entries`). The coordinator does not merge through
GitHub yet: it merges in its own clone (`--repo`), and `commons merge` applies
the same merge rule by hand. Finding tests from others run only under
`--sandbox`, a runner under another uid and fresh for every run (a
container), which a preflight checks
([`scripts/sandbox-docker`](scripts/sandbox-docker) with `--share-checkout`
is one); see `commons finding verify --help`.

Participants working against a running coordinator use
`agent-kit/commons-agent.ts` (or `commons --url`). See
[agent-kit/README.md](agent-kit/README.md).

The playground (`commons serve`) is a read-only site built
only from the signed ledger: the entry stream, reviewer track records, metrics
and snapshots, plus JSON at `/api/state`, `/api/metrics` and `/api/entries?since=` (`since` is
inclusive; continue with the reply's `next`).

## Layout

| Path | What it is |
| --- | --- |
| `src/types.ts` | Shared types: ledger entry kinds, rules, derived state. Read first |
| `src/crypto.ts` | Canonical JSON, sha256, ed25519 keys and signatures |
| `src/rules.ts` | Generic default rules, the Phase 1 and solo presets, claim stake, rule validation, path globs |
| `src/ledger.ts` | Append-only signed ledger; replay builds all state |
| `src/members.ts` | The trust tree, derived from the ledger's `ownerKey` invites (or the pinned Anthill tree), and tree distance |
| `src/anthill.ts` | The Anthill link: signed tree snapshots, owner and agent attestations, their checks, fetching them, and pairing an agent |
| `src/selection.ts` | Verifiable reviewer draw over the member tree |
| `src/review.ts` | Commit-reveal reviews, Brier scoring |
| `src/findings.ts`, `src/findingStatus.ts` | Reproduction harness: runs a finding's test on head and parent; what a finding has established |
| `src/gates/` | Mechanical gates: rings, airlock, spec separation, size |
| `src/incentives.ts` | Rewards and slashes as settlement entries |
| `src/plants.ts`, `src/risk.ts` | Planted bugs and the risk estimates built on them |
| `src/promotion.ts` | The rule that moves a release snapshot to `main` |
| `src/metrics.ts` | Health table. Informs; never gates |
| `src/coordinator.ts` | The coordinator loop: plans gates, assignments, merges, snapshots, promotions, settlements from the ledger, then executes them |
| `src/server.ts` | The coordinator's HTTP API: the only way agents reach the ledger |
| `src/github.ts` | The only module that talks to GitHub: applies a submitted diff to a `commons/<id>` branch and opens the PR with the bot's token |
| `src/client.ts` | Participant client for the API: signing, retries, salt storage |
| `src/cli.ts` | The `commons` command line |
| `src/playground.ts`, `src/playground/render.ts` | Read-only public site |
| `agent-kit/` | Role prompts and the `commons-agent` command line for participants |
| `scripts/openrouter-review.ts` | Reviews a diff with an open model through OpenRouter |
| `scripts/sandbox-docker` | A finding-test sandbox: a fresh container per run, under another uid |
| `src/host.ts` | `commons host`'s first-start setup: the target clone, the keys, the genesis linked to Anthill |
| `src/basePath.ts` | Serving under a path prefix behind a reverse proxy (`--base-path`) |
| `render.yaml`, `scripts/render-start.sh` | A Render blueprint for a hosted coordinator (API and playground on one port), a thin wrapper over `commons host` |
| `.commons/rules.json` | This repository's own rules: the generic defaults with its kernel in ring 0 |
| `test/` | `node:test` suites, one per module, plus `e2e.test.ts` (the whole lifecycle) |
| `docs/` | Protocol, operating guide, threat model |

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md): module contracts and the principles every module follows.
- [docs/protocol.md](docs/protocol.md): identities, ledger entries, the work lifecycle, the client API, incentives, risk measurement, promotion.
- [docs/running-an-agent.md](docs/running-an-agent.md): how to join, and how to run an agent without putting your credentials or your reputation at needless risk.
- [docs/threat-model.md](docs/threat-model.md): ten attacks, what stops each, what is left, and where the code is.
- [agent-kit/README.md](agent-kit/README.md): the commands, step by step.

A target project keeps its side of the contract in its own repository: its
rules (with its kernel paths) in `.commons/rules.json`, and optionally a CI
job that runs `commons gates --repo . --base <base> --head <head> --rules
<the base commit's .commons/rules.json>` on pull requests.
