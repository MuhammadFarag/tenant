# Troubleshooting

Diagnostics for when something in a tenant breaks. Start with `tenant doctor NAME`.
Each section says whether doctor already reports the problem and how far these
steps go beyond it.

Conventions:
- `NAME` is the tenant's name; `NAME-tenant-share` is its share group.
- Steps marked **(sudo)** need an admin password; everything else is read-only
  unless it says otherwise.
- Run these from **your own terminal**, not inside `tenant shell`, unless a step
  says to run it as the tenant.
- Don't run `tenant` itself under `sudo`; it calls sudo where it needs it.

## Quick triage

| Symptom | Section |
|---|---|
| Something inside the tenant hangs, then times out | [Connections hang](#connections-hang) |
| You don't know which host an app is trying to reach | [Find the dropped destination](#find-the-dropped-destination) |
| `critical: … anchor not referenced from /etc/pf.conf`, or a reapply fails with `the kernel has no pass/block rules` | [Firewall not loaded after a macOS update](#firewall-not-loaded-after-a-macos-update) |
| `critical: pf is globally disabled` | [pf disabled](#pf-disabled) |
| An OAuth callback or dev server on `127.0.0.1` isn't reachable | [Host can't reach a tenant listener](#host-cant-reach-a-tenant-listener) |
| `Could not connect to the Gradle daemon` (or Maven, sbt, Kotlin workers) | [JVM builds fail](#jvm-builds-fail) |
| You can't write a file the tenant created (`E212`, `AccessDeniedException`) | [Host can't write tenant files](#host-cant-write-tenant-files) |
| The tenant sees a share but gets permission denied inside it | [Tenant denied inside a share](#tenant-denied-inside-a-share) |
| `ACL grant on PATH incomplete — chmod: Failed to set ACL …` | [Incomplete ACL grant](#incomplete-acl-grant) |
| `critical: … primary group …`, or the tenant can suddenly read your home | [Primary group reset](#primary-group-reset) |
| `SSH_AUTH_SOCK` note, or sudoers changes vanished after an update | [sudoers and SSH_AUTH_SOCK](#sudoers-and-ssh_auth_sock) |
| `security exited with code 51` at shell entry, or a dialog asks for the tenant's password | [Keychain won't unlock](#keychain-wont-unlock-security-exited-with-code-51) |
| `this verb needs sudo and no terminal is attached` | [No terminal for sudo](#no-terminal-for-sudo) |
| `refusing to enter 'NAME' with no terminal to confirm` | [Shell refuses without a terminal](#shell-refuses-without-a-terminal) |
| Host git: `detected dubious ownership in repository` | [Host git and dubious ownership](#host-git-and-dubious-ownership) |
| A TUI renders wrongly inside `tenant shell` | [Terminal rendering inside the tenant](#terminal-rendering-inside-the-tenant) |
| `npm i -g` fails with `EACCES` inside the tenant | [Global npm installs](#global-npm-installs) |

## Egress firewall

### Connections hang

**Symptom.** A download, package install or API call inside the tenant hangs
and eventually times out (`operation timed out`, `Failed to connect … after
300005 ms`).

**Why it hangs.** The tenant's anchor *drops* packets to hosts outside its
allowlist instead of rejecting them, so the client waits for its own timeout.
Several causes look identical: the host isn't allowlisted, its DNS answer moved
since the anchor loaded (CDNs rotate within minutes), pf skipped a hostname it
couldn't resolve at load time, or the service itself is down.

**Doctor:** reports `egress host H now resolves to …, outside the loaded pf
table` (warning) for hostname entries. The steps below cover the rest.

**Diagnose.**
1. `tenant doctor NAME`. Look for the resolve-drift warning.
2. **(sudo)** List the tenant's tables, then the addresses actually loaded:
   ```
   sudo pfctl -a tenant-NAME -s Tables
   sudo pfctl -a tenant-NAME -t allowed -T show
   ```
   Hosts declared with non-443 ports live in their own table (for example
   `allowed_443_22`).
3. Resolve the host yourself and compare with step 2:
   ```
   dig +short H
   dig +short AAAA H
   ```
   - An answer that isn't in the table: a stale resolve or CDN rotation.
   - The host has no addresses in the table at all: pf couldn't resolve it when
     the anchor loaded.
4. Try it from inside the tenant and see where it actually connected:
   ```
   tenant shell NAME -- curl -sS --max-time 8 -o /dev/null -w '%{http_code} %{remote_ip}\n' https://H
   ```
   A timeout (`000`) means blocked; a status code means allowed.

Don't use `dig` *inside* the tenant: the anchor blocks all UDP, so DNS queries
from the tenant fail even when name resolution through the system resolver
works. Check DNS from your own terminal.

**Fix.**
- `tenant reload NAME` re-resolves every hostname. Enough for a host whose
  address moved once.
- For CDN-fronted hosts (Google, Fastly, Cloudflare, CloudFront), pin the
  provider's published ranges as CIDR entries in an include fragment, then
  `tenant reload NAME`. See `tenant help profile`. A reload does nothing for an
  entry that's already a CIDR.
- If the host simply isn't allowlisted, add it to the profile and reload.

### Find the dropped destination

**Symptom.** An app hangs and you don't know which hosts it needs.

**Doctor:** not covered.

**Diagnose** by logging the anchor's catch-all block:
1. **(sudo)** `sudo $EDITOR /etc/pf.anchors/tenant-NAME`, and add `log` to the
   last line so it reads:
   ```
   block out log quick proto { tcp udp } from any to any user NAME
   ```
2. **(sudo)** `sudo pfctl -f /etc/pf.conf`
3. **(sudo)** In another terminal: `sudo tcpdump -nei pflog0`
4. Reproduce the hang in a tenant session that's **already open**. Starting a
   new `tenant shell` re-renders the anchor and removes your `log` edit.
5. Each dropped connection shows the destination address and port. Identify it
   with `dig -x ADDRESS`.
6. `tenant reload NAME` restores the profile's anchor.

Lighter alternative: **(sudo)** `sudo pfctl -a tenant-NAME -vsr` shows rule
counters; the block rule's counter climbs while the app is being dropped.

### Firewall not loaded after a macOS update

**Symptom.** `critical: tenant 'NAME' anchor not referenced from /etc/pf.conf`,
or a reapply fails with `pf reloaded, but the kernel has no pass/block rules for
anchor tenant-NAME — its egress allowlist is not enforced`. Until fixed, the
tenant's egress is unfiltered.

**Why.** macOS updates replace `/etc/pf.conf` with Apple's stock file, which
drops the `anchor` / `load anchor` lines for every tenant.

**Doctor:** reports it (critical; `--strict` exits 2). The steps below confirm
the cause and give a manual fallback.

**Diagnose.**
1. `grep -n 'tenant-NAME' /etc/pf.conf`. No match: the reference was wiped.
2. **(sudo)** `sudo pfctl -a tenant-NAME -s rules`. Empty: nothing loaded.
3. **(sudo)** `sudo pfctl -si | head -3`. `Status: Disabled` is a different
   problem; see [pf disabled](#pf-disabled).
4. **(sudo)** `sudo ls -l /etc/pf.anchors/tenant-NAME`. The anchor file itself
   usually survives.
5. To confirm an update did it: `ls -l /etc/pf.conf /etc/sudoers /etc/pam.d/sudo`.
   An update stamps all three with the same time.

**Fix.** `tenant reload` (no name) re-adds the reference for every tenant;
`tenant shell` and `tenant mode` also re-add it for their tenant.

Don't restore `/etc/pf.conf.tenant-backup`: it's the snapshot from the last
`create` or `destroy` and lacks every tenant created since.

Manual fallback:
1. **(sudo)** Back up `/etc/pf.conf`, then append exactly these two lines
   (`load anchor` must stay on one line):
   ```
   anchor "tenant-NAME"
   load anchor "tenant-NAME" from "/etc/pf.anchors/tenant-NAME"
   ```
2. **(sudo)** `sudo pfctl -n -f /etc/pf.conf` (validates), then
   `sudo pfctl -f /etc/pf.conf`.
3. **(sudo)** Confirm with `sudo pfctl -a tenant-NAME -s rules`.

Loading rules straight into the anchor (`pfctl -a tenant-NAME -f FILE`) fills
it but doesn't filter anything: without the reference in `/etc/pf.conf`, pf
never evaluates the anchor.

### pf disabled

**Doctor:** reports `critical: pf is globally disabled`.

**Diagnose.** **(sudo)** `sudo pfctl -si | head -3`

**Fix.** **(sudo)** `sudo pfctl -e`, then check `sudo pfctl -sr`. Whatever you
disabled pf to get around may come back.

### Kernel rules or anchor file out of sync

**Doctor:** reports `pf anchor drift` or `anchor file drift` (warnings).

**Diagnose.**
- **(sudo)** `sudo pfctl -a tenant-NAME -sr`: both a `pass` and a `block` line
  should be present.
- **(sudo)** `sudo cat /etc/pf.anchors/tenant-NAME`, compared with the profile.

**Fix.** `tenant reload NAME`.

## Inbound loopback

### Host can't reach a tenant listener

**Symptom.** An OAuth redirect to `127.0.0.1:PORT` never completes, or a dev
server the tenant runs isn't reachable from your browser.

**Doctor:** shows the inbound posture (locked, declared ports, or permissive),
but doesn't test a particular port.

**Diagnose.**
1. **(sudo)** `sudo lsof -nP -iTCP:PORT -sTCP:LISTEN`. Is something listening,
   and is it the tenant?
2. `curl -4 http://127.0.0.1:PORT/`
   - Hangs for seconds: the firewall is dropping it.
   - Refused instantly: nothing is listening on that address family (a server
     bound to IPv4 only refuses `::1`).
3. A reproducible probe, run with a sudo session cached:
   ```
   sudo -u NAME nc -l PORT >/dev/null 2>&1 & sleep 0.4
   nc -z -G 2 -w 2 127.0.0.1 PORT; echo $?
   kill %1
   ```
   `0` means reachable; a failure after a second or two means pf dropped it; a
   fast failure means refused.

**What to expect** under the default `restricted` posture: a declared port is
reachable by everyone, including other tenants; an undeclared port is blocked
for everyone, including the tenant itself.

**Fix.**
- Known port: add it to `[inbound] ports` in the profile and `tenant reload NAME`.
- One-off (an OAuth flow on a random port): `tenant inbound NAME permissive`,
  then `tenant inbound NAME restricted` afterwards.
- OAuth also needs the provider's hosts in `[allowlist.runtime]` for the token
  exchange.

A `tenant shell` entry re-renders the anchor, so hand-loaded pf experiments
don't survive it.

### JVM builds fail

**Symptom.** `Daemon server started on 127.0.0.1:NNNNN` followed by `Could not
connect to the Gradle daemon`, or test workers failing the same way. The same
applies to Maven, sbt, Bazel and Kotlin.

**Why.** JVM build tools fork workers that call back over random loopback ports,
which `restricted` blocks. Daemon-off settings don't avoid it.

**Doctor:** shows `inbound posture is permissive (profile)` once fixed; doesn't
flag the mismatch.

**Fix.** Add `posture = "permissive"` under `[inbound]` in the profile and run
`tenant reload NAME`.

### Tenant can't reach a host service

`[inbound]` only governs listeners the **tenant** opens. The tenant's own
connections to services you run on loopback (databases, adb, dev servers)
always pass; declare nothing for them. If one fails, look at the service and
what it's bound to, not the inbound posture.

## Shares and the co-working directory

### Host can't write tenant files

**Symptom.** You can read a file the tenant created but can't save it
(`E212: Can't open file for writing`, `AccessDeniedException` in an IDE).
Three causes; check in this order.

1. **You're not in the share group.**
   `dseditgroup -o checkmember -m "$USER" NAME-tenant-share; echo $?`
   Doctor reports this (`host … not in share group`). Fix: `tenant reload NAME`.
2. **Your terminal predates the membership.** The check above says you're a
   member, but `id -Gn | tr ' ' '\n' | grep -c NAME-tenant-share` prints `0`.
   macOS fixes a process's groups when it starts. Doctor doesn't detect this.
   Fix: open a new terminal window and retry.
3. **The file was moved in rather than created in place.** Tools that write a
   temp file and rename it (Gradle, Maven, cargo, npm, IDEs) produce files
   without the inherited permission. `ls -le PATH`: an in-place file shows
   `group:NAME-tenant-share inherited allow …`; a moved-in one doesn't. Doctor
   lists them (`entries under … lack the 'NAME-tenant-share' ACE`). Fix:
   `tenant reload NAME`, or keep build output outside the shared tree.

New files showing mode `755` (owner-only write) is normal: the inherited
permission, not the mode bits, gives the other side write access. Don't change
the umask.

### Tenant denied inside a share

**Symptom.** The share's symlink resolves inside the tenant, but reading or
writing in it fails.

**Doctor:** checks the share's top-level permission and lists moved-in entries,
but doesn't test whether the tenant can actually reach the files.

**Diagnose.**
1. `id NAME`. If it shows `gid=20(staff)` without `NAME-tenant-share`, see
   [Primary group reset](#primary-group-reset).
2. `ls -lde HOST_PATH`: is the `group:NAME-tenant-share` entry present?
3. `ls -le HOST_PATH/subdir`: are entries deeper in the tree missing it?
4. **(sudo)** Test as the tenant:
   ```
   sudo -n -u NAME /bin/test -r 'HOST_PATH/sub/file'; echo $?
   sudo -n -u NAME /bin/test -w 'HOST_PATH/sub/file'; echo $?
   ```
   `0` allowed, `1` denied. If sudo prints `a password is required`, you got
   no answer; run `sudo -v` and retry.

**Fix.** `tenant reload NAME` re-walks the share. Manual fallback **(sudo)**:
```
sudo chmod -R +a "group:NAME-tenant-share allow read,write,execute,delete,append,file_inherit,directory_inherit" HOST_PATH
```
For a read-only share, leave out `write,delete,append`.

### Incomplete ACL grant

**Symptom.** `tenant reload` warns `ACL grant on PATH incomplete — chmod:
Failed to set ACL on file 'X': No such file or directory`. The rest of the tree
was granted.

**Why.** A dangling symlink or socket in the tree, often left by a container or
a database (a `mysql.sock` pointing to a Linux path).

**Diagnose.**
```
find -L HOST_PATH -type l    # dangling symlinks
find HOST_PATH -type s       # sockets
```

**Fix.** Usually nothing: the warning is harmless. If it bothers you, remove or
relocate the artifact; expect it back whenever the service recreates it.

### Co-working directory or share symlink problems

**Doctor:** reports a missing co-working directory, a stripped permission on
it, and share symlinks that are absent or point elsewhere, each with its own
fix. `tenant reload NAME` repairs all of them.

To look by hand: `ls -lde /Users/Shared/tenants/NAME` (expect `drwxrws---`,
owned by you and `NAME-tenant-share`, with the inherited group entry), and
**(sudo)** `sudo -n -u NAME /usr/bin/readlink TENANT_PATH`.

### Host git and dubious ownership

**Symptom.** Host git refuses a repository the tenant created: `detected dubious
ownership in repository at '…'`.

**Why.** The working tree is owned by the tenant, not you. Expected.

**Fix.** Allow the shared tenant tree, and only that:
```
git config --global --add safe.directory '/Users/Shared/tenants/*'
```

## macOS updates

Updates rewrite state `tenant` set up: `/etc/pf.conf`, local user records and
`/etc/sudoers`. Drop-ins in `/etc/sudoers.d/` and `/etc/pam.d/sudo_local`
survive. After any macOS update, run `tenant reload` and then `tenant doctor`.

### Primary group reset

**Symptom.** Shares stop working ("permission denied" through a symlink that
resolves), and at the same time doctor reports the tenant can read things in
your home such as `~/.ssh`.

**Why.** The update recreated the tenant's user record with primary group
`staff` (20), which drops the share group and gains access to anything `staff`
can enter.

**Doctor:** reports primary-group drift (critical), and `tenant shell` asks
before entering.

**Diagnose.**
```
dscl . -read /Users/NAME PrimaryGroupID         # expect the share group's id, not 20
dscl . -read /Groups/NAME-tenant-share PrimaryGroupID
id NAME
```

**Fix.** `tenant reload NAME`. If a share still denies access, **(sudo)**
`sudo dsmemberutil flushcache`. Processes already running as the tenant keep
the old groups until they restart.

### Firewall reference wiped

See [Firewall not loaded after a macOS update](#firewall-not-loaded-after-a-macos-update).

### sudoers and SSH_AUTH_SOCK

**Doctor:** notes (info) that sudo forwards `SSH_AUTH_SOCK` into `tenant
shell` sessions. On a default host that's harmless: launchd's agent socket sits
in a directory only you can open, so the tenant can't use it.

**If you want it stripped anyway** **(sudo)**: `sudo visudo -f
/etc/sudoers.d/tenant` and add:
```
Defaults env_keep -= "SSH_AUTH_SOCK"
```
`env_delete` looks like the right setting but does nothing while `env_reset` is
on, which is the macOS default.

**Checks.**
- `ls /etc/sudoers.d`. Name the drop-in `tenant`: sudo ignores files whose
  names contain a `.` or end in `~`, but doctor reads every file, so a misnamed
  drop-in fools doctor without taking effect.
- **(sudo)** `sudo visudo -c` validates the whole configuration.
- **(sudo)** `sudo -u NAME /usr/bin/env | grep SSH_AUTH_SOCK` shows whether the
  variable still reaches the tenant.

### Touch ID for sudo gone

**Doctor:** reports `Touch ID for sudo` missing (info).

**Diagnose.** `grep pam_tid /etc/pam.d/sudo /etc/pam.d/sudo_local`

**Fix.** `tenant setup`. It writes to `sudo_local`, which updates don't touch.

## Keychain

### Keychain won't unlock (`security exited with code 51`)

#### Symptoms

- `tenant shell NAME` or `tenant bootstrap NAME` fails with:

  ```
  tenant: failed to unlock keychain for 'NAME': security exited with code 51:
  security: SecKeychainUnlock tenant.keychain-db: The user name or passphrase you entered is not correct.
  ```

- A macOS dialog asks for the tenant's password, because the keychain stayed
  locked and something inside the tenant (git, gh, Claude Code) needs it.

#### What it means

`tenant` unlocks the tenant's `~/Library/Keychains/tenant.keychain-db` with a
password it stashed in **your** login keychain (service `tenant-NAME`). Exit 51
means the file exists but the stashed password doesn't open it. (A missing file
gives "could not be found" instead.) Either the keychain was replaced or
re-keyed, or the stash was overwritten.

#### Diagnose

1. When was the stash written?

   ```
   security find-generic-password -a NAME -s tenant-NAME | grep -E '"(cdat|mdat)"'
   ```

2. When was the keychain created and last written?

   ```
   sudo -iu NAME stat -f 'born %SB  modified %Sm' Library/Keychains/tenant.keychain-db
   ```

   - **Keychain born after the stash** → the keychain was replaced after
     `tenant` stashed its password. Something deleted and recreated it.
   - **Stash modified after the keychain was born** → the stash was overwritten
     (e.g. a `tenant create` that found an existing keychain).

3. Was it you? Look for keychain commands in your shell history:

   ```
   grep -n "keychain" ~/.zsh_history | tail -20
   ```

   zsh history timestamps are Unix seconds; convert with `date -r <seconds>`.

4. Was it an agent session? Search transcripts written since the keychain's
   birth date, on your account and inside the tenant:

   ```
   find ~/.claude/projects -name '*.jsonl' -newermt 'YYYY-MM-DD' -exec grep -l -e create-keychain -e delete-keychain {} +
   sudo find /Users/NAME/.claude -name '*.jsonl' -newermt 'YYYY-MM-DD' -exec grep -l -e create-keychain -e delete-keychain {} +
   ```

5. Was it macOS? Check for an update or a login session around the birth time,
   and the security logs for that window (logs rotate within days, so check soon):

   ```
   system_profiler SPInstallHistoryDataType | grep -A5 -i macos
   last NAME | head -5
   log show --start 'YYYY-MM-DD HH:MM:00' --end 'YYYY-MM-DD HH:MM:00' --info \
     --predicate 'process == "securityd" OR process == "SecurityAgent" OR eventMessage CONTAINS[c] "keychain"'
   ```

6. Is the old keychain still around?

   ```
   sudo find /Users/NAME -name '*keychain*' 2>/dev/null
   ```

   If a keychain from before the replacement still exists, it should open with
   the stash. Moving it back restores everything it held.

#### Recover

If you know the current keychain's password (from step 3 or 4), re-key it in
place and keep its contents. Paste the stash as the new password:

```
security find-generic-password -a NAME -s tenant-NAME -w | pbcopy
sudo -iu NAME security set-keychain-password tenant.keychain-db
```

Otherwise move it aside and create a fresh keychain keyed to the stash. Apps in
the tenant sign in again once:

```
sudo -iu NAME mv Library/Keychains/tenant.keychain-db Library/Keychains/tenant.keychain-db.replaced
sudo -iu NAME security create-keychain -p "$(security find-generic-password -a NAME -s tenant-NAME -w)" tenant.keychain-db
sudo -iu NAME security default-keychain -s tenant.keychain-db
sudo -iu NAME security list-keychains -s tenant.keychain-db
sudo -iu NAME security set-keychain-settings tenant.keychain-db
```

Run these from **your** shell, not inside `tenant shell`: the `$(…)` must read
your keychain, where the stash lives. If it comes back empty, `security`
silently prompts for a password instead.

#### Verify

```
sudo -iu NAME security unlock-keychain -p "$(security find-generic-password -a NAME -s tenant-NAME -w)" tenant.keychain-db && echo "stash opens it"
sudo -iu NAME security default-keychain
tenant shell NAME -- true
```

### Tenant still on `login.keychain-db`

**Symptom.** Exit 51 on unlock although the stash is fine, on a tenant created
before `tenant` switched to `tenant.keychain-db`.

**Doctor:** reports `keychain absent` and prints a four-command recipe.

**Diagnose.** **(sudo)** `sudo ls -l /Users/NAME/Library/Keychains/`. Only
`login.keychain-db` and no `tenant.keychain-db` means it predates the switch.
macOS 26.6 and later refuse to unlock a keychain with that name from outside
the tenant's own login session.

**Fix.** Run doctor's recipe from your own terminal (see the warning under
[Recover](#recover) above about where the `$(…)` runs).

### Don't probe with `show-keychain-info`

`sudo -iu NAME security show-keychain-info …` pops a macOS dialog even without
a terminal. To check a tenant keychain, unlock it with the stash as in
[Verify](#verify) above.

## sudo, terminals and shell entry

### No terminal for sudo

**Symptom.** `tenant: this verb needs sudo and no terminal is attached — run it
in your terminal, or run 'sudo -v' in this session first`.

**Diagnose.** `sudo -n true; echo $?`. Non-zero: no cached sudo.

**Fix.** Run `sudo -v` first in the same session, or run the command from your
terminal.

### Shell refuses without a terminal

**Symptom.** `tenant: refusing to enter 'NAME' with no terminal to confirm: …
critical doctor finding above`.

**Why.** The tenant has a problem shell entry can't repair (pf disabled, or a
reset primary group), and there's no terminal to ask you.

**Fix.** `tenant doctor NAME` and fix the critical findings, or pass `-y` to
enter anyway.

## Inside the tenant

### Terminal rendering inside the tenant

**Symptom.** Full-screen programs render wrongly inside `tenant shell`,
typically with terminals such as Ghostty that set a non-standard `$TERM`.

**Diagnose.** `tenant shell NAME -- infocmp "$TERM"`. An error means the
tenant has no description of your terminal.

**Fix** (once per tenant): `infocmp -x "$TERM" | tenant shell NAME -- tic -x -`

### Global npm installs

**Symptom.** `npm i -g` fails with `EACCES … mkdir '/usr/local/lib/node_modules/…'`.

**Diagnose.** `tenant shell NAME -- npm config get prefix`. A prefix owned by
you (`/usr/local`, `/opt/homebrew`) isn't writable by the tenant.

**Fix.** Give the tenant its own prefix:
`tenant shell NAME -- npm config set prefix '~/.npm-global'`, and add
`~/.npm-global/bin` to the tenant's `PATH`.

### Host paths in the tenant's dotfiles

**Symptom.** `command not found` inside the tenant, and its `~/.zshenv.local`
(or similar) contains your own paths such as `/Users/<you>/…`, or entries like
`/bin:/platform-tools:…`.

**Why.** `tenant` versions before 0.1.0-alpha.11 expanded `$VARIABLES` in
bootstrap commands twice, writing your PATH into the tenant's files.

**Diagnose.** `tenant shell NAME -- cat ~/.zshenv.local`

**Fix.** Correct the file and re-run `tenant bootstrap NAME` with a current
`tenant`.

## Reading your home directory

**Symptom.** Doctor reports the tenant can read or list paths in your home.

**Doctor:** reports these (critical for secrets like `~/.ssh`, warning for
listing your home) without a fix, because the right fix depends on your setup.

**Diagnose.** `stat -f %Sp ~`. Any permission for "other" (the macOS default is
`drwxr-xr-x`) lets tenants in.

**Fix.** `chmod 750 ~`, or deny only the tenant with
`chmod +a "user:NAME deny read,execute,readattr" ~`. Either can affect File
Sharing or other local users of your home.

## Validate a profile without sudo

`tenant reload NAME --dry-run -v` previews the merged profile: the anchor it
would render and the share operations, without changing anything.
