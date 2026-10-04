# Troubleshooting

Manual diagnostics for problems `tenant doctor` doesn't explain yet. Replace
`NAME` with the tenant's name. Every check here is read-only unless a step says
otherwise.

## Tenant keychain won't unlock (`security exited with code 51`)

### Symptoms

- `tenant shell NAME` or `tenant bootstrap NAME` fails with:

  ```
  tenant: failed to unlock keychain for 'NAME': security exited with code 51:
  security: SecKeychainUnlock tenant.keychain-db: The user name or passphrase you entered is not correct.
  ```

- A macOS dialog asks for the tenant's password, because the keychain stayed
  locked and something inside the tenant (git, gh, Claude Code) needs it.

### What it means

`tenant` unlocks the tenant's `~/Library/Keychains/tenant.keychain-db` with a
password it stashed in **your** login keychain (service `tenant-NAME`). Exit 51
means the file exists but the stashed password doesn't open it. (A missing file
gives "could not be found" instead.) Either the keychain was replaced or
re-keyed, or the stash was overwritten.

### Diagnose

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

### Recover

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

### Verify

```
sudo -iu NAME security unlock-keychain -p "$(security find-generic-password -a NAME -s tenant-NAME -w)" tenant.keychain-db && echo "stash opens it"
sudo -iu NAME security default-keychain
tenant shell NAME -- true
```
