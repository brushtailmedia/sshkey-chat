# Backup & restore operations runbook

Server-side backup/restore feature: scheduled
nightly snapshots by default, on-demand manual backups via the CLI,
and a restore command that handles the destructive operation safely.
This runbook covers what operators need to know.

## What gets backed up

Each backup is a single `.tar.gz` containing:

```
backup-<YYYYMMDD-HHMMSS>[-<label>].tar.gz
  data/
    data.db, rooms.db, users.db          (SQLite Online Backup snapshots)
    room-*.db, group-*.db, dm-*.db       (SQLite Online Backup snapshots)
    files/<fileID>                       (attachment blobs — plain copy)
    pending-keys.log                     (pending-signup queue)
    audit.log                            (server audit log)
  config/
    host_key                             (SSH server host key, mode 0600 preserved)
    server.toml                          (server config; opt out via include_config_files)
```

**`rooms.toml` is NOT included** — it's a seed file that's ignored
once `rooms.db` exists, so bundling it would be misleading on restore.

**SQLite DBs use the Online Backup API** so backups run safely while
the server keeps serving clients. No downtime, no client disconnects.

**Attachment blobs are immutable** after upload — copying them mid-
upload is safe at the file level. A backup that captures a partial
upload-in-progress will leave that file orphaned in the tarball; the
server's startup `cleanOrphanFiles` sweep handles it on next launch.

## Scheduled backups (the default)

The reference `server.toml` ships with `[backup] enabled = true`
because data loss on a chat server is catastrophic and `skip_if_idle
= true` prevents noise on unused deployments. Fresh-install test
servers produce at most one ~30KB schema-only tarball and then skip
subsequent ticks until there's real activity.

Default cadence: every 24 hours, starting 60 seconds after server
startup. Default retention: keep the 10 most recent tarballs AND
delete anything older than 30 days (whichever rule fires first;
both are hard upper bounds).

To opt out for throwaway test/dev instances:

```toml
[backup]
enabled = false
```

To run the scheduler at a different cadence:

```toml
[backup]
interval = "6h"
```

Interval changes require a server restart — the scheduler ticker is
created at startup and doesn't observe SIGHUP config reloads.

## Manual backup

Operators take manual backups before risky maintenance: server
binary upgrades, config rewrites, data migrations.

```bash
# Snapshot to the configured dest_dir
sshkey-ctl backup

# Tag the snapshot with a human-readable label
sshkey-ctl backup --label pre-upgrade

# Write to a custom directory (e.g., a mounted archive volume)
sshkey-ctl backup --out /mnt/archive --label monthly
```

Manual backups use the same SQLite Online Backup API as the
scheduler — clients keep chatting throughout. Elapsed time is
dominated by attachment size; a deployment with 10GB of attachments
takes however long it takes to copy + gzip 10GB of files.

Labels must match `[A-Za-z0-9_-]{1,32}`. Spaces, dots, slashes are
rejected at flag-parse time before any filesystem touch.

## Listing backups

```bash
sshkey-ctl list-backups
```

Output:

```
NAME                                          SIZE      AGE           LABEL
backup-20260419-143022-pre-upgrade.tar.gz     847M      just now      pre-upgrade
backup-20260419-031000.tar.gz                 845M      11h           -
backup-20260418-031000.tar.gz                 843M      1d            -
backup-20260417-031000.tar.gz                 841M      2d            -
...
```

Sorted newest-first. Pre-restore tarballs (created automatically
when an operator runs `restore`) appear with the `pre-restore` label.

## Off-host backup transfer

Out of scope for the built-in feature. Standard tools work fine:

```bash
# nightly rsync to an archive host
rsync -a --remove-source-files \
  /var/sshkey-chat/backups/ \
  archive.example.com:/srv/sshkey-archives/

# pull a specific snapshot on demand
scp server:/var/sshkey-chat/backups/backup-20260419-143022-pre-upgrade.tar.gz ./
```

The backups directory is just files — anything that copies files
works. Combine with cron, systemd timers, or your existing
file-shipping pipeline.

## Restore

Restore is the destructive operation. It overwrites every artefact
in the tarball with the contents of that tarball, requires the
server to be stopped, and (by default) creates a pre-restore backup
of the current state before doing anything irreversible.

### The flow

```bash
# 1. Stop the server
systemctl stop sshkey-chat                       # systemd
docker compose down sshkey-chat                  # docker compose
kill $(cat /var/sshkey-chat/sshkey-server.pid)   # direct SIGTERM

# 2. Verify it's actually stopped
sshkey-ctl status
# Process: not running

# 3. Run the restore
sshkey-ctl restore /var/sshkey-chat/backups/backup-20260419-143022-pre-upgrade.tar.gz
```

What you'll see:

```
restore: validating tarball...
restore: tarball OK (47 entries)
Create pre-restore backup of current state? [Y/n]: <Enter>
restore: creating pre-restore backup of current state...
restore: pre-restore backup wrote /var/sshkey-chat/backups/backup-20260419-151533-pre-restore.tar.gz (847 MB)
restore: moving current state to /var/sshkey-chat/pre-restore-20260419-151540
restore: moved 47 existing artefacts to safety dir
restore: extracting tarball...
restore: extracted 47 entries
restore: running integrity check on every restored DB...
restore: integrity check passed (45 DBs)
restore: complete. Start the server when ready.
        Original state preserved at /var/sshkey-chat/pre-restore-20260419-151540 — remove it after verifying the restored server works.
```

```bash
# 4. Start the server
systemctl start sshkey-chat
sshkey-ctl status                                # confirm running
```

### Restore safety nets

Three independent layers protect against accidental data loss:

1. **Lockfile blocks restore-while-server-runs** (mechanical, no
   prompt to misread). If you forgot to stop the server, restore
   refuses with the live PID printed:

   ```
   sshkey-ctl: server is running (PID 4821, started 2026-04-19T14:30:22Z); stop it before running restore
   ```

   No files are touched.

2. **Pre-restore backup** captures current state as a portable
   tarball before extraction. Default Y on the prompt (just hit
   Enter); non-TTY runs default to yes too. If the new state is
   wrong, you can roll back with another `restore` against the
   pre-restore tarball.

3. **Safety directory** holds the raw moved files at
   `<dataDir>/pre-restore-<timestamp>/`. This is a local file move,
   not a tarball — non-portable, not in `list-backups`, and not
   restorable via `sshkey-ctl restore`. Use it for immediate
   recovery if extraction fails partway through; rsync the files
   back manually.

### Skipping the pre-restore backup

For scripted use or when you've already taken a recent manual
backup:

```bash
sshkey-ctl restore <tarball> --no-pre-backup
```

Risk: if the new state is wrong, your only rollback is the safety
directory, which is local-only.

### Rolling back after a bad restore

If the restored state turns out wrong, the pre-restore tarball
gives you a clean rollback path:

```bash
# Find the pre-restore tarball
sshkey-ctl list-backups | grep pre-restore

# Stop the server, restore from the pre-restore tarball
systemctl stop sshkey-chat
sshkey-ctl restore /var/sshkey-chat/backups/backup-20260419-151533-pre-restore.tar.gz
systemctl start sshkey-chat
```

### Restoring to a fresh machine

The `host_key` is in every tarball (assuming `include_config_files
= true`). Restoring to a new machine preserves the original host
key, so existing clients continue to recognize the server without
SSH host-key warnings.

```bash
# On the new machine:
mkdir -p /etc/sshkey-chat /var/sshkey-chat/data /var/sshkey-chat/data/files
chown -R sshkey-chat:sshkey-chat /var/sshkey-chat /etc/sshkey-chat
sshkey-ctl restore /tmp/backup-20260419-143022.tar.gz --no-pre-backup
systemctl start sshkey-chat
```

`--no-pre-backup` is appropriate here because there's no current
state worth saving on a fresh machine.

### Recovering from extraction failures

If extraction fails partway through (disk full, tarball CRC error
mid-stream), the safety directory holds the original files
intact. Recovery options:

**Option A — abort the restore, restore original state:**

```bash
SAFETY=/var/sshkey-chat/pre-restore-20260419-151533
cd $SAFETY
rsync -a data/ /var/sshkey-chat/data/
cp config/host_key /etc/sshkey-chat/host_key
cp config/server.toml /etc/sshkey-chat/server.toml
mv audit.log /var/sshkey-chat/audit.log
systemctl start sshkey-chat
```

**Option B — try again with a different tarball:**

```bash
sshkey-ctl restore /var/sshkey-chat/backups/backup-20260418-030000.tar.gz
# Creates a new safety directory; the previous one is preserved
```

After a successful restore, prune old safety directories manually:

```bash
rm -rf /var/sshkey-chat/pre-restore-*
```

## Configuration reference

```toml
[backup]
enabled = true                        # master switch; false disables scheduler (manual backup still works)
interval = "24h"                      # Go duration; ticker cadence
dest_dir = "backups"                  # relative → <dataDir>/backups, absolute used as-is
retention_count = 10                  # keep at most N tarballs (0 = unlimited)
retention_age = "720h"                # delete tarballs older than this (empty = no age cap)
compress = true                       # gzip the tarball
skip_if_idle = true                   # skip scheduler tick if no write activity since last backup
include_config_files = true           # bundle host_key + server.toml into config/
```

**Retention semantics:** OR — a tarball is deleted if it exceeds
either cap. Each cap is a hard upper bound. To get count-only
retention, set `retention_age = ""`. To get age-only retention,
set `retention_count = 0`.

**`skip_if_idle` detection:** compares (`PRAGMA data_version` on
data.db, max mtime of `data/files/`) against the values captured
at the last successful backup. Skip fires only if BOTH show no
change. After a server restart, the first scheduler tick always
runs (no baseline yet) — a restart often coincides with deployment
changes worth snapshotting.

**`include_config_files = false` use case:** operators who manage
`server.toml` via external configuration management (Ansible,
Terraform, NixOS) can opt out to avoid duplicate sources of truth.
`host_key` is also affected — if you opt out, the host_key won't be
in the tarball, and restore-to-a-new-machine will produce a fresh
host key that triggers SSH host-key warnings on every client.

## Monitoring

`sshkey-ctl status` shows backup outcome counters and timestamps:

```
sshkey-chat server status
─────────────────────────
Process:      running (PID 5124) since 2026-04-19T14:00:00Z
Users:        42 active, 3 retired
Rooms:        7
Pending keys: 0
Databases:    47 files, 1.2 GB
Backups:      18 successes, 0 failures
              last success: 2026-04-19T03:00:00Z
Config:       /etc/sshkey-chat
Data:         /var/sshkey-chat
```

If failures are climbing, check the server log for `scheduled
backup failed` lines — they include the underlying error. The
sidecar file at `<dataDir>/.backup-stats.json` carries the latest
error text:

```bash
cat /var/sshkey-chat/.backup-stats.json | jq .last_error_msg
```

## Common pitfalls

1. **Running `restore` while the server is up** — blocked by the
   lockfile with a clear PID-printed error. Stop the server, then
   retry.

2. **Disk fills mid-backup** — partial tarball is deleted (writes
   go to `*.tmp` and rename on success). `backup_failures_total`
   increments. Either clear space or move `dest_dir` to a larger
   filesystem.

3. **Disk fills mid-restore** — restore checks free space upfront
   (`tarballSize × 3` heuristic) and refuses cleanly if
   insufficient. If it slips through and extraction fails, the
   safety directory at `pre-restore-<ts>/` holds the originals;
   `rsync` them back.

4. **`--label` rejected** — labels must match
   `[A-Za-z0-9_-]{1,32}`. No slashes, no dots, no spaces. Common
   mistake: dates with colons (`--label 2026-04-19:nightly`) — use
   hyphens instead (`--label 2026-04-19-nightly`).

5. **Restoring a tarball from an incompatible server version** —
   not blocked at the tarball layer; `PRAGMA integrity_check` will
   fail post-extract if the schema is mismatched. Operator gets a
   clear error and the safety dir is intact for rollback.

6. **Operators forget the safety dir** — `pre-restore-*/`
   directories accumulate at `<dataDir>` if not pruned. Worth a
   periodic `du -sh <dataDir>/pre-restore-*` check; remove old
   ones after confirming the corresponding restored state works.

## What's NOT in scope

- **Remote backup destinations** (S3, rsync targets, SFTP) —
  combine local backups with `rsync`/`rclone` invoked separately.
- **Incremental backups / deduplication** — every backup is a full
  snapshot. Fine at ssh-chat's typical scale.
- **Backup encryption at rest** — tarballs contain SQLite files
  with E2E-encrypted message payloads; only metadata (user names,
  room names, timestamps) is unencrypted at the tarball layer.
  Operators who need at-rest encryption combine with `gpg` or
  filesystem-level encryption.
- **Cross-DB transactional consistency** — backups are independent
  per-DB snapshots. A `handleSend` firing mid-backup may capture
  the per-room DB before-commit and `data.db`'s `file_hashes` row
  after-commit (or vice versa). On restore, the startup
  `cleanOrphanFiles` sweep cleans any drift, and worst-case
  user-visible impact is a "missing attachment" message that the
  user can re-upload. Documented as accepted trade-off vs. blocking
  all writes during the backup window.
