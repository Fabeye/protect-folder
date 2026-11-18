# Example: three independent directories on three different disks

Protect-folder is disk-agnostic. A target is an absolute path to any directory on a POSIX filesystem
(ext4, xfs, btrfs, ...); it is identified by device + inode + mount, not by its name. The paths below are
only illustrations - use your own.

```bash
# 0. one-time
sudo ./install.sh
protect-folder doctor

# 1. three directories on three disks (a system SSD, an external SSD, an external HDD)
sudo protect-folder add --dry-run /home/me/private/notes             # look first
sudo protect-folder add /home/me/private/notes
sudo protect-folder add '/mnt/fast ssd/clients/Acme credentials'     # spaces are fine
sudo protect-folder add '/media/me/HDD1/Архив/секреты'               # so is Unicode
sudo -K                                                              # forget the sudo credential

# 2. see them (✓ verified  ? configured but not verified  — disabled  ✗ failed)
protect-folder list
protect-folder status '/mnt/fast ssd/clients/Acme credentials'

# 3. prove the layers work (synthetic marker, nothing real is read)
protect-folder verify
protect-folder verify --agent claude --live        # also drives a real claude session (uses quota)
sudo protect-folder verify --admin                 # root-only checks of snapshots / restore safety

# 4. work: agents only ever run through the wrapper
cd ~/code/my-project
protect-folder run -- claude
protect-folder run -- opencode
protect-folder run -- codex exec "summarise the repo"

# 5. a directory that must keep its owner/mode (e.g. shared with a service): SRT + hooks only
sudo protect-folder add --no-linux /srv/shared/reports
sudo protect-folder set-layers /srv/shared/reports --all      # later: turn everything on

# 6. give it back
sudo protect-folder remove /home/me/private/notes             # restores owner/mode/ACL after an identity check
```

A disk that is unplugged makes `run` refuse (the layer cannot be verified), never silently continue.
Re-mount it, or `sudo protect-folder remove --forget PATH` to drop the stale registration.
