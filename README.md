# sr-rules

每日构建 [Shadowrocket](https://github.com/ShadowrocketADC/shadowrocket) 可用规则，供移动端使用（去广告 + 国内外划分）。

参照 [`wx2020/smartdns-rules`](https://github.com/wx2020/smartdns-rules) 的代码架构（`sources.json` + `convert.py` + 每日 workflow + data 分支 + Release），但**数据源与产物不同**：

- 输入：`smartdns-rules` 每日产出的 `.lst`（ads / cn / not-cn）+ `flyzstu/sing-box-rules` 的 `geosite-gfw.json`
- 输出：`sr-rules.conf`（Shadowrocket 规则）+ 各 `.lst` + sha256 + `manifest.json`，发布到 GitHub 的 `data` 分支与每日 Release
- 发布账户：`lcuwx2016`（仓库 https://github.com/lcuwx2016/sr-rules ，public）

## 四个 job（sources.json）

| job | 输入源 | 产物用途 |
|---|---|---|
| `geosite-category-ads-all` | `wx2020/smartdns-rules@data/geosite-category-ads-all.lst` | 广告 REJECT |
| `cn` | `wx2020/smartdns-rules@data/cn.lst` | 国内域名 DIRECT |
| `not-cn` | `wx2020/smartdns-rules@data/not-cn.lst` | 归档（境外 AAAA 抑制由 `ipv6=false` 表达，不逐条列入 conf） |
| `geosite-gfw` | `flyzstu/sing-box-rules@rule-set-geosite/geosite-gfw.json` | GFW 域名 PROXY |

`ads-custom.lst` 是从 GW 导出的自定义广告域名（196 行），静态纳入仓库，构建时前置叠加在广告段最前。

## sr-rules.conf 段序

1. 广告 REJECT（`ads-custom` 前置 + `geosite-category-ads-all`）
2. 内网/特殊直连（`IP-CIDR DIRECT` + `skip-proxy`/`bypass-tun`）
3. GFW 域名 PROXY —— **先于国内段**，忠实复刻 GW 上 `geosite-gfw(6)` 早于 `geoip-cn(8)` 的顺序
4. 国内域名 DIRECT + `GEOIP,CN,DIRECT`
5. `FINAL,PROXY`

`[General]` 设 `ipv6=false`，对应 GW 全 IPv6 直连与 smartdns `not-cn` 抑制 AAAA。

无法用 Shadowrocket 语法表达的 GW 系统层行为（按源 IP 绕 TUN、端口协议直连、fake-ip、cf_alias ip-alias、DoT 经代理等）在 conf 头部逐条注明。

## 守卫

与上游同款：`count < min_lines` 或 `count < 上次 count * ratio_guard(0.5)` 即中止，不发布残缺数据。上次计数从 `data` 分支的 `manifest.json` 读取。

## 获取

- 滚动分支：`https://raw.githubusercontent.com/lcuwx2016/sr-rules/data/sr-rules.conf`
- 每日 Release：`https://github.com/lcuwx2016/sr-rules/releases`

## 本地构建

```sh
python3 convert.py --out-dir dist --sources sources.json
```

纯标准库，无第三方依赖。构建产物在 `dist/`（已 gitignore）。

## 来源与许可

数据来自 `wx2020/smartdns-rules`（其上游 `flyzstu/sing-box-rules` / `v2fly/domain-list-community`）与 `flyzstu/sing-box-rules`，遵循各自上游许可。
