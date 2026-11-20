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

`ads-custom.lst` 是自定义广告域名清单（395 行），静态纳入仓库，构建时前置叠加在广告段最前。其中 196 行来自上游文件，另 196 行是 sr 侧补充（微信广告域名 `wxsmw.wxs.qq.com` + 头条 byteimg 广告图正则 `^p[0-9]+-` 展开为 `p1~p99` 的具体域名——Shadowrocket 无 `DOMAIN-REGEX` 规则类型，只能展开）。

另有一组 **IP+端口降级规则**存于 `ads-ip-reject.lst`（8 个硬编码 DNS/广告 IP）。上游原规则是 `ip_cidr + port [80,443/8091]` 组合拦截，Shadowrocket 单维度规则无法表达，故降级为全端口 `IP-CIDR,...,REJECT`，在广告段之后、内网直连段之前输出。这些 IP 本就是硬编码 DNS/广告 IP，全拦符合意图；sr 的 `dns-server` 走 DoH，不受影响。纯端口规则（8091）无法表达，已丢弃。

## sr-rules.conf 段序

1. 广告 REJECT（`ads-custom` 前置 + `geosite-category-ads-all`）
2. 内网/特殊直连（`IP-CIDR DIRECT` + `skip-proxy`/`bypass-tun`）
3. GFW 域名 PROXY —— **先于国内段**，匹配上游 `geosite-gfw` 早于 `geoip-cn` 的顺序
4. not-cn 域名 PROXY —— 境外域名显式走代理；与 cn 名单重叠的 156 个域名已剔除，避免误伤国内站
5. 国内域名 DIRECT + `GEOIP,CN,DIRECT`（**不带 `no-resolve`**：保留对「未收录国内域名」的 GEOIP 兜底，避免它们掉进 FINAL 走代理）
6. `FINAL,PROXY`

`[General]` 设 `ipv6=true`，保留国内域名的 IPv6 直连；境外域名靠 not-cn 段显式 PROXY 拦截，而非靠全局关闭 IPv6。`dns-server` 用国内 DoH，仅服务「直连域名建连 + 代理节点域名」的本地解析；域名类规则按字符串匹配不经 DNS，落到 GEOIP 的域名才触发本地解析。

无法用 Shadowrocket 语法表达的系统层行为（按源 IP 绕 TUN、端口协议直连、fake-ip、cf_alias ip-alias、DoT 经代理等）在 conf 头部逐条注明。

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
