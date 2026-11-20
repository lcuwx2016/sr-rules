# sr-rules 项目记忆

## 定位

每日构建 Shadowrocket 规则，供移动端使用（去广告 + 国内外划分）。**GitHub 公开仓 `github.com/lcuwx2016/sr-rules`**（账户 lcuwx2016；main 源码，data 产物分支），工作区 `~/workspaces/sr-rules`。2026-11-20 立项。

同日用户要求从 Gitea 私库 `git.wx2020.cn/wx2020/sr-rules` 迁到 GitHub：原 Gitea 仓保留但不再发布，workflow 从 `.gitea/workflows/` 改为 `.github/workflows/`，`prev_manifest_url` 改 GitHub raw。

## 架构（参照 wx2020/smartdns-rules，但源与产物不同）

- `sources.json`：4 个 job + `min_lines` + `ratio_guard=0.5` + `prev_manifest_url`（指向 GitHub data 分支 manifest，public 可裸读）。
- `convert.py`：纯标准库；`.lst` 源直接读行，`ruleset-json` 源解析 sing-box rule-set 的 `domain`/`domain_suffix`；归一化（复用上游 ALLOWED/BAD_CHARS）、去重排序；输出 `<name>.lst` + `.sha256` + `manifest.json` + `sr-rules.conf`。
- `ads-custom.lst`：自定义广告域名清单，上游文件 196 行 + sr 侧补充 196 行（微信 `wxsmw.wxs.qq.com` + 头条 byteimg 正则 `^p[0-9]+-` 展开 `p1~p99`），共 395 行；静态入库，构建时归一化后前置叠加广告段。
- `ads-ip-reject.lst`：上游三条 IP+端口手写规则的降级清单（8 个硬编码 DNS/广告 IP），因 Shadowrocket 无法表达 `ip_cidr + port` 组合，降为全端口 `IP-CIDR,...,REJECT`；`convert.py --ip-reject` 读入，输出在广告段之后、内网直连之前。纯端口 8091 规则丢弃。
- `.github/workflows/daily.yml`：cron `30 19 * * *`（UTC，比上游 smartdns-rules 的 19:20 晚 10 分钟）→ checkout → setup-python 3.12 → convert → `peaceiris/actions-gh-pages@v4` 发布到 data 分支（force_orphan）→ `softprops/action-gh-release@v2` 建 Release 上传 11 个资产（沿用上游同款 action）。

## 关键设计

- **GFW 段排在 CN 段之前**：匹配上游 `geosite-gfw` 早于 `geoip-cn` 的顺序，套 CF 但命中 gfw 的域名（如 `*.pages.dev`）仍走代理。
- **ipv6=true + not-cn 参与生成（2026-11-20 用户纠正后定案）**：早先 `ipv6=false` 是错误推导（用户从未要求全局关 IPv6，且与上游「IPv6 开、仅抑制境外 AAAA」语义相反——会误关国内域名 IPv6）。现改为 `ipv6=true` 保留国内 IPv6 直连；not-cn.lst 参与规则生成，写成 `DOMAIN-SUFFIX,...,PROXY`，**排在 CN 段之后**（更窄的 DIRECT 先命中）。剔除与 cn 重叠的 156 个域名 + Apple 根域，避免误伤。
- **Apple 根域整体直连（2026-11-20）**：上游 sing-box 用 DNS 规则 `geosite-apple → dns_local` + route.rules `geosite-apple → direct` 让 apple 全家直连（但其 DNS 模块在该机未监听端口、链路实为 dnsmasq→smartdns，apple 直连真正靠 cn.lst 国内解析 + geoip-cn + sniff）。sr 对齐做法：`APPLE_DIRECT_ROOTS`（apple.com/icloud.com/mzstatic.com/itunes.com/me.com/aaplimg.com/apple-dns.net/apple-mapkit.com/apple-cloudkit.com）显式写 DIRECT，并从 not-cn 段剔除。段序对调后 apple 子域（www/itunes/music/a1.mzstatic）也各自命中 cn 的 DIRECT，不再被根域 PROXY 抢走。`DOMAIN-SUFFIX` 是后缀匹配（含裸域本身+所有子域），「更窄的写更前」是 Shadowrocket 官方原则。
- **GEOIP,CN,DIRECT 不加 no-resolve（稳妥方案）**：加 no-resolve 会失去对「未收录国内域名」的 GEOIP 捞回兜底，使其掉进 FINAL 走代理；境外漏网域名由上一段的 not-cn 显式 PROXY 解决，误判风险可控。`dns-server` 在国外分流阶段不参与（域名类规则不经 DNS，仅 GEOIP 需要本地解析），不会走运营商 DNS。
- **CF anycast 直连段按用户要求不生成**。
- 跨策略重复（域名既在广告 REJECT 又在 GFW PROXY / CN DIRECT）是按 first-match 优先级命中的预期设计。

## GitHub Actions 要点

- workflow 放 `.github/workflows/`；`permissions: contents: write` 才能推 data 分支。
- `actions/setup-python@v5` 用 `"3.12"`（ubuntu-latest 已切 26.04，3.8 缓存被移除会失败）。
- tag 用 `data-YYYYMMDD`（重名时加时分秒后缀），Release 用 `softprops/action-gh-release@v2`，避免手工 curl。
- 凭据：GitHub OAuth token 在 `~/.config/openchamber/github-auth.json` 的 `credentials[]`（`lcuwx2016` = `github.com#31233561`），用 curl API 建仓/触发 dispatch；本地 push 用 token 经 HTTPS（gh 当前登录的是 wx2020，不能直接用于 lcuwx2016）。
- **公开仓不写设备/部署代号**：所有入库文件（含产物 conf 头部）禁用「GW」等内网设备名，统一用「上游分流体系 / 上游规则」——2026-11-20 用户明确要求。

## 已验证（2026-11-20）

- 本地 `convert.py` 构建通过：4 job 计数 ads 200374 / cn 110199 / not-cn 27357 / gfw 4434，`sr-rules.conf` 315233 行，语法自检 0 error（FINAL 唯一末条、段序 gfw@200568 < cn@205002）。
- Gitea 时期（迁移前）Actions 手动触发跑通：data 分支 11 个产物、Release 11 个资产；期间修掉两个坑（产物落根目录需先移 dist、Release 资产不能再用 dist/*）。
- GitHub 侧（2026-11-20）：`github.com/lcuwx2016/sr-rules`（public）；按用户要求清除旧历史（wx2020 身份的提交、旧 data 分支/Release/tag 全删），现为 lcuwx2016 身份单提交 `c0a8f8f`。重新触发的 GitHub Actions（run `44697735387`）**success**：data 分支 12 个文件（11 产物 + `.nojekyll`）、Release `data-20261120` 11 个资产，manifest 四 job 计数与本地一致；产物 conf 头部已无 `openwrt-gw` 字样。
