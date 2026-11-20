#!/usr/bin/env python3
"""Build daily Shadowrocket rules from smartdns-rules + flyzstu geosite.

参照 wx2020/smartdns-rules 的 convert.py 架构：sources.json 定义 jobs 与守卫，
拉取 .lst（纯域名）与 .json（sing-box rule-set），归一化/去重/排序，
输出 *.lst + *.lst.sha256 + manifest.json + sr-rules.conf。

sr-rules.conf 的段序语义：
  1 广告 REJECT → 2 内网直连 → 3 GFW PROXY → 4 国内 DIRECT → 5 FINAL,PROXY
  （GFW 排在 CN 之前，匹配上游路由中 geosite-gfw 早于 geoip-cn 的顺序）
纯标准库，无第三方依赖。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

ALLOWED = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$")
BAD_CHARS = set("*()^$[]?\\+|, \t/\"'<>@#&=%!")

SKIP_PROXY = (
    "192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, "
    "*.local, *.lan, *.internal, e.crashlytics.com, captive.apple.com, "
    "sequoia.apple.com, seed-sequoia.siri.apple.com, *.ls.apple.com, 52.198.175.31/32"
)
BYPASS_TUN = (
    "10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,"
    "192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,"
    "198.51.100.0/24,203.0.113.0/24,233.252.0.0/24,224.0.0.0/4,255.255.255.255/32,"
    "::1/128,::ffff:0:0/96,::ffff:0:0:0/96,64:ff9b::/96,64:ff9b:1::/48,100::/64,"
    "2001::/32,2001:20::/28,2001:db8::/32,2002::/16,3fff::/20,5f00::/16,"
    "fc00::/7,fe80::/10,ff00::/8,52.198.175.31/32"
)
DIRECT_CIDRS = [
    "192.168.0.0/16", "10.0.0.0/8", "100.64.0.0/10", "10.64.0.0/24",
    "172.19.0.0/30", "127.0.0.0/8", "52.198.175.31/32",
]
# Apple 根域整体直连，对齐上游 geosite-apple 集合（apple.com/icloud.com 等被 not-cn 判境外）
APPLE_DIRECT_ROOTS = [
    "apple.com", "icloud.com", "mzstatic.com", "itunes.com", "me.com",
    "aaplimg.com", "apple-dns.net", "apple-mapkit.com", "apple-cloudkit.com",
]


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sr-rules/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def normalize(entry: str):
    d = entry.strip().lower().lstrip(".")
    if not d or len(d) > 253:
        return None
    if any(c in d for c in BAD_CHARS):
        return None
    if not ALLOWED.match(d):
        return None
    return d


def collect_lst(url: str, domains: set) -> None:
    text = fetch(url).decode("utf-8", errors="replace")
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        n = normalize(s)
        if n:
            domains.add(n)


def collect_ruleset(url: str, domains: set) -> None:
    data = json.loads(fetch(url))
    for rule in data.get("rules", []) or []:
        for key in ("domain", "domain_suffix"):
            for item in rule.get(key, []) or []:
                if isinstance(item, str):
                    n = normalize(item)
                    if n:
                        domains.add(n)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_prev_manifest(url: str | None) -> dict:
    if not url:
        return {}
    try:
        return json.loads(fetch(url))
    except Exception as exc:  # noqa: BLE001 - first run / offline is fine
        print(f"[warn] no previous manifest ({exc})", file=sys.stderr)
        return {}


def load_custom_ads(path: Path) -> list:
    if not path.exists():
        print(f"[warn] {path} not found, skip custom ads", file=sys.stderr)
        return []
    seen, out = set(), []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        n = normalize(s)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def load_ip_reject(path: Path) -> list:
    """读入 IP+端口降级清单（CIDR 列表）；忽略注释与空行。"""
    if not path.exists():
        print(f"[warn] {path} not found, skip ip reject", file=sys.stderr)
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "/" not in s:
            print(f"[warn] invalid CIDR in ip-reject: {s}", file=sys.stderr)
            continue
        out.append(s)
    return out


def build_conf(out: Path, jobs: dict, custom_ads: list, ip_rejects: list, generated_at: str) -> Path:
    lines = []
    a = lines.append
    a("# Shadowrocket 规则 — 由 sr-rules 每日构建")
    a(f"# 构建时间 (UTC): {generated_at}")
    a("# 来源: wx2020/smartdns-rules (ads/cn/not-cn) + flyzstu/sing-box-rules (gfw)")
    a("# 分流语义：去广告 + 国内外划分")
    a("#")
    a("# 段序 (first-match):")
    a("#   1 广告 REJECT (ads-custom 前置 + geosite-category-ads-all + IP 降级清单)")
    a("#   2 内网/特殊直连")
    a("#   3 GFW 域名 PROXY (先于 CN，匹配上游 gfw 早于 cn 的顺序)")
    a("#   4 国内域名 DIRECT (含 apple 根域整体直连) + GEOIP,CN,DIRECT")
    a("#   3b not-cn 域名 PROXY (排在 CN 之后：更窄的 DIRECT 先命中，避免根域宽规则抢走子域)")
    a("#   5 FINAL,PROXY")
    a("#   GEOIP 不带 no-resolve，保留国内漏网域名的 GEOIP 兜底")
    a("#   ipv6=true：保留国内域名 IPv6 直连；境外域名由 not-cn 段显式 PROXY，不靠全局关 IPv6")
    a("")
    a("[General]")
    a("ipv6 = true")
    a("bypass-system = true")
    a(f"skip-proxy = {SKIP_PROXY}")
    a(f"bypass-tun = {BYPASS_TUN}")
    a("dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query")
    a("")
    a("[Rule]")
    a("# ===== 1. 广告 REJECT ===== ")
    ad_seen = set()
    for d in custom_ads:
        if d not in ad_seen:
            ad_seen.add(d)
            a(f"DOMAIN-SUFFIX,{d},REJECT")
    for d in jobs["geosite-category-ads-all"]:
        if d not in ad_seen:
            ad_seen.add(d)
            a(f"DOMAIN-SUFFIX,{d},REJECT")
    a("")
    a("# ===== 1b. IP+端口广告规则降级为全端口 REJECT（原 port 80/443/8091 限定） =====")
    for cidr in ip_rejects:
        a(f"IP-CIDR,{cidr},REJECT")
    a("")
    a("# ===== 2. 内网/特殊直连 =====")
    for cidr in DIRECT_CIDRS:
        a(f"IP-CIDR,{cidr},DIRECT")
    a("DOMAIN-SUFFIX,wx2020.cn,DIRECT")
    a("DOMAIN-SUFFIX,wx2020.fun,DIRECT")
    a("DOMAIN,myip.ipip.net,DIRECT")
    a("")
    a("# ===== 3. GFW 域名 PROXY =====")
    for d in jobs["geosite-gfw"]:
        a(f"DOMAIN-SUFFIX,{d},PROXY")
    a("")
    a("# ===== 4. 国内域名 DIRECT（遮蔽去重：删被前置宽规则覆盖的窄域名） =====")
    # DOMAIN-SUFFIX 是后缀匹配，窄域名若真后缀已在前面输出为 DIRECT，则永远命中不到，
    # 删掉不改变 first-match 结果（cn 段本次约 69 条，含被裸 "cn" 遮蔽的 10 条）。
    direct_emitted = set()
    for d in jobs["cn"]:
        # 裸 "cn" 规则已覆盖整个 .cn 域，所有 *.cn 独立条目均为冗余，直接过滤
        if d.endswith(".cn"):
            continue
        parts = d.split(".")
        if any(".".join(parts[i:]) in direct_emitted for i in range(1, len(parts))):
            continue
        direct_emitted.add(d)
        a(f"DOMAIN-SUFFIX,{d},DIRECT")
    # Apple 根域整体直连（对齐上游 geosite-apple）：这些根域在 not-cn 里被判境外，
    # 但其子域在 cn 里判国内；若不在此显式 DIRECT，会被后面 not-cn 的根域 PROXY 抢走。
    for d in APPLE_DIRECT_ROOTS:
        a(f"DOMAIN-SUFFIX,{d},DIRECT")
    a("GEOIP,CN,DIRECT")
    a("")
    a("# ===== 3b. not-cn 域名 PROXY（遮蔽去重：删被前置宽规则覆盖的窄域名） =====")
    # 两类剔除，均不改变 first-match 结果：
    #   1) cn/apple/gfw 已覆盖者（误伤防护 + 跨段去重）
    #   2) 被「前置 PROXY 宽后缀」遮蔽的窄域名：DOMAIN-SUFFIX 是后缀匹配，
    #      若某条窄域名的真后缀已在前面输出过（gfw 段或更早的 not-cn 条目），
    #      它永远不会被命中——同策略 PROXY，删掉纯属去冗余。
    covered = set(jobs["cn"]) | set(APPLE_DIRECT_ROOTS) | set(jobs["geosite-gfw"])
    proxy_emitted = set(jobs["geosite-gfw"])  # gfw 段在前，全部已输出为 PROXY 后缀
    notcn_seen = set()
    for d in jobs["not-cn"]:
        if d in covered or d in notcn_seen:
            continue
        parts = d.split(".")
        shadowed = False
        for i in range(1, len(parts)):
            if ".".join(parts[i:]) in proxy_emitted:
                shadowed = True
                break
        if shadowed:
            continue
        notcn_seen.add(d)
        proxy_emitted.add(d)
        a(f"DOMAIN-SUFFIX,{d},PROXY")
    a("")
    a("# ===== 5. 兜底 =====")
    a("FINAL,PROXY")
    conf = out / "sr-rules.conf"
    conf.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return conf


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="dist")
    ap.add_argument("--sources", default="sources.json")
    ap.add_argument("--custom-ads", default="ads-custom.lst")
    ap.add_argument("--ip-reject", default="ads-ip-reject.lst")
    ap.add_argument("--prev-manifest-url", default=None)
    ap.add_argument("--ratio-guard", type=float, default=None)
    args = ap.parse_args()

    cfg = json.loads(Path(args.sources).read_text(encoding="utf-8"))
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    prev_url = args.prev_manifest_url or cfg.get("prev_manifest_url")
    ratio = args.ratio_guard if args.ratio_guard is not None else float(cfg.get("ratio_guard", 0.5))
    prev_jobs = load_prev_manifest(prev_url).get("jobs", {})

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest = {"generated_at_utc": generated_at, "jobs": {}, "conf": {}}
    domains_by_job = {}

    for job in cfg["jobs"]:
        name = job["name"]
        domains: set = set()
        for url in job["sources"]:
            n0 = len(domains)
            if job.get("kind") == "ruleset-json":
                collect_ruleset(url, domains)
            else:
                collect_lst(url, domains)
            print(f"[{name}] {url} -> +{len(domains) - n0} domains")
        lines = sorted(domains)
        count = len(lines)

        min_lines = int(job.get("min_lines", 0))
        if count < min_lines:
            sys.exit(f"[guard] {name}: {count} < min_lines={min_lines}, abort")
        prev_count = prev_jobs.get(name, {}).get("count")
        if prev_count and count < prev_count * ratio:
            sys.exit(f"[guard] {name}: {count} < {prev_count} * {ratio}, abort")

        lst = out / f"{name}.lst"
        lst.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        digest = sha256_file(lst)
        (out / f"{name}.lst.sha256").write_text(f"{digest}  {name}.lst\n", encoding="ascii")
        manifest["jobs"][name] = {
            "count": count,
            "sha256": digest,
            "sources": job["sources"],
        }
        domains_by_job[name] = lines
        print(f"[{name}] {count} domains")

    conf = build_conf(
        out, domains_by_job,
        load_custom_ads(Path(args.custom_ads)),
        load_ip_reject(Path(args.ip_reject)),
        generated_at,
    )
    conf_digest = sha256_file(conf)
    (out / "sr-rules.conf.sha256").write_text(
        f"{conf_digest}  sr-rules.conf\n", encoding="ascii"
    )
    manifest["conf"] = {
        "sha256": conf_digest,
        "lines": len(conf.read_text(encoding="utf-8").splitlines()),
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"done -> {out}  (sr-rules.conf {manifest['conf']['lines']} lines)")


if __name__ == "__main__":
    main()
