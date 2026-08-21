#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sing-box 轻量 Web 面板  (纯标准库，无第三方依赖)
功能: 建节点(7种协议) / 出站管理 / 节点绑定出站 / 分享链接 / 订阅
"""
import base64
import gzip
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SB_BIN = "/usr/local/sing-box/sing-box"
SB_ETC = "/etc/sing-box"
SB_CONF = f"{SB_ETC}/config.json"
CERT_DIR = f"{SB_ETC}/cert"
PANEL_CFG = f"{SB_ETC}/panel.json"
SUB_DIR = f"{SB_ETC}/sub"
META_FILE = f"{SB_ETC}/nodemeta.json"   # tag -> 分享链接/展示信息

# ── Xray-core（第二核心，可选安装）──
XR_BIN = "/usr/local/xray/xray"
XR_ETC = "/etc/xray"
XR_CONF = f"{XR_ETC}/config.json"
XR_SVC = "xray"
DEFAULT_CORE = "sing-box"

LOCK = threading.Lock()
SESSIONS = {}
SESSION_TTL = 8 * 3600

# ════════════════════════════════════════════
# 工具
# ════════════════════════════════════════════
def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def cfg():
    return load_json(SB_CONF, {"log": {"level": "warn"}, "inbounds": [],
                               "outbounds": [{"type": "direct", "tag": "direct"}],
                               "route": {"rules": [{"action": "sniff"}], "final": "direct"}})


def meta():
    return load_json(META_FILE, {})


_IP_CACHE = {"ip": "", "t": 0}


def public_ip(force=False):
    """带缓存的公网 IP。避免每次请求都跑 curl 拖住面板。"""
    now = time.time()
    if not force and _IP_CACHE["ip"] and now - _IP_CACHE["t"] < 3600:
        return _IP_CACHE["ip"]
    # 先试本地路由（瞬间返回，无网络请求）
    c, o, _ = sh("ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K\\S+'", 3)
    local = o.strip()
    for u in ("https://api.ipify.org", "https://ip.sb"):
        c, o, _ = sh(f"curl -s4 --max-time 3 {u}", 5)
        if c == 0 and o.strip():
            _IP_CACHE.update(ip=o.strip(), t=now)
            return _IP_CACHE["ip"]
    # 取不到就用上次结果或本地地址，绝不阻塞
    ip = _IP_CACHE["ip"] or local or "127.0.0.1"
    _IP_CACHE.update(ip=ip, t=now)
    return ip


def rand_port():
    """随机可用端口。纯 Python 探测，不起子进程，最多尝试 30 次。"""
    import socket as _sk
    used = used_ports()
    for _ in range(30):
        p = secrets.randbelow(40000) + 20000
        if p in used:
            continue
        free = True
        for fam, typ in ((_sk.AF_INET, _sk.SOCK_STREAM), (_sk.AF_INET, _sk.SOCK_DGRAM)):
            try:
                with _sk.socket(fam, typ) as t:
                    t.setsockopt(_sk.SOL_SOCKET, _sk.SO_REUSEADDR, 1)
                    t.bind(("", p))
            except OSError:
                free = False
                break
        if free:
            return p
    return secrets.randbelow(40000) + 20000


def gen_uuid():
    c, o, _ = sh(f"{SB_BIN} generate uuid")
    return o.strip() if c == 0 and o else ""


def gen_reality():
    c, o, _ = sh(f"{SB_BIN} generate reality-keypair")
    priv = pub = ""
    for line in o.splitlines():
        low = line.lower()
        if "private" in low:
            priv = line.split()[-1]
        elif "public" in low:
            pub = line.split()[-1]
    return priv, pub


_CERT_CACHE = {"t": 0, "v": []}


def list_certs():
    now = time.time()
    if _CERT_CACHE["v"] and now - _CERT_CACHE["t"] < 300:
        return _CERT_CACHE["v"]
    out = []
    if os.path.isdir(CERT_DIR):
        for d in sorted(os.listdir(CERT_DIR)):
            fc = f"{CERT_DIR}/{d}/fullchain.pem"
            pk = f"{CERT_DIR}/{d}/privkey.pem"
            if os.path.exists(fc) and os.path.exists(pk):
                c, o, _ = sh(f"openssl x509 -in {fc} -noout -enddate")
                out.append({"domain": d, "cert": fc, "key": pk,
                            "expire": o.replace("notAfter=", "").strip()})
    _CERT_CACHE.update(t=now, v=out)
    return out


ACME_HOME = "/root/.acme.sh"


def find_acme():
    """在常见位置查找 acme.sh"""
    for p in (f"{ACME_HOME}/acme.sh",
              os.path.expanduser("~/.acme.sh/acme.sh"),
              "/usr/local/bin/acme.sh",
              "/root/acme.sh/acme.sh"):
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def install_acme(email):
    """安装 acme.sh，显式指定 HOME，带备用源"""
    env = "HOME=/root "
    srcs = [
        "https://get.acme.sh",
        "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh",
    ]
    last = ""
    for i, src in enumerate(srcs):
        if i == 0:
            cmd = f'{env}curl -fsSL {src} | {env}sh -s -- --install --home {ACME_HOME} --accountemail {email}'
        else:
            cmd = (f'cd /tmp && {env}curl -fsSL {src} -o acme.sh && chmod +x acme.sh && '
                   f'{env}./acme.sh --install --home {ACME_HOME} --accountemail {email}')
        c, o, e = sh(cmd, 90)
        if find_acme():
            return True, ""
        last = (e or o or "")[-400:]
    return False, last or "未知错误"


CERT_JOB = {"running": False, "domain": "", "ok": None, "msg": "", "step": ""}


def preflight_cert(domain):
    """申请前预检：DNS 是否指向本机、80 端口是否可用"""
    myip = public_ip()
    c, o, _ = sh(f"getent ahostsv4 {domain} | head -1 | awk '{{print $1}}'", 10)
    resolved = o.strip()
    if not resolved:
        return False, f"域名 {domain} 无法解析，请先添加 A 记录"
    if resolved != myip:
        return False, (f"域名解析到 {resolved}，但本机公网 IP 是 {myip}\n"
                       f"请把 {domain} 的 A 记录指向 {myip}，等 DNS 生效后再试")
    # 80 端口本地是否被非 sing-box 占用
    _, who, _ = sh("ss -ltnp 2>/dev/null | grep ':80 ' | head -1")
    if who.strip() and "sing-box" not in who:
        return False, f"80 端口被占用，请先停止:\n{who.strip()}"
    return True, ""


def issue_cert_async(domain):
    """后台线程申请，不阻塞面板"""
    def work():
        CERT_JOB.update(running=True, domain=domain, ok=None, msg="", step="预检中")
        try:
            okk, m = preflight_cert(domain)
            if not okk:
                CERT_JOB.update(ok=False, msg=m)
                return
            CERT_JOB["step"] = "申请中（Let's Encrypt 验证）"
            okk, m = issue_cert(domain)
            CERT_JOB.update(ok=okk, msg=m)
        except Exception as e:
            CERT_JOB.update(ok=False, msg=f"异常: {e}")
        finally:
            CERT_JOB.update(running=False, step="")
    threading.Thread(target=work, daemon=True).start()


def issue_cert(domain):
    acme = find_acme()
    if not acme:
        okk, msg = install_acme(f"admin@{domain}")
        if not okk:
            return False, f"acme.sh 安装失败: {msg}"
        acme = find_acme()
        if not acme:
            return False, "acme.sh 安装后仍找不到可执行文件"

    envp = f"HOME=/root {acme}"
    os.makedirs(f"{CERT_DIR}/{domain}", exist_ok=True)

    # ① 若 acme.sh 本地已有有效证书，直接安装，不消耗签发配额
    for d in (f"{ACME_HOME}/{domain}_ecc", f"{ACME_HOME}/{domain}"):
        src = f"{d}/fullchain.cer"
        if os.path.exists(src):
            c, o, _ = sh(f"openssl x509 -in {src} -noout -checkend 604800", 10)
            if c == 0:      # 7 天内不过期 → 可直接用
                ecc = "--ecc" if d.endswith("_ecc") else ""
                sh(f"{envp} --install-cert -d {domain} {ecc} "
                   f"--fullchain-file {CERT_DIR}/{domain}/fullchain.pem "
                   f"--key-file {CERT_DIR}/{domain}/privkey.pem "
                   f'--reloadcmd "systemctl restart sing-box; '
       f'systemd-run --collect --on-active=2 --unit=sbpanel-reload systemctl restart singbox-panel"', 60)
                if os.path.exists(f"{CERT_DIR}/{domain}/fullchain.pem"):
                    return True, "已复用本地现有证书（未消耗签发次数）"

    sh(f"{envp} --set-default-ca --server letsencrypt", 30)

    # 检查 80 端口占用（standalone 验证需要）
    c80, who, _ = sh("ss -ltnp 2>/dev/null | grep ':80 ' | head -1")
    stopped_sb = False
    if who.strip():
        if "sing-box" in who:
            sh("systemctl stop sing-box"); stopped_sb = True
        else:
            return False, f"80 端口被占用，请先停止该服务:\n{who.strip()}"
    else:
        sh("systemctl stop sing-box"); stopped_sb = True

    c, o, e = sh(f"{envp} --issue -d {domain} --standalone --keylength ec-256", 120)
    out = (o or "") + (e or "")

    # ② 撞 Let's Encrypt 限流 → 自动改用 ZeroSSL 重试
    if c != 0 and "rateLimited" in out:
        sh(f"{envp} --set-default-ca --server zerossl", 30)
        c, o2, e2 = sh(f"{envp} --issue -d {domain} --standalone --keylength ec-256", 120)
        out = (o2 or "") + (e2 or "")
        if c == 0:
            out += "\n(已自动改用 ZeroSSL 签发)"

    if c != 0:
        if stopped_sb:
            sh("systemctl start sing-box")
        if "rateLimited" in out:
            import re as _re
            m = _re.search(r"retry after ([0-9\-]+ [0-9:]+ UTC)", out)
            when = m.group(1) if m else "稍后"
            return False, (f"Let's Encrypt 限流：同一域名 7 天内最多 5 张证书。\n"
                           f"可在 {when} 后重试，或换一个子域名（如 tw2.688660.xyz）立即申请。\n"
                           f"ZeroSSL 备用通道也失败了，可能需要邮箱验证。")
        return False, f"申请失败，请确认 {domain} 已解析到本机且 80 端口放行\n{out[-450:]}"

    # 续期后同时重载 sing-box 与面板（面板可能正用此证书跑 HTTPS）
    sh(f"{envp} --install-cert -d {domain} --ecc "
       f"--fullchain-file {CERT_DIR}/{domain}/fullchain.pem "
       f"--key-file {CERT_DIR}/{domain}/privkey.pem "
       f'--reloadcmd "systemctl restart sing-box; '
       f'systemd-run --collect --on-active=2 --unit=sbpanel-reload systemctl restart singbox-panel"', 60)
    sh("systemctl start sing-box")

    _CERT_CACHE.update(t=0, v=[])
    if not os.path.exists(f"{CERT_DIR}/{domain}/fullchain.pem"):
        return False, "证书已签发但安装失败，请查看 /root/.acme.sh 日志"
    # 面板正用此域名时，安全地重启自己以加载新证书
    if load_json(PANEL_CFG, {}).get("tls_domain") == domain:
        safe_restart_self(3)
    return True, "证书申请成功"


# ════════════════════════════════════════════
# Reality dest 扫描（测 TLS1.3 / H2 / 延迟）
# ════════════════════════════════════════════
DEST_CANDIDATES = [
    "www.nvidia.com", "www.lovelive-anime.jp", "addons.mozilla.org",
    "www.apple.com", "gateway.icloud.com", "www.swift.com",
    "one-piece.com", "www.sega.com", "www.tesla.com",
    "dl.google.com", "www.samsung.com", "cdn-dynmedia-1.microsoft.com",
    "s0.awsstatic.com", "player.live-video.net", "www.cisco.com",
]


def _probe_openssl(host, port, timeout):
    """兜底：Python ssl 不支持 TLS1.3 时改用 openssl 命令行"""
    r = {"host": host, "ok": False, "ms": -1, "tls": "", "h2": False, "err": ""}
    t0 = time.time()
    c, o, e = sh(f"echo | openssl s_client -connect {host}:{port} "
                 f"-servername {host} -tls1_3 -alpn h2 2>/dev/null", timeout + 2)
    r["ms"] = int((time.time() - t0) * 1000)
    if "TLSv1.3" in o:
        r["tls"] = "TLSv1.3"
        r["h2"] = "ALPN protocol: h2" in o
        r["ok"] = r["h2"]
        if not r["h2"]:
            r["err"] = "不支持H2"
    else:
        r["err"] = "不支持TLS1.3"
        r["ms"] = -1 if not o else r["ms"]
    return r


def probe_dest(host, port=443, timeout=5):
    import ssl
    import socket
    # 本机 Python 若不支持 TLS1.3（如 macOS LibreSSL），走 openssl 兜底
    if not getattr(ssl, "HAS_TLSv1_3", False):
        return _probe_openssl(host, port, timeout)

    r = {"host": host, "ok": False, "ms": -1, "tls": "", "h2": False, "err": ""}
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass
        t0 = time.time()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                r["ms"] = int((time.time() - t0) * 1000)
                r["tls"] = ss.version() or ""
                r["h2"] = (ss.selected_alpn_protocol() == "h2")
                try:
                    ci = ss.cipher() or ()
                    r["cipher"] = ci[0] if ci else ""
                    cert = ss.getpeercert() or {}
                    iss = dict(x[0] for x in cert.get("issuer", []))
                    r["issuer"] = iss.get("organizationName") or iss.get("commonName") or ""
                except Exception:
                    pass
                # 合格条件: TLS1.3 + H2
                r["ok"] = (r["tls"] == "TLSv1.3" and r["h2"])
                if not r["ok"]:
                    miss = []
                    if r["tls"] != "TLSv1.3":
                        miss.append(f"需TLS1.3(实为{r['tls']})")
                    if not r["h2"]:
                        miss.append("不支持H2")
                    r["err"] = " ".join(miss)
    except Exception as e:
        r["err"] = str(e)[:60]
    return r


def scan_dests(hosts=None):
    hosts = hosts or DEST_CANDIDATES
    res = [None] * len(hosts)

    def work(i, h):
        res[i] = probe_dest(h)

    ts = []
    for i, h in enumerate(hosts):
        t = threading.Thread(target=work, args=(i, h), daemon=True)
        t.start()
        ts.append(t)
    for t in ts:
        t.join(timeout=8)
    out = [r for r in res if r]
    # 合格的按延迟升序在前，不合格的在后
    out.sort(key=lambda x: (not x["ok"], x["ms"] if x["ms"] >= 0 else 99999))
    return out


def cleanup_disk(deep=False):
    """清理残留临时文件与旧备份。deep=True 时连 apt 缓存/日志一起清。"""
    freed = []
    d = os.path.dirname(SB_BIN)
    # 1) 本程序产生的临时目录（含旧版遗留在 /tmp 的）
    for pat in (f"{d}/.up-*", "/tmp/sbup-*", "/var/tmp/sbup-*"):
        c, o, _ = sh(f"du -scm {pat} 2>/dev/null | tail -1 | awk '{{print $1}}'")
        try:
            mb = int(o.strip())
        except ValueError:
            mb = 0
        if mb > 0:
            sh(f"rm -rf {pat}")
            freed.append(f"临时文件 {mb}MB")
    # 2) sing-box 旧版本备份（不保留）
    c, o, _ = sh(f"ls -1 {SB_BIN}.bak.* 2>/dev/null")
    olds = [x for x in o.splitlines() if x.strip()]
    if olds:
        tot = 0
        for f in olds:
            try:
                tot += os.path.getsize(f) // 1024 // 1024
            except OSError:
                pass
            sh(f"rm -f '{f}'")
        freed.append(f"旧版本文件 {len(olds)} 个 / {tot}MB")
    # 3) py 编译缓存
    sh(f"rm -rf {SB_ETC}/__pycache__ 2>/dev/null")
    if deep:
        sh("apt-get clean >/dev/null 2>&1")
        sh("journalctl --vacuum-size=30M >/dev/null 2>&1")
        sh("rm -f /root/.acme.sh/acme.sh.log 2>/dev/null")
        freed.append("apt缓存/系统日志")
    return freed


def disk_report():
    out = {}
    for p in ("/", "/tmp", os.path.dirname(SB_BIN)):
        c, o, _ = sh(f"df -Pm {p} 2>/dev/null | tail -1 | awk '{{print $2\" \"$4}}'")
        try:
            tot, av = o.split()
            out[p] = {"total": int(tot), "avail": int(av)}
        except ValueError:
            pass
    _, fs, _ = sh("findmnt -no FSTYPE /tmp 2>/dev/null")
    out["tmp_is_ram"] = fs.strip() == "tmpfs"
    return out


def janitor_loop():
    """后台定期清理：启动后 1 分钟跑一次，之后每 12 小时一次"""
    time.sleep(60)
    while True:
        try:
            cleanup_disk(deep=False)
            # 内存侧清理：过期会话、超量任务记录
            now = time.time()
            for k in [k for k, v in SESSIONS.items() if v <= now]:
                SESSIONS.pop(k, None)
            if len(globals().get("SPEED_JOB", {})) > 50:
                globals()["SPEED_JOB"].clear()
            del AUTO_LOG[:-10]
        except Exception:
            pass
        time.sleep(12 * 3600)


HEARTBEAT = {"t": time.time()}


def watchdog_loop(host, port, use_tls=False):
    """看门狗：面板卡死时自杀让 systemd 拉起。
    判定必须同时满足「探测无响应」和「心跳陈旧」，避免误杀。"""
    import socket as _sk
    time.sleep(120)
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    fails = 0
    while True:
        time.sleep(60)
        # 心跳：只要近 5 分钟内有请求被处理过，就说明面板是活的
        fresh = (time.time() - HEARTBEAT["t"]) <= 300
        if fresh:
            fails = 0
            continue

        # 心跳陈旧才主动探测（TLS 面板要用 TLS 握手，否则必然失败）
        ok = False
        try:
            raw = _sk.create_connection((probe_host, port), timeout=8)
            try:
                if use_tls:
                    import ssl as _s
                    c = _s.SSLContext(_s.PROTOCOL_TLS_CLIENT)
                    c.check_hostname = False
                    c.verify_mode = _s.CERT_NONE
                    conn = c.wrap_socket(raw, server_hostname=probe_host)
                else:
                    conn = raw
                conn.sendall(b"GET /__ping HTTP/1.0\r\n\r\n")
                ok = b"200" in conn.recv(64)
            finally:
                try:
                    conn.close()
                except Exception:
                    raw.close()
        except Exception:
            ok = False

        if ok:
            fails = 0
            continue
        fails += 1
        print(f"[watchdog] 无响应且心跳陈旧 {fails}/3", file=sys.stderr)
        if fails >= 3:
            print("[watchdog] 面板卡死，退出由 systemd 重启", file=sys.stderr)
            os._exit(1)


def safe_restart_self(delay=1):
    """重启面板自身。必须脱离自己的 cgroup，否则会被一起杀掉导致服务停摆。"""
    c, _, _ = sh("command -v systemd-run")
    if c == 0:
        sh(f"systemd-run --collect --on-active={delay} "
           f"--unit=sbpanel-restart-{secrets.token_hex(3)} "
           f"systemctl restart singbox-panel", 10)
    else:
        # 兜底：用 setsid + nohup 脱离进程组
        sh(f"setsid nohup sh -c 'sleep {delay}; systemctl restart singbox-panel' "
           f">/dev/null 2>&1 &", 5)


def prune_orphan_rules(c):
    """清理孤儿路由规则：指向不存在出站的绑定、无对应入站的 QUIC 拒绝、重复规则"""
    obs = {o.get("tag") for o in c.get("outbounds", [])}
    ins = {i.get("tag") for i in c.get("inbounds", [])}
    rules = c.get("route", {}).get("rules", [])
    out, seen, removed = [], set(), 0
    for r in rules:
        # 指向已删除出站的规则
        if r.get("outbound") and r["outbound"] not in obs:
            removed += 1; continue
        # inbound 里已不存在的入站，摘掉
        if r.get("inbound"):
            rest = [x for x in r["inbound"] if x in ins]
            if not rest:
                removed += 1; continue
            if rest != r["inbound"]:
                r = dict(r, inbound=rest)
        # 完全重复的规则去重
        key = json.dumps(r, sort_keys=True, ensure_ascii=False)
        if key in seen:
            removed += 1; continue
        seen.add(key)
        out.append(r)
    if removed:
        c["route"]["rules"] = out
    return removed


def apply_config(new_cfg):
    """校验并写入，失败自动回滚"""
    try:
        n = prune_orphan_rules(new_cfg)
        if n:
            print(f"[config] 清理 {n} 条孤儿/重复路由规则", file=sys.stderr)
    except Exception:
        pass
    old = None
    if os.path.exists(SB_CONF):
        with open(SB_CONF) as f:
            old = f.read()
    save_json(SB_CONF, new_cfg)
    c, o, e = sh(f"{SB_BIN} check -c {SB_CONF}")
    if c != 0:
        if old is not None:
            with open(SB_CONF, "w") as f:
                f.write(old)
        return False, (e or o or "配置校验失败")
    c2, _, e2 = sh("systemctl restart sing-box")
    time.sleep(1)
    c3, st, _ = sh("systemctl is-active sing-box")
    if st.strip() != "active":
        if old is not None:
            with open(SB_CONF, "w") as f:
                f.write(old)
            sh("systemctl restart sing-box")
        _, log, _ = sh("journalctl -u sing-box -n 15 --no-pager")
        return False, f"启动失败已回滚:\n{log}"
    return True, "ok"


# ════════════════════════════════════════════
# Xray-core：inbound 生成
# ════════════════════════════════════════════
def _dur_ms(v):
    """'1m' / '30s' / '1h' -> 毫秒"""
    m = re.match(r"^(\d+)([smh])$", str(v).strip())
    if not m:
        return 0
    n = int(m.group(1))
    return n * {"s": 1000, "m": 60000, "h": 3600000}[m.group(2)]


def gen_reality_x():
    """优先用 xray 自己生成密钥；两核心的 Reality 都是 X25519，格式互通"""
    if xr_installed():
        c, o, _ = sh(f"{XR_BIN} x25519")
        priv = pub = ""
        for line in o.splitlines():
            low = line.lower()
            if "private" in low:
                priv = line.split()[-1]
            elif "public" in low or "password" in low:
                pub = line.split()[-1]
        if priv and pub:
            return priv, pub
    return gen_reality()


def apply_advanced_x(ib, ss, uri, proto, f):
    """把高级选项写进 Xray inbound / streamSettings，并同步修正分享链接"""
    keys = {a["k"] for a in (PROTOCOLS.get(proto, {}).get("adv_xray") or [])}
    if not keys:
        return ib, ss, uri

    sock = {}
    if "tfo" in keys and _bl(f, "tfo"):
        sock["tcpFastOpen"] = True
    if "mptcp" in keys and _bl(f, "mptcp"):
        sock["tcpMptcp"] = True
    if sock:
        ss["sockopt"] = sock

    if "tls_min" in keys and ss.get("security") == "tls":
        t = ss.setdefault("tlsSettings", {})
        t["minVersion"] = "1.2" if f.get("tls_min") == "1.2" else "1.3"
        a = f.get("alpn", "不设置")
        if a != "不设置":
            t["alpn"] = [x.strip() for x in a.split(",") if x.strip()]
            if uri.startswith(("vless://", "trojan://")):
                uri = _uq(uri, alpn=a)

    if "transport" in keys:
        sel = f.get("transport", "")
        raw = (f.get("tr_path") or "/").strip()
        host = (f.get("tr_host") or "").strip()
        path = raw if raw.startswith("/") else "/" + raw
        kind = ""
        if sel.startswith("WebSocket"):
            kind = "ws"
            ss["network"] = "ws"
            w = {"path": path}
            if host:
                w["host"] = host
            ss["wsSettings"] = w
        elif sel.startswith("gRPC"):
            kind = "grpc"
            ss["network"] = "grpc"
            ss["grpcSettings"] = {"serviceName": raw.lstrip("/") or "grpc"}
            path = raw.lstrip("/") or "grpc"
        elif sel.startswith("HTTPUpgrade"):
            kind = "httpupgrade"
            ss["network"] = "httpupgrade"
            h = {"path": path}
            if host:
                h["host"] = host
            ss["httpupgradeSettings"] = h
        elif sel.startswith("XHTTP"):
            kind = "xhttp"
            ss["network"] = "xhttp"
            x = {"path": path, "mode": "auto"}
            if host:
                x["host"] = host
            ss["xhttpSettings"] = x
        elif sel.startswith("mKCP"):
            kind = "kcp"
            ss["network"] = "kcp"
            k = {"header": {"type": f.get("kcp_header", "none") or "none"},
                 "uplinkCapacity": 100, "downlinkCapacity": 100,
                 "congestion": True, "mtu": 1350, "tti": 50,
                 "readBufferSize": 2, "writeBufferSize": 2}
            if (f.get("kcp_seed") or "").strip():
                k["seed"] = f["kcp_seed"].strip()
            ss["kcpSettings"] = k

        if kind:
            # vision 流控只能配原始 TCP
            for cl in ((ib.get("settings") or {}).get("clients") or []):
                cl.pop("flow", None)
            if uri.startswith("vmess://"):
                try:
                    vm = json.loads(base64.b64decode(uri[8:] + "==").decode())
                    vm["net"] = kind
                    if kind == "kcp":
                        # vmess 链接里 kcp 用 type=伪装类型、path=seed
                        vm["type"] = f.get("kcp_header", "none") or "none"
                        vm["path"] = (f.get("kcp_seed") or "").strip()
                    else:
                        vm["path"] = path
                    if host:
                        vm["host"] = host
                    uri = "vmess://" + b64(json.dumps(vm, ensure_ascii=False))
                except Exception:
                    pass
            else:
                kw = {"type": kind, "flow": None}
                kw["serviceName" if kind == "grpc" else "path"] = path
                if host:
                    kw["host"] = host
                if kind == "kcp":
                    kw["headerType"] = f.get("kcp_header", "none")
                    if (f.get("kcp_seed") or "").strip():
                        kw["seed"] = f["kcp_seed"].strip()
                uri = _uq(uri, **kw)
    return ib, ss, uri


def _sb_ob_to_xray(o):
    """sing-box 出站 -> Xray 出站（出站仍在 sing-box 侧统一管理，这里只做镜像）"""
    t, tag = o.get("type"), o.get("tag")
    addr = o.get("server")
    try:
        port = int(o.get("server_port") or 0)
    except (TypeError, ValueError):
        return None
    if not addr or not port or t not in ("socks", "http"):
        return None
    srv = {"address": addr, "port": port}
    if o.get("username"):
        srv["users"] = [{"user": o["username"], "pass": o.get("password", "")}]
    x = {"tag": tag, "protocol": t, "settings": {"servers": [srv]}}
    tls = o.get("tls") or {}
    if t == "http" and tls.get("enabled"):
        x["streamSettings"] = {"security": "tls",
                               "tlsSettings": {"serverName": tls.get("server_name") or addr}}
    return x


def xr_sync_outbounds(xc):
    """把出站镜像进 Xray 配置。direct 必须排在第一位（Xray 用 outbounds[0] 作默认）"""
    keep = [o for o in xc.get("outbounds", []) if o.get("tag") in ("direct", "block")]
    if not any(o.get("tag") == "direct" for o in keep):
        keep.insert(0, {"tag": "direct", "protocol": "freedom", "settings": {}})
    if not any(o.get("tag") == "block" for o in keep):
        keep.append({"tag": "block", "protocol": "blackhole", "settings": {}})
    keep.sort(key=lambda o: 0 if o.get("tag") == "direct" else 1)
    mirrored = [x for x in (_sb_ob_to_xray(o) for o in cfg().get("outbounds", [])) if x]
    xc["outbounds"] = keep + mirrored
    valid = {o["tag"] for o in xc["outbounds"]}
    xc.setdefault("routing", {}).setdefault("rules", [])
    rules = [r for r in xc["routing"]["rules"] if r.get("outboundTag") in valid]
    # 清孤儿：出站没了之后，只剩挡 QUIC 的 block 规则会白白拖慢节点
    bound = set()
    for r in rules:
        if r.get("outboundTag") not in ("block", "direct"):
            bound |= set(r.get("inboundTag") or [])
    kept = []
    for r in rules:
        if r.get("outboundTag") == "block":
            rest = [t for t in (r.get("inboundTag") or []) if t in bound]
            if not rest:
                continue
            r = dict(r, inboundTag=rest)
        kept.append(r)
    xc["routing"]["rules"] = kept
    return xc


def xr_resync():
    """出站增删改后，把 Xray 侧镜像刷新一遍（无 Xray 或无节点时静默跳过）"""
    if not xr_installed():
        return True, "ok"
    xc = xr_sync_outbounds(xcfg())
    if not xc.get("inbounds"):
        save_json(XR_CONF, xc)
        return True, "ok"
    return apply_xconfig(xc)


def xr_set_bind(xc, tag, ob_tag, block_quic=True):
    """设置 Xray 节点的出站绑定；ob_tag 为空或 direct 表示解绑"""
    rules = [r for r in xc.get("routing", {}).get("rules", [])
             if tag not in (r.get("inboundTag") or [])]
    new = []
    if ob_tag and ob_tag != "direct":
        if block_quic:
            # QUIC 走 SOCKS5 落地常不稳，挡掉 UDP/443 强制回退 TCP（其他 UDP 不受影响）
            new.append({"type": "field", "inboundTag": [tag],
                        "network": "udp", "port": "443", "outboundTag": "block"})
        new.append({"type": "field", "inboundTag": [tag], "outboundTag": ob_tag})
    xc.setdefault("routing", {})["rules"] = new + rules
    return xc


def xr_binds():
    """Xray 侧 tag -> 出站名"""
    out = {}
    if not xr_installed():
        return out
    for r in xcfg().get("routing", {}).get("rules", []):
        if r.get("outboundTag") in ("block", None):
            continue
        for t in (r.get("inboundTag") or []):
            out[t] = r["outboundTag"]
    return out


def build_xray_inbound(proto, f, tag):
    """返回 (xray_inbound, share_uri)"""
    if "xray" not in (PROTOCOLS.get(proto, {}).get("cores") or []):
        raise ValueError(f"Xray-core 不支持 {proto}")
    port = int(f["port"])
    name = f.get("name") or tag
    cert = f.get("cert", "")
    cp = kp = domain = ""
    if cert:
        domain = cert
        cp, kp = f"{CERT_DIR}/{domain}/fullchain.pem", f"{CERT_DIR}/{domain}/privkey.pem"

    ib = {"tag": tag, "listen": "::", "port": port,
          "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}
    ss = {"network": "tcp"}
    tlsc = {"certificates": [{"certificateFile": cp, "keyFile": kp}]}

    if proto == "vless":
        priv, pub = gen_reality_x()
        try:
            n_sid = max(1, min(8, int(f.get("sid_count", 8))))
        except (TypeError, ValueError):
            n_sid = 8
        sids = [secrets.token_hex(x) for x in [8, 5, 4, 6, 3, 7, 2, 1][:n_sid]]
        dest, srv = f["dest"], f["server"]
        use_vision = not f.get("flow", "").startswith("无")
        cl = {"id": f["uuid"], "email": tag}
        if use_vision:
            cl["flow"] = "xtls-rprx-vision"
        ib["protocol"] = "vless"
        ib["settings"] = {"clients": [cl], "decryption": "none"}
        ss["security"] = "reality"
        # SNI 留空则跟随目标域名；支持逗号分隔多个
        snis = [x.strip() for x in (f.get("sni") or "").split(",") if x.strip()] or [dest]
        rs = {"dest": f"{dest}:443", "serverNames": snis,
              "privateKey": priv, "shortIds": sids}
        try:
            xv = int(f.get("xver", 0) or 0)
        except (TypeError, ValueError):
            xv = 0
        if xv:
            rs["xver"] = xv
        md = str(f.get("maxdiff", "0")).strip()
        if md and md != "0":
            rs["maxTimeDiff"] = _dur_ms(md)
        for key, fk in (("minClientVer", "min_client"), ("maxClientVer", "max_client")):
            v = (f.get(fk) or "").strip()
            if v and re.match(r"^\d+\.\d+\.\d+$", v):
                rs[key] = v
        ss["realitySettings"] = rs
        fp = f.get("utls") or "chrome"
        spx = (f.get("spiderx") or "/").strip() or "/"
        uri = (f"vless://{f['uuid']}@{srv}:{port}?encryption=none&security=reality"
               f"&sni={snis[0]}&fp={fp}&pbk={pub}&sid={sids[0]}&spx={uenc(spx)}&type=tcp"
               + ("&flow=xtls-rprx-vision" if use_vision else "")
               + f"#{uenc(name)}")

    elif proto == "vless-tls":
        ib["protocol"] = "vless"
        ib["settings"] = {"clients": [{"id": f["uuid"], "email": tag}], "decryption": "none"}
        ss["security"] = "tls"
        ss["tlsSettings"] = dict(tlsc, serverName=domain)
        uri = (f"vless://{f['uuid']}@{domain}:{port}?encryption=none&security=tls"
               f"&sni={domain}&fp=chrome&type=tcp#{uenc(name)}")

    elif proto == "vmess":
        ib["protocol"] = "vmess"
        ib["settings"] = {"clients": [{"id": f["uuid"], "alterId": 0, "email": tag}]}
        ss["security"] = "tls"
        ss["tlsSettings"] = dict(tlsc, serverName=domain)
        vm = {"v": "2", "ps": name, "add": domain, "port": str(port), "id": f["uuid"],
              "aid": "0", "net": "tcp", "type": "none", "host": domain,
              "tls": "tls", "sni": domain}
        uri = "vmess://" + b64(json.dumps(vm, ensure_ascii=False))

    elif proto == "trojan":
        ib["protocol"] = "trojan"
        ib["settings"] = {"clients": [{"password": f["password"], "email": tag}]}
        ss["security"] = "tls"
        ss["tlsSettings"] = dict(tlsc, serverName=domain)
        uri = (f"trojan://{uenc(f['password'])}@{domain}:{port}"
               f"?security=tls&sni={domain}&type=tcp&fp=chrome#{uenc(name)}")

    elif proto == "shadowsocks":
        method, pw, srv = f["method"], f["password"], f["server"]
        ib["protocol"] = "shadowsocks"
        ib["settings"] = {"method": method, "password": pw, "network": "tcp,udp"}
        uri = f"ss://{b64(method + ':' + pw)}@{srv}:{port}#{uenc(name)}"

    elif proto == "socks":
        srv = f["server"]
        ib["protocol"] = "socks"
        st = {"udp": True}
        if f.get("user"):
            st["auth"] = "password"
            st["accounts"] = [{"user": f["user"], "pass": f["password"]}]
            uri = f"socks://{b64(f['user'] + ':' + f['password'])}@{srv}:{port}#{uenc(name)}"
        else:
            st["auth"] = "noauth"
            uri = f"socks5://{srv}:{port}#{uenc(name)}"
        ib["settings"] = st

    elif proto == "http":
        srv = domain or f["server"]
        ib["protocol"] = "http"
        st = {}
        if f.get("user"):
            st["accounts"] = [{"user": f["user"], "pass": f["password"]}]
        ib["settings"] = st
        if cert:
            ss["security"] = "tls"
            ss["tlsSettings"] = dict(tlsc, serverName=domain)
            scheme = "https"
        else:
            scheme = "http"
        auth = f"{uenc(f['user'])}:{uenc(f['password'])}@" if f.get("user") else ""
        uri = f"{scheme}://{auth}{srv}:{port}#{uenc(name)}"
    else:
        raise ValueError("Xray-core 不支持该协议")

    ib, ss, uri = apply_advanced_x(ib, ss, uri, proto, f)
    # 嗅探（表单没提交这些键时保持默认全开）
    if any(k in f for k in ("sniff", "sniff_http", "sniff_tls", "sniff_quic")):
        if _bl(f, "sniff"):
            over = [n for n, k in (("http", "sniff_http"), ("tls", "sniff_tls"),
                                   ("quic", "sniff_quic")) if _bl(f, k)]
            sn = {"enabled": True, "destOverride": over or ["http", "tls"]}
            if _bl(f, "sniff_route_only"):
                sn["routeOnly"] = True
            ib["sniffing"] = sn
        else:
            ib["sniffing"] = {"enabled": False}
    ib["streamSettings"] = ss
    return ib, uri


# ════════════════════════════════════════════
# Xray-core：安装 / 配置 / 校验
# ════════════════════════════════════════════
XRAY_SKELETON = {
    "log": {"loglevel": "warning"},
    "inbounds": [],
    "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}},
                  {"tag": "block", "protocol": "blackhole", "settings": {}}],
    "routing": {"domainStrategy": "AsIs", "rules": []},
}


def xr_installed():
    return os.path.exists(XR_BIN)


def xcfg():
    """读取 Xray 配置，缺失时返回骨架"""
    c = load_json(XR_CONF, None)
    if not isinstance(c, dict) or "inbounds" not in c:
        return json.loads(json.dumps(XRAY_SKELETON))
    c.setdefault("outbounds", list(XRAY_SKELETON["outbounds"]))
    c.setdefault("routing", {"domainStrategy": "AsIs", "rules": []})
    c["routing"].setdefault("rules", [])
    return c


def xr_version():
    if not xr_installed():
        return ""
    c, o, _ = sh(f"{XR_BIN} version")
    if c == 0 and o:
        parts = o.splitlines()[0].split()
        # "Xray 25.3.6 (Xray, Penetrator) ..." -> 25.3.6
        return parts[1] if len(parts) > 1 else ""
    return ""


def ensure_xray_unit():
    """写入并启用 xray systemd 单元（幂等）"""
    unit = f"""[Unit]
Description=Xray Service (panel)
Documentation=https://xtls.github.io
After=network.target nss-lookup.target

[Service]
Type=simple
Environment=HOME=/root
ExecStart={XR_BIN} run -c {XR_CONF}
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
"""
    path = "/etc/systemd/system/xray.service"
    old = ""
    if os.path.exists(path):
        with open(path) as fp:
            old = fp.read()
    if old.strip() != unit.strip():
        with open(path, "w") as fp:
            fp.write(unit)
        sh("systemctl daemon-reload")
    sh(f"systemctl enable {XR_SVC} >/dev/null 2>&1")


def apply_xconfig(new_cfg):
    """校验并写入 Xray 配置，失败自动回滚"""
    if not xr_installed():
        return False, "Xray-core 未安装，请先到「版本」页安装"
    ensure_xray_unit()
    os.makedirs(XR_ETC, exist_ok=True)
    old = None
    if os.path.exists(XR_CONF):
        with open(XR_CONF) as f:
            old = f.read()
    save_json(XR_CONF, new_cfg)
    c, o, e = sh(f"{XR_BIN} run -test -c {XR_CONF}", 25)
    if c != 0:
        if old is not None:
            with open(XR_CONF, "w") as f:
                f.write(old)
        return False, f"Xray 配置校验失败:\n{(e or o)[:400]}"
    # 没有入站时不需要跑服务，停掉省内存
    if not new_cfg.get("inbounds"):
        sh(f"systemctl stop {XR_SVC}")
        return True, "ok"
    sh(f"systemctl restart {XR_SVC}")
    time.sleep(1)
    _, st, _ = sh(f"systemctl is-active {XR_SVC}")
    if st.strip() != "active":
        if old is not None:
            with open(XR_CONF, "w") as f:
                f.write(old)
            sh(f"systemctl restart {XR_SVC}")
        _, log, _ = sh(f"journalctl -u {XR_SVC} -n 15 --no-pager")
        return False, f"Xray 启动失败已回滚:\n{log[-400:]}"
    return True, "ok"


def xr_fetch_versions(limit=5):
    c, o, _ = sh("curl -fsSL --max-time 20 "
                 "'https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10'", 25)
    if c != 0 or not o:
        return []
    try:
        rel = json.loads(o)
    except Exception:
        return []
    out = []
    for r in rel:
        if r.get("draft"):
            continue
        out.append({"ver": r.get("tag_name", "").lstrip("v"),
                    "pre": bool(r.get("prerelease")),
                    "date": (r.get("published_at") or "")[:10],
                    "note": (r.get("body") or "").strip()[:300]})
        if len(out) >= limit:
            break
    return out


def _xr_asset():
    return {"amd64": "Xray-linux-64.zip",
            "arm64": "Xray-linux-arm64-v8a.zip",
            "armv7": "Xray-linux-arm32-v7a.zip"}.get(get_arch(), "Xray-linux-64.zip")


def xr_install_version(ver, job=None):
    """下载安装指定版本 Xray（zip 用 Python 解，不依赖 unzip）"""
    def step(t):
        if job is not None:
            job["step"] = t

    ver = ver.lstrip("v").strip()
    if not re.match(r"^[0-9][0-9A-Za-z.\-]*$", ver):
        return False, "版本号格式无效"
    asset = _xr_asset()
    gh = f"https://github.com/XTLS/Xray-core/releases/download/v{ver}/{asset}"
    mirrors = [gh, f"https://ghfast.top/{gh}", f"https://gh-proxy.com/{gh}"]

    dest_dir = os.path.dirname(XR_BIN)
    os.makedirs(dest_dir, exist_ok=True)
    tmp = f"{dest_dir}/.up-{secrets.token_hex(4)}"
    os.makedirs(tmp, exist_ok=True)
    zpath = f"{tmp}/x.zip"
    try:
        got = False
        lasterr = ""
        for i, url in enumerate(mirrors):
            step(f"下载 Xray ({'官方源' if i == 0 else '镜像 ' + str(i)})")
            c, o, e = sh(f"curl -fL --max-time 240 --retry 2 -o {zpath} '{url}'", 260)
            if c == 0 and os.path.exists(zpath) and os.path.getsize(zpath) > 1024 * 1024:
                got = True
                break
            lasterr = (e or o or "下载中断")[:200]
        if not got:
            return False, f"下载失败：{lasterr}\n{gh}"

        step("解压")
        import zipfile
        binsrc = ""
        try:
            with zipfile.ZipFile(zpath) as z:
                nm = next((n for n in z.namelist()
                           if n.rstrip("/").split("/")[-1] == "xray"), "")
                if not nm:
                    return False, "压缩包内未找到 xray 可执行文件"
                with z.open(nm) as src, open(f"{tmp}/xray", "wb") as dst:
                    dst.write(src.read())
            binsrc = f"{tmp}/xray"
        except zipfile.BadZipFile:
            return False, "压缩包损坏，请重试或换镜像"
        if os.path.getsize(binsrc) < 5 * 1024 * 1024:
            return False, "解出的文件异常偏小"

        step("安装中")
        bak = f"{tmp}/xray.prev"
        had = os.path.exists(XR_BIN)
        if had:
            sh(f"cp {XR_BIN} {bak}")
            sh(f"systemctl stop {XR_SVC}")
        c, _, e = sh(f"install -m 755 {binsrc} {XR_BIN}")
        if c != 0:
            return False, f"安装失败: {e}"

        ensure_xray_unit()
        os.makedirs(XR_ETC, exist_ok=True)
        if not os.path.exists(XR_CONF):
            save_json(XR_CONF, XRAY_SKELETON)

        step("校验配置")
        c, o, e = sh(f"{XR_BIN} run -test -c {XR_CONF}", 25)
        if c != 0:
            if had:
                sh(f"cp {bak} {XR_BIN}")
                sh(f"systemctl start {XR_SVC}")
            return False, f"新版本无法加载当前配置，已回滚:\n{(e or o)[:400]}"

        # 有节点才起服务
        if xcfg().get("inbounds"):
            step("启动服务")
            sh(f"systemctl start {XR_SVC}")
            time.sleep(1)
            _, st, _ = sh(f"systemctl is-active {XR_SVC}")
            if st.strip() != "active":
                if had:
                    sh(f"cp {bak} {XR_BIN}")
                    sh(f"systemctl restart {XR_SVC}")
                _, log, _ = sh(f"journalctl -u {XR_SVC} -n 15 --no-pager")
                return False, f"启动失败，已回滚:\n{log[-400:]}"
        return True, xr_version()
    finally:
        sh(f"rm -rf {tmp}")


XVER_JOB = {"running": False, "ver": "", "ok": None, "msg": "", "step": ""}


def xr_install_async(ver):
    if XVER_JOB["running"]:
        return False, "已有安装任务在进行"

    def run():
        XVER_JOB.update(running=True, ver=ver, ok=None, msg="", step="准备中")
        try:
            okk, msg = xr_install_version(ver, XVER_JOB)
            XVER_JOB.update(ok=okk, msg=str(msg))
        except Exception as e:
            XVER_JOB.update(ok=False, msg=f"异常: {e}")
        finally:
            XVER_JOB.update(running=False, step="")
    threading.Thread(target=run, daemon=True).start()
    return True, "已开始"


def core_of(tag, m=None):
    """节点属于哪个核心"""
    m = m if m is not None else meta()
    return (m.get(tag) or {}).get("core") or DEFAULT_CORE


def used_ports():
    """两个核心已占用的端口（跨核心冲突检测用）"""
    used = set()
    for i in cfg().get("inbounds", []):
        if i.get("listen_port"):
            used.add(int(i["listen_port"]))
    if xr_installed():
        for i in xcfg().get("inbounds", []):
            if i.get("port"):
                try:
                    used.add(int(i["port"]))
                except (TypeError, ValueError):
                    pass
    return used


def all_tags():
    tags = {i.get("tag") for i in cfg().get("inbounds", [])}
    if xr_installed():
        tags |= {i.get("tag") for i in xcfg().get("inbounds", [])}
    return tags | set(meta().keys())


def uenc(s):
    return urllib.parse.quote(str(s), safe="")


def b64(s):
    return base64.b64encode(s.encode()).decode()


# ════════════════════════════════════════════
# 协议定义 —— 表单字段 + inbound + 分享链接
# ════════════════════════════════════════════
PROTOCOLS = {
    "hysteria2": {
        "label": "Hysteria2", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-hysteria2"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "password", "l": "认证密码", "t": "text", "auto": "pass"},
            {"k": "obfs", "l": "混淆密码 (留空不启用)", "t": "text", "auto": "pass"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
            {"k": "up", "l": "上行带宽 Mbps (0=不限，启用Brutal需填)", "t": "number", "d": "0"},
            {"k": "down", "l": "下行带宽 Mbps (0=不限)", "t": "number", "d": "0"},
            {"k": "hop", "l": "端口跳跃 (如 20000-22000，留空不启用)", "t": "text", "d": ""},
            {"k": "masq_type", "l": "伪装方式", "t": "select",
             "opts": ["内置页面(最快，不出网)", "反代网站(内容最真实)", "不伪装(返回404)"],
             "d": "内置页面(最快，不出网)"},
            {"k": "masq", "l": "反代目标 (仅「反代网站」时生效)", "t": "text",
             "d": "https://www.bing.com"},
        ],
    },
    "vless": {
        "label": "VLESS + Reality", "needs_cert": False,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-reality"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "uuid", "l": "UUID", "t": "text", "auto": "uuid"},
            {"k": "dest", "l": "偷取目标 (dest)", "t": "dest", "d": "www.nvidia.com"},
            {"k": "server", "l": "客户端连接地址", "t": "text", "auto": "ip"},
            {"k": "flow", "l": "流控", "t": "select",
             "opts": ["xtls-rprx-vision (推荐，性能最好)", "无"],
             "d": "xtls-rprx-vision (推荐，性能最好)"},
            {"k": "regen", "l": "Reality 密钥", "t": "select",
             "opts": ["保持现有密钥（编辑时推荐）", "重新生成密钥对"],
             "d": "保持现有密钥（编辑时推荐）"},
            {"k": "sid_count", "l": "Short ID 数量 (多个更难被特征匹配)", "t": "select",
             "opts": ["8", "5", "3", "1"], "d": "8"},
            {"k": "maxdiff", "l": "最大时间差 (防重放，0=关闭)", "t": "select",
             "opts": ["0", "1m", "5m", "1h"], "d": "0"},
        ],
    },
    "anytls": {
        "label": "AnyTLS", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-anytls"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "password", "l": "密码", "t": "text", "auto": "pass"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
        ],
    },
    "trojan": {
        "label": "Trojan", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-trojan"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "password", "l": "密码", "t": "text", "auto": "pass"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
        ],
    },
    "tuic": {
        "label": "TUIC v5", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-tuic"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "uuid", "l": "UUID", "t": "text", "auto": "uuid"},
            {"k": "password", "l": "密码", "t": "text", "auto": "pass"},
            {"k": "cc", "l": "拥塞控制", "t": "select", "opts": ["bbr", "cubic", "new_reno"], "d": "bbr"},
            {"k": "zrtt", "l": "0-RTT 握手 (更快，但略降抗检测)", "t": "select",
             "opts": ["关闭", "开启"], "d": "关闭"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
        ],
    },
    "vmess": {
        "label": "VMess + TLS", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-vmess"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "uuid", "l": "UUID", "t": "text", "auto": "uuid"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
        ],
    },
    "vless-tls": {
        "label": "VLESS + TLS (真证书)", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-vless-tls"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "uuid", "l": "UUID", "t": "text", "auto": "uuid"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
        ],
    },
    "hysteria": {
        "label": "Hysteria v1 (旧版)", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-hy1"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "authstr", "l": "认证字符串", "t": "text", "auto": "pass"},
            {"k": "up", "l": "上行 Mbps", "t": "number", "d": "50"},
            {"k": "down", "l": "下行 Mbps", "t": "number", "d": "200"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
        ],
    },
    "shadowtls": {
        "label": "ShadowTLS v3 + SS", "needs_cert": False,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-shadowtls"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "password", "l": "ShadowTLS 密码", "t": "text", "auto": "pass"},
            {"k": "sspass", "l": "SS 密码", "t": "text", "auto": "sspass"},
            {"k": "dest", "l": "握手目标 (需TLS1.3)", "t": "dest", "d": "www.apple.com"},
            {"k": "server", "l": "客户端连接地址", "t": "text", "auto": "ip"},
        ],
    },
    "naive": {
        "label": "NaiveProxy", "needs_cert": True,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-naive"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "user", "l": "用户名", "t": "text", "d": "user"},
            {"k": "password", "l": "密码", "t": "text", "auto": "pass"},
            {"k": "cert", "l": "证书域名", "t": "cert"},
        ],
    },
    "snell": {
        "label": "Snell v4", "needs_cert": False,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-snell"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "psk", "l": "PSK 密钥", "t": "text", "auto": "pass"},
            {"k": "obfs", "l": "混淆", "t": "select", "opts": ["关闭", "http", "tls"], "d": "关闭"},
            {"k": "server", "l": "客户端连接地址", "t": "text", "auto": "ip"},
        ],
    },
    "mixed": {
        "label": "Mixed (SOCKS+HTTP)", "needs_cert": False,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-mixed"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "user", "l": "用户名 (留空=无认证)", "t": "text", "d": "user"},
            {"k": "password", "l": "密码", "t": "text", "auto": "pass"},
            {"k": "server", "l": "客户端连接地址", "t": "text", "auto": "ip"},
        ],
    },
    "http": {
        "label": "HTTP 代理", "needs_cert": False,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-http"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "user", "l": "用户名 (留空=无认证)", "t": "text", "d": "user"},
            {"k": "password", "l": "密码", "t": "text", "auto": "pass"},
            {"k": "cert", "l": "证书域名 (留空=明文HTTP)", "t": "cert"},
            {"k": "server", "l": "客户端连接地址", "t": "text", "auto": "ip"},
        ],
    },
    "socks": {
        "label": "SOCKS5", "needs_cert": False,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-socks"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "user", "l": "用户名 (留空=无认证)", "t": "text", "d": "user"},
            {"k": "password", "l": "密码", "t": "text", "auto": "pass"},
            {"k": "server", "l": "客户端连接地址", "t": "text", "auto": "ip"},
        ],
    },
    "shadowsocks": {
        "label": "Shadowsocks 2022", "needs_cert": False,
        "fields": [
            {"k": "name", "l": "节点名称", "t": "text", "d": "节点-ss"},
            {"k": "port", "l": "监听端口", "t": "number", "auto": "port"},
            {"k": "method", "l": "加密方式", "t": "select",
             "opts": ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                      "2022-blake3-chacha20-poly1305", "aes-128-gcm", "chacha20-ietf-poly1305"],
             "d": "2022-blake3-aes-128-gcm"},
            {"k": "password", "l": "密码", "t": "text", "auto": "sspass"},
            {"k": "server", "l": "客户端连接地址", "t": "text", "auto": "ip"},
        ],
    },
}


# ════════════════════════════════════════════
# 高级选项 —— 加速 / 抗封锁 / 传输层（对齐 s-ui）
# ════════════════════════════════════════════
ADV_TCP = [
    {"k": "tfo", "l": "TCP Fast Open", "t": "bool", "d": "0",
     "h": "首包随握手一起发，省一个 RTT。少数运营商中间设备会丢弃，连不上就关掉"},
    {"k": "mptcp", "l": "TCP Multi Path", "t": "bool", "d": "0",
     "h": "多路径 TCP（手机 WiFi+蜂窝同时用），客户端也要开才生效"},
]
ADV_UDP = [
    {"k": "udpfrag", "l": "允许 UDP 分片", "t": "bool", "d": "0",
     "h": "转发被分片的 UDP 包，部分游戏 / BT 需要"},
    {"k": "udpto", "l": "UDP 会话超时", "t": "text", "d": "5m",
     "h": "如 5m / 30s。调短省内存，太短会导致游戏语音断流"},
]
ADV_MUX = [
    {"k": "mux", "l": "允许多路复用", "t": "bool", "d": "0",
     "h": "多个请求共用一条连接，网页秒开；大文件下载可能变慢。与 vision 流控互斥"},
    {"k": "mux_pad", "l": "复用流量填充", "t": "bool", "d": "0",
     "h": "给复用流加随机填充，削弱流量指纹（略增开销）"},
    {"k": "mux_brutal", "l": "Brutal 拥塞控制", "t": "bool", "d": "0",
     "h": "无视丢包按固定带宽发包，丢包线路提速明显；需下面两项都填"},
    {"k": "mux_up", "l": "Brutal 上行 Mbps", "t": "number", "d": "0"},
    {"k": "mux_down", "l": "Brutal 下行 Mbps", "t": "number", "d": "0"},
]
ADV_TLS = [
    {"k": "tls_min", "l": "TLS 最低版本", "t": "select", "opts": ["1.3", "1.2"], "d": "1.3",
     "h": "1.3 更快更隐蔽；只有老客户端连不上时才降到 1.2"},
    {"k": "alpn", "l": "ALPN", "t": "select",
     "opts": ["不设置", "h2,http/1.1", "h2", "http/1.1"], "d": "不设置",
     "h": "h2 多路复用更快；改动后客户端需重新拉订阅，不确定就保持不设置"},
]
TRANSPORTS = [
    {"k": "transport", "l": "传输层", "t": "select",
     "opts": ["TCP (原始，最快)", "WebSocket", "gRPC", "HTTPUpgrade"], "d": "TCP (原始，最快)",
     "h": "原始 TCP 延迟最低；WS / HTTPUpgrade 可过 CDN；gRPC 抗干扰强"},
    {"k": "tr_path", "l": "路径 / 服务名", "t": "text", "d": "/",
     "h": "WS 与 HTTPUpgrade 填路径（如 /ws）；gRPC 填 serviceName"},
    {"k": "tr_host", "l": "Host 伪装", "t": "text", "d": "",
     "h": "留空则用证书域名。套 CDN 时填回源域名"},
    {"k": "tr_ed", "l": "WebSocket 0-RTT", "t": "bool", "d": "0",
     "h": "首包塞进握手，省一个 RTT（仅 WebSocket 生效）"},
]

# ── 表单分组（对齐 3x-ui 的标签页）──
G_BASE, G_PROTO, G_TRANS = "基础配置", "协议", "传输"
G_SEC, G_SNIFF, G_ADV = "安全", "嗅探", "高级配置"

_FIELD_GROUP = {
    # 基础
    "name": G_BASE, "port": G_BASE, "server": G_BASE, "hop": G_BASE,
    # 协议
    "uuid": G_PROTO, "password": G_PROTO, "method": G_PROTO, "user": G_PROTO,
    "authstr": G_PROTO, "psk": G_PROTO, "sspass": G_PROTO, "flow": G_PROTO,
    "cc": G_PROTO, "zrtt": G_PROTO, "up": G_PROTO, "down": G_PROTO,
    # 安全
    "cert": G_SEC, "dest": G_SEC, "sni": G_SEC, "regen": G_SEC,
    "sid_count": G_SEC, "maxdiff": G_SEC, "utls": G_SEC, "xver": G_SEC,
    "min_client": G_SEC, "max_client": G_SEC, "spiderx": G_SEC,
    "tls_min": G_SEC, "alpn": G_SEC, "obfs": G_SEC,
    "masq_type": G_SEC, "masq": G_SEC,
    # 传输
    "transport": G_TRANS, "tr_path": G_TRANS, "tr_host": G_TRANS,
    "tr_ed": G_TRANS, "kcp_seed": G_TRANS, "kcp_header": G_TRANS,
    # 嗅探
    "sniff": G_SNIFF, "sniff_http": G_SNIFF, "sniff_tls": G_SNIFF,
    "sniff_quic": G_SNIFF, "sniff_route_only": G_SNIFF, "sniff_note": G_SNIFF,
    # 其余（tfo/mptcp/udp*/mux*）归高级
}

# ── Xray 嗅探设置（3x-ui 的「嗅探」页）──
XADV_SNIFF = [
    {"k": "sniff", "l": "启用嗅探", "t": "bool", "d": "1",
     "h": "识别流量真实域名，路由规则和日志才能按域名匹配。关掉只能按 IP 走"},
    {"k": "sniff_http", "l": "识别 HTTP", "t": "bool", "d": "1"},
    {"k": "sniff_tls", "l": "识别 TLS", "t": "bool", "d": "1"},
    {"k": "sniff_quic", "l": "识别 QUIC", "t": "bool", "d": "1"},
    {"k": "sniff_route_only", "l": "仅用于路由", "t": "bool", "d": "0",
     "h": "只拿嗅探结果做路由判断，不改写真实目标地址。走 CDN 回源时打开"},
]
_SB_SNIFF_NOTE = [
    {"k": "sniff_note", "t": "note",
     "l": "sing-box 1.11 起嗅探改为全局路由动作，不再按节点单独配置。"
          "当前配置里已有一条 sniff 规则对所有入站生效，无需在这里设置。"},
]

# 每个协议可用的核心
_CORE_MAP = {'vless': ['sing-box', 'xray'], 'vless-tls': ['sing-box', 'xray'], 'vmess': ['sing-box', 'xray'], 'trojan': ['sing-box', 'xray'], 'shadowsocks': ['sing-box', 'xray'], 'socks': ['sing-box', 'xray'], 'http': ['sing-box', 'xray'], 'hysteria2': ['sing-box'], 'hysteria': ['sing-box'], 'tuic': ['sing-box'], 'anytls': ['sing-box'], 'shadowtls': ['sing-box'], 'naive': ['sing-box'], 'snell': ['sing-box'], 'mixed': ['sing-box']}
for _p, _c in _CORE_MAP.items():
    PROTOCOLS[_p]["cores"] = _c

# ── Xray 专用高级选项（字段名与 sing-box 侧保持一致，写入时映射到 Xray schema）──
XADV_SOCK = [
    {"k": "tfo", "l": "TCP Fast Open", "t": "bool", "d": "0",
     "h": "首包随握手一起发，省一个 RTT。中间设备可能丢弃，连不上就关掉"},
    {"k": "mptcp", "l": "TCP Multi Path", "t": "bool", "d": "0",
     "h": "多路径 TCP，客户端也要开才生效"},
]
XADV_TLS = [
    {"k": "tls_min", "l": "TLS 最低版本", "t": "select", "opts": ["1.3", "1.2"], "d": "1.3",
     "h": "1.3 更快更隐蔽；只有老客户端连不上时才降到 1.2"},
    {"k": "alpn", "l": "ALPN", "t": "select",
     "opts": ["不设置", "h2,http/1.1", "h2", "http/1.1"], "d": "不设置",
     "h": "改动后客户端需重新拉订阅，不确定就保持不设置"},
]
XTRANSPORTS = [
    {"k": "transport", "l": "传输层", "t": "select",
     "opts": ["TCP (原始，最快)", "WebSocket", "gRPC", "HTTPUpgrade",
              "XHTTP (Xray 专属，过 CDN 最好)", "mKCP (Xray 专属，抗丢包)"],
     "d": "TCP (原始，最快)",
     "h": "XHTTP 与 mKCP 是 Xray 独有；mKCP 用带宽换丢包恢复，适合线路差但别开在没必要的地方"},
    {"k": "tr_path", "l": "路径 / 服务名", "t": "text", "d": "/",
     "h": "WS / HTTPUpgrade / XHTTP 填路径；gRPC 填 serviceName"},
    {"k": "tr_host", "l": "Host 伪装", "t": "text", "d": "",
     "h": "留空则用证书域名。套 CDN 时填回源域名"},
    {"k": "kcp_seed", "l": "mKCP 混淆密码", "t": "text", "d": "",
     "h": "仅 mKCP 生效，两端必须一致。留空则不混淆"},
    {"k": "kcp_header", "l": "mKCP 伪装类型", "t": "select",
     "opts": ["none", "srtp", "utp", "wechat-video", "dtls", "wireguard"], "d": "none",
     "h": "仅 mKCP 生效，把流量伪装成视频通话 / BT 等"},
]

XADV_REALITY = [
    {"k": "sni", "l": "SNI (留空=用目标域名)", "t": "text", "d": "",
     "h": "客户端握手时用的域名，通常与目标一致。多个用逗号分隔"},
    {"k": "utls", "l": "uTLS 指纹", "t": "select",
     "opts": ["chrome", "firefox", "safari", "ios", "edge", "android", "random"],
     "d": "chrome", "h": "客户端伪装成哪种浏览器的 TLS 指纹，写进分享链接"},
    {"k": "xver", "l": "Xver (PROXY protocol)", "t": "select",
     "opts": ["0", "1", "2"], "d": "0",
     "h": "回落到本机其他服务时才用，0 = 关闭。不确定就保持 0"},
    {"k": "min_client", "l": "最小客户端版本", "t": "text", "d": "1.0.0",
     "h": "低于此版本的 Xray 客户端会被拒绝。1.0.0 等于不限制"},
    {"k": "max_client", "l": "最大客户端版本", "t": "text", "d": "",
     "h": "留空 = 不限制。格式 x.y.z"},
    {"k": "spiderx", "l": "SpiderX", "t": "text", "d": "/",
     "h": "客户端爬取目标站的起始路径，写进分享链接"},
]

_XADV_MAP = {
    "vless":       XADV_REALITY + XADV_SOCK,
    "vless-tls":   XADV_SOCK + XADV_TLS + XTRANSPORTS,
    "vmess":       XADV_SOCK + XADV_TLS + XTRANSPORTS,
    "trojan":      XADV_SOCK + XADV_TLS + XTRANSPORTS,
    "shadowsocks": XADV_SOCK,
    "socks":       XADV_SOCK,
    "http":        XADV_SOCK,
}
for _p, _a in _XADV_MAP.items():
    PROTOCOLS[_p]["adv_xray"] = _a + XADV_SNIFF

_ADV_MAP = {
    "hysteria2":   ADV_UDP,
    "hysteria":    ADV_UDP,
    "tuic":        ADV_UDP,
    "vless":       ADV_TCP + ADV_UDP + ADV_MUX,
    "vless-tls":   ADV_TCP + ADV_UDP + ADV_MUX + ADV_TLS + TRANSPORTS,
    "vmess":       ADV_TCP + ADV_UDP + ADV_MUX + ADV_TLS + TRANSPORTS,
    "trojan":      ADV_TCP + ADV_UDP + ADV_MUX + ADV_TLS + TRANSPORTS,
    "anytls":      ADV_TCP + ADV_UDP + ADV_TLS,
    "naive":       ADV_TCP + ADV_UDP + ADV_TLS,
    "shadowtls":   ADV_TCP,
    "snell":       ADV_TCP + ADV_UDP,
    "mixed":       ADV_TCP + ADV_UDP,
    "http":        ADV_TCP + ADV_UDP,
    "socks":       ADV_TCP + ADV_UDP,
    "shadowsocks": ADV_TCP + ADV_UDP + ADV_MUX,
}
for _p, _a in _ADV_MAP.items():
    PROTOCOLS[_p]["adv"] = _a + _SB_SNIFF_NOTE


# 给所有字段打上分组标签（未列出的一律归「高级配置」）
for _spec in PROTOCOLS.values():
    for _key in ("fields", "adv", "adv_xray"):
        for _f in (_spec.get(_key) or []):
            _f.setdefault("g", _FIELD_GROUP.get(_f["k"], G_ADV))


def _bl(f, k):
    return str(f.get(k, "0")).lower() in ("1", "true", "on", "yes")


def _uq(uri, **kw):
    """给 url 风格的分享链接补/改查询参数（保留 #备注）"""
    base, _, frag = uri.partition("#")
    for k, v in kw.items():
        if v is None:
            base = re.sub(rf"[&?]{k}=[^&]*", "", base)
            continue
        v = uenc(v)
        if re.search(rf"[&?]{k}=", base):
            base = re.sub(rf"([&?]{k}=)[^&]*", lambda m: m.group(1) + v, base)
        else:
            base += ("&" if "?" in base else "?") + f"{k}={v}"
    return base + ("#" + frag if frag else "")


def apply_advanced(ib, uri, proto, f):
    """把高级选项写进 inbound，并同步修正分享链接。返回 (ib, uri)"""
    keys = {a["k"] for a in (PROTOCOLS.get(proto, {}).get("adv") or [])}
    if not keys:
        return ib, uri

    # —— 监听层：TCP / UDP ——
    if "tfo" in keys and _bl(f, "tfo"):
        ib["tcp_fast_open"] = True
    if "mptcp" in keys and _bl(f, "mptcp"):
        ib["tcp_multi_path"] = True
    if "udpfrag" in keys and _bl(f, "udpfrag"):
        ib["udp_fragment"] = True
    if "udpto" in keys:
        t = (f.get("udpto") or "").strip()
        if t and t != "5m" and re.match(r"^\d+[smh]$", t):
            ib["udp_timeout"] = t

    # —— 多路复用（与 xtls-rprx-vision 互斥，vision 优先）——
    _vision = any(u.get("flow") for u in ib.get("users", []))
    if "mux" in keys and _bl(f, "mux") and not _vision:
        mx = {"enabled": True}
        if _bl(f, "mux_pad"):
            mx["padding"] = True
        if _bl(f, "mux_brutal"):
            try:
                up, dn = int(f.get("mux_up") or 0), int(f.get("mux_down") or 0)
            except (TypeError, ValueError):
                up = dn = 0
            if up > 0 and dn > 0:
                mx["brutal"] = {"enabled": True, "up_mbps": up, "down_mbps": dn}
        ib["multiplex"] = mx

    tls = ib.get("tls")
    # —— TLS ——
    if tls:
        if "tls_min" in keys:
            tls["min_version"] = "1.2" if f.get("tls_min") == "1.2" else "1.3"
        if "alpn" in keys:
            a = f.get("alpn", "h2,http/1.1")
            if a == "不设置":
                tls.pop("alpn", None)
            else:
                tls["alpn"] = [x.strip() for x in a.split(",") if x.strip()]
                if uri.startswith(("vless://", "trojan://")):
                    uri = _uq(uri, alpn=a)

    # —— 传输层 ——
    if "transport" in keys:
        sel = f.get("transport", "")
        raw = (f.get("tr_path") or "/").strip()
        host = (f.get("tr_host") or "").strip()
        kind = path = ""
        if sel.startswith("WebSocket"):
            kind, path = "ws", (raw if raw.startswith("/") else "/" + raw)
            tr = {"type": "ws", "path": path}
            if host:
                tr["headers"] = {"Host": host}
            if _bl(f, "tr_ed"):
                tr["early_data_header_name"] = "Sec-WebSocket-Protocol"
                tr["max_early_data"] = 2048
            ib["transport"] = tr
        elif sel.startswith("gRPC"):
            kind = "grpc"
            path = raw.lstrip("/") or "grpc"
            ib["transport"] = {"type": "grpc", "service_name": path}
        elif sel.startswith("HTTPUpgrade"):
            kind, path = "httpupgrade", (raw if raw.startswith("/") else "/" + raw)
            tr = {"type": "httpupgrade", "path": path}
            if host:
                tr["host"] = host
            ib["transport"] = tr

        if kind:
            # vision 流控与非 TCP 传输互斥
            for u in ib.get("users", []):
                u.pop("flow", None)
            if uri.startswith("vmess://"):
                try:
                    vm = json.loads(base64.b64decode(uri[8:] + "==").decode())
                    vm["net"] = kind
                    if kind == "grpc":
                        vm["path"] = path
                    else:
                        vm["path"] = path
                    if host:
                        vm["host"] = host
                    uri = "vmess://" + b64(json.dumps(vm, ensure_ascii=False))
                except Exception:
                    pass
            else:
                kw = {"type": kind, "flow": None}
                kw["serviceName" if kind == "grpc" else "path"] = path
                if host:
                    kw["host"] = host
                uri = _uq(uri, **kw)
    return ib, uri


def build_inbound(proto, f, tag):
    """返回 (inbound, share_uri)"""
    port = int(f["port"])
    name = f.get("name") or tag
    cert = f.get("cert", "")
    cp, kp, domain = "", "", ""
    if cert:
        domain = cert
        cp, kp = f"{CERT_DIR}/{domain}/fullchain.pem", f"{CERT_DIR}/{domain}/privkey.pem"

    if proto == "hysteria2":
        ib = {"type": "hysteria2", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"password": f["password"]}],
              "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cp, "key_path": kp}}
        up, dn = int(f.get("up") or 0), int(f.get("down") or 0)
        if up > 0:
            ib["up_mbps"] = up
        if dn > 0:
            ib["down_mbps"] = dn
        if up > 0 or dn > 0:
            ib["ignore_client_bandwidth"] = False
        mt = f.get("masq_type", "")
        if mt.startswith("反代"):
            ib["masquerade"] = {"type": "proxy",
                                "url": f.get("masq") or "https://www.bing.com",
                                "rewrite_host": True}
        elif mt.startswith("不伪装"):
            pass  # 不配置 masquerade，sing-box 返回 404
        else:
            ib["masquerade"] = {
                "type": "string",
                "status_code": 200,
                "headers": {"Content-Type": ["text/html; charset=utf-8"],
                            "Server": ["nginx"]},
                "content": ("<!doctype html><html><head><meta charset=utf-8>"
                            "<title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;"
                            "font-family:Tahoma,Verdana,Arial,sans-serif}</style></head><body>"
                            "<h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server "
                            "is successfully installed and working. Further configuration is required.</p>"
                            "<p>For online documentation and support please refer to "
                            "<a href=\"http://nginx.org/\">nginx.org</a>.<br/>"
                            "Commercial support is available at "
                            "<a href=\"http://nginx.com/\">nginx.com</a>.</p>"
                            "<p><em>Thank you for using nginx.</em></p></body></html>")}
        q = f"security=tls&sni={domain}&insecure=0&fastopen=0&alpn=h3"
        if f.get("obfs"):
            ib["obfs"] = {"type": "salamander", "password": f["obfs"]}
            q += f"&obfs=salamander&obfs-password={uenc(f['obfs'])}"
        if f.get("hop"):
            q += f"&mport={f['hop']}"
        uri = f"hysteria2://{uenc(f['password'])}@{domain}:{port}?{q}#{uenc(name)}"

    elif proto == "vless":
        priv, pub = gen_reality()
        # 多个 short_id：长度不一，更贴近真实分布
        try:
            n_sid = max(1, min(8, int(f.get("sid_count", 8))))
        except (TypeError, ValueError):
            n_sid = 8
        lens = [8, 5, 4, 6, 3, 7, 2, 1][:n_sid]
        sids = [secrets.token_hex(x) for x in lens]
        sid = sids[0]
        dest = f["dest"]
        srv = f["server"]
        use_vision = not f.get("flow", "").startswith("无")
        user = {"uuid": f["uuid"]}
        if use_vision:
            user["flow"] = "xtls-rprx-vision"
        ib = {"type": "vless", "tag": tag, "listen": "::", "listen_port": port,
              "users": [user],
              "tls": {"enabled": True, "server_name": dest,
                      "reality": {"enabled": True,
                                  "handshake": {"server": dest, "server_port": 443},
                                  "private_key": priv, "short_id": sids}}}
        md = str(f.get("maxdiff", "0")).strip()
        if md and md != "0":
            ib["tls"]["reality"]["max_time_difference"] = md
        uri = (f"vless://{f['uuid']}@{srv}:{port}?encryption=none&security=reality"
               f"&sni={dest}&fp=chrome&pbk={pub}&sid={sid}&type=tcp"
               + (f"&flow=xtls-rprx-vision" if use_vision else "")
               + f"#{uenc(name)}")

    elif proto == "anytls":
        ib = {"type": "anytls", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"password": f["password"]}], "padding_scheme": [],
              "tls": {"enabled": True, "certificate_path": cp, "key_path": kp}}
        uri = f"anytls://{uenc(f['password'])}@{domain}:{port}?security=tls&sni={domain}&insecure=0#{uenc(name)}"

    elif proto == "trojan":
        ib = {"type": "trojan", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"password": f["password"]}],
              "tls": {"enabled": True, "certificate_path": cp, "key_path": kp}}
        uri = f"trojan://{uenc(f['password'])}@{domain}:{port}?security=tls&sni={domain}&type=tcp&fp=chrome#{uenc(name)}"

    elif proto == "tuic":
        ib = {"type": "tuic", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"uuid": f["uuid"], "password": f["password"]}],
              "congestion_control": f.get("cc", "bbr"),
              "zero_rtt_handshake": f.get("zrtt", "").startswith("开启"),
              "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cp, "key_path": kp}}
        uri = (f"tuic://{f['uuid']}:{uenc(f['password'])}@{domain}:{port}"
               f"?congestion_control={f.get('cc','bbr')}&alpn=h3&sni={domain}#{uenc(name)}")

    elif proto == "vmess":
        ib = {"type": "vmess", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"uuid": f["uuid"], "alterId": 0}],
              "tls": {"enabled": True, "certificate_path": cp, "key_path": kp}}
        vm = {"v": "2", "ps": name, "add": domain, "port": str(port), "id": f["uuid"],
              "aid": "0", "net": "tcp", "type": "none", "host": domain,
              "tls": "tls", "sni": domain}
        uri = "vmess://" + b64(json.dumps(vm, ensure_ascii=False))

    elif proto == "vless-tls":
        ib = {"type": "vless", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"uuid": f["uuid"]}],
              "tls": {"enabled": True, "server_name": domain,
                      "certificate_path": cp, "key_path": kp}}
        uri = (f"vless://{f['uuid']}@{domain}:{port}?encryption=none&security=tls"
               f"&sni={domain}&fp=chrome&type=tcp#{uenc(name)}")

    elif proto == "hysteria":
        ib = {"type": "hysteria", "tag": tag, "listen": "::", "listen_port": port,
              "up_mbps": int(f.get("up") or 50), "down_mbps": int(f.get("down") or 200),
              "users": [{"auth_str": f["authstr"]}],
              "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cp, "key_path": kp}}
        uri = (f"hysteria://{domain}:{port}?auth={uenc(f['authstr'])}&peer={domain}"
               f"&upmbps={f.get('up',50)}&downmbps={f.get('down',200)}&alpn=h3#{uenc(name)}")

    elif proto == "shadowtls":
        dest, srv = f["dest"], f["server"]
        det = f"{tag}-ss"
        ib = {"type": "shadowtls", "tag": tag, "listen": "::", "listen_port": port,
              "version": 3, "users": [{"password": f["password"]}],
              "handshake": {"server": dest, "server_port": 443},
              "strict_mode": True, "detour": det}
        # ShadowTLS 需配套一个内部 SS 入站
        extra_ss = {"type": "shadowsocks", "tag": det, "listen": "127.0.0.1",
                    "method": "2022-blake3-aes-128-gcm", "password": f["sspass"]}
        ib["_extra_inbound"] = extra_ss
        ssb = b64("2022-blake3-aes-128-gcm:" + f["sspass"])
        uri = (f"ss://{ssb}@{srv}:{port}?plugin=shadow-tls;"
               f"host={dest};password={uenc(f['password'])};version=3#{uenc(name)}")

    elif proto == "naive":
        ib = {"type": "naive", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"username": f["user"], "password": f["password"]}],
              "tls": {"enabled": True, "server_name": domain,
                      "certificate_path": cp, "key_path": kp}}
        uri = f"naive+https://{uenc(f['user'])}:{uenc(f['password'])}@{domain}:{port}#{uenc(name)}"

    elif proto == "snell":
        srv = f["server"]
        ib = {"type": "snell", "tag": tag, "listen": "::", "listen_port": port,
              "users": [{"psk": f["psk"]}], "version": 4}
        ob = f.get("obfs", "关闭")
        q = ""
        if ob != "关闭":
            ib["obfs"] = {"type": ob}
            q = f"&obfs={ob}"
        uri = f"snell://{uenc(f['psk'])}@{srv}:{port}?version=4{q}#{uenc(name)}"

    elif proto == "mixed":
        srv = f["server"]
        ib = {"type": "mixed", "tag": tag, "listen": "::", "listen_port": port}
        if f.get("user"):
            ib["users"] = [{"username": f["user"], "password": f["password"]}]
            uri = f"socks://{b64(f['user'] + ':' + f['password'])}@{srv}:{port}#{uenc(name)}"
        else:
            uri = f"socks5://{srv}:{port}#{uenc(name)}"

    elif proto == "http":
        srv = domain or f["server"]
        ib = {"type": "http", "tag": tag, "listen": "::", "listen_port": port}
        if f.get("user"):
            ib["users"] = [{"username": f["user"], "password": f["password"]}]
        if cert:
            ib["tls"] = {"enabled": True, "server_name": domain,
                         "certificate_path": cp, "key_path": kp}
            scheme = "https"
        else:
            scheme = "http"
        auth = f"{uenc(f['user'])}:{uenc(f['password'])}@" if f.get("user") else ""
        uri = f"{scheme}://{auth}{srv}:{port}#{uenc(name)}"

    elif proto == "socks":
        srv = f["server"]
        ib = {"type": "socks", "tag": tag, "listen": "::", "listen_port": port}
        if f.get("user"):
            ib["users"] = [{"username": f["user"], "password": f["password"]}]
            uri = f"socks://{b64(f['user'] + ':' + f['password'])}@{srv}:{port}#{uenc(name)}"
        else:
            uri = f"socks5://{srv}:{port}#{uenc(name)}"

    elif proto == "shadowsocks":
        method, pw, srv = f["method"], f["password"], f["server"]
        ib = {"type": "shadowsocks", "tag": tag, "listen": "::", "listen_port": port,
              "method": method, "password": pw}
        uri = f"ss://{b64(method + ':' + pw)}@{srv}:{port}#{uenc(name)}"
    else:
        raise ValueError("不支持的协议")

    extra = ib.pop("_extra_inbound", None)
    ib, uri = apply_advanced(ib, uri, proto, f)
    if extra:
        ib["_extra_inbound"] = extra
    return ib, uri


# ════════════════════════════════════════════
# 版本管理（升级 / 降级）
# ════════════════════════════════════════════
SB_DIR = "/usr/local/sing-box"
VER_PIN = f"{SB_ETC}/version.pin"


def get_arch():
    c, o, _ = sh("uname -m")
    return {"x86_64": "amd64", "amd64": "amd64",
            "aarch64": "arm64", "arm64": "arm64",
            "armv7l": "armv7"}.get(o.strip(), "amd64")


def cur_version():
    c, o, _ = sh(f"{SB_BIN} version")
    if c == 0 and o:
        parts = o.splitlines()[0].split()
        return parts[-1] if parts else ""
    return ""


def fetch_versions(limit=5):
    """从 GitHub 拉最近的版本列表"""
    c, o, _ = sh("curl -fsSL --max-time 20 "
                 "'https://api.github.com/repos/SagerNet/sing-box/releases?per_page=10'", 25)
    if c != 0 or not o:
        return []
    try:
        rel = json.loads(o)
    except Exception:
        return []
    out = []
    for r in rel:
        if r.get("draft"):
            continue
        out.append({
            "ver": r.get("tag_name", "").lstrip("v"),
            "pre": bool(r.get("prerelease")),
            "date": (r.get("published_at") or "")[:10],
            "note": (r.get("body") or "").strip()[:300],
        })
        if len(out) >= limit:
            break
    return out


VER_JOB = {"running": False, "ver": "", "ok": None, "msg": "", "step": ""}


def install_version(ver, job=None):
    def step(t):
        if job is not None:
            job["step"] = t

    ver = ver.lstrip("v").strip()
    if not re.match(r"^[0-9][0-9A-Za-z.\-]*$", ver):
        return False, "版本号格式无效"
    arch = get_arch()
    pkg = f"sing-box-{ver}-linux-{arch}"
    gh = f"https://github.com/SagerNet/sing-box/releases/download/v{ver}/{pkg}.tar.gz"
    mirrors = [gh,
               f"https://ghfast.top/{gh}",
               f"https://gh-proxy.com/{gh}"]

    # 直接解压到 sing-box 所在分区（通常是根盘，空间比 tmpfs 的 /tmp 大）
    def free_mb(path):
        c, o, _ = sh(f"df -Pm {path} 2>/dev/null | tail -1 | awk '{{print $4}}'")
        try:
            return int(o.strip())
        except ValueError:
            return -1

    dest_dir = os.path.dirname(SB_BIN)
    os.makedirs(dest_dir, exist_ok=True)
    avail = free_mb(dest_dir)
    if 0 <= avail < 100:
        return False, (f"磁盘空间不足：{dest_dir} 仅剩 {avail}MB，需要至少 100MB\n"
                       f"清理建议： apt-get clean ; journalctl --vacuum-size=20M")

    tmp = f"{dest_dir}/.up-{secrets.token_hex(4)}"
    os.makedirs(tmp, exist_ok=True)
    try:
        # 流式下载并只解压 sing-box 二进制（跳过 libcronet.so 等），磁盘峰值最小
        okdl = False
        lasterr = ""
        for i, url in enumerate(mirrors):
            step(f"下载并解压 ({'官方源' if i == 0 else '镜像 ' + str(i)})")
            sh(f"rm -rf {tmp}/* 2>/dev/null")
            # 精确路径：GNU tar 与 bsdtar 均支持
            c, o, e = sh(
                f"curl -fL --max-time 240 --retry 2 --retry-delay 2 '{url}' | "
                f"tar -xzf - -C {tmp} '{pkg}/sing-box' 2>&1", 260)
            found = sh(f"find {tmp} -type f -name sing-box | head -1")[1].strip()
            if not found:
                # 兜底：包内目录名与预期不符时用通配
                sh(f"rm -rf {tmp}/* 2>/dev/null")
                sh(f"curl -fL --max-time 240 '{url}' | "
                   f"tar -xzf - -C {tmp} --wildcards '*/sing-box' 2>&1", 260)
                found = sh(f"find {tmp} -type f -name sing-box | head -1")[1].strip()
            if found and os.path.getsize(found) > 5 * 1024 * 1024:
                binsrc = found
                okdl = True
                break
            lasterr = (e or o or "下载或解压中断")[:200]
        if not okdl:
            return False, f"下载失败：{lasterr}\n{gh}"

        step("安装中")
        # 临时备份仅用于失败回滚，成功后随 tmp 目录一并删除，不留残余
        bak = f"{tmp}/sing-box.prev"
        if os.path.exists(SB_BIN):
            sh(f"cp {SB_BIN} {bak}")
        sh("systemctl stop sing-box")
        c, _, e = sh(f"install -m 755 {binsrc} {SB_BIN}")
        if c != 0:
            sh("systemctl start sing-box")
            return False, f"安装失败: {e}"

        step("校验配置")
        c, o, e = sh(f"{SB_BIN} check -c {SB_CONF}")
        if c != 0:
            if os.path.exists(bak):
                sh(f"cp {bak} {SB_BIN}")
            sh("systemctl start sing-box")
            return False, f"新版本无法加载当前配置，已回滚:\n{(e or o)[:400]}"

        step("启动服务")
        sh("systemctl start sing-box")
        time.sleep(1)
        _, st, _ = sh("systemctl is-active sing-box")
        if st.strip() != "active":
            if os.path.exists(bak):
                sh(f"cp {bak} {SB_BIN}")
                sh("systemctl restart sing-box")
            _, log, _ = sh("journalctl -u sing-box -n 15 --no-pager")
            return False, f"启动失败，已回滚:\n{log[-400:]}"

        # 只保留最近 3 个备份
        # 成功：清掉全部历史备份与临时文件，不保留旧版本
        sh(f"rm -f {SB_BIN}.bak.* 2>/dev/null")
        cleanup_disk(deep=False)
        return True, cur_version()
    finally:
        sh(f"rm -rf {tmp}")


AUTO_LOG = []          # 最近几次自动更新记录


def auto_update_loop():
    """按配置定期检查并自动升级 sing-box。默认关闭。"""
    time.sleep(120)                      # 启动后先等 2 分钟
    while True:
        try:
            pc = load_json(PANEL_CFG, {})
            au = pc.get("auto_update") or {}
            if not au.get("enabled"):
                time.sleep(1800)
                continue
            hours = max(1, int(au.get("interval_hours", 12)))

            # 版本锁定时不自动更新
            if os.path.exists(VER_PIN):
                AUTO_LOG.append({"t": time.strftime("%m-%d %H:%M"),
                                 "msg": "已锁定版本，跳过"})
                time.sleep(hours * 3600)
                continue
            if VER_JOB.get("running") or CERT_JOB.get("running"):
                time.sleep(600)
                continue

            lst = fetch_versions()
            if not lst:
                time.sleep(hours * 3600)
                continue
            # stable = 只跟正式版；all = 含预发布
            if au.get("channel", "stable") == "stable":
                target = next((v["ver"] for v in lst if not v["pre"]), "")
            else:
                target = lst[0]["ver"]
            cur = cur_version()
            if not target or target == cur:
                AUTO_LOG.append({"t": time.strftime("%m-%d %H:%M"),
                                 "msg": f"已是最新 {cur}"})
                time.sleep(hours * 3600)
                continue

            VER_JOB.update(running=True, ver=target, ok=None, msg="", step="自动更新")
            okk, r = install_version(target, VER_JOB)
            VER_JOB.update(running=False, ok=okk,
                           msg=(f"已切换到 {r}" if okk else r), step="")
            AUTO_LOG.append({"t": time.strftime("%m-%d %H:%M"),
                             "msg": (f"自动升级 {cur} → {target} 成功" if okk
                                     else f"自动升级到 {target} 失败(已回滚): {r[:120]}")})
            del AUTO_LOG[:-10]
            time.sleep(hours * 3600)
        except Exception as e:
            AUTO_LOG.append({"t": time.strftime("%m-%d %H:%M"), "msg": f"异常: {e}"})
            time.sleep(3600)


def install_version_async(ver):
    def work():
        VER_JOB.update(running=True, ver=ver, ok=None, msg="", step="准备")
        try:
            okk, r = install_version(ver, VER_JOB)
            VER_JOB.update(ok=okk, msg=(f"已切换到 {r}" if okk else r))
        except Exception as e:
            VER_JOB.update(ok=False, msg=f"异常: {e}")
        finally:
            VER_JOB.update(running=False, step="")
    threading.Thread(target=work, daemon=True).start()


# ════════════════════════════════════════════
# 订阅
# ════════════════════════════════════════════
def sub_token():
    p = load_json(PANEL_CFG, {})
    t = p.get("sub_token")
    if not t:
        t = secrets.token_hex(16)
        p["sub_token"] = t
        save_json(PANEL_CFG, p)
    return t


def rebuild_sub():
    os.makedirs(SUB_DIR, exist_ok=True)
    m = meta()
    uris = [v["uri"] for v in m.values() if v.get("uri")]
    tok = sub_token()
    for old in os.listdir(SUB_DIR):
        if old != tok:
            try:
                os.remove(f"{SUB_DIR}/{old}")
            except OSError:
                pass
    with open(f"{SUB_DIR}/{tok}", "w") as f:
        f.write(b64("\n".join(uris)))
    return tok


# ════════════════════════════════════════════
# API
# ════════════════════════════════════════════
def api_status():
    _, ver, _ = sh(f"{SB_BIN} version")
    ver = ver.splitlines()[0].split()[-1] if ver else "未知"
    _, act, _ = sh("systemctl is-active sing-box")
    c = cfg()
    n_sb = len(c.get("inbounds", []))
    xi = xr_installed()
    n_xr = 0
    xrun = False
    xver = ""
    if xi:
        n_xr = len(xcfg().get("inbounds", []))
        xver = xr_version()
        _, xact, _ = sh(f"systemctl is-active {XR_SVC}")
        xrun = xact.strip() == "active"
    return {"version": ver, "running": act.strip() == "active",
            "ip": public_ip(),
            "inbounds": n_sb + n_xr,
            "xray_installed": xi, "xray_version": xver,
            "xray_running": xrun, "xray_nodes": n_xr, "sb_nodes": n_sb,
            "outbounds": len([o for o in c.get("outbounds", []) if o.get("type") != "direct"])}


def api_inbounds():
    c, m = cfg(), meta()
    out = []
    binds = {}
    for r in c.get("route", {}).get("rules", []):
        ob = r.get("outbound")
        if not ob:
            continue
        for t in (r.get("inbound") or []):
            binds[t] = ob
    for ib in c.get("inbounds", []):
        t = ib.get("tag")
        info = m.get(t, {})
        out.append({"tag": t, "type": ib.get("type"), "port": ib.get("listen_port"),
                    "name": info.get("name", t), "uri": info.get("uri", ""),
                    "core": "sing-box", "bind": binds.get(t, "direct")})
    if xr_installed():
        xb = xr_binds()
        for ib in xcfg().get("inbounds", []):
            t = ib.get("tag")
            info = m.get(t, {})
            out.append({"tag": t, "type": ib.get("protocol"), "port": ib.get("port"),
                        "name": info.get("name", t), "uri": info.get("uri", ""),
                        "core": "xray", "bind": xb.get(t, "direct")})
    return out


def api_outbounds():
    out = []
    for o in cfg().get("outbounds", []):
        if o.get("type") == "direct":
            continue
        out.append({"tag": o.get("tag"), "type": o.get("type"),
                    "server": o.get("server", ""), "port": o.get("server_port", ""),
                    "auth": bool(o.get("username")),
                    "tls": bool((o.get("tls") or {}).get("enabled"))})
    return out


def api_add_inbound(body):
    proto = body.get("proto")
    if proto not in PROTOCOLS:
        return False, "未知协议"
    core = body.get("core") or DEFAULT_CORE
    spec = PROTOCOLS[proto]
    if core not in (spec.get("cores") or [DEFAULT_CORE]):
        return False, f"{spec['label']} 不支持用 {core} 运行"
    if core == "xray" and not xr_installed():
        return False, "Xray-core 未安装，请先到「版本」页安装"
    f = body.get("fields", {})
    if spec["needs_cert"]:
        d = f.get("cert", "")
        if not d or not os.path.exists(f"{CERT_DIR}/{d}/fullchain.pem"):
            return False, "请先选择或申请有效证书"
    # 跨核心端口冲突检查（两个核心不能抢同一端口）
    try:
        port = int(f.get("port"))
    except (TypeError, ValueError):
        return False, "端口无效"
    if port in used_ports():
        return False, f"端口 {port} 已被另一个节点占用（两个核心共用同一端口空间）"

    base = f"{proto}-{'x' if core == 'xray' else 'in'}"
    tag, n = base, 1
    exist = all_tags()
    while tag in exist:
        tag = f"{base}-{n}"; n += 1

    try:
        if core == "xray":
            ib, uri = build_xray_inbound(proto, f, tag)
        else:
            ib, uri = build_inbound(proto, f, tag)
    except Exception as e:
        return False, f"生成失败: {e}"

    if core == "xray":
        xc = xr_sync_outbounds(xcfg())
        xc.setdefault("inbounds", []).append(ib)
        okk, msg = apply_xconfig(xc)
    else:
        c = cfg()
        extra = ib.pop("_extra_inbound", None)   # ShadowTLS 配套内部入站
        c.setdefault("inbounds", []).append(ib)
        if extra:
            c["inbounds"].append(extra)
        okk, msg = apply_config(c)
    if not okk:
        return False, msg

    m = meta()
    m[tag] = {"name": f.get("name", tag), "uri": uri, "proto": proto, "core": core,
              "fields": f, "created": time.strftime("%F %T")}
    save_json(META_FILE, m)
    rebuild_sub()
    if proto == "hysteria2" and f.get("hop"):
        setup_hop(f["hop"], int(f["port"]))
    return True, {"tag": tag, "uri": uri}


def setup_hop(rng, target):
    mm = re.match(r"^(\d+)-(\d+)$", rng.strip())
    if not mm:
        return
    s, e = mm.group(1), mm.group(2)
    _, nic, _ = sh("ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+' | head -1")
    nic = nic.strip() or "eth0"
    sh(f"iptables -t nat -C PREROUTING -i {nic} -p udp --dport {s}:{e} "
       f"-j DNAT --to-destination :{target} 2>/dev/null || "
       f"iptables -t nat -A PREROUTING -i {nic} -p udp --dport {s}:{e} "
       f"-j DNAT --to-destination :{target}")
    sh("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent >/dev/null 2>&1; "
       "netfilter-persistent save >/dev/null 2>&1", 60)


def _cert_domain(path):
    """/etc/sing-box/cert/DOMAIN/fullchain.pem -> DOMAIN"""
    if not path:
        return ""
    p = path.rstrip("/").split("/")
    return p[-2] if len(p) >= 2 else ""


def inbound_to_fields(ib, proto, info):
    """从实际配置反推表单字段，使任何版本创建的节点都能编辑"""
    f = {"name": info.get("name") or ib.get("tag", ""),
         "port": str(ib.get("listen_port", ""))}
    tls = ib.get("tls") or {}
    users = ib.get("users") or [{}]
    u0 = users[0] if users else {}
    cert = _cert_domain(tls.get("certificate_path", ""))
    if cert:
        f["cert"] = cert
    # 客户端连接地址：优先从已存链接里取，其次证书域名/公网IP
    srv = ""
    uri = info.get("uri", "")
    m = re.search(r"@([^:/?#]+):", uri)
    if m:
        srv = m.group(1)
    f["server"] = srv or cert or public_ip()

    if proto == "hysteria2":
        f["password"] = u0.get("password", "")
        f["obfs"] = (ib.get("obfs") or {}).get("password", "")
        f["up"] = str(ib.get("up_mbps", 0) or 0)
        f["down"] = str(ib.get("down_mbps", 0) or 0)
        mq = ib.get("masquerade")
        if not mq:
            f["masq_type"] = "不伪装(返回404)"
        elif (mq or {}).get("type") == "proxy":
            f["masq_type"] = "反代网站(内容最真实)"
            f["masq"] = mq.get("url", "")
        else:
            f["masq_type"] = "内置页面(最快，不出网)"
        mm = re.search(r"mport=([0-9\-]+)", uri)
        f["hop"] = mm.group(1) if mm else ""
    elif proto == "vless":
        f["uuid"] = u0.get("uuid", "")
        f["dest"] = tls.get("server_name", "")
        f["flow"] = ("xtls-rprx-vision (推荐，性能最好)" if u0.get("flow") else "无")
        f["regen"] = "保持现有密钥（编辑时推荐）"
        _r = (tls.get("reality") or {})
        f["sid_count"] = str(len(_r.get("short_id") or [])) or "8"
        f["maxdiff"] = _r.get("max_time_difference", "0") or "0"
    elif proto in ("vless-tls", "vmess"):
        f["uuid"] = u0.get("uuid", "")
    elif proto in ("anytls", "trojan"):
        f["password"] = u0.get("password", "")
    elif proto == "tuic":
        f["uuid"] = u0.get("uuid", "")
        f["password"] = u0.get("password", "")
        f["cc"] = ib.get("congestion_control", "bbr")
        f["zrtt"] = "开启" if ib.get("zero_rtt_handshake") else "关闭"
    elif proto == "hysteria":
        f["authstr"] = u0.get("auth_str", "")
        f["up"] = str(ib.get("up_mbps", 50))
        f["down"] = str(ib.get("down_mbps", 200))
    elif proto == "shadowtls":
        f["password"] = u0.get("password", "")
        f["dest"] = (ib.get("handshake") or {}).get("server", "")
        det = ib.get("detour", "")
        ss = next((x for x in cfg().get("inbounds", []) if x.get("tag") == det), {})
        f["sspass"] = ss.get("password", "")
    elif proto == "naive":
        f["user"] = u0.get("username", "")
        f["password"] = u0.get("password", "")
    elif proto == "snell":
        f["psk"] = u0.get("psk", "")
        f["obfs"] = (ib.get("obfs") or {}).get("type", "关闭") or "关闭"
    elif proto in ("socks", "mixed", "http"):
        f["user"] = u0.get("username", "")
        f["password"] = u0.get("password", "")
        if proto == "http" and not cert:
            f["cert"] = ""
    elif proto == "shadowsocks":
        f["method"] = ib.get("method", "2022-blake3-aes-128-gcm")
        f["password"] = ib.get("password", "")

    # ── 高级选项反推 ──
    keys = {a["k"] for a in (PROTOCOLS.get(proto, {}).get("adv") or [])}
    if "tfo" in keys:
        f["tfo"] = "1" if ib.get("tcp_fast_open") else "0"
        f["mptcp"] = "1" if ib.get("tcp_multi_path") else "0"
    if "udpfrag" in keys:
        f["udpfrag"] = "1" if ib.get("udp_fragment") else "0"
        f["udpto"] = ib.get("udp_timeout") or "5m"
    if "mux" in keys:
        mx = ib.get("multiplex") or {}
        f["mux"] = "1" if mx.get("enabled") else "0"
        f["mux_pad"] = "1" if mx.get("padding") else "0"
        br = mx.get("brutal") or {}
        f["mux_brutal"] = "1" if br.get("enabled") else "0"
        f["mux_up"] = str(br.get("up_mbps", 0) or 0)
        f["mux_down"] = str(br.get("down_mbps", 0) or 0)
    if "tls_min" in keys:
        f["tls_min"] = tls.get("min_version") or "1.3"
        al = tls.get("alpn")
        f["alpn"] = ",".join(al) if al else "不设置"
    if "transport" in keys:
        tr = ib.get("transport") or {}
        tt = tr.get("type", "")
        f["transport"] = {"ws": "WebSocket", "grpc": "gRPC",
                          "httpupgrade": "HTTPUpgrade"}.get(tt, "TCP (原始，最快)")
        f["tr_path"] = tr.get("service_name") or tr.get("path") or "/"
        f["tr_host"] = tr.get("host") or (tr.get("headers") or {}).get("Host", "") or ""
        f["tr_ed"] = "1" if tr.get("max_early_data") else "0"
    return f


def xinbound_to_fields(ib, proto, info):
    """从 Xray inbound 反推表单字段（手工改过配置或 meta 丢失时兜底）"""
    ss = ib.get("streamSettings") or {}
    st = ib.get("settings") or {}
    cls = (st.get("clients") or [{}])
    c0 = cls[0] if cls else {}
    tls = ss.get("tlsSettings") or {}
    rs = ss.get("realitySettings") or {}
    f = {"name": info.get("name") or ib.get("tag", ""),
         "port": str(ib.get("port", ""))}
    cert = _cert_domain((tls.get("certificates") or [{}])[0].get("certificateFile", ""))
    if cert:
        f["cert"] = cert
    srv = ""
    m = re.search(r"@([^:/?#]+):", info.get("uri", ""))
    if m:
        srv = m.group(1)
    f["server"] = srv or cert or public_ip()

    if proto == "vless":
        f["uuid"] = c0.get("id", "")
        f["dest"] = (rs.get("dest") or "").rsplit(":", 1)[0]
        f["sni"] = ",".join(rs.get("serverNames") or [])
        f["flow"] = "xtls-rprx-vision (推荐，性能最好)" if c0.get("flow") else "无"
        f["regen"] = "保持现有密钥（编辑时推荐）"
        f["sid_count"] = str(len(rs.get("shortIds") or [])) or "8"
        md = rs.get("maxTimeDiff") or 0
        f["maxdiff"] = {0: "0", 60000: "1m", 300000: "5m", 3600000: "1h"}.get(md, "0")
        f["xver"] = str(rs.get("xver", 0) or 0)
        f["min_client"] = rs.get("minClientVer", "1.0.0") or "1.0.0"
        f["max_client"] = rs.get("maxClientVer", "") or ""
        mfp = re.search(r"[?&]fp=([^&#]+)", info.get("uri", ""))
        msx = re.search(r"[?&]spx=([^&#]+)", info.get("uri", ""))
        f["utls"] = mfp.group(1) if mfp else "chrome"
        f["spiderx"] = urllib.parse.unquote(msx.group(1)) if msx else "/"
    elif proto in ("vless-tls", "vmess"):
        f["uuid"] = c0.get("id", "")
    elif proto == "trojan":
        f["password"] = c0.get("password", "")
    elif proto == "shadowsocks":
        f["method"] = st.get("method", "2022-blake3-aes-128-gcm")
        f["password"] = st.get("password", "")
    elif proto in ("socks", "http"):
        acc = (st.get("accounts") or [{}])[0]
        f["user"] = acc.get("user", "")
        f["password"] = acc.get("pass", "")

    sn = ib.get("sniffing") or {}
    over = set(sn.get("destOverride") or [])
    f["sniff"] = "1" if sn.get("enabled") else "0"
    for n, k in (("http", "sniff_http"), ("tls", "sniff_tls"), ("quic", "sniff_quic")):
        f[k] = "1" if n in over else "0"
    f["sniff_route_only"] = "1" if sn.get("routeOnly") else "0"

    keys = {a["k"] for a in (PROTOCOLS.get(proto, {}).get("adv_xray") or [])}
    sock = ss.get("sockopt") or {}
    if "tfo" in keys:
        f["tfo"] = "1" if sock.get("tcpFastOpen") else "0"
        f["mptcp"] = "1" if sock.get("tcpMptcp") else "0"
    if "tls_min" in keys:
        f["tls_min"] = tls.get("minVersion") or "1.3"
        al = tls.get("alpn")
        f["alpn"] = ",".join(al) if al else "不设置"
    if "transport" in keys:
        net = ss.get("network", "tcp")
        f["transport"] = {"ws": "WebSocket", "grpc": "gRPC",
                          "httpupgrade": "HTTPUpgrade",
                          "xhttp": "XHTTP (Xray 专属，过 CDN 最好)",
                          "kcp": "mKCP (Xray 专属，抗丢包)"}.get(net, "TCP (原始，最快)")
        cf = (ss.get("wsSettings") or ss.get("httpupgradeSettings")
              or ss.get("xhttpSettings") or {})
        f["tr_path"] = (ss.get("grpcSettings") or {}).get("serviceName") or cf.get("path") or "/"
        f["tr_host"] = cf.get("host") or ""
        k = ss.get("kcpSettings") or {}
        f["kcp_seed"] = k.get("seed", "")
        f["kcp_header"] = (k.get("header") or {}).get("type", "none")
    return f


def guess_proto(ib):
    """无记录时从配置判断协议种类"""
    t = ib.get("type")
    tls = ib.get("tls") or {}
    if t == "vless":
        return "vless" if (tls.get("reality") or {}).get("enabled") else "vless-tls"
    return t if t in PROTOCOLS else ""


def _edit_xray_inbound(tag, body, m, info):
    xc = xr_sync_outbounds(xcfg())
    old = next((i for i in xc.get("inbounds", []) if i.get("tag") == tag), None)
    if not old:
        return False, "节点不存在"
    proto = body.get("proto") or info.get("proto")
    if proto not in PROTOCOLS:
        return False, "未知协议"
    f = body.get("fields", {})
    if PROTOCOLS[proto]["needs_cert"]:
        d = f.get("cert", "")
        if d and not os.path.exists(f"{CERT_DIR}/{d}/fullchain.pem"):
            return False, "所选证书不存在"
    try:
        newport = int(f.get("port"))
    except (TypeError, ValueError):
        return False, "端口无效"
    if newport != old.get("port") and newport in used_ports():
        return False, f"端口 {newport} 已被另一个节点占用"
    try:
        ib, uri = build_xray_inbound(proto, f, tag)
    except Exception as e:
        return False, f"生成失败: {e}"
    # Reality：默认沿用原密钥，选了「重新生成」或 dest 变了才换
    if proto == "vless":
        oss, nss = (old.get("streamSettings") or {}), (ib.get("streamSettings") or {})
        oldr, newr = (oss.get("realitySettings") or {}), (nss.get("realitySettings") or {})
        same_dest = oldr.get("dest") == newr.get("dest")
        if same_dest and oldr.get("privateKey") and not str(f.get("regen", "")).startswith("重新生成"):
            newr["privateKey"] = oldr["privateKey"]
            newr["shortIds"] = oldr.get("shortIds", newr.get("shortIds"))
            oldpub = re.search(r"pbk=([^&#]+)", info.get("uri", ""))
            oldsid = re.search(r"sid=([^&#]+)", info.get("uri", ""))
            if oldpub:
                uri = re.sub(r"pbk=[^&#]+", f"pbk={oldpub.group(1)}", uri)
            if oldsid:
                uri = re.sub(r"sid=[^&#]+", f"sid={oldsid.group(1)}", uri)
    xc["inbounds"] = [ib if i.get("tag") == tag else i for i in xc.get("inbounds", [])]
    okk, msg = apply_xconfig(xc)
    if not okk:
        return False, msg
    info.update({"name": f.get("name", tag), "uri": uri, "proto": proto, "core": "xray",
                 "fields": f, "edited": time.strftime("%F %T")})
    m[tag] = info
    save_json(META_FILE, m)
    rebuild_sub()
    return True, {"tag": tag, "uri": uri}


def api_edit_inbound(tag, body):
    m = meta()
    info = m.get(tag, {})
    if core_of(tag, m) == "xray":
        return _edit_xray_inbound(tag, body, m, info)
    c = cfg()
    old = next((i for i in c.get("inbounds", []) if i.get("tag") == tag), None)
    if not old:
        return False, "节点不存在"
    proto = body.get("proto") or info.get("proto")
    if proto not in PROTOCOLS:
        return False, "未知协议"
    f = body.get("fields", {})
    if PROTOCOLS[proto]["needs_cert"]:
        d = f.get("cert", "")
        if d and not os.path.exists(f"{CERT_DIR}/{d}/fullchain.pem"):
            return False, "所选证书不存在"
    try:
        ib, uri = build_inbound(proto, f, tag)
    except Exception as e:
        return False, f"生成失败: {e}"
    # Reality：默认沿用原密钥；选了「重新生成」或 dest 变了才换新的
    if proto == "vless":
        oldr = ((old.get("tls") or {}).get("reality") or {})
        newr = ((ib.get("tls") or {}).get("reality") or {})
        same_dest = (old.get("tls") or {}).get("server_name") == (ib.get("tls") or {}).get("server_name")
        want_regen = str(f.get("regen", "")).startswith("重新生成")
        if same_dest and oldr.get("private_key") and not want_regen:
            newr["private_key"] = oldr["private_key"]
            newr["short_id"] = oldr.get("short_id", newr.get("short_id"))
            # 分享链接里的公钥同步回旧值
            oldpub = re.search(r"pbk=([^&#]+)", info.get("uri", ""))
            oldsid = re.search(r"sid=([^&#]+)", info.get("uri", ""))
            if oldpub:
                uri = re.sub(r"pbk=[^&#]+", f"pbk={oldpub.group(1)}", uri)
            if oldsid:
                uri = re.sub(r"sid=[^&#]+", f"sid={oldsid.group(1)}", uri)
    extra = ib.pop("_extra_inbound", None)

    # 原地替换，保持顺序；同时更新 ShadowTLS 的配套入站
    newins = []
    for i in c.get("inbounds", []):
        if i.get("tag") == tag:
            newins.append(ib)
        elif i.get("tag") == f"{tag}-ss":
            continue          # 旧的配套入站丢弃，稍后按需重建
        else:
            newins.append(i)
    if extra:
        newins.append(extra)
    c["inbounds"] = newins

    okk, msg = apply_config(c)
    if not okk:
        return False, msg
    info.update({"name": f.get("name", tag), "uri": uri, "proto": proto,
                 "fields": f, "edited": time.strftime("%F %T")})
    m[tag] = info
    save_json(META_FILE, m)
    rebuild_sub()
    return True, {"tag": tag, "uri": uri}


def api_del_inbound(tag):
    m0 = meta()
    if core_of(tag, m0) == "xray":
        xc = xr_sync_outbounds(xcfg())
        xc["inbounds"] = [i for i in xc.get("inbounds", []) if i.get("tag") != tag]
        xc["routing"]["rules"] = [r for r in xc.get("routing", {}).get("rules", [])
                                  if tag not in (r.get("inboundTag") or [])]
        okk, msg = apply_xconfig(xc)
        if not okk:
            return False, msg
        m0.pop(tag, None)
        save_json(META_FILE, m0)
        rebuild_sub()
        return True, "已删除"
    c = cfg()
    # ShadowTLS 的配套内部入站一并删除
    drop = {tag, f"{tag}-ss"}
    c["inbounds"] = [i for i in c.get("inbounds", []) if i.get("tag") not in drop]
    rules = c.get("route", {}).get("rules", [])
    c["route"]["rules"] = [r for r in rules if tag not in (r.get("inbound") or [])]
    okk, msg = apply_config(c)
    if not okk:
        return False, msg
    m = meta()
    m.pop(tag, None)
    save_json(META_FILE, m)
    rebuild_sub()
    return True, "已删除"


def _parse_ob(body):
    """解析出站表单，返回 (ob_dict, err)"""
    kind = body.get("kind", "socks")
    srv = (body.get("server") or "").strip()
    port = str(body.get("port") or "").strip()
    user = (body.get("username") or "").strip()
    pw = (body.get("password") or "").strip()
    # 兼容旧的 ip:端口:账号:密码 一行格式
    raw = (body.get("raw") or "").strip()
    if raw and not srv:
        parts = raw.split(":")
        if len(parts) >= 2:
            srv, port = parts[0].strip(), parts[1].strip()
            user = parts[2] if len(parts) > 2 else ""
            pw = parts[3] if len(parts) > 3 else ""
    if not srv:
        return None, "服务器地址不能为空"
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return None, "服务器端口无效"

    tag = (body.get("tag") or "").strip() or f"{kind}-{srv.split('.')[-1]}"
    if kind == "http":
        ob = {"type": "http", "tag": tag, "server": srv, "server_port": int(port)}
        if body.get("tls"):
            ob["tls"] = {"enabled": True, "server_name": srv, "insecure": True}
    else:
        ob = {"type": "socks", "tag": tag, "server": srv, "server_port": int(port),
              "version": str(body.get("version") or "5")}
        net = (body.get("network") or "").strip()
        if net in ("tcp", "udp"):
            ob["network"] = net          # 留空 = TCP/UDP 都启用
        if body.get("uot"):
            ob["udp_over_tcp"] = True
    if user:
        ob["username"] = user
        ob["password"] = pw
    return ob, None


def api_add_outbound(body):
    binds = body.get("binds") or []
    kind = body.get("kind", "socks")
    ob, err = _parse_ob(body)
    if err:
        return False, err
    tag = ob["tag"]
    c = cfg()
    if any(o.get("tag") == tag for o in c.get("outbounds", [])):
        return False, f"出站名 {tag} 已存在"
    c.setdefault("outbounds", []).append(ob)

    # 同时绑定所选节点（合并到一次写入，避免多次重启）
    xr_binds_sel = [b for b in binds if core_of(b) == "xray"]
    if binds:
        valid = {i.get("tag") for i in c.get("inbounds", [])}
        binds = [b for b in binds if b in valid]
        rules = c.get("route", {}).get("rules", [{"action": "sniff"}])
        # 移除这些入站的旧绑定；旧 QUIC 规则里也把它们摘掉，防止重复累积
        cleaned = []
        for r in rules:
            inb = set(r.get("inbound") or [])
            if not inb:
                cleaned.append(r); continue
            if r.get("protocol") == "quic" and r.get("action") == "reject":
                rest = [x for x in (r.get("inbound") or []) if x not in set(binds)]
                if rest:
                    cleaned.append(dict(r, inbound=rest))
                continue
            if inb & set(binds):
                continue
            cleaned.append(r)
        rules = cleaned
        head = rules[:1] if rules and rules[0].get("action") == "sniff" else []
        tail = rules[1:] if head else rules
        new_rules = []
        # QUIC/UDP 走 SOCKS5 常不稳（落地多半不支持 UDP ASSOCIATE）
        # 默认把这些节点的 QUIC 拒掉，强制回退 TCP —— 显著更稳
        if kind == "http" or body.get("block_quic", True):
            new_rules.append({"inbound": binds, "protocol": "quic", "action": "reject"})
        new_rules += [{"inbound": [b], "outbound": tag} for b in binds]
        c["route"]["rules"] = head + new_rules + tail

    okk, msg = apply_config(c)
    if not okk:
        return False, msg
    # Xray 侧节点的绑定：镜像出站后写 routing 规则
    if xr_binds_sel and xr_installed():
        xc = xr_sync_outbounds(xcfg())
        for b in xr_binds_sel:
            xc = xr_set_bind(xc, b, tag, body.get("block_quic", True))
        okx, msgx = apply_xconfig(xc)
        if not okx:
            return False, f"sing-box 侧已保存，但 Xray 侧绑定失败：{msgx}"
    return True, {"tag": tag, "bound": len(binds) + len(xr_binds_sel)}


def api_edit_outbound(tag, body):
    c = cfg()
    if not any(o.get("tag") == tag for o in c.get("outbounds", [])):
        return False, "出站不存在"
    ob, err = _parse_ob(body)
    if err:
        return False, err
    newtag = ob["tag"]
    if newtag != tag and any(o.get("tag") == newtag for o in c.get("outbounds", [])):
        return False, f"出站名 {newtag} 已存在"

    c["outbounds"] = [ob if o.get("tag") == tag else o for o in c.get("outbounds", [])]
    # 改名时同步路由绑定与 final
    if newtag != tag:
        for r in c.get("route", {}).get("rules", []):
            if r.get("outbound") == tag:
                r["outbound"] = newtag
        if c.get("route", {}).get("final") == tag:
            c["route"]["final"] = newtag

    okk, msg = apply_config(c)
    if not okk:
        return False, msg
    # Xray 侧同步改名（镜像重建 + 绑定跟着新名字走）
    if xr_installed() and newtag != tag:
        xc = xcfg()
        for r in xc.get("routing", {}).get("rules", []):
            if r.get("outboundTag") == tag:
                r["outboundTag"] = newtag
        save_json(XR_CONF, xc)
    xr_resync()
    return True, {"tag": newtag}


def api_del_outbound(tag):
    c = cfg()
    c["outbounds"] = [o for o in c.get("outbounds", []) if o.get("tag") != tag]
    rules = c.get("route", {}).get("rules", [])
    # 先记下绑到此出站的入站，它们的 QUIC 拒绝规则也要一并清掉
    freed = set()
    for r in rules:
        if r.get("outbound") == tag:
            freed |= set(r.get("inbound") or [])
    kept = []
    for r in rules:
        if r.get("outbound") == tag:
            continue                                   # 绑定规则
        if r.get("protocol") == "quic" and r.get("action") == "reject":
            rest = [x for x in (r.get("inbound") or []) if x not in freed]
            if not rest:
                continue                               # 该 QUIC 规则已无对应入站，丢弃
            r = dict(r, inbound=rest)                  # 只保留仍绑着别的出站的入站
        kept.append(r)
    c["route"]["rules"] = kept
    if c.get("route", {}).get("final") == tag:
        c["route"]["final"] = "direct"
    okk, msg = apply_config(c)
    if not okk:
        return False, msg
    xr_resync()
    return True, "已删除"


def api_bind(inbound, outbound):
    if core_of(inbound) == "xray":
        if not xr_installed():
            return False, "Xray-core 未安装"
        xc = xr_sync_outbounds(xcfg())
        if outbound and outbound != "direct" and \
           not any(o.get("tag") == outbound for o in xc.get("outbounds", [])):
            return False, f"出站 {outbound} 不存在或类型不被 Xray 支持（仅 SOCKS5 / HTTP）"
        xc = xr_set_bind(xc, inbound, outbound)
        okk, msg = apply_xconfig(xc)
        return (True, "已更新") if okk else (False, msg)
    c = cfg()
    rules = c.get("route", {}).get("rules", [{"action": "sniff"}])
    cleaned = []
    for r in rules:
        inb = r.get("inbound") or []
        if inbound not in inb:
            cleaned.append(r); continue
        # 该入站的 QUIC 拒绝规则：摘掉它，其他入站保留
        if r.get("protocol") == "quic" and r.get("action") == "reject":
            rest = [x for x in inb if x != inbound]
            if rest:
                cleaned.append(dict(r, inbound=rest))
        # 绑定规则直接丢弃（下面会重建）
    rules = cleaned
    if outbound and outbound != "direct":
        head = rules[:1] if rules and rules[0].get("action") == "sniff" else []
        tail = rules[1:] if head else rules
        rules = head + [{"inbound": [inbound], "outbound": outbound}] + tail
    c["route"]["rules"] = rules
    okk, msg = apply_config(c)
    return (True, "已更新") if okk else (False, msg)


SPEED_JOB = {}     # tag -> {running, ok, msg, ip, latency, speed}


def _proxy_arg(o):
    srv, port = o.get("server"), o.get("server_port")
    auth = f"{o['username']}:{o.get('password','')}@" if o.get("username") else ""
    if o.get("type") == "http":
        sch = "https" if (o.get("tls") or {}).get("enabled") else "http"
        return f"-x {sch}://{auth}{srv}:{port}" + (" --proxy-insecure" if sch == "https" else "")
    return f"--socks5-hostname {auth}{srv}:{port}"


def speedtest_outbound(tag):
    """经出站测延迟（gstatic 204，3 次取平均/最快）+ 出口 IP"""
    job = SPEED_JOB.setdefault(tag, {})
    job.update(running=True, ok=None, msg="", step="测试中")
    try:
        o = next((x for x in cfg().get("outbounds", []) if x.get("tag") == tag), None)
        if not o:
            job.update(running=False, ok=False, msg="出站不存在")
            return
        px = _proxy_arg(o)
        url = "https://www.gstatic.com/generate_204"

        # time_connect = 到落地服务器的 TCP 握手耗时（与 3x-ui 口径一致）
        # time_total   = 经落地访问目标站的完整往返，仅作参考
        lats, totals = [], []
        for i in range(3):
            job["step"] = f"测试中 {i + 1}/3"
            c, out, _ = sh(f"curl -s -o /dev/null --max-time 8 {px} "
                           f"-w '%{{http_code}} %{{time_connect}} %{{time_total}}' {url}", 12)
            try:
                code, tc, tt = out.split()
                if code in ("204", "200"):
                    lats.append(float(tc) * 1000)
                    totals.append(float(tt) * 1000)
            except ValueError:
                pass
        if not lats:
            job.update(running=False, ok=False, msg="不通（检查地址/账号密码）")
            return

        avg = round(sum(lats) / len(lats))
        best = round(min(lats))
        total = round(sum(totals) / len(totals)) if totals else 0
        # 顺带取出口 IP（失败不影响结果）
        _, ipout, _ = sh(f"curl -s --max-time 8 {px} https://api.ipify.org", 12)
        ip = ipout.strip()[:45]

        job.update(running=False, ok=True, latency=avg, best=best, ip=ip,
                   total=total,
                   loss=round((3 - len(lats)) / 3 * 100),
                   msg=f"{avg}ms（最快 {best}ms）" + (f" · {ip}" if ip else ""))
    except Exception as e:
        job.update(running=False, ok=False, msg=f"异常: {e}")


def speedtest_async(tag):
    threading.Thread(target=speedtest_outbound, args=(tag,), daemon=True).start()


def api_test_outbound(tag):
    o = next((x for x in cfg().get("outbounds", []) if x.get("tag") == tag), None)
    if not o:
        return {"ok": False, "msg": "出站不存在"}
    srv, port = o.get("server"), o.get("server_port")
    auth = ""
    if o.get("username"):
        auth = f"{o['username']}:{o.get('password','')}@"
    if o.get("type") == "http":
        sch = "https" if (o.get("tls") or {}).get("enabled") else "http"
        proxy = f"-x {sch}://{auth}{srv}:{port}" + (" --proxy-insecure" if sch == "https" else "")
    else:
        proxy = f"--socks5-hostname {auth}{srv}:{port}"
    c, out, _ = sh(f"curl -s --max-time 10 {proxy} https://api.ipify.org", 15)
    if c == 0 and out.strip():
        return {"ok": True, "msg": f"可用 · 出口 IP {out.strip()}"}
    c2, _, _ = sh(f"timeout 5 bash -c '</dev/tcp/{srv}/{port}'")
    return {"ok": False, "msg": "端口通但代理无响应(检查账号密码)" if c2 == 0 else f"不可达 {srv}:{port}"}


# ════════════════════════════════════════════
# HTTP
# ════════════════════════════════════════════
HTML = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sing-box 面板</title><style>
:root{
 --bg:#0d0f13; --bg2:#141721; --card:#171a23; --card2:#1c2029;
 --line:#242938; --line2:#2e3546;
 --tx:#e8eaf0; --tx2:#8b93a7; --tx3:#5c6478;
 --pri:#3b82f6; --pri2:#2563eb; --ok:#34d399; --warn:#fbbf24; --err:#f87171;
 --r:12px; --r2:9px; --sh:0 1px 3px rgba(0,0,0,.4),0 8px 24px -8px rgba(0,0,0,.5);
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);
 font:14px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Segoe UI",sans-serif;
 -webkit-font-smoothing:antialiased}
a{color:var(--pri);text-decoration:none}
a:hover{opacity:.8}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px 48px}
header{position:sticky;top:0;z-index:20;background:rgba(13,15,19,.85);
 backdrop-filter:blur(12px);border-bottom:1px solid var(--line);
 display:flex;align-items:center;gap:20px;padding:14px 0;margin-bottom:22px;flex-wrap:wrap}
h1{font-size:16px;font-weight:650;letter-spacing:.2px;white-space:nowrap}
.stat{display:flex;gap:16px;font-size:12.5px;color:var(--tx2);flex-wrap:wrap;flex:1}
.stat b{color:var(--tx);font-weight:600}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;vertical-align:1px}
.on{background:var(--ok);box-shadow:0 0 0 3px rgba(52,211,153,.15)}
.off{background:var(--err);box-shadow:0 0 0 3px rgba(248,113,113,.15)}
.tabs{display:flex;gap:2px;margin-bottom:20px;flex-wrap:wrap;
 background:var(--bg2);padding:4px;border-radius:var(--r);width:fit-content}
.tab{padding:7px 16px;border-radius:var(--r2);cursor:pointer;color:var(--tx2);
 font-size:13.5px;font-weight:500;transition:.15s;user-select:none}
.tab:hover{color:var(--tx)}
.tab.active{background:var(--card2);color:#fff;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
 padding:16px 18px;margin-bottom:12px;transition:.15s}
.card:hover{border-color:var(--line2)}
.card h3{font-size:14.5px;font-weight:600;margin-bottom:10px;
 display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{font-size:10.5px;padding:2px 8px;border-radius:20px;background:var(--bg2);
 color:var(--tx2);font-weight:500;border:1px solid var(--line)}
.badge.bs{background:rgba(59,130,246,.12);color:#8ab4f8;border-color:rgba(59,130,246,.3)}
.badge.bx{background:rgba(251,191,36,.12);color:#f5c563;border-color:rgba(251,191,36,.3)}
.row{display:flex;justify-content:space-between;align-items:center;gap:12px;
 padding:7px 0;font-size:13px;border-bottom:1px solid var(--line)}
.row:last-of-type{border:0}
.row>span:first-child{color:var(--tx2);white-space:nowrap}
.row>span:last-child{text-align:right;word-break:break-all}
.uri{background:#0a0c10;border:1px solid var(--line);border-radius:var(--r2);
 padding:10px 12px;font:11.5px/1.55 ui-monospace,Menlo,monospace;
 word-break:break-all;color:#8fd0ff;margin-top:10px;cursor:pointer;transition:.15s;
 max-height:88px;overflow:auto}
.uri:hover{border-color:var(--pri);background:#0b1220}
button{background:var(--pri);color:#fff;border:0;border-radius:var(--r2);
 padding:8px 15px;font-size:13.5px;font-weight:500;cursor:pointer;
 font-family:inherit;transition:.15s;white-space:nowrap}
button:hover{background:var(--pri2)}
button:active{transform:translateY(1px)}
button:disabled{opacity:.45;cursor:not-allowed}
.btn2{background:var(--card2);color:var(--tx);border:1px solid var(--line2)}
.btn2:hover{background:#252b38;border-color:#3a4356}
.btnd{background:rgba(248,113,113,.1);color:var(--err);border:1px solid rgba(248,113,113,.25)}
.btnd:hover{background:rgba(248,113,113,.18)}
.acts{display:flex;gap:8px;margin-top:13px;flex-wrap:wrap}
label{display:block;font-size:12.5px;color:var(--tx2);margin:13px 0 5px;font-weight:500}
label .hint{color:var(--tx3);font-weight:400;font-size:11.5px;margin-left:6px}
input,select{width:100%;background:#0a0c10;border:1px solid var(--line2);
 border-radius:var(--r2);padding:9px 11px;color:var(--tx);font-size:13.5px;
 font-family:inherit;transition:.15s}
input:focus,select:focus{outline:0;border-color:var(--pri);box-shadow:0 0 0 3px rgba(59,130,246,.12)}
input::placeholder{color:var(--tx3)}
select{cursor:pointer}
.f2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.f2 label{margin-top:13px}
@media(max-width:560px){.f2{grid-template-columns:1fr}}
.chk{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:var(--r2);
 cursor:pointer;margin:0;color:var(--tx);font-size:13.5px;transition:.12s}
.chk:hover{background:var(--card2)}
.chk input{width:16px;height:16px;accent-color:var(--pri);flex:0 0 auto;cursor:pointer}
.chk span{flex:0 0 auto;white-space:nowrap}
.chk i{color:var(--tx3);font-style:normal;font-size:11.5px;line-height:1.45;flex:1;min-width:0}
.chk em{color:var(--warn);font-style:normal;font-size:11px;margin-left:7px}
.chkbox{background:#0a0c10;border:1px solid var(--line2);border-radius:var(--r2);
 padding:5px;max-height:220px;overflow:auto}
.ftabs{display:flex;gap:2px;margin:16px 0 4px;border-bottom:1px solid var(--line);
 overflow-x:auto;scrollbar-width:none}
.ftabs::-webkit-scrollbar{display:none}
.ftab{padding:8px 13px;cursor:pointer;color:var(--tx2);font-size:13px;font-weight:500;
 white-space:nowrap;border-bottom:2px solid transparent;margin-bottom:-1px;transition:.15s;
 user-select:none;display:flex;align-items:center;gap:5px}
.ftab:hover{color:var(--tx)}
.ftab.active{color:var(--pri);border-bottom-color:var(--pri)}
.ftab b{font-size:10px;font-weight:600;background:var(--card2);color:var(--tx3);
 padding:1px 5px;border-radius:9px}
.ftab.active b{background:rgba(59,130,246,.16);color:var(--pri)}
.fpane[hidden]{display:none}
.fpane>label:first-child{margin-top:6px}
.segs{display:flex;gap:4px;background:var(--bg2);padding:4px;border-radius:var(--r2);margin-top:5px}
.seg{flex:1;text-align:center;padding:8px 10px;border-radius:7px;cursor:pointer;
 font-size:13.5px;font-weight:500;color:var(--tx2);transition:.15s;user-select:none}
.seg:hover{color:var(--tx)}
.seg.active{background:var(--card2);color:#fff;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.seg.dis{opacity:.4;cursor:not-allowed}
details{border:1px solid var(--line);border-radius:var(--r2);margin-top:14px;
 background:var(--bg2);overflow:hidden}
details[open]{border-color:var(--line2)}
summary{padding:10px 13px;cursor:pointer;font-size:13px;color:var(--tx2);
 font-weight:500;user-select:none;list-style:none;transition:.12s}
summary:hover{color:var(--tx);background:var(--card2)}
summary::-webkit-details-marker{display:none}
summary::before{content:"\25B8";display:inline-block;margin-right:8px;transition:.2s;color:var(--tx3)}
details[open] summary::before{transform:rotate(90deg)}
.dbody{padding:2px 13px 14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(3px);
 display:none;align-items:center;justify-content:center;padding:20px;z-index:99}
.modal.show{display:flex;animation:fade .18s ease}
@keyframes fade{from{opacity:0}to{opacity:1}}
.mbox{background:var(--card);border:1px solid var(--line2);border-radius:16px;
 padding:22px 24px;max-width:560px;width:100%;max-height:88vh;overflow:auto;box-shadow:var(--sh);
 animation:pop .2s cubic-bezier(.2,.9,.3,1.2)}
@keyframes pop{from{transform:translateY(12px) scale(.98);opacity:0}}
.mbox h2{font-size:16.5px;font-weight:650;margin-bottom:4px}
.toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%);
 background:var(--card2);border:1px solid var(--line2);padding:11px 20px;
 border-radius:11px;display:none;z-index:100;max-width:90%;font-size:13.5px;box-shadow:var(--sh)}
.toast.show{display:block;animation:up .22s cubic-bezier(.2,.9,.3,1.2)}
@keyframes up{from{transform:translate(-50%,14px);opacity:0}}
.toast.err{border-color:rgba(248,113,113,.4);color:#ffb4b4}
.toast.ok{border-color:rgba(52,211,153,.4);color:#8ff0c4}
.alert{background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.28);
 color:#f5d78e;border-radius:var(--r2);padding:11px 13px;font-size:12.5px;
 margin-bottom:10px;line-height:1.7}
.cmd{background:#0a0c10;border:1px solid var(--line);border-radius:7px;padding:8px 10px;
 margin-top:8px;font:11px/1.5 ui-monospace,Menlo,monospace;color:#8fd0ff;
 word-break:break-all;user-select:all}
.empty{text-align:center;color:var(--tx3);padding:44px 20px;font-size:13.5px}
pre{background:#0a0c10;padding:12px;border-radius:var(--r2);overflow:auto;
 font:11.5px/1.6 ui-monospace,Menlo,monospace;max-height:420px;color:var(--tx2)}
.scanning{color:var(--tx2);font-size:13px;padding:12px}
.scanlist{margin-top:8px;border:1px solid var(--line);border-radius:var(--r2);
 overflow:auto;max-height:280px}
.scanrow{display:flex;justify-content:space-between;align-items:center;gap:10px;
 padding:9px 12px;font-size:13px;border-bottom:1px solid var(--line);transition:.12s}
.scanrow:last-child{border:0}
.scanrow b{font-weight:500;font-size:12px}
.sok{cursor:pointer}.sok b{color:var(--ok)}
.sok:hover{background:rgba(52,211,153,.08)}
.sbad{opacity:.42}.sbad b{color:var(--tx2)}
.vtag{font-size:10px;padding:1.5px 7px;border-radius:10px;margin-left:6px}
.vtag.pre{background:rgba(251,191,36,.14);color:var(--warn)}
.vtag.rel{background:rgba(52,211,153,.14);color:var(--ok)}
.vcur{background:rgba(52,211,153,.07)}
.spin{display:inline-block;width:12px;height:12px;border:2px solid var(--line2);
 border-top-color:var(--pri);border-radius:50%;animation:sp .7s linear infinite;
 vertical-align:-1px;margin-right:7px}
@keyframes sp{to{transform:rotate(360deg)}}
.login{max-width:350px;margin:16vh auto}
.login .card{padding:24px}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:#3a4356}
</style></head><body>
<div id="login" class="wrap login" style="display:none">
  <div class="card"><h3>sing-box 面板</h3>
    <label>用户名</label><input type="text" id="usr" autocomplete="username"
      onkeydown="if(event.key==='Enter')document.getElementById('pw').focus()">
    <label>密码</label><input type="password" id="pw" autocomplete="current-password"
      onkeydown="if(event.key==='Enter')doLogin()">
    <div class="acts"><button onclick="doLogin()">登录</button></div>
  </div>
</div>
<div id="app" style="display:none"><div class="wrap">
<header><h1>sing-box 面板</h1>
  <div class="stat" id="stat"></div>
  <div style="display:flex;gap:8px">
    <button class="btn2" onclick="restart()">重启</button>
    <button class="btn2" onclick="logout()">退出</button>
  </div>
</header>
<div class="tabs">
  <div class="tab active" data-t="in" onclick="tab('in')">节点</div>
  <div class="tab" data-t="out" onclick="tab('out')">出站</div>
  <div class="tab" data-t="cert" onclick="tab('cert')">证书</div>
  <div class="tab" data-t="sub" onclick="tab('sub')">订阅</div>
  <div class="tab" data-t="ver" onclick="tab('ver')">版本</div>
  <div class="tab" data-t="log" onclick="tab('log')">日志</div>
</div>
<div id="v-in"><div class="acts" style="margin-bottom:14px"><button onclick="newNode()">+ 添加节点</button></div><div id="inlist" class="grid"></div></div>
<div id="v-out" style="display:none"><div class="acts" style="margin-bottom:14px"><button onclick="newOut()">+ 添加出站</button>
 <button class="btn2" onclick="speedAll()">⚡ 全部测延迟</button></div><div id="outlist" class="grid"></div></div>
<div id="v-cert" style="display:none"><div class="acts" style="margin-bottom:14px"><button onclick="newCert()">+ 申请证书</button></div><div id="certlist" class="grid"></div></div>
<div id="v-sub" style="display:none"><div class="card"><h3>订阅链接</h3>
 <div class="uri" id="suburl" onclick="cp(this.textContent)"></div>
 <div id="subinfo" style="margin-top:12px"></div></div></div>
<div id="v-ver" style="display:none"><div id="verbox"></div></div>
<div id="v-log" style="display:none"><div class="card">
 <div class="segs" style="margin-bottom:12px">
  <div class="seg active" data-l="sing-box" onclick="pickLog('sing-box')">sing-box 日志</div>
  <div class="seg" data-l="xray" onclick="pickLog('xray')">Xray 日志</div>
 </div>
 <div class="acts" style="margin-bottom:10px"><button class="btn2" onclick="loadLog()">刷新</button></div>
 <pre id="logbox"></pre></div></div>
</div></div>
<div class="modal" id="modal"><div class="mbox" id="mbox"></div></div>
<div class="toast" id="toast"></div>
<script>
const BASE='__BASE__';
let TK=localStorage.getItem('tk')||'',PROTOS={},CERTS=[],OUTS=[],ST={},LOGCORE='sing-box';
function msg(t,ok){const e=document.getElementById('toast');e.textContent=t;e.className='toast show '+(ok?'ok':'err');setTimeout(()=>e.className='toast',3500)}
async function api(p,m,b){const r=await fetch(BASE+'/api'+p,{method:m||'GET',headers:{'Content-Type':'application/json','X-Token':TK},body:b?JSON.stringify(b):null});
 if(r.status===401){TK='';localStorage.removeItem('tk');show(0);throw new Error('未登录')}return r.json()}
function show(in_){document.getElementById('login').style.display=in_?'none':'block';document.getElementById('app').style.display=in_?'block':'none';if(in_)refresh()}
async function doLogin(){const pw=document.getElementById('pw').value;
 const us=document.getElementById('usr').value;
 const r=await(await fetch(BASE+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:us,password:pw})})).json();
 if(r.ok){TK=r.token;localStorage.setItem('tk',TK);show(1)}else msg('密码错误')}
function logout(){TK='';localStorage.removeItem('tk');show(0)}
function tab(t){document.querySelectorAll('.tab').forEach(e=>e.classList.toggle('active',e.dataset.t===t));
 ['in','out','cert','sub','ver','log'].forEach(x=>document.getElementById('v-'+x).style.display=x===t?'block':'none');
 if(t==='cert')loadCerts();if(t==='sub')loadSub();if(t==='ver')loadVer();if(t==='log')loadLog()}
function closeM(){document.getElementById('modal').classList.remove('show')}
function cp(t){navigator.clipboard.writeText(t).then(()=>msg('已复制',1))}
async function refresh(){const s=await api('/status');
 ST=s;
 const xr=s.xray_installed?`<span><span class="dot ${s.xray_running?'on':'off'}"></span>Xray <b>${s.xray_version||'?'}</b> · ${s.xray_nodes} 节点</span>`:'';
 document.getElementById('stat').innerHTML=`<span><span class="dot ${s.running?'on':'off'}"></span>sing-box <b>${s.version}</b> · ${s.sb_nodes} 节点</span>${xr}<span>IP <b>${s.ip}</b></span><span>出站 <b>${s.outbounds}</b></span>`;
 PROTOS=await api('/protocols');loadIn();loadOut()}
async function loadIn(){const l=await api('/inbounds');OUTS=await api('/outbounds');
 document.getElementById('inlist').innerHTML=l.length?l.map(n=>`<div class="card"><h3>${esc(n.name)}<span class="badge">${n.type}</span><span class="badge ${n.core==='xray'?'bx':'bs'}">${n.core==='xray'?'Xray':'sing-box'}</span></h3>
  <div class="row"><span>标签</span><span>${n.tag}</span></div>
  <div class="row"><span>端口</span><span>${n.port}</span></div>
  <div class="row"><span>出站</span><span>${n.bind==='direct'?'直连':esc(n.bind)}</span></div>
  ${n.uri?`<div class="uri" onclick="cp(this.textContent)">${esc(n.uri)}</div>`:''}
  <div class="acts"><button class="btn2" onclick="editNode('${encodeURIComponent(n.tag)}')">编辑</button>
  <button class="btn2" onclick="bindDlg('${encodeURIComponent(n.tag)}','${encodeURIComponent(n.bind)}')">绑定出站</button>
  <button class="btnd" onclick="delIn('${encodeURIComponent(n.tag)}')">删除</button></div></div>`).join(''):'<div class="empty">还没有节点，点上方添加</div>'}
async function loadOut(){OUTS=await api('/outbounds');
 document.getElementById('outlist').innerHTML=OUTS.length?OUTS.map(o=>`<div class="card"><h3>${esc(o.tag)}<span class="badge">${o.type}</span></h3>
  <div class="row"><span>地址</span><span>${o.server}</span></div>
  <div class="row"><span>端口</span><span>${o.port}</span></div>
  <div class="row"><span>协议</span><span>${o.type==='http'?(o.tls?'HTTPS':'HTTP'):'SOCKS5'}${o.auth?' · 已认证':' · 无认证'}</span></div>
  <div class="row"><span>状态</span><span id="t-${esc(o.tag)}">-</span></div>
  <div class="row"><span>延迟</span><span id="sp-${esc(o.tag)}">-</span></div>
  <div class="acts"><button class="btn2" onclick="testOut('${encodeURIComponent(o.tag)}')">测试</button>
  <button class="btn2" onclick="speedOut('${encodeURIComponent(o.tag)}')">⚡ 测延迟</button>
  <button class="btn2" onclick="editOut('${encodeURIComponent(o.tag)}')">编辑</button>
  <button class="btnd" onclick="delOut('${encodeURIComponent(o.tag)}')">删除</button></div></div>`).join(''):'<div class="empty">暂无出站，节点走本机直连</div>'}
async function loadCerts(){const r=await api('/certs');CERTS=r.certs||[];
 const cur=r.panel_tls||'';
 let head=`<div class="card" style="grid-column:1/-1"><h3>面板访问方式</h3>
   <div class="row"><span>当前</span><span>${cur?`<b style="color:#3ddc84">https://${esc(cur)}:${r.panel_port}</b>`:`http://127.0.0.1:${r.panel_port} <i style="color:#6b7280;font-style:normal">(仅本机，需 SSH 隧道)</i>`}</span></div>
   <div class="acts"><button class="btn2" onclick="pathDlg()">更换访问路径</button>
   ${cur?`<button class="btnd" onclick="setPanelTls('')">关闭 HTTPS，改回仅本机</button>`:''}</div>
   ${cur?'':`<p style="color:#8b93a1;font-size:12px;margin-top:8px">下方证书点「用于面板」即可用域名 HTTPS 访问</p>`}</div>`;
 document.getElementById('certlist').innerHTML=head+(CERTS.length?CERTS.map(c=>`<div class="card">
   <h3>${c.domain}${cur===c.domain?'<span class="badge" style="background:#1e3a2a;color:#8ff0b5">面板使用中</span>':''}</h3>
   <div class="row"><span>到期</span><span>${c.expire}</span></div>
   ${cur!==c.domain?`<div class="acts"><button class="btn2" onclick="setPanelTls('${c.domain}')">用于面板 HTTPS</button></div>`:''}
   </div>`).join(''):'<div class="empty">暂无证书，点上方申请</div>')}
function pathDlg(){document.getElementById('mbox').innerHTML=`<h2>更换面板访问路径</h2>
 <p style="color:#8b93a1;font-size:13px;margin-bottom:8px">路径可防止面板被扫描器发现。更换后旧地址立即 404</p>
 <label>路径（留空=取消路径，4-64 位字母/数字/-/_）</label>
 <input id="pp-v" placeholder="留空则取消">
 <div class="acts"><button onclick="savePath(0)">保存</button>
 <button class="btn2" onclick="savePath(1)">随机生成</button>
 <button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show')}
async function savePath(rand){
 const r=await api('/panel-path','POST',{path:rand?'':document.getElementById('pp-v').value,random:!!rand});
 if(!r.ok)return msg(r.msg);
 document.getElementById('mbox').innerHTML=`<h2>路径已更换</h2>
  <p style="color:#8b93a1;font-size:13px;margin:8px 0">请用新地址访问（当前页面已失效）：</p>
  <div class="uri" onclick="cp(this.textContent)">${esc(r.url)}</div>
  <div class="acts"><button onclick="location.href='${r.url}'">前往新地址</button></div>`}
async function setPanelTls(d){
 if(d&&!confirm(`将面板改为 https://${d}:端口 访问？\n\n注意：面板会监听公网，建议用防火墙限制来源 IP。`))return;
 if(!d&&!confirm('关闭 HTTPS？面板将只监听 127.0.0.1，需要 SSH 隧道才能访问。'))return;
 const r=await api('/panel-tls','POST',{domain:d});
 if(r.ok){document.getElementById('mbox').innerHTML=`<h2>面板正在重启</h2>
   <p style="color:#8b93a1;font-size:13px;margin:10px 0">请用新地址访问（含路径，点击可复制）：</p>
   <div class="uri" onclick="cp(this.textContent)">${esc(r.url)}</div>
   ${r.hint?`<p style="color:#f0c674;font-size:12px">${esc(r.hint.trim())}</p>`:''}
   <p style="color:#8b93a1;font-size:13px;margin:14px 0 6px">订阅链接同步更新为：</p>
   <div class="uri" onclick="cp(this.textContent)">${esc(r.suburl||'')}</div>
   <p style="color:#f0c674;font-size:12px;margin-top:6px">⚠ 客户端里的订阅地址需要改成新的</p>
   <div class="acts">${d?`<button onclick="location.href='${r.url}'">前往新地址</button>`:''}
   <button class="btn2" onclick="closeM()">关闭</button></div>`;
  document.getElementById('modal').classList.add('show')}else msg(r.msg)}
async function loadSub(){let r;
 try{r=await api('/sub')}catch(e){
   document.getElementById('subinfo').innerHTML=`<div class="alert">加载失败: ${esc(e.message||e)}</div>`;return}
 if(!r||!r.url){document.getElementById('subinfo').innerHTML=
   `<div class="alert">接口异常${r&&r.msg?': '+esc(r.msg):''}<div class="cmd">journalctl -u singbox-panel -n 30 --no-pager</div></div>`;return}
 document.getElementById('suburl').textContent=r.url;
 let h='';
 if(r.legacy)h+=`<div class="alert">⚠ 订阅服务仍在用旧版(http.server)，会导致订阅为空或被下载。<br>
   在服务器执行下面命令切换到新版：<div class="cmd">sed -i 's|ExecStart=.*|ExecStart=/usr/bin/python3 /etc/sing-box/panel.py --sub|;/WorkingDirectory/d' /etc/systemd/system/singbox-sub.service \&\& systemctl daemon-reload \&\& systemctl restart singbox-sub</div></div>`;
 if(!r.running)h+=`<div class="alert">⚠ 订阅端口未监听，可能被其他程序占用：
   <div class="cmd">ss -ltnp | grep :端口号  →  确认后 systemctl restart singbox-panel</div></div>`;
 h+=`<div class="row"><span>节点数</span><span><b>${r.count}</b></span></div>`;
 h+=`<div class="row"><span>地址类型</span><span>${r.domain?`<b style="color:#3ddc84">域名 HTTPS</b>`:'IP + HTTP <i style="color:#6b7280;font-style:normal;font-size:12px">（证书页启用 HTTPS 后自动改用域名）</i>'}</span></div>`;
 if(r.count)h+=`<div class="row"><span>包含</span><span>${r.names.map(esc).join('、')}</span></div>`;
 else h+=`<div class="alert">订阅内没有节点。请先到「节点」页创建节点。</div>`;
 h+=`<div class="acts"><button class="btn2" onclick="window.open(document.getElementById('suburl').textContent+'?plain=1')">查看明文内容</button>
   <button class="btn2" onclick="subTokenDlg()">更换订阅地址</button></div>`;
 h+=`<p style="color:#8b93a1;font-size:12px;margin-top:10px">点击链接可复制 · token 即密码，勿外泄</p>`;
 document.getElementById('subinfo').innerHTML=h}
async function xrayCard(){
 const r=await api('/xray-versions').catch(()=>null);
 if(!r)return '';
 if(!r.installed){
  return `<div class="card"><h3>Xray-core <span class="badge bx">未安装</span></h3>
   <p style="color:#8b93a1;font-size:12.5px;line-height:1.7">
   装上之后创建节点可以选择由 Xray 运行。它独有 <b>XHTTP</b>(过 CDN 最好) 和 <b>mKCP</b>(抗丢包)
   两种传输层，而 Hysteria2 / TUIC / AnyTLS 这类只有 sing-box 有。<br>
   两个核心各跑各的服务、各自一份配置，互不影响；没有 Xray 节点时服务不会启动，不占内存。</p>
   <div class="acts"><button onclick="xInstall('')">安装最新版 ${r.latest?esc(r.latest):''}</button></div></div>`}
 const rows=(r.list||[]).map(v=>{const isCur=v.ver===r.current;
   return `<div class="scanrow${isCur?' vcur':''}">
    <span>${v.ver} ${v.pre?'<span class="vtag pre">预发布</span>':'<span class="vtag rel">正式版</span>'}
    <i style="color:#6b7280;font-style:normal;font-size:12px">${v.date}</i></span>
    ${isCur?'<b style="color:#3ddc84">使用中</b>'
           :`<button class="btn2" style="padding:4px 12px;font-size:12px" onclick="xInstall('${v.ver}')">切换</button>`}
   </div>`}).join('');
 const up=r.has_update?`<div class="alert" style="background:#16241c;border-color:#2d7f4f;color:#8ff0b5">
   Xray 有新版本 <b>${esc(r.latest)}</b>（当前 ${esc(r.current)}）
   <div class="acts"><button onclick="xInstall('${r.latest}')">升级</button></div></div>`:'';
 return `<div class="card"><h3>Xray-core <span class="badge bx">${esc(r.current||'?')}</span></h3>
  ${up}
  <div class="row"><span>节点数</span><span><b>${r.nodes}</b></span></div>
  <div class="scanlist" style="margin-top:10px">${rows}</div>
  <div class="acts"><button class="btn2" onclick="doRestart('xray')">重启 Xray</button>
  ${r.nodes?'':'<button class="btnd" onclick="xUninstall()">卸载 Xray</button>'}</div></div>`}

async function xInstall(v){
 if(!confirm(v?('切换 Xray 到 '+v+'？'):'安装最新版 Xray-core？'))return;
 const r=await api('/xray-install','POST',{version:v});
 if(!r.ok)return msg(r.msg);
 msg('正在安装，请稍候…',1);
 const t=setInterval(async()=>{
  let j;try{j=await api('/xray-job')}catch(e){return}
  if(j.running){msg((j.step||'处理中')+'…',1);return}
  clearInterval(t);
  if(j.ok===false)alert('失败：'+j.msg);else msg('Xray 已就绪 '+(j.msg||''),1);
  loadVer();refresh()},1500)}

async function xUninstall(){if(!confirm('卸载 Xray-core？（需先删光 Xray 节点）'))return;
 const r=await api('/xray-uninstall','POST',{});
 msg(r.msg,r.ok?1:0);if(r.ok){loadVer();refresh()}}

async function doRestart(core){const r=await api('/restart','POST',{core:core||'all'});
 msg(r.ok?'已重启':(r.msg||'重启失败'),r.ok?1:0);setTimeout(refresh,1200)}

async function loadVer(){const box=document.getElementById('verbox');
 box.innerHTML='<div class="card"><div class="scanning">检查更新中…</div></div>';
 const r=await api('/versions');
 const cur=r.current||'未知',pin=r.pinned||'';
 let banner='';
 if(r.has_update){banner=`<div class="alert" style="background:#16241c;border-color:#2d7f4f;color:#8ff0b5">
   🎉 有新版本 <b>${esc(r.latest)}</b> 可用（当前 ${esc(cur)}）
   ${r.note?`<div style="color:#8b93a1;font-size:12px;margin-top:6px;white-space:pre-wrap;max-height:80px;overflow:auto">${esc(r.note)}</div>`:''}
   <div class="acts"><button onclick="doInstall('${r.latest}')">立即升级</button></div></div>`}
 else if(r.latest){banner=`<div class="alert" style="background:#1a1d23;border-color:#2c313a;color:#8b93a1">✓ 已是最新版本 ${esc(cur)}</div>`}
 const rows=(r.list||[]).map(v=>{
   const isCur=v.ver===cur;
   const tag=v.pre?'<span class="vtag pre">预发布</span>':'<span class="vtag rel">正式版</span>';
   return `<div class="scanrow${isCur?' vcur':''}">
     <span>${v.ver} ${tag} <i style="color:#6b7280;font-style:normal;font-size:12px">${v.date}</i></span>
     ${isCur?'<b style="color:#3ddc84">使用中</b>'
            :`<button class="btn2" style="padding:4px 12px;font-size:12px" onclick="doInstall('${v.ver}')">切换</button>`}
   </div>`}).join('');
 const xh=await xrayCard();
 const dk=await api('/disk').catch(()=>null);
 let disk='';
 if(dk){const root=dk['/']||{},t=dk['/tmp']||{};
  const low=(root.avail||999)<150;
  disk=`<div class="card"><h3>磁盘 ${low?'<span class="badge" style="background:#3a1f22;color:#ff8080">空间不足</span>':''}</h3>
   <div class="row"><span>根分区 /</span><span>可用 <b>${root.avail||'?'}MB</b> / ${root.total||'?'}MB</span></div>
   <div class="row"><span>/tmp</span><span>可用 ${t.avail||'?'}MB / ${t.total||'?'}MB ${dk.tmp_is_ram?'<i style="color:#f0c674;font-style:normal;font-size:12px">内存盘</i>':''}</span></div>
   <div class="acts"><button class="btn2" onclick="doClean(0)">清理残留</button>
   <button class="btn2" onclick="doClean(1)">深度清理 (含apt/日志)</button></div>
   <p style="color:#8b93a1;font-size:12px;margin-top:8px">升级需要约 100MB。后台每 12 小时自动清理一次残留</p></div>`}
 box.innerHTML=banner+xh+disk+`<div class="card"><h3>当前版本</h3>
   <div class="row"><span>版本</span><span><b>${esc(cur)}</b></span></div>
   <div class="row"><span>锁定</span><span>${pin?`<b style="color:#f0c674">${esc(pin)}</b>`:'未锁定'}</span></div>
   <div class="acts">
     <button class="btn2" onclick="loadVer()">🔄 检查更新</button>
     <button class="btn2" onclick="doPin(${pin?'false':'true'})">${pin?'解除锁定':'锁定当前版本'}</button>
     <button class="btn2" onclick="manualVer()">安装其他版本</button>
   </div>
   <p style="color:#8b93a1;font-size:12px;margin-top:8px">锁定后切换版本会二次确认，防止误升级</p></div>
  <div class="card"><h3>自动更新 ${r.auto&&r.auto.enabled?'<span class="badge" style="background:#1e3a2a;color:#8ff0b5">已开启</span>':'<span class="badge">已关闭</span>'}</h3>
   <label class="chk" style="margin:6px 0"><input type="checkbox" id="au-on" ${r.auto&&r.auto.enabled?'checked':''}>
     <span>发现新版本时自动升级 <i>失败会自动回滚</i></span></label>
   <label>更新通道</label>
   <select id="au-ch">
     <option value="stable" ${(!r.auto||r.auto.channel==='stable')?'selected':''}>仅正式版（推荐，稳定）</option>
     <option value="all" ${r.auto&&r.auto.channel==='all'?'selected':''}>含预发布 beta/alpha（尝鲜，有风险）</option>
   </select>
   <label>检查间隔（小时）</label>
   <input id="au-iv" type="number" min="1" value="${(r.auto&&r.auto.interval_hours)||12}">
   <div class="acts"><button onclick="saveAuto()">保存</button></div>
   ${pin?`<p style="color:#f0c674;font-size:12px;margin-top:8px">⚠ 当前已锁定版本，自动更新不会执行</p>`:''}
   ${(r.auto_log&&r.auto_log.length)?`<p style="color:#8b93a1;font-size:12px;margin-top:10px">最近记录：</p>
     <div style="font-size:12px;color:#6b7280;line-height:1.8">${r.auto_log.slice().reverse().map(x=>`${x.t} · ${esc(x.msg)}`).join('<br>')}</div>`:''}
  </div>
  <div class="card"><h3>最近版本 <span class="badge">最新 ${(r.list||[]).length} 个</span></h3>
   <div class="scanlist">${rows||'<div class="empty">获取失败，检查服务器能否访问 GitHub</div>'}</div>
   <p style="color:#8b93a1;font-size:12px;margin-top:8px">需要更早的版本请用「安装其他版本」手动输入</p></div>`}
async function doInstall(v){const r0=await api('/versions');
 if(r0.pinned&&r0.pinned!==v&&!confirm(`当前锁定在 ${r0.pinned}，确定切换到 ${v}？`))return;
 if(!confirm(`切换到 sing-box ${v}？\n\n会自动备份当前版本，若新版本无法加载配置将自动回滚。`))return;
 const r=await api('/install-version','POST',{version:v});
 if(!r.ok){alert(r.msg);return}
 document.getElementById('mbox').innerHTML=`<h2>切换到 ${esc(v)}</h2>
  <div id="vstat" class="alert" style="background:#1a1d23;border-color:#2c313a;color:#8b93a1">
    <span class="spin"></span> 准备中…</div>
  <div class="acts"><button class="btn2" onclick="closeM()">后台运行，关闭窗口</button></div>`;
 document.getElementById('modal').classList.add('show');
 pollVer()}
async function pollVer(){
 for(let i=0;i<120;i++){
   await new Promise(r=>setTimeout(r,2000));
   let s;try{s=await api('/version-status')}catch(e){return}
   const box=document.getElementById('vstat');if(!box)return;
   if(s.running){box.innerHTML=`<span class="spin"></span> ${esc(s.step||'处理中')}… (${(i+1)*2}s)`;continue}
   if(s.ok===true){box.style.cssText='background:#16241c;border-color:#2d7f4f;color:#8ff0b5';
     box.textContent='✓ '+s.msg;loadVer();refresh();setTimeout(closeM,1500);return}
   if(s.ok===false){box.style.cssText='';
     box.innerHTML='✗ '+esc(s.msg).replace(/\n/g,'<br>');return}
 }
 const box=document.getElementById('vstat');if(box)box.textContent='超时，请查看日志';}
function manualVer(){document.getElementById('mbox').innerHTML=`<h2>手动指定版本</h2>
 <label>版本号（不带 v 前缀）</label><input id="mv" placeholder="1.14.0-beta.7">
 <div class="acts"><button onclick="(async()=>{const v=document.getElementById('mv').value.trim();if(!v)return;closeM();doInstall(v)})()">安装</button>
 <button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show')}
async function saveAuto(){
 const en=document.getElementById('au-on').checked;
 const ch=document.getElementById('au-ch').value;
 const iv=parseInt(document.getElementById('au-iv').value)||12;
 if(en&&ch==='all'&&!confirm('含预发布通道会自动升到 beta/alpha 版本。\n\n预发布版可能引入不兼容变更，确定开启？'))return;
 const r=await api('/auto-update','POST',{enabled:en,channel:ch,interval_hours:iv});
 msg(r.msg,1);loadVer()}
async function doClean(deep){
 if(deep&&!confirm('深度清理会清空 apt 缓存并压缩系统日志，确定？'))return;
 msg('清理中…',1);
 const r=await api('/cleanup','POST',{deep:!!deep});
 msg(r.msg,1);loadVer()}
async function doPin(p){const r=await api('/pin-version','POST',{pin:p});msg(r.msg,1);loadVer()}
function subTokenDlg(){document.getElementById('mbox').innerHTML=`<h2>更换订阅地址</h2>
 <p style="color:#f0c674;font-size:13px;margin-bottom:8px">⚠ 更换后旧地址立即失效，所有客户端都要改成新地址</p>
 <label>自定义 token（留空则随机生成）</label>
 <input id="st-tok" placeholder="8-64 位字母/数字/-/_">
 <div class="acts"><button onclick="saveSubToken()">更换</button>
 <button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show')}
async function saveSubToken(){
 const r=await api('/sub-token','POST',{token:document.getElementById('st-tok').value});
 if(!r.ok)return msg(r.msg);
 document.getElementById('mbox').innerHTML=`<h2>订阅地址已更换</h2>
  <div class="uri" onclick="cp(this.textContent)">${esc(r.url)}</div>
  <p style="color:#f0c674;font-size:12px;margin-top:8px">旧地址已失效，请更新所有客户端</p>
  <div class="acts"><button onclick="closeM();loadSub()">完成</button></div>`}
async function loadLog(){const r=await api('/logs?core='+LOGCORE);
 document.getElementById('logbox').textContent=r.log||'（无日志）'}
function pickLog(c){LOGCORE=c;
 document.querySelectorAll('#v-log .seg').forEach(e=>e.classList.toggle('active',e.dataset.l===c));
 loadLog()}
function esc(s){return String(s).replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]))}
async function editNode(t0){const t=decodeURIComponent(t0);
 const d=await api('/inbound-detail/'+encodeURIComponent(t));
 if(!d.ok)return msg(d.msg||'读取失败');
 const spec=PROTOS[d.proto];
 if(!spec)return msg('未知协议');
 document.getElementById('mbox').innerHTML=`<h2>编辑节点 · ${esc(d.name)}</h2>
  <p style="color:#8b93a1;font-size:12px;margin-bottom:6px">协议：${esc(spec.label)} · 核心：<b>${d.core==='xray'?'Xray-core':'sing-box'}</b>（均不可更改）· 出站绑定保持不变</p>
  <div id="fields"></div>
  <div class="acts"><button onclick="saveEdit('${encodeURIComponent(t)}','${d.proto}','${d.core}')">保存</button>
  <button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show');
 if(spec.needs_cert&&!CERTS.length){const cr=await api('/certs');CERTS=cr.certs||[]}
 const gv=f=>d.fields[f.k]!==undefined?String(d.fields[f.k]):(f.d||'');
 document.getElementById('fields').innerHTML=buildForm(spec,gv,d.core)}
async function saveEdit(t0,proto,core){const t=decodeURIComponent(t0);
 const fs=collectF(PROTOS[proto],core);
 const r=await api('/inbound-edit/'+encodeURIComponent(t),'POST',{proto:proto,fields:fs});
 if(r.ok){closeM();msg('已保存，客户端需重新拉订阅',1);loadIn();refresh()}else alert(r.msg)}
function newNode(){
 const xok=!!ST.xray_installed;
 document.getElementById('mbox').innerHTML=`<h2>添加节点</h2>
 <label>运行核心 <span class="hint">决定这个节点由哪个程序跑，可用协议随之变化</span></label>
 <div class="segs">
  <div class="seg active" data-c="sing-box" onclick="pickCore('sing-box')">sing-box</div>
  <div class="seg${xok?'':' dis'}" data-c="xray" onclick="${xok?"pickCore('xray')":"msg('请先到「版本」页安装 Xray-core')"}">Xray-core${xok?'':' (未安装)'}</div>
 </div>
 <label>协议</label><select id="proto" onchange="renderF()"></select><div id="fields"></div>
 <div class="acts"><button onclick="saveNode()">创建</button><button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show');pickCore('sing-box')}

// 当前添加表单选中的核心
let NEWCORE='sing-box';
function pickCore(c){NEWCORE=c;
 document.querySelectorAll('.seg').forEach(e=>e.classList.toggle('active',e.dataset.c===c));
 const sel=document.getElementById('proto'),keep=sel.value;
 const list=Object.entries(PROTOS).filter(([k,v])=>(v.cores||['sing-box']).indexOf(c)>=0);
 sel.innerHTML=list.map(([k,v])=>`<option value="${k}">${v.label}</option>`).join('');
 if(list.some(([k])=>k===keep))sel.value=keep;
 renderF()}

// 该协议在当前核心下的高级选项
function advOf(spec,core){return (core==='xray'?spec.adv_xray:spec.adv)||[]}
async function renderF(){const p=document.getElementById('proto').value,spec=PROTOS[p];
 if(!spec)return;
 if(spec.needs_cert&&!CERTS.length){const cr=await api('/certs');CERTS=cr.certs||[]}
 const a=await api('/autofill');
 const gv=f=>f.auto?(a[f.auto]||''):(f.d||'');
 document.getElementById('fields').innerHTML=buildForm(spec,gv,NEWCORE)}

// 单个字段 -> HTML
function fld(f,v){v=v===undefined?'':String(v);
 if(f.t==='note')return `<div class="alert" style="margin-top:12px">${esc(f.l)}</div>`;
 const h=f.h?`<span class="hint">${esc(f.h)}</span>`:'';
 if(f.t==='bool')return `<label class="chk"><input type="checkbox" id="f-${f.k}" ${v==='1'?'checked':''}><span>${esc(f.l)}</span>${f.h?`<i>${esc(f.h)}</i>`:''}</label>`;
 if(f.t==='cert'){const o=CERTS.map(c=>`<option value="${c.domain}" ${c.domain===v?'selected':''}>${c.domain}</option>`).join('');
  return `<label>${esc(f.l)}${h}</label>`+(CERTS.length?`<select id="f-${f.k}">${o}</select>`:`<div class="alert">无可用证书，请先到「证书」页申请</div>`)}
 if(f.t==='select')return `<label>${esc(f.l)}${h}</label><select id="f-${f.k}">${f.opts.map(o=>`<option ${o===v?'selected':''}>${esc(o)}</option>`).join('')}</select>`;
 if(f.t==='dest')return `<label>${esc(f.l)} <a href="javascript:;" onclick="scanDest()">⚡ 扫描可用目标</a></label>
  <input id="f-${f.k}" type="text" value="${esc(v)}"><div id="scanres"></div>`;
 return `<label>${esc(f.l)}${h}</label><input id="f-${f.k}" type="${f.t}" value="${esc(v)}">`}

const GROUPS=['基础配置','协议','传输','安全','嗅探','高级配置'];
// 按分组渲染成标签页（所有字段都留在 DOM 里，切换只改显示）
function buildForm(spec,gv,core){
 const all=(spec.fields||[]).concat(advOf(spec,core||'sing-box'));
 const by={};GROUPS.forEach(g=>by[g]=[]);
 all.forEach(f=>{const g=by[f.g]?f.g:'高级配置';by[g].push(f)});
 const live=GROUPS.filter(g=>by[g].length);
 const tabs=live.map((g,i)=>
  `<div class="ftab${i?'':' active'}" data-g="${g}" onclick="fgo('${g}')">${g}<b>${by[g].length}</b></div>`).join('');
 const panes=live.map((g,i)=>
  `<div class="fpane" data-g="${g}"${i?' hidden':''}>${by[g].map(f=>fld(f,gv(f))).join('')}</div>`).join('');
 return `<div class="ftabs">${tabs}</div>${panes}`}
function fgo(g){
 document.querySelectorAll('.ftab').forEach(e=>e.classList.toggle('active',e.dataset.g===g));
 document.querySelectorAll('.fpane').forEach(e=>e.hidden=(e.dataset.g!==g))}

// 收集表单（含高级选项）
function collectF(spec,core){const fs={};
 (spec.fields||[]).concat(advOf(spec,core||'sing-box')).forEach(f=>{
  if(f.t==='note')return;
  const e=document.getElementById('f-'+f.k);
  if(e)fs[f.k]=(f.t==='bool')?(e.checked?'1':'0'):e.value});
 return fs}
async function scanDest(){const box=document.getElementById('scanres');
 box.innerHTML='<div class="scanning">扫描中，约 8 秒…</div>';
 const r=await api('/scan');
 box.innerHTML=`<div class="scanlist">`+r.map(x=>{
   const cls=x.ok?'sok':'sbad';
   const info=x.ok
     ?`${x.ms}ms · TLS1.3 · H2${x.issuer?' · '+esc(x.issuer):''}`
     :(x.err||'不可用');
   return `<div class="scanrow ${cls}" ${x.ok?`onclick="pickDest('${x.host}')"`:''}>
     <span>${x.host}</span><b>${info}</b></div>`}).join('')+`</div>
   <div style="color:#6b7280;font-size:12px;margin-top:6px">点击绿色条目即可选用（需 TLS1.3 + H2 才合格）</div>`}
function pickDest(h){document.getElementById('f-dest').value=h;
 document.getElementById('scanres').innerHTML='';msg('已选用 '+h,1)}
async function saveNode(){const p=document.getElementById('proto').value;
 const fs=collectF(PROTOS[p],NEWCORE);
 const r=await api('/inbounds','POST',{proto:p,core:NEWCORE,fields:fs});
 if(r.ok){closeM();msg('节点已创建',1);loadIn();refresh()}else msg(r.msg)}
async function delIn(t0){const t=decodeURIComponent(t0);if(!confirm('删除节点 '+t+'?'))return;const r=await api('/inbounds/'+encodeURIComponent(t),'DELETE');
 if(r.ok){msg('已删除',1);loadIn();refresh()}else msg(r.msg)}
function obForm(d){  // d=已有数据(编辑) 或 null(新增)
 d=d||{};
 const k=d.kind||'socks';
 return `<label>类型</label>
 <select id="o-kind" onchange="onKindChange()">
   <option value="socks" ${k==='socks'?'selected':''}>SOCKS（支持 UDP，推荐）</option>
   <option value="http" ${k==='http'?'selected':''}>HTTP / HTTPS（仅 TCP）</option>
 </select>
 <div class="f2">
  <div><label>标签</label><input id="o-tag" value="${esc(d.tag||'')}" placeholder="留空自动生成"></div>
  <div><label>服务器地址</label><input id="o-srv" value="${esc(d.server||'')}" placeholder="1.2.3.4"></div>
 </div>
 <div class="f2">
  <div><label>服务器端口</label><input id="o-port" type="number" value="${esc(d.port||'')}" placeholder="1080"></div>
  <div id="o-verbox"><label>版本</label>
   <select id="o-ver">
    <option value="5" ${String(d.version||'5')==='5'?'selected':''}>5</option>
    <option value="4a" ${d.version==='4a'?'selected':''}>4a</option>
    <option value="4" ${d.version==='4'?'selected':''}>4</option>
   </select></div>
 </div>
 <div class="f2">
  <div><label>用户名</label><input id="o-user" value="${esc(d.username||'')}" placeholder="留空=无认证"></div>
  <div><label>密码</label><input id="o-pass" value="${esc(d.password||'')}"></div>
 </div>
 <div id="o-netbox"><label>网络</label>
  <select id="o-net">
   <option value="" ${!d.network?'selected':''}>TCP/UDP（默认）</option>
   <option value="tcp" ${d.network==='tcp'?'selected':''}>仅 TCP</option>
   <option value="udp" ${d.network==='udp'?'selected':''}>仅 UDP</option>
  </select></div>
 <label class="chk" id="o-tlsrow" style="display:${k==='http'?'flex':'none'};margin:8px 0">
   <input type="checkbox" id="o-tls" ${d.tls?'checked':''}>
   <span>使用 HTTPS 连接落地 <i>落地需支持 TLS</i></span></label>
 <label class="chk" id="o-uotrow" style="display:${k==='http'?'none':'flex'};margin:4px 0">
   <input type="checkbox" id="o-uot" ${d.uot?'checked':''}>
   <span>UDP over TCP <i>仅当落地支持 UoT 时勾选</i></span></label>`}

function onKindChange(){const k=document.getElementById('o-kind').value,g=id=>document.getElementById(id);
 const http=k==='http';
 if(g('o-tlsrow'))g('o-tlsrow').style.display=http?'flex':'none';
 if(g('o-uotrow'))g('o-uotrow').style.display=http?'none':'flex';
 if(g('o-verbox'))g('o-verbox').style.display=http?'none':'block';
 if(g('o-netbox'))g('o-netbox').style.display=http?'none':'block';
 if(g('o-quicrow'))g('o-quicrow').style.display=http?'none':'flex'}

function obPayload(){const g=id=>document.getElementById(id);
 const k=g('o-kind').value;
 return {kind:k, tag:g('o-tag').value.trim(), server:g('o-srv').value.trim(),
   port:g('o-port').value.trim(), username:g('o-user').value.trim(),
   password:g('o-pass').value, version:g('o-ver')?g('o-ver').value:'5',
   network:(k==='socks'&&g('o-net'))?g('o-net').value:'',
   tls:k==='http'&&g('o-tls')?g('o-tls').checked:false,
   uot:g('o-uot')?g('o-uot').checked:false}}

async function newOut(){const nodes=await api('/inbounds');
 const list=nodes.length?nodes.map(n=>`<label class="chk"><input type="checkbox" class="nd" value="${n.tag}">
   <span>${esc(n.name)}</span><span class="badge ${n.core==='xray'?'bx':'bs'}">${n.core==='xray'?'Xray':'sb'}</span>
   <i>${n.type} · ${n.port}</i>${n.bind!=='direct'?`<em>当前: ${esc(n.bind)}</em>`:''}</label>`).join('')
   :'<div style="color:#5a626e;font-size:13px;padding:6px 0">还没有节点</div>';
 document.getElementById('mbox').innerHTML=`<h2>添加出站</h2>${obForm(null)}
 <label style="margin-top:14px">绑定节点 (可多选，选中的节点全部流量走此出站)
   ${nodes.length?'<a href="javascript:;" onclick="allNd(1)">全选</a> / <a href="javascript:;" onclick="allNd(0)">清空</a>':''}</label>
 <div class="chkbox">${list}</div>
 <label class="chk" id="o-quicrow" style="margin:8px 0"><input type="checkbox" id="o-blockquic" checked>
   <span>拒绝 QUIC，强制走 TCP <i>推荐 · 多数落地不支持 UDP</i></span></label>
 <div class="acts"><button onclick="saveOut()">添加</button><button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show');onKindChange()}

function allNd(v){document.querySelectorAll('.nd').forEach(e=>e.checked=!!v)}

async function saveOut(){const binds=[...document.querySelectorAll('.nd:checked')].map(e=>e.value);
 const g=id=>document.getElementById(id);
 const p=obPayload();p.binds=binds;p.block_quic=g('o-blockquic')?g('o-blockquic').checked:true;
 const r=await api('/outbounds','POST',p);
 if(r.ok){closeM();msg('出站已添加'+(binds.length?`，已绑定 ${binds.length} 个节点`:''),1);loadOut();loadIn();refresh()}else msg(r.msg)}

async function speedAll(){const l=await api('/outbounds');
 if(!l.length)return msg('暂无出站');
 msg(`开始测延迟 ${l.length} 个出站…`,1);
 for(const o of l)speedOut(encodeURIComponent(o.tag));}
async function speedOut(t0){const t=decodeURIComponent(t0);
 const box=document.getElementById('sp-'+t);
 if(box)box.innerHTML='<span class="spin"></span> 启动…';
 await api('/speedtest/'+encodeURIComponent(t));
 for(let i=0;i<20;i++){
   await new Promise(r=>setTimeout(r,1500));
   let s;try{s=await api('/speed-status/'+encodeURIComponent(t))}catch(e){return}
   const b=document.getElementById('sp-'+t);if(!b)return;
   if(s.running){b.innerHTML=`<span class="spin"></span> ${esc(s.step||'测试中')}`;continue}
   if(s.ok===true){
     const col=s.latency<=100?'#3ddc84':(s.latency<=250?'#f0c674':'#ff8080');
     b.innerHTML=`<b style="color:${col}">${s.latency}ms</b>`
       +(s.best!==s.latency?` <i style="color:#6b7280;font-style:normal;font-size:12px">最快 ${s.best}ms</i>`:'')
       +(s.total?` <i style="color:#6b7280;font-style:normal;font-size:12px">· 完整往返 ${s.total}ms</i>`:'')
       +(s.loss?` <span style="color:#ff8080;font-size:12px">丢包 ${s.loss}%</span>`:'')
       +(s.ip?` <i style="color:#6b7280;font-style:normal;font-size:12px">${esc(s.ip)}</i>`:'');
     return}
   if(s.ok===false){b.innerHTML=`<span style="color:#ff8080">${esc(s.msg)}</span>`;return}
 }
 const b=document.getElementById('sp-'+t);if(b)b.textContent='超时';}
async function editOut(t0){const t=decodeURIComponent(t0);
 const d=await api('/outbound-detail/'+encodeURIComponent(t));
 if(!d.ok)return msg(d.msg||'读取失败');
 document.getElementById('mbox').innerHTML=`<h2>编辑出站 · ${esc(t)}</h2>
  <p style="color:#8b93a1;font-size:12px;margin-bottom:6px">改名后节点绑定会自动跟随</p>
  ${obForm(d)}
  <div class="acts"><button onclick="saveEditOut('${encodeURIComponent(t)}')">保存</button>
  <button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show');onKindChange()}

async function saveEditOut(t0){const t=decodeURIComponent(t0);
 const r=await api('/outbound-edit/'+encodeURIComponent(t),'POST',obPayload());
 if(r.ok){closeM();msg('已保存',1);loadOut();loadIn()}else msg(r.msg)}

async function delOut(t0){const t=decodeURIComponent(t0);if(!confirm('删除出站 '+t+'?'))return;const r=await api('/outbounds/'+encodeURIComponent(t),'DELETE');
 if(r.ok){msg('已删除',1);loadOut();loadIn()}else msg(r.msg)}
async function testOut(t0){const t=decodeURIComponent(t0);(document.getElementById('t-'+t)||{}).textContent='测试中…';const r=await api('/test/'+encodeURIComponent(t));
 (document.getElementById('t-'+t)||{}).textContent=r.msg}
function bindDlg(tag0,cur0){const tag=decodeURIComponent(tag0),cur=decodeURIComponent(cur0);const o=OUTS.map(x=>`<option value="${x.tag}" ${x.tag===cur?'selected':''}>${x.tag}</option>`).join('');
 document.getElementById('mbox').innerHTML=`<h2>绑定出站</h2><p style="color:#8b93a1;font-size:13px">节点 <b>${tag}</b> 的全部流量将走所选出站</p>
 <label>出站</label><select id="b-out"><option value="direct" ${cur==='direct'?'selected':''}>direct (本机直连)</option>${o}</select>
 <div class="acts"><button onclick="saveBind('${encodeURIComponent(tag)}')">保存</button><button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show')}
async function saveBind(tag0){const tag=decodeURIComponent(tag0);const r=await api('/bind','POST',{inbound:tag,outbound:document.getElementById('b-out').value});
 if(r.ok){closeM();msg('已更新',1);loadIn()}else msg(r.msg)}
function newCert(){document.getElementById('mbox').innerHTML=`<h2>申请证书</h2>
 <p style="color:#8b93a1;font-size:13px">域名需已解析到本机，且 80 端口可用</p>
 <label>域名</label><input id="c-domain" placeholder="example.com">
 <div class="acts"><button onclick="saveCert(this)">申请</button><button class="btn2" onclick="closeM()">取消</button></div>`;
 document.getElementById('modal').classList.add('show')}
async function saveCert(b){const d=document.getElementById('c-domain').value.trim();
 if(!d)return msg('请填域名');
 b.disabled=true;b.textContent='提交中…';
 const r=await api('/certs','POST',{domain:d});
 if(!r.ok){msg(r.msg);b.disabled=false;b.textContent='申请';return}
 document.getElementById('mbox').innerHTML=`<h2>申请证书 · ${esc(d)}</h2>
  <div id="cstat" class="alert" style="background:#1a1d23;border-color:#2c313a;color:#8b93a1">
    <span class="spin"></span> 正在预检…</div>
  <div class="acts"><button class="btn2" onclick="closeM()">后台运行，关闭窗口</button></div>`;
 pollCert()}
async function pollCert(){
 for(let i=0;i<90;i++){
   await new Promise(r=>setTimeout(r,2000));
   let s;try{s=await api('/cert-status')}catch(e){return}
   const box=document.getElementById('cstat');if(!box)return;
   if(s.running){box.innerHTML=`<span class="spin"></span> ${esc(s.step||'处理中')}… (${(i+1)*2}s)`;continue}
   if(s.ok===true){box.className='alert';box.style.cssText='background:#16241c;border-color:#2d7f4f;color:#8ff0b5';
     box.textContent='✓ '+s.msg;CERTS=[];loadCerts();
     setTimeout(closeM,1500);return}
   if(s.ok===false){box.className='alert';box.style.cssText='';
     box.innerHTML='✗ '+esc(s.msg).replace(/\n/g,'<br>');return}
 }
 const box=document.getElementById('cstat');if(box)box.textContent='超时，请查看服务器日志';}
async function restart(){const r=await api('/restart','POST',{core:'all'});
 msg(r.ok?'已重启':'失败',r.ok);refresh()}
// 仅当「按下」和「松开」都在遮罩上才关闭——避免拖选文字时误关
let _mdOnMask=false;
document.getElementById('modal').addEventListener('mousedown',e=>{_mdOnMask=(e.target.id==='modal')});
document.getElementById('modal').addEventListener('click',e=>{
 if(e.target.id==='modal'&&_mdOnMask)closeM();_mdOnMask=false});
(async()=>{if(TK){try{await api('/status');show(1)}catch(e){show(0)}}else show(0)})();
</script></body></html>"""


class PanelHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128      # 默认只有 5，堆积时会直接拒绝连接
    allow_reuse_address = True


class QuietMixin:
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            self.close_connection = True      # 客户端中断/扫描器探测，静默忽略

    def handle_error(self, *a):
        pass


class Handler(QuietMixin, BaseHTTPRequestHandler):
    server_version = "sb-panel"
    protocol_version = "HTTP/1.1"  # 复用连接：一次握手跑完整页所有 API
    disable_nagle_algorithm = True  # 小响应立即发出，省 40ms
    timeout = 30                  # 单个请求最长 30 秒，避免僵死占用线程

    def log_message(self, *a):
        pass

    def _send(self, code, data, ctype="application/json"):
        HEARTBEAT["t"] = time.time()
        self._sent = True
        body = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
        enc = ""
        if len(body) > 1024 and "gzip" in self.headers.get("Accept-Encoding", ""):
            try:
                body, enc = gzip.compress(body, 6), "gzip"
            except Exception:
                enc = ""
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if "json" in ctype or "html" in ctype else ""))
        self.send_header("Content-Length", str(len(body)))
        if enc:
            self.send_header("Content-Encoding", enc)
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("X-Content-Type-Options", "nosniff")
        if "html" in ctype:
            # 面板升级后立刻生效，不让浏览器拿旧界面
            self.send_header("Cache-Control", "no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        tk = self.headers.get("X-Token", "")
        exp = SESSIONS.get(tk)
        now = time.time()
        if exp and exp > now:
            return True
        SESSIONS.pop(tk, None)
        return False

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n)) if n else {}
        except Exception:
            return {}

    def _strip_base(self, p):
        """校验并剥离面板路径前缀；不匹配返回 None"""
        base = load_json(PANEL_CFG, {}).get("path", "") or ""
        if not base:
            return p
        base = "/" + base.strip("/")
        if p == base:
            return "/"
        if p.startswith(base + "/"):
            return p[len(base):]
        return None

    def _guard(self, fn):
        """统一兜底：任何情况下都要回一个响应，否则 keep-alive 连接会挂死"""
        try:
            r = fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                return self._send(500, {"ok": False, "msg": f"服务端错误: {e}"})
            except Exception:
                return
        if r is None and not getattr(self, "_sent", False):
            try:
                return self._send(404, {"ok": False, "msg": "未知接口"})
            except Exception:
                return
        return r

    def do_GET(self):
        return self._guard(self._do_GET)

    def do_POST(self):
        return self._guard(self._do_POST)

    def do_DELETE(self):
        return self._guard(self._do_DELETE)

    def _do_GET(self):
        _u = urllib.parse.urlparse(self.path)
        raw = _u.path
        q = urllib.parse.parse_qs(_u.query)
        if raw == "/__ping":
            return self._send(200, b"pong", "text/plain")
        p = self._strip_base(raw)
        if p is None:
            return self._send(404, b"404 Not Found", "text/plain")
        if p in ("/", "/index.html"):
            base = load_json(PANEL_CFG, {}).get("path", "") or ""
            base = ("/" + base.strip("/")) if base else ""
            return self._send(200, HTML.replace("__BASE__", base).encode(), "text/html")
        if not p.startswith("/api/"):
            return self._send(404, {"ok": False})
        if not self._auth():
            return self._send(401, {"ok": False, "msg": "未登录"})
        # 证书任务状态：不加锁，避免申请期间面板卡死
        if p == "/api/cert-status":
            return self._send(200, dict(CERT_JOB))
        if p == "/api/version-status":
            return self._send(200, dict(VER_JOB))
        if p.startswith("/api/speedtest/"):
            t = urllib.parse.unquote(p[len("/api/speedtest/"):])
            if not SPEED_JOB.get(t, {}).get("running"):
                speedtest_async(t)
            return self._send(200, {"ok": True, "started": True})
        if p.startswith("/api/speed-status/"):
            t = urllib.parse.unquote(p[len("/api/speed-status/"):])
            return self._send(200, dict(SPEED_JOB.get(t, {})))
        if p == "/api/status":
            return self._send(200, api_status())
        # 只读接口不加锁：避免慢命令把整个面板卡死
        if True:
            if p == "/api/protocols":
                return self._send(200, PROTOCOLS)
            if p == "/api/inbounds":
                return self._send(200, api_inbounds())
            if p == "/api/outbounds":
                return self._send(200, api_outbounds())
            if p.startswith("/api/outbound-detail/"):
                t = urllib.parse.unquote(p[len("/api/outbound-detail/"):])
                o = next((x for x in cfg().get("outbounds", []) if x.get("tag") == t), None)
                if not o:
                    return self._send(200, {"ok": False, "msg": "出站不存在"})
                return self._send(200, {"ok": True, "tag": t,
                                        "kind": o.get("type", "socks"),
                                        "server": o.get("server", ""),
                                        "port": o.get("server_port", ""),
                                        "username": o.get("username", ""),
                                        "password": o.get("password", ""),
                                        "version": str(o.get("version", "5")),
                                        "network": o.get("network", ""),
                                        "tls": bool((o.get("tls") or {}).get("enabled")),
                                        "uot": bool(o.get("udp_over_tcp"))})
            if p.startswith("/api/inbound-detail/"):
                t = urllib.parse.unquote(p[len("/api/inbound-detail/"):])
                m0 = meta()
                info = m0.get(t, {})
                core = core_of(t, m0)
                if core == "xray":
                    ib = next((i for i in xcfg().get("inbounds", [])
                               if i.get("tag") == t), None)
                    if not ib:
                        return self._send(200, {"ok": False, "msg": "节点不存在"})
                    proto = info.get("proto") or ""
                    if proto not in PROTOCOLS:
                        return self._send(200, {"ok": False,
                                                "msg": f"暂不支持编辑该类型：{ib.get('protocol')}"})
                    fields = info.get("fields") or xinbound_to_fields(ib, proto, info)
                    return self._send(200, {"ok": True, "tag": t, "proto": proto,
                                            "core": "xray", "fields": fields,
                                            "port": ib.get("port"),
                                            "name": info.get("name", t)})
                ib = next((i for i in cfg().get("inbounds", []) if i.get("tag") == t), None)
                if not ib:
                    return self._send(200, {"ok": False, "msg": "节点不存在"})
                proto = info.get("proto") or guess_proto(ib)
                if proto not in PROTOCOLS:
                    return self._send(200, {"ok": False,
                                            "msg": f"暂不支持编辑该类型：{ib.get('type')}"})
                fields = info.get("fields")
                if not fields:
                    fields = inbound_to_fields(ib, proto, info)   # 旧节点反推
                return self._send(200, {"ok": True, "tag": t, "proto": proto,
                                        "core": "sing-box", "fields": fields,
                                        "port": ib.get("listen_port"),
                                        "name": info.get("name", t)})
            if p == "/api/certs":
                pc = load_json(PANEL_CFG, {})
                return self._send(200, {"certs": list_certs(),
                                        "panel_tls": pc.get("tls_domain", ""),
                                        "panel_port": pc.get("port", 2095),
                                        "panel_host": pc.get("host", "127.0.0.1")})
            if p == "/api/autofill":
                pc = load_json(PANEL_CFG, {})
                # 连接地址优先用面板证书域名，其次公网 IP
                addr = pc.get("tls_domain", "") or public_ip()
                return self._send(200, {"port": rand_port(), "uuid": gen_uuid(),
                                        "pass": secrets.token_urlsafe(12),
                                        "sspass": base64.b64encode(secrets.token_bytes(16)).decode(),
                                        "ip": addr, "rawip": public_ip()})
            if p == "/api/sub":
                tok = rebuild_sub()
                pc = load_json(PANEL_CFG, {})
                m = meta()
                uris = [v["uri"] for v in m.values() if v.get("uri")]
                # 订阅已并入本进程：发一次真实请求判断（比探测端口可靠）
                sp = int(pc.get("sub_port", 8080))
                _sch = "https" if pc.get("tls_domain") else "http"
                _k = "-k " if _sch == "https" else ""
                cc, code, _ = sh(f"curl -s -o /dev/null --max-time 4 {_k}"
                                 f"-w '%{{http_code}}' {_sch}://127.0.0.1:{sp}/{tok}", 8)
                running = code.strip() == "200"
                if not running:   # 回退：看端口是否真的没在监听
                    _, lsn, _ = sh(f"ss -ltn 2>/dev/null | grep -c ':{sp} '")
                    if lsn.strip() not in ("0", ""):
                        running = True   # 端口在听，只是本地请求失败，不算故障
                # 仅当仍存在旧的独立服务文件时才提示迁移
                legacy = os.path.exists("/etc/systemd/system/singbox-sub.service")
                sdom = pc.get("tls_domain", "")
                _sch = "https" if sdom else "http"
                _host = sdom or public_ip()
                return self._send(200, {
                    "url": f"{_sch}://{_host}:{pc.get('sub_port', 8080)}/{tok}",
                    "domain": sdom,
                    "count": len(uris),
                    "names": [v.get("name", k) for k, v in m.items() if v.get("uri")],
                    "running": running,
                    "legacy": legacy,
                })
            if p == "/api/disk":
                return self._send(200, disk_report())
            if p == "/api/logs":
                which = q.get("core", ["sing-box"])[0]
                svc = XR_SVC if which == "xray" else "sing-box"
                _, log, _ = sh(f"journalctl -u {svc} -n 80 --no-pager")
                return self._send(200, {"log": log or f"（{svc} 无日志）"})
            if p.startswith("/api/test/"):
                tag = urllib.parse.unquote(p[len("/api/test/"):])
                return self._send(200, api_test_outbound(tag))
            if p == "/api/scan":
                return self._send(200, scan_dests())
            if p == "/api/xray-versions":
                lst = xr_fetch_versions()
                cur = xr_version()
                latest = lst[0]["ver"] if lst else ""
                return self._send(200, {
                    "installed": xr_installed(), "current": cur, "list": lst,
                    "latest": latest,
                    "has_update": bool(latest and cur and latest != cur),
                    "nodes": len(xcfg().get("inbounds", [])) if xr_installed() else 0})
            if p == "/api/xray-job":
                return self._send(200, XVER_JOB)
            if p == "/api/versions":
                pin = ""
                if os.path.exists(VER_PIN):
                    pin = open(VER_PIN).read().strip()
                au = pc0.get("auto_update") or {} if (pc0 := load_json(PANEL_CFG, {})) else {}
                lst = fetch_versions()
                cur = cur_version()
                latest = lst[0]["ver"] if lst else ""
                stable = next((v["ver"] for v in lst if not v["pre"]), "")
                return self._send(200, {
                    "current": cur, "pinned": pin, "list": lst,
                    "latest": latest, "stable": stable,
                    "has_update": bool(latest and cur and latest != cur),
                    "note": lst[0]["note"] if lst else "",
                    "auto": {"enabled": bool(au.get("enabled")),
                             "channel": au.get("channel", "stable"),
                             "interval_hours": int(au.get("interval_hours", 12))},
                    "auto_log": AUTO_LOG[-5:],
                })
        return self._send(404, {"ok": False})

    def _do_POST(self):
        p = self._strip_base(urllib.parse.urlparse(self.path).path)
        if p is None:
            return self._send(404, {"ok": False})
        b = self._body()
        if p == "/api/login":
            pc = load_json(PANEL_CFG, {})
            h = hashlib.sha256((b.get("password", "") + pc.get("salt", "")).encode()).hexdigest()
            # 旧配置没有 username 字段时不校验用户名，保证升级后仍能登录
            want_user = pc.get("username", "")
            got_user = (b.get("username") or "").strip()
            user_ok = (not want_user) or (got_user == want_user)
            if user_ok and h == pc.get("pwhash"):
                now = time.time()
                # 清理过期会话，防止长期运行内存增长
                for k in [k for k, v in SESSIONS.items() if v <= now]:
                    SESSIONS.pop(k, None)
                if len(SESSIONS) > 50:            # 上限，最旧的先出
                    for k in sorted(SESSIONS, key=SESSIONS.get)[:len(SESSIONS) - 50]:
                        SESSIONS.pop(k, None)
                tk = secrets.token_hex(24)
                SESSIONS[tk] = now + SESSION_TTL
                return self._send(200, {"ok": True, "token": tk})
            time.sleep(1)
            return self._send(200, {"ok": False})
        if not self._auth():
            return self._send(401, {"ok": False, "msg": "未登录"})
        with LOCK:
            if p == "/api/inbounds":
                okk, r = api_add_inbound(b)
                return self._send(200, {"ok": okk, "msg": r if not okk else "", "data": r if okk else None})
            if p == "/api/outbounds":
                okk, r = api_add_outbound(b)
                return self._send(200, {"ok": okk, "msg": r if not okk else ""})
            if p.startswith("/api/outbound-edit/"):
                t = urllib.parse.unquote(p[len("/api/outbound-edit/"):])
                okk, r = api_edit_outbound(t, b)
                return self._send(200, {"ok": okk, "msg": r if not okk else "已保存"})
            if p.startswith("/api/inbound-edit/"):
                t = urllib.parse.unquote(p[len("/api/inbound-edit/"):])
                okk, r = api_edit_inbound(t, b)
                return self._send(200, {"ok": okk, "msg": r if not okk else "已保存"})
            if p == "/api/bind":
                okk, r = api_bind(b.get("inbound"), b.get("outbound"))
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/certs":
                d = (b.get("domain") or "").strip()
                if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", d):
                    return self._send(200, {"ok": False, "msg": "域名格式无效"})
                if CERT_JOB["running"]:
                    return self._send(200, {"ok": False, "msg": "已有证书任务在进行中"})
                issue_cert_async(d)
                return self._send(200, {"ok": True, "async": True})
            if p == "/api/cleanup":
                freed = cleanup_disk(deep=bool(b.get("deep")))
                return self._send(200, {"ok": True,
                                        "msg": ("已清理：" + "、".join(freed)) if freed else "没有可清理的内容",
                                        "disk": disk_report()})
            if p == "/api/restart":
                which = b.get("core") or "sing-box"
                if which == "xray":
                    if not xr_installed():
                        return self._send(200, {"ok": False, "msg": "Xray-core 未安装"})
                    c, _, _ = sh(f"systemctl restart {XR_SVC}")
                    return self._send(200, {"ok": c == 0})
                if which == "all":
                    c, _, _ = sh("systemctl restart sing-box")
                    if xr_installed() and xcfg().get("inbounds"):
                        sh(f"systemctl restart {XR_SVC}")
                    return self._send(200, {"ok": c == 0})
                c, _, _ = sh("systemctl restart sing-box")
                return self._send(200, {"ok": c == 0})
            if p == "/api/xray-install":
                ver = (b.get("version") or "").strip()
                if not ver:
                    lst = xr_fetch_versions(1)
                    if not lst:
                        return self._send(200, {"ok": False, "msg": "拉取版本列表失败"})
                    ver = lst[0]["ver"]
                okk, msg = xr_install_async(ver)
                return self._send(200, {"ok": okk, "msg": msg, "async": True})
            if p == "/api/xray-uninstall":
                if xcfg().get("inbounds"):
                    return self._send(200, {"ok": False,
                                            "msg": "请先删除所有 Xray 节点再卸载"})
                sh(f"systemctl disable --now {XR_SVC} >/dev/null 2>&1")
                sh("rm -f /etc/systemd/system/xray.service; systemctl daemon-reload")
                sh(f"rm -rf {os.path.dirname(XR_BIN)} {XR_ETC}")
                return self._send(200, {"ok": True, "msg": "Xray-core 已卸载"})
            if p == "/api/install-version":
                ver = (b.get("version") or "").strip()
                if VER_JOB["running"]:
                    return self._send(200, {"ok": False, "msg": "已有升级任务进行中"})
                install_version_async(ver)
                return self._send(200, {"ok": True, "async": True})
            if p == "/api/sub-token":
                pc = load_json(PANEL_CFG, {})
                nt = (b.get("token") or "").strip()
                if nt:
                    if not re.match(r"^[A-Za-z0-9_-]{8,64}$", nt):
                        return self._send(200, {"ok": False,
                                                "msg": "token 需为 8-64 位字母/数字/-/_"})
                else:
                    nt = secrets.token_hex(16)
                old = pc.get("sub_token", "")
                pc["sub_token"] = nt
                save_json(PANEL_CFG, pc)
                if old:
                    sh(f"rm -f '{SUB_DIR}/{old}' 2>/dev/null")
                rebuild_sub()
                sp = pc.get("sub_port", 8080)
                dom = pc.get("tls_domain", "")
                url = (f"https://{dom}:{sp}/{nt}" if dom
                       else f"http://{public_ip()}:{sp}/{nt}")
                return self._send(200, {"ok": True, "token": nt, "url": url,
                                        "msg": "订阅地址已更换，旧地址立即失效"})

            if p == "/api/panel-path":
                pc = load_json(PANEL_CFG, {})
                np = (b.get("path") or "").strip().strip("/")
                if np and not re.match(r"^[A-Za-z0-9_-]{4,64}$", np):
                    return self._send(200, {"ok": False,
                                            "msg": "路径需为 4-64 位字母/数字/-/_，或留空取消"})
                if b.get("random"):
                    np = secrets.token_hex(8)
                pc["path"] = np
                save_json(PANEL_CFG, pc)
                port = pc.get("port", 2095)
                dom = pc.get("tls_domain", "")
                host = dom or (public_ip() if pc.get("host") == "0.0.0.0" else pc.get("host", "127.0.0.1"))
                sch = "https" if dom else "http"
                newurl = f"{sch}://{host}:{port}" + (f"/{np}" if np else "")
                return self._send(200, {"ok": True, "path": np, "url": newurl,
                                        "msg": "路径已更换，请用新地址访问"})

            if p == "/api/auto-update":
                pc = load_json(PANEL_CFG, {})
                pc["auto_update"] = {
                    "enabled": bool(b.get("enabled")),
                    "channel": b.get("channel", "stable"),
                    "interval_hours": max(1, int(b.get("interval_hours", 12))),
                }
                save_json(PANEL_CFG, pc)
                st = "已开启" if pc["auto_update"]["enabled"] else "已关闭"
                ch = "仅正式版" if pc["auto_update"]["channel"] == "stable" else "含预发布"
                return self._send(200, {"ok": True,
                                        "msg": f"自动更新{st}（{ch}，每 {pc['auto_update']['interval_hours']} 小时检查）"})
            if p == "/api/pin-version":
                if b.get("pin"):
                    with open(VER_PIN, "w") as fh:
                        fh.write(cur_version())
                    return self._send(200, {"ok": True, "msg": f"已锁定 {cur_version()}"})
                if os.path.exists(VER_PIN):
                    os.remove(VER_PIN)
                return self._send(200, {"ok": True, "msg": "已解除锁定"})
            if p == "/api/panel-tls":
                dom = (b.get("domain") or "").strip()
                pc = load_json(PANEL_CFG, {})
                if dom:
                    if not os.path.exists(f"{CERT_DIR}/{dom}/fullchain.pem"):
                        return self._send(200, {"ok": False, "msg": "该域名没有可用证书"})
                    pc["tls_domain"] = dom
                    pc["host"] = "0.0.0.0"      # 用域名访问必须监听公网
                else:
                    pc.pop("tls_domain", None)
                    pc["host"] = "127.0.0.1"    # 关闭 HTTPS 时收回本机
                save_json(PANEL_CFG, pc)
                port = pc.get("port", 2095)
                pth = pc.get("path", "")
                pth = ("/" + pth.strip("/")) if pth else ""
                url = (f"https://{dom}:{port}{pth}" if dom
                       else f"http://127.0.0.1:{port}{pth}")
                hint = "" if dom else "  (需 SSH 隧道)"
                # 延迟重启（脱离自身 cgroup，否则服务会停摆）
                safe_restart_self(2)
                sp = pc.get("sub_port", 8080)
                suburl = (f"https://{dom}:{sp}/{sub_token()}" if dom
                          else f"http://{public_ip()}:{sp}/{sub_token()}")
                return self._send(200, {"ok": True, "url": url, "hint": hint,
                                        "suburl": suburl,
                                        "msg": "面板将在 2 秒后重启，请用新地址访问"})
        return self._send(404, {"ok": False})

    def _do_DELETE(self):
        if not self._auth():
            return self._send(401, {"ok": False})
        p = self._strip_base(urllib.parse.urlparse(self.path).path)
        if p is None:
            return self._send(404, {"ok": False})
        with LOCK:
            if p.startswith("/api/inbounds/"):
                tag = urllib.parse.unquote(p[len("/api/inbounds/"):])
                okk, m = api_del_inbound(tag)
                return self._send(200, {"ok": okk, "msg": m})
            if p.startswith("/api/outbounds/"):
                tag = urllib.parse.unquote(p[len("/api/outbounds/"):])
                okk, m = api_del_outbound(tag)
                return self._send(200, {"ok": okk, "msg": m})
        return self._send(404, {"ok": False})


class SubHandler(QuietMixin, BaseHTTPRequestHandler):
    """订阅服务：以 text/plain 返回，浏览器内联显示而非下载"""
    server_version = "sb-sub"

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        token = u.path.lstrip("/")
        qs = urllib.parse.parse_qs(u.query)
        real = sub_token()

        if not token or token != real:
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        m = meta()
        uris = [v["uri"] for v in m.values() if v.get("uri")]
        plain = "\n".join(uris)
        # ?plain=1 返回明文，默认 base64（各客户端通用）
        content = plain if qs.get("plain") else base64.b64encode(plain.encode()).decode()
        body = content.encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", "inline")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Profile-Update-Interval", "24")
        self.send_header("Profile-Title",
                         base64.b64encode("sing-box".encode()).decode())
        self.send_header("Subscription-Userinfo",
                         "upload=0; download=0; total=0; expire=0")
        self.end_headers()
        self.wfile.write(body)


def run_sub_server():
    pc = load_json(PANEL_CFG, {})
    port = int(pc.get("sub_port", 8080))
    os.makedirs(SUB_DIR, exist_ok=True)
    print(f"sing-box subscription on http://0.0.0.0:{port}/{sub_token()}")
    ThreadingHTTPServer(("0.0.0.0", port), SubHandler).serve_forever()


def main():
    if "--sub" in sys.argv:
        return run_sub_server()
    pc = load_json(PANEL_CFG, {})
    host = pc.get("host", "127.0.0.1")
    port = int(pc.get("port", 2095))
    if not pc.get("pwhash"):
        print("未初始化，请先运行部署脚本的「Web 面板」菜单设置密码", file=sys.stderr)
        sys.exit(1)
    os.makedirs(SUB_DIR, exist_ok=True)
    rebuild_sub()
    threading.Thread(target=janitor_loop, daemon=True).start()
    threading.Thread(target=auto_update_loop, daemon=True).start()
    _wd_tls = bool(pc.get("tls_domain")) and os.path.exists(
        f"{CERT_DIR}/{pc.get('tls_domain', '')}/fullchain.pem")
    threading.Thread(target=watchdog_loop, args=(host, port, _wd_tls), daemon=True).start()

    # 订阅服务与面板同进程（省一个 Python 解释器约 20MB）
    sub_port = int(pc.get("sub_port", 8080))
    if sub_port and sub_port != port:
        try:
            subd = PanelHTTPServer(("0.0.0.0", sub_port), SubHandler)
            sscheme = "http"
            sdom = pc.get("tls_domain", "")
            if sdom:
                sc, sk = f"{CERT_DIR}/{sdom}/fullchain.pem", f"{CERT_DIR}/{sdom}/privkey.pem"
                if os.path.exists(sc) and os.path.exists(sk):
                    import ssl as _s
                    sctx = _s.SSLContext(_s.PROTOCOL_TLS_SERVER)
                    sctx.load_cert_chain(sc, sk)
                    subd.socket = sctx.wrap_socket(subd.socket, server_side=True)
                    sscheme = "https"
            threading.Thread(target=subd.serve_forever, daemon=True).start()
            print(f"subscription on {sscheme}://{sdom or '0.0.0.0'}:{sub_port}/{sub_token()}")
        except OSError as e:
            print(f"订阅端口 {sub_port} 启动失败: {e}", file=sys.stderr)

    httpd = PanelHTTPServer((host, port), Handler)
    scheme = "http"
    dom = pc.get("tls_domain", "")
    if dom:
        cert = f"{CERT_DIR}/{dom}/fullchain.pem"
        key = f"{CERT_DIR}/{dom}/privkey.pem"
        if os.path.exists(cert) and os.path.exists(key):
            import ssl as _ssl
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            scheme = "https"
        else:
            print(f"警告: 证书缺失 {cert}，已回退 HTTP", file=sys.stderr)
    shown = dom if scheme == "https" else host
    pth = pc.get("path", "")
    pth = ("/" + pth.strip("/")) if pth else ""
    print(f"sing-box panel on {scheme}://{shown}:{port}{pth}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
