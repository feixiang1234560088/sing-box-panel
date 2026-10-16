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
    used = {i.get("listen_port") for i in cfg().get("inbounds", [])}
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


WEB_UNITS = {"nginx": "nginx", "apache2": "apache2", "httpd": "httpd",
             "caddy": "caddy", "haproxy": "haproxy", "lighttpd": "lighttpd"}


def port80_holder():
    """返回 (占用行, 可临时让路的 systemd 服务名)。

    standalone 验证要独占 80 端口。占着的是常见 Web 服务时，签发前停、签发后启，
    停顿只有几十秒；不认识的程序不擅自动它，交给用户处理。"""
    _, who, _ = sh("ss -ltnp 2>/dev/null | grep -E ':80\\s' | head -1")
    who = who.strip()
    if not who or "sing-box" in who:
        return who, ""
    m = re.search(r'users:\(\("([^"]+)"', who)
    unit = WEB_UNITS.get(m.group(1) if m else "", "")
    if unit and sh(f"systemctl is-active {unit}", 5)[1].strip() != "active":
        unit = ""                        # 不是 systemd 管的，停了也拉不起来，别碰
    return who, unit


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
    who, unit = port80_holder()
    if who and "sing-box" not in who and not unit:
        return False, f"80 端口被未知程序占用，请先停止:\n{who}"
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
                   f'--reloadcmd "systemctl restart sing-box"', 60)
                if os.path.exists(f"{CERT_DIR}/{domain}/fullchain.pem"):
                    return True, "已复用本地现有证书（未消耗签发次数）"

    sh(f"{envp} --set-default-ca --server letsencrypt", 30)

    # 检查 80 端口占用（standalone 验证需要）
    who, unit = port80_holder()
    if who and "sing-box" not in who and not unit:
        return False, f"80 端口被未知程序占用，请先停止该服务:\n{who}"
    sh("systemctl stop sing-box"); stopped_sb = True
    # nginx 等让路：钩子由 acme.sh 自己执行并写进域名配置，自动续期时同样生效；
    # 签发失败它也会跑 post-hook，不会把 nginx 晾在停止状态
    hooks = (f' --pre-hook "systemctl stop {unit}" --post-hook "systemctl start {unit}"'
             if unit else "")
    issue = f"{envp} --issue -d {domain} --standalone --keylength ec-256{hooks}"

    c, o, e = sh(issue, 120)
    out = (o or "") + (e or "")

    # ② 撞 Let's Encrypt 限流 → 自动改用 ZeroSSL 重试
    if c != 0 and "rateLimited" in out:
        sh(f"{envp} --set-default-ca --server zerossl", 30)
        c, o2, e2 = sh(issue, 120)
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
       f'--reloadcmd "systemctl restart sing-box"', 60)
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


HEARTBEAT = {"t": time.time(), "panel": 0.0, "sub": 0.0}

# ════════════════════════════════════════════
# 线程监管：后台线程崩了要自己爬起来，并留下痕迹
# 以前是裸 daemon 线程，异常逃逸到顶层就静默消失，外部完全看不出来
# ════════════════════════════════════════════
SUPERVISED = {}          # name -> {alive, restarts, last_error, last_error_at, started_at}
RUNLOG = []              # 最近的运行事件，健康接口和日志页共用


def runlog(msg, level="info"):
    RUNLOG.append({"t": time.strftime("%m-%d %H:%M:%S"), "level": level, "msg": str(msg)[:300]})
    del RUNLOG[:-200]
    if level in ("error", "warn"):
        print(f"[{level}] {msg}", file=sys.stderr)


def _swallow(fn, *args):
    """跑一个可能永远不返回、也可能抛错的收尾动作，调用方不关心结果。"""
    try:
        fn(*args)
    except Exception:
        pass


def supervise(name, fn, *args, oneshot=False):
    """启动一个受监管的常驻线程。

    对常驻服务来说「正常返回」同样是故障（比如 serve_forever 被 shutdown），
    所以除非显式声明 oneshot，返回和抛异常都会触发退避重启。
    连续稳定运行超过 60 秒就把退避时间重置，避免长期服务偶尔重启一次后
    背着几十秒的延迟。"""
    st = SUPERVISED.setdefault(name, {"alive": False, "restarts": -1,
                                      "last_error": "", "last_error_at": "",
                                      "started_at": ""})

    def wrapper():
        delay = 5
        while True:
            st["alive"] = True
            st["restarts"] += 1
            st["started_at"] = time.strftime("%m-%d %H:%M:%S")
            if st["restarts"]:
                runlog(f"线程 {name} 第 {st['restarts']} 次重启", "warn")
            t0 = time.time()
            try:
                fn(*args)
                st["alive"] = False
                if oneshot:
                    return
                st["last_error"] = "正常返回（常驻服务不应退出）"
                st["last_error_at"] = time.strftime("%m-%d %H:%M:%S")
                runlog(f"线程 {name} 退出了，准备重启", "warn")
            except Exception as e:
                st["alive"] = False
                st["last_error"] = f"{type(e).__name__}: {e}"
                st["last_error_at"] = time.strftime("%m-%d %H:%M:%S")
                runlog(f"线程 {name} 异常退出: {st['last_error']}", "error")
            if time.time() - t0 > 60:
                delay = 5                        # 之前稳定跑过，退避归零
            time.sleep(delay)
            delay = min(delay * 2, 60)           # 5→10→20→40→60 封顶

    t = threading.Thread(target=wrapper, name=name, daemon=True)
    t.start()
    return t


def port_alive(host, port, timeout=5):
    """端口是否还在监听（只做 TCP 连接，不发数据）"""
    import socket as _sk
    try:
        with _sk.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False



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
        runlog(f"面板无响应且心跳陈旧 {fails}/3", "warn")
        if fails >= 3:
            runlog("面板卡死，退出由 systemd 重启", "error")
            os._exit(1)


def sub_watchdog_loop():
    """订阅服务专用看门狗：端口没在听就单独把它拉起来，不牵连整个进程。
    这是 D1/D3 的正面修复 —— 以前订阅死了没有任何机制会发现。"""
    time.sleep(90)
    fails = 0
    while True:
        time.sleep(30)
        port = SUB_STATE.get("port") or 0
        if not port:
            continue
        if port_alive("127.0.0.1", port, timeout=5):
            fails = 0
            continue
        fails += 1
        runlog(f"订阅端口 {port} 无响应 {fails}/2", "warn")
        if fails < 2:
            continue
        fails = 0
        # 先把旧监听器关掉，让 supervisor 的重启循环接手。
        # 注意 shutdown() 是**无限期**等待 serve_forever 退出 —— 服务真卡死时它
        # 永远等不到，会把看门狗自己一起拖死（曾经就这么静默瘫了一整天）。
        # 所以：先 force_stop 打断 accept，shutdown 丢到临时线程里且不等它。
        srv = SUB_STATE.get("server")
        if srv is not None:
            runlog("正在强制关闭旧订阅监听器", "warn")
            try:
                srv.force_stop()
            except Exception:
                pass
            threading.Thread(target=lambda: _swallow(srv.shutdown),
                             daemon=True).start()
        # 给 supervisor 一点时间走完重启循环，再判断要不要补一刀
        time.sleep(15)
        st = SUPERVISED.get("subscription") or {}
        if not st.get("alive"):
            runlog("订阅监管线程已不在，重新拉起", "warn")
            supervise("subscription", sub_serve_forever, port)


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


def _wait_active(unit, timeout=12):
    """轮询等待服务真正 active。sing-box 要绑端口、载证书，1 秒往往不够，
    以前只 sleep(1) 就判定失败，会误触发回滚并再重启一次。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, st, _ = sh(f"systemctl is-active {unit}", 5)
        st = st.strip()
        if st == "active":
            return True
        if st in ("failed", "inactive"):
            return False
        time.sleep(0.5)
    _, st, _ = sh(f"systemctl is-active {unit}", 5)
    return st.strip() == "active"


def apply_config(new_cfg):
    """校验并写入，失败自动回滚。

    写入前统一做两件事：把用户表同步进各节点的 users，确保流量统计用的
    Clash API 存在。放在这里而不是各个接口里，任何改配置的路径都不会漏掉。"""
    try:
        n = prune_orphan_rules(new_cfg)
        if n:
            print(f"[config] 清理 {n} 条孤儿/重复路由规则", file=sys.stderr)
    except Exception:
        pass
    managed = sync_users(new_cfg)
    ensure_clash_api(new_cfg)
    okk, msg = _apply_config(new_cfg)
    if okk:
        _save_managed(managed)                 # 只有真正生效才记账，回滚时保持旧记录
    # sing-box 的报错带终端颜色码，显示到网页上是乱码
    return okk, re.sub(r"\x1b\[[0-9;]*m", "", msg) if isinstance(msg, str) else msg


def _apply_config(new_cfg):
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
    # 先清掉 systemd 的启动失败计数，否则短时间内多次重启会撞上
    # StartLimitBurst（默认 10 秒 5 次），单元被打成 failed 后不再自动拉起
    cache_bust()                               # 配置变了，服务状态和证书清单都要重算
    sh("systemctl reset-failed sing-box")
    sh("systemctl restart sing-box")
    if not _wait_active("sing-box"):
        if old is not None:
            with open(SB_CONF, "w") as f:
                f.write(old)
            sh("systemctl reset-failed sing-box")
            sh("systemctl restart sing-box")
            _wait_active("sing-box")          # 确认回滚后真的起来了
        _, log, _ = sh("journalctl -u sing-box -n 15 --no-pager")
        return False, f"启动失败已回滚:\n{log}"
    return True, "ok"


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
            {"k": "obfs_type", "l": "混淆方式", "t": "select",
             "opts": ["salamander (推荐，开销最小)", "gecko (随机包长，抗特征更强)", "关闭"],
             "d": "salamander (推荐，开销最小)"},
            {"k": "obfs", "l": "混淆密码 (留空则不启用混淆)", "t": "text", "auto": "pass"},
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

ADV_HY2 = [
    {"k": "bbr", "l": "BBR 档位", "t": "select",
     "opts": ["standard (默认)", "aggressive (抢带宽更积极)", "conservative (最温和)"],
     "d": "standard (默认)",
     "h": "服务端发数据用的拥塞控制档位，直接影响客户端的下载速度。"
          "拥堵线路可试 aggressive；变差就退回 standard"},
    {"k": "force_bbr", "l": "强制客户端也用 BBR", "t": "bool", "d": "0",
     "h": "上下行留空时生效。防止客户端自己声明带宽而切成 Brutal —— "
          "Brutal 无视丢包硬发，拥堵线路上只会更糟"},
    {"k": "gecko_min", "l": "gecko 最小包长", "t": "number", "d": "512",
     "h": "仅 gecko 混淆生效。小包会被填充到这个长度，调大更抗特征但更费带宽"},
    {"k": "gecko_max", "l": "gecko 最大包长", "t": "number", "d": "1200",
     "h": "仅 gecko 混淆生效。别超过链路 MTU，否则会分片"},
]

_ADV_MAP = {
    "hysteria2":   ADV_UDP + ADV_HY2,
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
    PROTOCOLS[_p]["adv"] = _a


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
        # BBR 档位：只有上下行留空（即真的走 BBR）时才写，填了带宽是 Brutal，写了也无效
        _bbr = (str(f.get("bbr") or "").split() or ["standard"])[0]
        if up <= 0 and dn <= 0 and _bbr in ("conservative", "aggressive"):
            ib["bbr_profile"] = _bbr
        # 强制客户端用 BBR，防止它自己声明带宽切成 Brutal
        if up <= 0 and dn <= 0 and _bl(f, "force_bbr"):
            ib["ignore_client_bandwidth"] = True

        q = f"security=tls&sni={domain}&insecure=0&fastopen=0&alpn=h3"
        _ot = (str(f.get("obfs_type") or "").split() or ["salamander"])[0]
        if _ot not in ("salamander", "gecko", "关闭"):
            _ot = "salamander"
        if f.get("obfs") and _ot != "关闭":
            ob = {"type": _ot, "password": f["obfs"]}
            if _ot == "gecko":
                try:
                    gmin, gmax = int(f.get("gecko_min") or 512), int(f.get("gecko_max") or 1200)
                except (TypeError, ValueError):
                    gmin, gmax = 512, 1200
                if 0 < gmin <= gmax:
                    ob["min_packet_size"], ob["max_packet_size"] = gmin, gmax
            ib["obfs"] = ob
            q += f"&obfs={_ot}&obfs-password={uenc(f['obfs'])}"
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
LOG_LEVELS = ["trace", "debug", "info", "warn", "error", "fatal", "panic"]


def api_log_state():
    lg = cfg().get("log") or {}
    return {"enabled": not lg.get("disabled", False),
            "level": lg.get("level", "warn"),
            "levels": LOG_LEVELS}


def api_set_log(enabled, level=None):
    """开关 sing-box 日志。关闭后不再写 journald，省磁盘与 IO"""
    c = cfg()
    lg = dict(c.get("log") or {})
    if enabled:
        lg.pop("disabled", None)
        lv = (level or lg.get("level") or "warn").strip()
        if lv not in LOG_LEVELS:
            return False, f"未知日志级别：{lv}"
        lg["level"] = lv
        lg.setdefault("timestamp", True)
    else:
        lg["disabled"] = True
    c["log"] = lg
    okk, msg = apply_config(c)
    if not okk:
        return False, msg
    return True, ("日志已开启（级别 " + lg["level"] + "）" if enabled
                  else "日志已关闭，sing-box 不再写入 journald")


START_TS = time.time()


TLS_CTXS = {}          # name -> SSLContext，热重载时逐个换掉证书
CERT_SIG = {"sig": "", "fails": 0}


def _cert_sig(cert, key):
    """证书+私钥的内容指纹。用内容而不是 mtime，避免 acme 只 touch 不换内容时空重载"""
    h = hashlib.sha256()
    for f in (cert, key):
        try:
            with open(f, "rb") as fh:
                h.update(fh.read())
        except Exception:
            return ""
    return h.hexdigest()


def register_tls(name, ctx, cert, key):
    TLS_CTXS[name] = {"ctx": ctx, "cert": cert, "key": key}
    if not CERT_SIG["sig"]:
        CERT_SIG["sig"] = _cert_sig(cert, key)


def in_use_cert_domains():
    """当前在用的所有证书域名：面板自己的 + 各节点入站引用的"""
    doms = set()
    d = load_json(PANEL_CFG, {}).get("tls_domain", "")
    if d:
        doms.add(d)
    try:
        for ib in cfg().get("inbounds", []):
            dd = _cert_domain((ib.get("tls") or {}).get("certificate_path", ""))
            if dd:
                doms.add(dd)
    except Exception:
        pass
    return sorted(doms)


CERT_RENEW = {"last_run": "", "last_result": "", "fails": 0}


def cert_renew_loop():
    """证书续期兜底。

    acme.sh 自己有 cron，但它是静默的：cron 没装上、HOME 没设、
    80 端口被占……任何一种情况都会让续期悄无声息地失败，直到证书过期
    整套服务一起挂。这里每天主动查一次剩余天数，不足 25 天就调用
    acme --cron 让它自己判断并续期（acme 内部有幂等判断，不会重复签发）。"""
    time.sleep(180)
    while True:
        try:
            doms = in_use_cert_domains()
            need = [(d, cert_days_left(d)) for d in doms]
            need = [(d, n) for d, n in need if n is not None and n < 25]
            if need:
                acme = find_acme()
                if not acme:
                    runlog(f"证书 {need[0][0]} 剩余 {need[0][1]} 天，但找不到 acme.sh", "error")
                    CERT_RENEW["fails"] += 1
                else:
                    for d, n in need:
                        runlog(f"证书 {d} 剩余 {n} 天，触发续期", "warn")
                    # 早先签的证书没记钩子，后来装的 nginx 会让它们续期失败 —— 这里兜住
                    _, unit = port80_holder()
                    if unit:
                        sh(f"systemctl stop {unit}", 30)
                    try:
                        c, o, e = sh(f"HOME=/root {acme} --cron --home {ACME_HOME}", 300)
                    finally:
                        if unit:
                            sh(f"systemctl start {unit}", 30)
                    time.sleep(5)
                    after = {d: cert_days_left(d) for d, _ in need}
                    okd = [d for d, n in need if (after.get(d) or 0) > n]
                    if okd:
                        CERT_RENEW["fails"] = 0
                        cache_bust("certs")
                        CERT_RENEW["last_result"] = f"已续期: {', '.join(okd)}"
                        runlog(f"证书续期成功: {', '.join(okd)}")
                        # 文件已换，热重载线程会在 5 分钟内自动换掉面板/订阅的证书
                    else:
                        CERT_RENEW["fails"] += 1
                        CERT_RENEW["last_result"] = (e or o or "无输出")[-200:]
                        runlog(f"证书续期未生效({CERT_RENEW['fails']} 次): "
                               f"{CERT_RENEW['last_result']}", "error")
            else:
                CERT_RENEW["last_result"] = "无需续期"
            CERT_RENEW["last_run"] = time.strftime("%m-%d %H:%M")
        except Exception as e:
            runlog(f"续期检查异常: {type(e).__name__}: {e}", "error")
        time.sleep(12 * 3600)


def cert_reload_loop():
    """证书热重载：acme 续期后就地换证书，不用重启进程。

    SSLContext.load_cert_chain 可以重复调用，替换后的证书对
    之后新建立的 TLS 握手生效，已有连接不受影响。
    连续失败 3 次才退回重启进程这条粗暴路径。"""
    time.sleep(60)
    while True:
        time.sleep(300)                       # 5 分钟看一次足够，证书 60 天才换一次
        if not TLS_CTXS:
            continue
        one = next(iter(TLS_CTXS.values()))
        sig = _cert_sig(one["cert"], one["key"])
        if not sig or sig == CERT_SIG["sig"]:
            continue                          # 没变，或文件读不出来（可能正在被写）

        ok, failed = 0, []
        for name, e in TLS_CTXS.items():
            try:
                e["ctx"].load_cert_chain(e["cert"], e["key"])
                ok += 1
            except Exception as ex:
                failed.append(f"{name}: {type(ex).__name__}")

        if failed:
            CERT_SIG["fails"] += 1
            runlog(f"证书热重载失败({CERT_SIG['fails']}/3): {'; '.join(failed)}", "error")
            if CERT_SIG["fails"] >= 3:
                runlog("热重载连续失败，退回重启进程", "warn")
                CERT_SIG["fails"] = 0
                safe_restart_self(2)
            continue

        CERT_SIG["sig"] = sig
        CERT_SIG["fails"] = 0
        cache_bust("certs")                    # 证书换了，天数缓存立刻失效
        d = cert_days_left(load_json(PANEL_CFG, {}).get("tls_domain", ""))
        runlog(f"证书已热重载，{ok} 个监听器生效"
               + (f"，新证书剩余 {d} 天" if d is not None else ""))


_TTL_CACHE = {}


def cached(key, ttl, fn):
    """带 TTL 的结果缓存。健康接口每 60 秒被轮询一次，
    证书天数、服务状态这些都不需要每次都真去算 —— 以前每次调用要拉起
    5 个子进程，一天 7000 多次，在小内存 VPS 上是纯浪费。"""
    now = time.time()
    e = _TTL_CACHE.get(key)
    if e and now - e[0] < ttl:
        return e[1]
    v = fn()
    _TTL_CACHE[key] = (now, v)
    return v


def cache_bust(prefix=""):
    """证书换了、配置改了之后主动让缓存失效"""
    for k in [k for k in _TTL_CACHE if not prefix or k.startswith(prefix)]:
        _TTL_CACHE.pop(k, None)


def cert_days_left(dom):
    """证书剩余天数；取不到返回 None"""
    if not dom:
        return None
    f = f"{CERT_DIR}/{dom}/fullchain.pem"
    if not os.path.exists(f):
        return None
    c, o, _ = sh(f"openssl x509 -enddate -noout -in {f}", 10)
    if c != 0 or "=" not in o:
        return None
    try:
        import calendar
        t = time.strptime(o.split("=", 1)[1].strip(), "%b %d %H:%M:%S %Y %Z")
        return int((calendar.timegm(t) - time.time()) // 86400)
    except Exception:
        return None


def proc_rss_mb():
    try:
        with open(f"/proc/{os.getpid()}/status") as fh:
            for ln in fh:
                if ln.startswith("VmRSS:"):
                    return round(int(ln.split()[1]) / 1024, 1)
    except Exception:
        pass
    return None


def api_health():
    """一次性回答『现在各子系统是否正常』。免鉴权，不含任何敏感信息。

    昂贵的部分都走缓存：证书天数一天最多变一次，服务状态也不需要秒级精度。
    端口探测和线程状态是内存操作，不缓存。"""
    pc = load_json(PANEL_CFG, {})
    dom = pc.get("tls_domain", "")
    all_certs = cached("certs", 3600, lambda: [
        {"domain": d, "days_left": cert_days_left(d)} for d in in_use_cert_domains()])
    days = next((c["days_left"] for c in all_certs if c["domain"] == dom), None)
    min_days = min([c["days_left"] for c in all_certs
                    if c["days_left"] is not None], default=None)
    sb_state = cached("sb_state", 10,
                      lambda: (sh("systemctl is-active sing-box", 5)[1].strip() or "unknown"))
    sub_port = SUB_STATE.get("port") or 0
    sub_ok = bool(sub_port) and port_alive("127.0.0.1", sub_port, 3)

    threads = {}
    for name, st in SUPERVISED.items():
        threads[name] = {"alive": st["alive"], "restarts": max(0, st["restarts"]),
                         "started_at": st["started_at"],
                         "last_error": st["last_error"],
                         "last_error_at": st["last_error_at"]}

    # 显式分级，不靠关键词匹配 —— 加新检查时不会因为忘了改关键词而误判
    issues = []                                   # (severity, text)
    if sub_port and not sub_ok:
        issues.append(("red", "订阅端口未监听"))
    if sb_state != "active":
        issues.append(("red", f"sing-box 状态 {sb_state}"))
    for n, t in threads.items():
        if not t["alive"]:
            issues.append(("red", f"线程 {n} 未运行"))
    for c in all_certs:
        dl = c["days_left"]
        if dl is None:
            issues.append(("yellow", f"证书 {c['domain']} 无法读取"))
        elif dl < 0:
            issues.append(("red", f"证书 {c['domain']} 已过期 {-dl} 天"))
        elif dl < 7:
            issues.append(("red", f"证书 {c['domain']} 仅剩 {dl} 天"))
        elif dl < 15:
            issues.append(("yellow", f"证书 {c['domain']} 剩余 {dl} 天"))
    if CERT_RENEW["fails"] >= 2:
        issues.append(("red", f"证书续期连续失败 {CERT_RENEW['fails']} 次"))
    if CERT_SIG["fails"] >= 2:
        issues.append(("yellow", f"证书热重载失败 {CERT_SIG['fails']} 次"))

    problems = [t for _, t in issues]
    level = ("red" if any(sev == "red" for sev, _ in issues)
             else "yellow" if issues else "green")

    return {
        "level": level,
        "problems": problems,
        "uptime_sec": int(time.time() - START_TS),
        "rss_mb": proc_rss_mb(),
        "threads": threads,
        "subscription": {"port": sub_port, "scheme": SUB_STATE.get("scheme", "http"),
                         "listening": sub_ok},
        "singbox": {"state": sb_state, "inbounds": len(cfg().get("inbounds", []))},
        "cert": {"domain": dom, "days_left": days, "min_days_left": min_days,
                 "all": all_certs,
                 "hot_reload": bool(TLS_CTXS),
                 "listeners": sorted(TLS_CTXS.keys()),
                 "reload_fails": CERT_SIG["fails"],
                 "renew": {"last_run": CERT_RENEW["last_run"],
                           "last_result": CERT_RENEW["last_result"],
                           "fails": CERT_RENEW["fails"]}},
        "heartbeat": {
            "panel_ago": int(time.time() - HEARTBEAT["panel"]) if HEARTBEAT["panel"] else None,
            "sub_ago": int(time.time() - HEARTBEAT["sub"]) if HEARTBEAT["sub"] else None,
        },
        "runlog": RUNLOG[-30:],
    }


def preflight(host, port, sub_port, dom):
    """启动自检：有问题要明确说出来，而不是静默降级后半夜出事"""
    import socket as _sk
    ok = True
    try:
        cfg()
    except Exception as e:
        runlog(f"自检: sing-box 配置无法解析: {e}", "error"); ok = False
    for nm, p_ in (("面板", port), ("订阅", sub_port)):
        if not p_:
            continue
        if port_alive("127.0.0.1", p_, 2):
            runlog(f"自检: {nm}端口 {p_} 已被占用", "error"); ok = False
    if dom:
        d = cert_days_left(dom)
        if d is None:
            runlog(f"自检: 证书 {dom} 不可读，将回退 HTTP", "warn")
        elif d < 0:
            runlog(f"自检: 证书 {dom} 已过期 {-d} 天", "error"); ok = False
        elif d < 15:
            runlog(f"自检: 证书 {dom} 仅剩 {d} 天", "warn")
    runlog("自检完成" + ("" if ok else "（存在问题，见上）"))
    return ok


def api_status():
    _, ver, _ = sh(f"{SB_BIN} version")
    ver = ver.splitlines()[0].split()[-1] if ver else "未知"
    _, act, _ = sh("systemctl is-active sing-box")
    c = cfg()
    return {"version": ver, "running": act.strip() == "active",
            "ip": public_ip(),
            "inbounds": len(c.get("inbounds", [])),
            "outbounds": len([o for o in c.get("outbounds", []) if o.get("type") != "direct"])}


def api_inbounds():
    c, m = cfg(), meta()
    out = []
    binds = {}
    for r in c.get("route", {}).get("rules", []):
        for t in (r.get("inbound") or []):
            binds[t] = r.get("outbound")
    d, now = load_users(), time.time()
    for ib in c.get("inbounds", []):
        t = ib.get("tag")
        if t.endswith("-ss") and ib.get("listen") == "127.0.0.1":
            continue                      # ShadowTLS 的内部入站，不单独展示
        info = m.get(t, {})
        p = node_proto(ib, m)
        tot = STATS["totals"].get(t, {})
        lv = STATS["live"].get(t, {})
        out.append({"tag": t, "type": ib.get("type"), "port": ib.get("listen_port"),
                    "proto": p, "name": info.get("name", t), "uri": info.get("uri", ""),
                    "bind": binds.get(t, "direct"),
                    "multi": p in MULTI_USER and bool(ib.get("users")),
                    "users": [u["name"] for u in d["users"] if t in (u.get("inbounds") or [])],
                    "active_users": sum(1 for u in d["users"]
                                        if t in (u.get("inbounds") or []) and user_active(u, now)),
                    "up": tot.get("up", 0), "down": tot.get("down", 0),
                    "conns": lv.get("conns", 0)})
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
    f = body.get("fields", {})
    spec = PROTOCOLS[proto]
    if spec["needs_cert"]:
        d = f.get("cert", "")
        if not d or not os.path.exists(f"{CERT_DIR}/{d}/fullchain.pem"):
            return False, "请先选择或申请有效证书"
    c = cfg()
    base = f"{proto}-in"
    tag, n = base, 1
    exist = {i.get("tag") for i in c.get("inbounds", [])}
    while tag in exist:
        tag = f"{base}-{n}"; n += 1
    try:
        ib, uri = build_inbound(proto, f, tag)
    except Exception as e:
        return False, f"生成失败: {e}"
    # ShadowTLS 需要配套的内部入站
    extra = ib.pop("_extra_inbound", None)
    c.setdefault("inbounds", []).append(ib)
    if extra:
        c["inbounds"].append(extra)
    old_users = load_json(USERS_FILE, None)
    set_node_users(tag, body.get("users"))
    okk, msg = apply_config(c)
    if not okk:
        if old_users is not None:
            save_json(USERS_FILE, old_users)
        return False, msg
    m = meta()
    m[tag] = {"name": f.get("name", tag), "uri": uri, "proto": proto,
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
        _ob = ib.get("obfs") or {}
        f["obfs"] = _ob.get("password", "")
        f["obfs_type"] = {
            "salamander": "salamander (推荐，开销最小)",
            "gecko": "gecko (随机包长，抗特征更强)",
        }.get(_ob.get("type"), "关闭" if not _ob else "salamander (推荐，开销最小)")
        f["gecko_min"] = str(_ob.get("min_packet_size", 512) or 512)
        f["gecko_max"] = str(_ob.get("max_packet_size", 1200) or 1200)
        f["bbr"] = {
            "aggressive": "aggressive (抢带宽更积极)",
            "conservative": "conservative (最温和)",
        }.get(ib.get("bbr_profile"), "standard (默认)")
        f["force_bbr"] = "1" if ib.get("ignore_client_bandwidth") else "0"
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


def guess_proto(ib):
    """无记录时从配置判断协议种类"""
    t = ib.get("type")
    tls = ib.get("tls") or {}
    if t == "vless":
        return "vless" if (tls.get("reality") or {}).get("enabled") else "vless-tls"
    return t if t in PROTOCOLS else ""


def api_edit_inbound(tag, body):
    c = cfg()
    old = next((i for i in c.get("inbounds", []) if i.get("tag") == tag), None)
    if not old:
        return False, "节点不存在"
    m = meta()
    info = m.get(tag, {})
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

    old_users = load_json(USERS_FILE, None)
    set_node_users(tag, body.get("users"))
    okk, msg = apply_config(c)
    if not okk:
        if old_users is not None:
            save_json(USERS_FILE, old_users)
        return False, msg
    info.update({"name": f.get("name", tag), "uri": uri, "proto": proto,
                 "fields": f, "edited": time.strftime("%F %T")})
    m[tag] = info
    save_json(META_FILE, m)
    rebuild_sub()
    return True, {"tag": tag, "uri": uri}


def api_del_inbound(tag):
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
    drop_node_from_users(tag)
    STATS["totals"].pop(tag, None)
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
    return (True, {"tag": tag, "bound": len(binds)}) if okk else (False, msg)


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
    return (True, {"tag": newtag}) if okk else (False, msg)


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
    return (True, "已删除") if okk else (False, msg)


def api_bind(inbound, outbound):
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
# ════════════════════════════════════════════
# 多用户（参照 s-ui 的 Clients）
#
# 用户表存在 users.json，节点配置里的 users 由 sync_users 每次应用配置时
# 重新生成：节点原有的用户（建节点时的那一个，也就是现有订阅）原样保留，
# 面板用户追加在后面。面板追加过哪些用户记在 managed 里，下次先摘掉再按
# 当前用户表重建 —— 这样删除、停用、到期都能干净地移除，又不碰手写的用户。
# ════════════════════════════════════════════
USERS_FILE = f"{SB_ETC}/users.json"
STATS_FILE = f"{SB_ETC}/stats.json"
USER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")

# 支持多用户的协议 -> sing-box 用户对象
# Shadowsocks 2022 多用户要求客户端带「服务端密钥:用户密钥」，开启后原有的单密码
# 链接立即失效；ShadowTLS / Snell 共用一个密钥 —— 这三种不做多用户，避免破坏现有订阅
MULTI_USER = {
    "hysteria2": lambda u: {"name": u["name"], "password": u["password"]},
    "vless":     lambda u: {"name": u["name"], "uuid": u["uuid"]},
    "vless-tls": lambda u: {"name": u["name"], "uuid": u["uuid"]},
    "trojan":    lambda u: {"name": u["name"], "password": u["password"]},
    "anytls":    lambda u: {"name": u["name"], "password": u["password"]},
    "tuic":      lambda u: {"name": u["name"], "uuid": u["uuid"], "password": u["password"]},
    "vmess":     lambda u: {"name": u["name"], "uuid": u["uuid"], "alterId": 0},
    "hysteria":  lambda u: {"name": u["name"], "auth_str": u["password"]},
    "naive":     lambda u: {"username": u["name"], "password": u["password"]},
    "socks":     lambda u: {"username": u["name"], "password": u["password"]},
    "mixed":     lambda u: {"username": u["name"], "password": u["password"]},
    "http":      lambda u: {"username": u["name"], "password": u["password"]},
}


def load_users():
    d = load_json(USERS_FILE, {})
    if not isinstance(d, dict):
        d = {}
    d.setdefault("users", [])
    d.setdefault("managed", {})
    return d


def save_users(d):
    save_json(USERS_FILE, d)


def _uid(x):
    return x.get("name") or x.get("username") or ""


def user_active(u, now=None):
    now = now or time.time()
    exp = int(u.get("expiry") or 0)
    return bool(u.get("enable", True)) and (exp == 0 or exp > now)


def node_proto(ib, m=None):
    m = meta() if m is None else m
    return (m.get(ib.get("tag"), {}) or {}).get("proto") or guess_proto(ib)


def sync_users(c):
    """把用户表写进各节点。返回新的 managed（应用成功后再保存）"""
    data = load_users()
    m, now = meta(), time.time()
    old = data.get("managed", {})
    new = {}
    for ib in c.get("inbounds", []):
        tag = ib.get("tag")
        drop = set(old.get(tag, []))
        cur = ib.get("users") or []
        base = [x for x in cur if _uid(x) not in drop] if drop else list(cur)
        mk = MULTI_USER.get(node_proto(ib, m))
        add = []
        # 节点本身没有认证用户（如无密码的 SOCKS）时不加：一加就变成必须认证，原链接失效
        if mk and base:
            flow = base[0].get("flow")
            taken = {_uid(x) for x in base}
            for u in data["users"]:
                if tag in (u.get("inbounds") or []) and user_active(u, now) \
                        and u["name"] not in taken:
                    o = mk(u)
                    if flow:
                        o["flow"] = flow
                    add.append(o)
        if drop or add:
            ib["users"] = base + add
        if add:
            new[tag] = [_uid(o) for o in add]
    return new


def _save_managed(managed):
    d = load_users()
    if d.get("managed") != managed:
        d["managed"] = managed
        save_users(d)


def swap_cred(uri, proto, u):
    """把节点分享链接里的凭据换成某个用户的"""
    if proto == "vmess":
        vm = json.loads(base64.b64decode(uri[8:] + "==").decode())
        vm["id"] = u["uuid"]
        return "vmess://" + b64(json.dumps(vm, ensure_ascii=False))
    if proto == "hysteria":
        return _uq(uri, auth=u["password"])
    if proto in ("vless", "vless-tls"):
        cred = u["uuid"]
    elif proto == "tuic":
        cred = f"{u['uuid']}:{uenc(u['password'])}"
    elif proto in ("naive", "http"):
        cred = f"{uenc(u['name'])}:{uenc(u['password'])}"
    elif proto in ("socks", "mixed"):
        cred = b64(f"{u['name']}:{u['password']}")
    else:
        cred = uenc(u["password"])
    return re.sub(r"^([a-z0-9+]+://)[^@/]*@", lambda mm: mm.group(1) + cred + "@", uri, count=1)


def user_links(u, c=None, m=None):
    c, m = c or cfg(), meta() if m is None else m
    out = []
    for ib in c.get("inbounds", []):
        tag = ib.get("tag")
        if tag not in (u.get("inbounds") or []):
            continue
        info = m.get(tag, {})
        proto = node_proto(ib, m)
        uri = info.get("uri", "")
        if not uri or proto not in MULTI_USER or not ib.get("users"):
            continue
        try:
            out.append({"tag": tag, "name": info.get("name", tag), "uri": swap_cred(uri, proto, u)})
        except Exception:
            pass
    return out


def sub_base_url():
    pc = load_json(PANEL_CFG, {})
    dom = pc.get("tls_domain", "")
    sch = "https" if dom else "http"
    return f"{sch}://{dom or public_ip()}:{pc.get('sub_port', 8080)}/"


def _new_user(name, f):
    return {"name": name, "enable": bool(f.get("enable", True)),
            "group": str(f.get("group") or "")[:32], "remark": str(f.get("remark") or "")[:200],
            "expiry": int(f.get("expiry") or 0), "inbounds": list(f.get("inbounds") or []),
            "uuid": f.get("uuid") or gen_uuid(),
            "password": f.get("password") or secrets.token_urlsafe(12),
            "sub": secrets.token_hex(16), "created": int(time.time())}


def _commit_users(d):
    """保存用户表并应用到 sing-box；失败时恢复原表"""
    old = load_json(USERS_FILE, None)
    save_users(d)
    okk, msg = apply_config(cfg())
    if not okk:
        if old is None:
            try:
                os.remove(USERS_FILE)
            except OSError:
                pass
        else:
            save_json(USERS_FILE, old)
    return okk, msg


def _clean_inbounds(tags):
    exist = {i.get("tag") for i in cfg().get("inbounds", [])}
    return [t for t in (tags or []) if t in exist]


def api_users():
    c, m = cfg(), meta()
    d, now = load_users(), time.time()
    nodes = []
    for ib in c.get("inbounds", []):
        t = ib.get("tag")
        if t.endswith("-ss") and ib.get("listen") == "127.0.0.1":
            continue                      # ShadowTLS 的内部入站
        p = node_proto(ib, m)
        nodes.append({"tag": t, "name": m.get(t, {}).get("name", t), "proto": p,
                      "multi": p in MULTI_USER and bool(ib.get("users"))})
    users = []
    for u in d["users"]:
        exp = int(u.get("expiry") or 0)
        users.append(dict(u, active=user_active(u, now), expired=bool(exp and exp <= now)))
    return {"users": users, "nodes": nodes, "sub_base": sub_base_url()}


def api_user_save(name, f, create):
    d = load_users()
    nn = (f.get("name") or "").strip()
    if not USER_NAME_RE.match(nn):
        return False, "用户名需为 1-32 位字母、数字、. _ -"
    names = {u["name"] for u in d["users"]}
    if create:
        if nn in names:
            return False, "用户名已存在"
        u = _new_user(nn, f)
        u["inbounds"] = _clean_inbounds(u["inbounds"])
        d["users"].append(u)
    else:
        u = next((x for x in d["users"] if x["name"] == name), None)
        if not u:
            return False, "用户不存在"
        if nn != name and nn in names:
            return False, "用户名已存在"
        u.update(name=nn, enable=bool(f.get("enable", True)),
                 group=str(f.get("group") or "")[:32], remark=str(f.get("remark") or "")[:200],
                 expiry=int(f.get("expiry") or 0), inbounds=_clean_inbounds(f.get("inbounds")))
        if f.get("uuid"):
            u["uuid"] = f["uuid"].strip()
        if f.get("password"):
            u["password"] = f["password"].strip()
    if not re.match(r"^[0-9a-fA-F-]{36}$", u["uuid"]):
        return False, "UUID 格式无效"
    okk, msg = _commit_users(d)
    return (True, "已保存") if okk else (False, msg)


def api_users_bulk(f):
    d = load_users()
    try:
        n = max(1, min(200, int(f.get("count") or 1)))
        start = max(0, int(f.get("start") or 1))
    except (TypeError, ValueError):
        return False, "数量无效"
    prefix = (f.get("prefix") or "user").strip()
    if not USER_NAME_RE.match(prefix + "0"):
        return False, "前缀只能包含字母、数字、. _ -"
    names = {u["name"] for u in d["users"]}
    made = 0
    for i in range(start, start + n * 3):
        if made >= n:
            break
        nm = f"{prefix}{i}"
        if nm in names or len(nm) > 32:
            continue
        u = _new_user(nm, f)
        u["inbounds"] = _clean_inbounds(u["inbounds"])
        d["users"].append(u)
        names.add(nm)
        made += 1
    okk, msg = _commit_users(d)
    return (True, f"已添加 {made} 个用户") if okk else (False, msg)


def api_user_del(names):
    d = load_users()
    keep = [u for u in d["users"] if u["name"] not in set(names)]
    if len(keep) == len(d["users"]):
        return False, "用户不存在"
    d["users"] = keep
    okk, msg = _commit_users(d)
    return (True, "已删除") if okk else (False, msg)


def api_user_reset(name, what):
    d = load_users()
    u = next((x for x in d["users"] if x["name"] == name), None)
    if not u:
        return False, "用户不存在"
    if what == "sub":
        u["sub"] = secrets.token_hex(16)
        save_users(d)                     # 订阅地址不影响 sing-box，不用重启
        return True, "订阅地址已更换，旧地址立即失效"
    u["uuid"], u["password"] = gen_uuid(), secrets.token_urlsafe(12)
    okk, msg = _commit_users(d)
    return (True, "凭据已重新生成，该用户需重新拉订阅") if okk else (False, msg)


def set_node_users(tag, names):
    """节点弹窗里勾选的用户 -> 写回用户表（不应用，交给调用方一起应用）"""
    if names is None:
        return
    d = load_users()
    want = set(names)
    for u in d["users"]:
        ins = [t for t in (u.get("inbounds") or []) if t != tag]
        if u["name"] in want:
            ins.append(tag)
        u["inbounds"] = ins
    save_users(d)


def drop_node_from_users(tag):
    d = load_users()
    changed = False
    for u in d["users"]:
        if tag in (u.get("inbounds") or []):
            u["inbounds"] = [t for t in u["inbounds"] if t != tag]
            changed = True
    if d.get("managed", {}).pop(tag, None) is not None:
        changed = True
    if changed:
        save_users(d)


def find_user_by_sub(tok):
    if not tok:
        return None
    return next((u for u in load_users()["users"] if u.get("sub") == tok), None)


USERS_SIG = {"v": None}


def users_loop():
    """到期检查：活跃用户集合一变（有人到期）就重新应用配置，把他从节点里摘掉"""
    time.sleep(20)
    # 面板升级后的第一次：配置里还没有 Clash API / 用户，补齐一次（sing-box 会重启一下）
    try:
        c = cfg()
        c2 = json.loads(json.dumps(c))
        sync_users(c2)
        ensure_clash_api(c2)
        if c.get("inbounds") and c2 != c:
            with LOCK:
                okk, msg = apply_config(cfg())
            runlog("已补齐流量统计接口 / 用户配置" if okk else f"补齐配置失败: {msg[:120]}",
                   "info" if okk else "error")
    except Exception as e:
        runlog(f"启动同步异常: {type(e).__name__}: {e}", "error")
    while True:
        try:
            now = time.time()
            sig = json.dumps(sorted((u["name"], tuple(sorted(u.get("inbounds") or [])))
                                    for u in load_users()["users"] if user_active(u, now)))
            if USERS_SIG["v"] is not None and sig != USERS_SIG["v"]:
                with LOCK:
                    okk, msg = apply_config(cfg())
                runlog("用户状态变化（到期/启用），已同步到节点" if okk
                       else f"用户同步失败: {msg[:120]}", "info" if okk else "error")
            USERS_SIG["v"] = sig
        except Exception as e:
            runlog(f"用户检查异常: {type(e).__name__}: {e}", "error")
        time.sleep(60)


# ════════════════════════════════════════════
# 流量统计：读 sing-box 的 Clash API（只监听 127.0.0.1）
#
# 官方 sing-box 的连接信息里只有入站标签、没有用户名，所以只能按节点统计。
# s-ui 能按用户统计，是因为它把 sing-box 编译进了自己的程序 —— 代价就是
# 没法自由选择 sing-box 版本。
# ════════════════════════════════════════════
def _free_local_port():
    import socket as _sk
    used = {i.get("listen_port") for i in cfg().get("inbounds", [])}
    for _ in range(50):
        p = 20000 + secrets.randbelow(40000)
        if p in used:
            continue
        s = _sk.socket()
        try:
            s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
        finally:
            s.close()
    return 29090


def ensure_clash_api(c):
    pc = load_json(PANEL_CFG, {})
    exp = c.get("experimental") or {}
    ca = exp.get("clash_api") or {}
    if pc.get("stats_disabled"):
        # 只撤掉面板自己加的那个，用户手写的不动
        if ca.get("external_controller") == f"127.0.0.1:{pc.get('clash_port')}":
            exp.pop("clash_api", None)
            if exp:
                c["experimental"] = exp
            else:
                c.pop("experimental", None)
        return
    if ca.get("external_controller"):
        # 已经有了（可能是用户自己配的）：沿用，不覆盖
        host, _, port = ca["external_controller"].rpartition(":")
        if port.isdigit() and (pc.get("clash_port") != int(port) or pc.get("clash_secret") != ca.get("secret", "")):
            pc.update(clash_port=int(port), clash_secret=ca.get("secret", ""),
                      clash_host=host if host not in ("", "0.0.0.0", "::", "[::]") else "127.0.0.1")
            save_json(PANEL_CFG, pc)
        return
    port = pc.get("clash_port") or _free_local_port()
    sec = pc.get("clash_secret") or secrets.token_hex(16)
    if pc.get("clash_port") != port or pc.get("clash_secret") != sec:
        pc.update(clash_port=port, clash_secret=sec, clash_host="127.0.0.1")
        save_json(PANEL_CFG, pc)
    exp["clash_api"] = {"external_controller": f"127.0.0.1:{port}", "secret": sec}
    c["experimental"] = exp


def clash_get(path, timeout=3):
    import urllib.request
    pc = load_json(PANEL_CFG, {})
    port = pc.get("clash_port")
    if not port:
        raise RuntimeError("Clash API 未配置")
    req = urllib.request.Request(f"http://{pc.get('clash_host', '127.0.0.1')}:{port}{path}")
    if pc.get("clash_secret"):
        req.add_header("Authorization", f"Bearer {pc['clash_secret']}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


STATS = {"ok": False, "err": "启动中", "totals": {}, "live": {}, "rate": {"up": 0, "down": 0},
         "conns": 0, "hist": [], "last": {}, "tot_raw": None, "t": 0, "saved": 0, "primed": False}


def _tag_of(cn):
    t = (cn.get("metadata") or {}).get("type", "")
    return t.split("/", 1)[1] if "/" in t else t


def stats_poll(count_totals=True):
    """读 Clash API：当前连接数、在线 IP、总速率。

    count_totals=False（iptables 计量可用）时，这里不再累计流量，各节点速率
    也沿用 iptables 算出的精确值 —— Clash API 漏掉短连接，只做兜底。"""
    d = clash_get("/connections")
    now = time.time()
    dt = max(0.5, now - STATS["t"]) if STATS["t"] else 0
    live, seen, last = {}, set(), STATS["last"]
    for cn in d.get("connections") or []:
        cid, tag = cn.get("id"), _tag_of(cn)
        up, dn = int(cn.get("upload") or 0), int(cn.get("download") or 0)
        pu, pd = last.get(cid, (0, 0))
        du, dd = max(0, up - pu), max(0, dn - pd)
        last[cid] = (up, dn)
        seen.add(cid)
        lv = live.setdefault(tag, {"conns": 0, "ips": set(), "du": 0, "dd": 0})
        lv["conns"] += 1
        ip = (cn.get("metadata") or {}).get("sourceIP")
        if ip:
            lv["ips"].add(ip)
        if STATS["primed"]:               # 第一轮只建基线，避免把面板重启前的量重复记一遍
            lv["du"] += du
            lv["dd"] += dd
            if count_totals:
                t = STATS["totals"].setdefault(tag, {"up": 0, "down": 0})
                t["up"] += du
                t["down"] += dd
    for cid in [k for k in last if k not in seen]:
        del last[cid]
    raw = (int(d.get("uploadTotal") or 0), int(d.get("downloadTotal") or 0))
    pr = STATS["tot_raw"]
    if pr and dt:
        STATS["rate"] = {"up": max(0, raw[0] - pr[0]) / dt, "down": max(0, raw[1] - pr[1]) / dt}
    STATS["tot_raw"] = raw
    if count_totals:
        STATS["live"] = {k: {"conns": v["conns"], "ips": len(v["ips"]),
                             "up_rate": v["du"] / dt if dt else 0, "down_rate": v["dd"] / dt if dt else 0}
                         for k, v in live.items()}
    else:
        ar = STATS.get("acct_rates") or {}
        tags = set(live) | set(ar)
        STATS["live"] = {k: dict({"up_rate": 0, "down_rate": 0}, **ar.get(k, {}),
                                 conns=live.get(k, {}).get("conns", 0),
                                 ips=len(live.get(k, {}).get("ips", ())))
                         for k in tags}
    STATS["conns"] = sum(v["conns"] for v in live.values())
    STATS["hist"].append([int(now), round(STATS["rate"]["up"]), round(STATS["rate"]["down"])])
    del STATS["hist"][:-120]
    STATS.update(t=now, ok=True, err="", primed=True)


# ── 精确计量：iptables 端口计数 ──
# 轮询 Clash API 只能看到「轮询那一刻还开着」的连接，两次轮询之间开始又结束的
# 短连接（网页请求、API 调用）会整个漏掉 —— 实测 2MB 的本地下载 0.1 秒就结束，
# 统计到的是 0。内核按端口计数每一个包，不漏也不受 sing-box 重启影响。
# 规则只计数、不带动作，不拦截任何流量。
ACCT = {"ok": None, "ports": None, "prev": {}, "t": 0, "err": ""}
ACCT_CHAINS = (("SBP_IN", "INPUT", "--dport"), ("SBP_OUT", "OUTPUT", "--sport"))
_ACCT_RE = re.compile(r"^\s*\d+\s+(\d+)\s+.*?\b(tcp|udp)\b.*?\b(dpt|spt):(\d+)")


def acct_ports(c):
    out = {}
    for ib in c.get("inbounds", []):
        p = ib.get("listen_port")
        if p and ib.get("listen") not in ("127.0.0.1", "::1", "localhost"):
            out[int(p)] = ib.get("tag")
    return out


def acct_tools():
    return [t for t in ("iptables", "ip6tables") if sh(f"command -v {t}", 5)[0] == 0]


def acct_read(tools):
    """返回 {端口: [入字节, 出字节]}；一条计数链都读不到时返回 None"""
    res, readable = {}, False
    for ipt in tools:
        for ch, _, _ in ACCT_CHAINS:
            c, o, _ = sh(f"{ipt} -w -nvxL {ch} 2>/dev/null", 10)
            if c != 0 or f"Chain {ch}" not in o:
                continue
            readable = True
            for ln in o.splitlines():
                mm = _ACCT_RE.match(ln)
                if mm:
                    r = res.setdefault(int(mm.group(4)), [0, 0])
                    r[0 if ch == "SBP_IN" else 1] += int(mm.group(1))
    return res if readable else None


def acct_setup(tools, ports):
    cmds = []
    for ipt in tools:
        for ch, hook, k in ACCT_CHAINS:
            cmds += [f"{ipt} -w -N {ch} 2>/dev/null",
                     f"{ipt} -w -C {hook} -j {ch} 2>/dev/null || {ipt} -w -I {hook} 1 -j {ch}",
                     f"{ipt} -w -F {ch}"]
            cmds += [f"{ipt} -w -A {ch} -p {pr} {k} {p}" for p in sorted(ports) for pr in ("tcp", "udp")]
    c, _, e = sh("; ".join(cmds) + "; true", 30)
    return c == 0


def acct_credit(cur, ports, dt):
    """把计数器增量记到对应节点上，返回各节点的实时速率"""
    rates = {}
    for port, (bi, bo) in cur.items():
        tag = ports.get(port)
        if not tag:
            continue
        pi, po = ACCT["prev"].get(port, (0, 0))
        di = bi - pi if bi >= pi else bi          # 计数器被清零过：本次读数就是增量
        do = bo - po if bo >= po else bo
        t = STATS["totals"].setdefault(tag, {"up": 0, "down": 0})
        t["up"] += di                              # 进服务器 = 用户上传
        t["down"] += do                            # 出服务器 = 用户下载
        if dt:
            rates[tag] = {"up_rate": di / dt, "down_rate": do / dt}
    ACCT["prev"] = {p: tuple(v) for p, v in cur.items()}
    return rates


def acct_poll():
    tools = ACCT.get("tools")
    if tools is None:
        tools = ACCT["tools"] = acct_tools()
    if not tools:
        ACCT.update(ok=False, err="系统没有 iptables")
        return None
    ports = acct_ports(cfg())
    now = time.time()
    dt = now - ACCT["t"] if ACCT["t"] else 0
    if ports != ACCT["ports"]:
        if ACCT["ports"]:
            old = acct_read(tools)
            if old is not None:
                acct_credit(old, ACCT["ports"], 0)            # 换规则前先把旧计数记账
        acct_setup(tools, ports)
        # 命令串末尾是 `; true`，退出码说明不了什么 —— 以能否读到计数链为准
        if acct_read(tools) is None:
            ACCT.update(ok=False, ports=None, err="iptables 计数链创建失败（可能只有 nftables 或权限不足）")
            return None
        ACCT.update(ports=ports, prev={}, t=now)
        return {}
    # ufw / firewalld 重载时可能把跳转规则冲掉，计数链还在但不再有包经过 —— 定期补回
    ACCT["n"] = ACCT.get("n", 0) + 1
    if ACCT["n"] % 20 == 0:
        sh("; ".join(f"{ipt} -w -C {hook} -j {ch} 2>/dev/null || {ipt} -w -I {hook} 1 -j {ch}"
                     for ipt in tools for ch, hook, _ in ACCT_CHAINS) + "; true", 15)
    cur = acct_read(tools)
    if cur is None:
        # 计数链被外部删掉了（如 iptables -F）：下一轮重建
        ACCT.update(ok=False, ports=None, err="计数链丢失，正在重建")
        return None
    rates = acct_credit(cur, ports, dt)
    ACCT.update(t=now, ok=True, err="")
    return rates


def stats_loop():
    STATS["totals"] = (load_json(STATS_FILE, {}) or {}).get("totals", {})
    time.sleep(8)
    n = 0
    while True:
        if load_json(PANEL_CFG, {}).get("stats_disabled"):
            STATS.update(ok=False, err="流量统计已关闭")
            time.sleep(30)
            continue
        # 实时连接数 / 在线 IP / 总速率：Clash API
        try:
            stats_poll(count_totals=not ACCT.get("ok"))
        except Exception as e:
            STATS.update(ok=False, err=f"{type(e).__name__}: {e}"[:160], primed=False,
                         t=0, tot_raw=None)
            STATS["last"].clear()
        # 累计流量：iptables 精确计数，每 9 秒读一次
        if n % 3 == 0:
            try:
                rates = acct_poll()
                if rates is not None:
                    STATS["acct_rates"] = rates
            except Exception as e:
                ACCT.update(ok=False, err=f"{type(e).__name__}: {e}"[:160])
        n += 1
        if time.time() - STATS["saved"] > 30:
            save_json(STATS_FILE, {"totals": STATS["totals"]})
            STATS["saved"] = time.time()
        time.sleep(3)


# ════════════════════════════════════════════
# 系统监控（仪表盘）：全部读 /proc，不起子进程
# ════════════════════════════════════════════
PROC = "/proc"
SYSMON = {"cpu": None, "net": None, "t": 0, "hist": [], "cur": {}}


def _rd(p):
    try:
        with open(p) as f:
            return f.read()
    except OSError:
        return ""


def _cpu_times():
    ln = _rd(f"{PROC}/stat").split("\n", 1)[0].split()
    if len(ln) < 5 or ln[0] != "cpu":
        return None
    v = [int(x) for x in ln[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v), idle


def _net_bytes():
    rx = tx = 0
    for ln in _rd(f"{PROC}/net/dev").splitlines()[2:]:
        name, _, rest = ln.partition(":")
        name = name.strip()
        if not rest or name == "lo" or name.startswith(("veth", "docker", "br-", "singtun", "tun")):
            continue
        f = rest.split()
        if len(f) >= 9:
            rx += int(f[0])
            tx += int(f[8])
    return rx, tx


def _meminfo():
    mi = {}
    for ln in _rd(f"{PROC}/meminfo").splitlines():
        k, _, v = ln.partition(":")
        try:
            mi[k] = int(v.split()[0]) * 1024
        except (ValueError, IndexError):
            pass
    return mi


def sys_sample():
    now = time.time()
    cur = {}
    ct = _cpu_times()
    if ct and SYSMON["cpu"]:
        dt_, di = ct[0] - SYSMON["cpu"][0], ct[1] - SYSMON["cpu"][1]
        cur["cpu"] = round(100.0 * (dt_ - di) / dt_, 1) if dt_ > 0 else 0.0
    SYSMON["cpu"] = ct
    nb = _net_bytes()
    if SYSMON["net"] and SYSMON["t"]:
        dt = max(0.5, now - SYSMON["t"])
        cur["rx"] = max(0, nb[0] - SYSMON["net"][0]) / dt
        cur["tx"] = max(0, nb[1] - SYSMON["net"][1]) / dt
    SYSMON["net"], SYSMON["t"] = nb, now
    cur["rx_total"], cur["tx_total"] = nb
    mi = _meminfo()
    if mi.get("MemTotal"):
        tot = mi["MemTotal"]
        used = tot - mi.get("MemAvailable", mi.get("MemFree", 0))
        cur["mem"] = {"used": used, "total": tot}
        cur["swap"] = {"used": mi.get("SwapTotal", 0) - mi.get("SwapFree", 0),
                       "total": mi.get("SwapTotal", 0)}
    try:
        st = os.statvfs("/")
        cur["disk"] = {"used": (st.f_blocks - st.f_bfree) * st.f_frsize,
                       "total": st.f_blocks * st.f_frsize}
    except OSError:
        pass
    try:
        cur["load"] = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        pass
    up = _rd(f"{PROC}/uptime").split()
    if up:
        cur["uptime"] = int(float(up[0]))
    SYSMON["cur"] = cur
    if "cpu" in cur:
        mem_pct = round(100.0 * cur["mem"]["used"] / cur["mem"]["total"], 1) if cur.get("mem") else 0
        SYSMON["hist"].append([int(now), cur["cpu"], mem_pct,
                               round(cur.get("rx", 0)), round(cur.get("tx", 0))])
        del SYSMON["hist"][:-120]


def sys_loop():
    while True:
        try:
            sys_sample()
        except Exception as e:
            SYSMON["cur"]["err"] = str(e)[:120]
        time.sleep(3)


def sys_static():
    def _f():
        cpu = next((ln.split(":", 1)[1].strip() for ln in _rd(f"{PROC}/cpuinfo").splitlines()
                    if ln.lower().startswith(("model name", "hardware"))), "")
        osr = next((ln.split("=", 1)[1].strip().strip('"') for ln in _rd("/etc/os-release").splitlines()
                    if ln.startswith("PRETTY_NAME=")), "")
        u = os.uname()
        return {"host": u.nodename, "kernel": u.release, "arch": u.machine, "os": osr,
                "cpu_model": cpu, "cores": os.cpu_count() or 0}
    return cached("sys_static", 3600, _f)


def sb_proc():
    def _f():
        _, pid, _ = sh("systemctl show -p MainPID --value sing-box", 5)
        pid = pid.strip()
        return int(pid) if pid.isdigit() and pid != "0" else 0
    pid = cached("sb_pid", 15, _f)
    if not pid:
        return {}
    out = {"pid": pid}
    for ln in _rd(f"{PROC}/{pid}/status").splitlines():
        if ln.startswith("VmRSS:"):
            out["rss"] = int(ln.split()[1]) * 1024
    stat = _rd(f"{PROC}/{pid}/stat")
    up = _rd(f"{PROC}/uptime").split()
    if stat and up:
        try:
            start = int(stat.rsplit(")", 1)[1].split()[19])
            out["uptime"] = int(float(up[0]) - start / os.sysconf("SC_CLK_TCK"))
        except (IndexError, ValueError, OSError):
            pass
    if not out.get("rss"):
        cache_bust("sb_pid")              # 进程换了（重启过），下次重新取 PID
    return out


def api_dashboard():
    c, m = cfg(), meta()
    d = load_users()
    now = time.time()
    nodes = []
    for ib in c.get("inbounds", []):
        t = ib.get("tag")
        if t.endswith("-ss") and ib.get("listen") == "127.0.0.1":
            continue
        lv = STATS["live"].get(t, {})
        tot = STATS["totals"].get(t, {})
        p = node_proto(ib, m)
        multi = p in MULTI_USER and bool(ib.get("users"))
        nodes.append({"tag": t, "name": m.get(t, {}).get("name", t), "proto": p,
                      "port": ib.get("listen_port"), "multi": multi,
                      # 不支持多用户的节点，分配了也不会生效，不能算进去
                      "users": sum(1 for u in d["users"] if t in (u.get("inbounds") or []) and user_active(u, now))
                      if multi else None,
                      "conns": lv.get("conns", 0), "ips": lv.get("ips", 0),
                      "up_rate": lv.get("up_rate", 0), "down_rate": lv.get("down_rate", 0),
                      "up": tot.get("up", 0), "down": tot.get("down", 0)})
    act = cached("sb_state", 10,
                 lambda: (sh("systemctl is-active sing-box", 5)[1].strip() or "unknown"))
    return {"sys": dict(SYSMON["cur"], **sys_static(), ip=public_ip()),
            "hist": SYSMON["hist"][-60:],
            "sb": dict(sb_proc(), running=act == "active", version=cur_version_cached(),
                       conns=STATS["conns"]),
            "stats": {"ok": STATS["ok"], "err": STATS["err"], "rate": STATS["rate"],
                      "mode": "iptables" if ACCT.get("ok") else "clash",
                      "acct_err": ACCT.get("err", ""),
                      "hist": STATS["hist"][-60:],
                      "disabled": bool(load_json(PANEL_CFG, {}).get("stats_disabled"))},
            "users": {"total": len(d["users"]),
                      "active": sum(1 for u in d["users"] if user_active(u, now))},
            "nodes": nodes}


def cur_version_cached():
    return cached("sb_ver", 60, cur_version)


def api_stats_reset(tag):
    if tag:
        STATS["totals"].pop(tag, None)
    else:
        STATS["totals"].clear()
    save_json(STATS_FILE, {"totals": STATS["totals"]})
    return True, "已清零"


def api_stats_toggle(on):
    pc = load_json(PANEL_CFG, {})
    if on:
        pc.pop("stats_disabled", None)
    else:
        pc["stats_disabled"] = True
    save_json(PANEL_CFG, pc)
    okk, msg = apply_config(cfg())
    return (True, "流量统计已" + ("开启" if on else "关闭")) if okk else (False, msg)


# ════════════════════════════════════════════
# 路由规则 / DNS 可视化编辑（参照 s-ui Rules / DNS）
# ════════════════════════════════════════════
def _dict_list(v, what):
    if not isinstance(v, list) or not all(isinstance(x, dict) for x in v):
        raise ValueError(f"{what} 格式错误")
    return v


def api_route_get():
    c = cfg()
    r = c.get("route") or {}
    return {"rules": r.get("rules") or [], "rule_set": r.get("rule_set") or [],
            "final": r.get("final") or "direct",
            "outbounds": [o.get("tag") for o in c.get("outbounds", [])],
            "inbounds": [i.get("tag") for i in c.get("inbounds", [])
                         if not (i.get("tag", "").endswith("-ss") and i.get("listen") == "127.0.0.1")],
            "dns_servers": [s.get("tag") for s in (c.get("dns") or {}).get("servers", [])]}


def api_route_set(b):
    c = cfg()
    try:
        rules = _dict_list(b.get("rules", []), "规则")
        rsets = _dict_list(b.get("rule_set", []), "规则集")
    except ValueError as e:
        return False, str(e)
    tags = [x.get("tag") for x in rsets]
    if any(not t for t in tags) or len(tags) != len(set(tags)):
        return False, "规则集标签不能为空或重复"
    # 按域名 / 协议分流离不开嗅探；用户把它删了就补回最前面
    if not any(r.get("action") == "sniff" for r in rules):
        rules = [{"action": "sniff"}] + rules
    route = dict(c.get("route") or {})
    route["rules"] = rules
    if rsets:
        route["rule_set"] = rsets
    else:
        route.pop("rule_set", None)
    final = (b.get("final") or "direct").strip()
    if final not in {o.get("tag") for o in c.get("outbounds", [])}:
        return False, f"默认出站 {final} 不存在"
    route["final"] = final
    # 远程规则集需要显式的 HTTP 客户端（1.14 起隐式默认已弃用）
    if any(x.get("type") == "remote" for x in rsets) and not c.get("http_clients"):
        c["http_clients"] = [{"tag": "direct-http"}]
        route["default_http_client"] = "direct-http"
    c["route"] = route
    okk, msg = apply_config(c)
    return (True, "路由已保存") if okk else (False, msg)


def api_dns_get():
    c = cfg()
    ddr = (c.get("route") or {}).get("default_domain_resolver")
    return {"dns": c.get("dns") or {},
            "resolver": (ddr.get("server") if isinstance(ddr, dict) else ddr) or "",
            "outbounds": [o.get("tag") for o in c.get("outbounds", [])],
            "rule_sets": [x.get("tag") for x in (c.get("route") or {}).get("rule_set", [])],
            "inbounds": [i.get("tag") for i in c.get("inbounds", [])]}


def api_dns_set(b):
    c = cfg()
    dns = b.get("dns")
    if not isinstance(dns, dict):
        return False, "DNS 格式错误"
    try:
        servers = _dict_list(dns.get("servers", []), "DNS 服务器")
        _dict_list(dns.get("rules", []), "DNS 规则")
    except ValueError as e:
        return False, str(e)
    st = [s.get("tag") for s in servers]
    if any(not t for t in st) or len(st) != len(set(st)):
        return False, "DNS 服务器标签不能为空或重复"
    dns = {k: v for k, v in dns.items() if v not in (None, "", [], {})}
    route = c.setdefault("route", {})
    if dns:
        c["dns"] = dns
    else:
        c.pop("dns", None)
    # 配了不止一个 DNS 服务器时，sing-box 要求指定出站解析域名用哪个（1.12 起）
    want = (b.get("resolver") or "").strip()
    if want and want not in st:
        return False, f"出站解析服务器 {want} 不存在"
    if not want and st:
        cur = route.get("default_domain_resolver")
        cur = cur.get("server") if isinstance(cur, dict) else cur
        want = cur if cur in st else (dns.get("final") if dns.get("final") in st else st[0])
    if want:
        route["default_domain_resolver"] = want
    else:
        route.pop("default_domain_resolver", None)
    okk, msg = apply_config(c)
    return (True, "DNS 已保存") if okk else (False, msg)


# ════════════════════════════════════════════
# 备份 / 恢复
# ════════════════════════════════════════════
def api_backup():
    pc = load_json(PANEL_CFG, {})
    return {"app": "sb-panel", "ver": 1, "time": time.strftime("%F %T"),
            "config": cfg(), "meta": meta(), "users": load_users(),
            "panel": {k: pc[k] for k in ("sub_token", "auto_update") if k in pc}}


def api_restore(b):
    bk = b.get("backup")
    if not isinstance(bk, dict) or bk.get("app") != "sb-panel" or not isinstance(bk.get("config"), dict):
        return False, "不是本面板导出的备份文件"
    if not isinstance(bk.get("config", {}).get("inbounds", []), list):
        return False, "备份里的配置格式错误"
    old_meta, old_users = load_json(META_FILE, {}), load_json(USERS_FILE, None)
    save_json(META_FILE, bk.get("meta") or {})
    save_json(USERS_FILE, bk.get("users") or {"users": [], "managed": {}})
    okk, msg = apply_config(bk["config"])
    if not okk:
        save_json(META_FILE, old_meta)
        if old_users is not None:
            save_json(USERS_FILE, old_users)
        return False, msg
    pc = load_json(PANEL_CFG, {})
    pc.update(bk.get("panel") or {})
    save_json(PANEL_CFG, pc)
    rebuild_sub()
    return True, "已恢复"


HTML = r"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sing-box 面板</title><style>
:root{
 --bg:#0d0f13; --bg2:#141721; --card:#171a23; --card2:#1c2029;
 --line:#242938; --line2:#2e3546;
 --tx:#e8eaf0; --tx2:#8b93a7; --tx3:#5c6478;
 --pri:#3b82f6; --pri2:#2563eb; --ok:#34d399; --warn:#fbbf24; --err:#f87171;
 --r:12px; --r2:9px; --sh:0 1px 3px rgba(0,0,0,.4),0 8px 24px -8px rgba(0,0,0,.5);
 --side:228px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);
 font:14px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC","Segoe UI",sans-serif;
 -webkit-font-smoothing:antialiased}
a{color:var(--pri);text-decoration:none}
a:hover{opacity:.8}
/* ── 布局：左侧导航（参照 s-ui）── */
.side{position:fixed;top:0;bottom:0;left:0;width:var(--side);background:var(--bg2);
 border-right:1px solid var(--line);display:flex;flex-direction:column;z-index:40;transition:transform .2s}
.brand{display:flex;align-items:center;gap:10px;padding:18px 18px 14px;font-weight:650;font-size:15.5px}
.brand i{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,var(--pri),#8b5cf6);
 display:grid;place-items:center;font-style:normal;font-size:14px;color:#fff}
.nav{flex:1;overflow-y:auto;padding:4px 10px 12px}
.nav a{display:flex;align-items:center;gap:11px;padding:8px 12px;margin:1px 0;border-radius:var(--r2);
 color:var(--tx2);font-size:13.5px;font-weight:500;cursor:pointer;user-select:none;transition:.12s}
.nav a:hover{background:var(--card2);color:var(--tx);opacity:1}
.nav a.active{background:rgba(59,130,246,.14);color:#fff}
.nav a.active svg{color:var(--pri)}
.nav svg{width:18px;height:18px;flex:0 0 auto}
.nav .sep{height:1px;background:var(--line);margin:8px 6px}
.sidefoot{padding:12px 16px;border-top:1px solid var(--line);font-size:11.5px;color:var(--tx3)}
.main{margin-left:var(--side);min-width:0}
.topbar{position:sticky;top:0;z-index:20;background:rgba(13,15,19,.92);backdrop-filter:blur(8px);
 border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:11px 24px;flex-wrap:wrap}
.topbar h1{font-size:16px;font-weight:650;white-space:nowrap}
.burger{display:none;background:none;border:0;padding:4px;color:var(--tx);cursor:pointer}
.burger svg{width:22px;height:22px}
.content{padding:20px 24px 48px;max-width:1320px}
.mask{display:none}
@media(max-width:900px){
 .side{transform:translateX(-100%)} .side.open{transform:none;box-shadow:var(--sh)}
 .main{margin-left:0} .burger{display:block}
 .mask.show{display:block;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:35}
 .content{padding:16px 14px 40px} .topbar{padding:10px 14px}}
@media(max-width:600px){.topbar .stat{display:none} .topbar{flex-wrap:nowrap} .topbar h1{flex:1}
 .content .tiles{grid-template-columns:1fr 1fr;gap:10px} .content .gauge{flex-direction:column;text-align:center;gap:6px;padding:12px 8px}
 .content .gauge svg{width:62px;height:62px} .content .gauge .gt{width:100%}}
.stat{display:flex;gap:16px;font-size:12.5px;color:var(--tx2);flex-wrap:wrap;flex:1}
.stat b{color:var(--tx);font-weight:600}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;vertical-align:1px}
.on{background:var(--ok);box-shadow:0 0 0 3px rgba(52,211,153,.15)}
.off{background:var(--err);box-shadow:0 0 0 3px rgba(248,113,113,.15)}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);
 padding:16px 18px;margin-bottom:12px;transition:border-color .15s;min-width:0}
.card:hover{border-color:var(--line2)}
.card h3{font-size:14.5px;font-weight:600;margin-bottom:10px;
 display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.card h3 .sp{flex:1}
.badge{font-size:10.5px;padding:2px 8px;border-radius:20px;background:var(--bg2);
 color:var(--tx2);font-weight:500;border:1px solid var(--line);white-space:nowrap}
.badge.g{background:rgba(52,211,153,.12);color:var(--ok);border-color:rgba(52,211,153,.3)}
.badge.y{background:rgba(251,191,36,.12);color:var(--warn);border-color:rgba(251,191,36,.3)}
.badge.r{background:rgba(248,113,113,.12);color:var(--err);border-color:rgba(248,113,113,.3)}
.badge.b{background:rgba(59,130,246,.12);color:#93c5fd;border-color:rgba(59,130,246,.3)}
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
.sm{padding:4px 10px;font-size:12px}
.acts{display:flex;gap:8px;margin-top:13px;flex-wrap:wrap;align-items:center}
.bar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.bar .sp{flex:1}
label{display:block;font-size:12.5px;color:var(--tx2);margin:13px 0 5px;font-weight:500}
label .hint{color:var(--tx3);font-weight:400;font-size:11.5px;margin-left:6px}
input,select,textarea{width:100%;background:#0a0c10;border:1px solid var(--line2);
 border-radius:var(--r2);padding:9px 11px;color:var(--tx);font-size:13.5px;
 font-family:inherit;transition:.15s}
textarea{font:12px/1.55 ui-monospace,Menlo,monospace;resize:vertical;min-height:64px}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--pri);box-shadow:0 0 0 3px rgba(59,130,246,.12)}
input::placeholder,textarea::placeholder{color:var(--tx3)}
select{cursor:pointer}
.bar input,.bar select{width:auto;padding:7px 10px;font-size:13px}
.f2{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}
.f3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0 12px}
@media(max-width:600px){.f2,.f3{grid-template-columns:1fr}}
.chk{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:var(--r2);
 cursor:pointer;margin:0;color:var(--tx);font-size:13.5px;transition:background-color .12s}
.chk:hover{background:var(--card2)}
.chk input{width:16px;height:16px;accent-color:var(--pri);flex:0 0 auto;cursor:pointer}
.chk span{flex:0 0 auto;white-space:nowrap}
.chk i{color:var(--tx3);font-style:normal;font-size:11.5px;line-height:1.45;flex:1;min-width:0}
.chk em{color:var(--warn);font-style:normal;font-size:11px;margin-left:7px}
.chk.dis{opacity:.45;cursor:not-allowed}
.hbadge{font-size:11.5px;padding:3px 10px;border-radius:20px;cursor:pointer;
 font-weight:600;white-space:nowrap;transition:.15s;border:1px solid transparent}
.hbadge.green{background:rgba(52,211,153,.12);color:var(--ok);border-color:rgba(52,211,153,.3)}
.hbadge.yellow{background:rgba(251,191,36,.12);color:var(--warn);border-color:rgba(251,191,36,.35)}
.hbadge.red{background:rgba(248,113,113,.14);color:var(--err);border-color:rgba(248,113,113,.4)}
.hgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px;margin-top:4px}
.hitem{background:var(--bg2);border:1px solid var(--line);border-radius:var(--r2);padding:9px 11px}
.hitem b{display:block;font-size:11.5px;color:var(--tx2);font-weight:500;margin-bottom:3px}
.hitem span{font-size:13px}
.chkbox{background:#0a0c10;border:1px solid var(--line2);border-radius:var(--r2);
 padding:5px;max-height:240px;overflow:auto}
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
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:12px}
@media(max-width:600px){.grid,.grid2{grid-template-columns:1fr}}
/* ── 仪表盘 ── */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px;margin-bottom:12px}
.gauge{display:flex;align-items:center;gap:14px;padding:16px}
.gauge svg{width:74px;height:74px;flex:0 0 auto}
.gauge .gt{min-width:0}
.gauge .gt b{display:block;font-size:12.5px;color:var(--tx2);font-weight:500}
.gauge .gt span{display:block;font-size:12px;color:var(--tx3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chart{width:100%;height:120px;display:block}
.legend{display:flex;gap:16px;font-size:12px;color:var(--tx2);margin-top:6px;flex-wrap:wrap}
.legend i{display:inline-block;width:10px;height:3px;border-radius:2px;margin-right:6px;vertical-align:3px}
.big{font-size:20px;font-weight:650;letter-spacing:.2px}
/* ── 表格 ── */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;color:var(--tx2);font-weight:500;font-size:12px;padding:8px 10px;
 border-bottom:1px solid var(--line2);white-space:nowrap}
.tbl td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
.tbl tr:hover td{background:rgba(255,255,255,.015)}
.tbl input[type=checkbox]{width:15px;height:15px;accent-color:var(--pri)}
.tw{overflow-x:auto;margin:0 -4px}
.num{font-variant-numeric:tabular-nums}
.mut{color:var(--tx3)}
/* 开关 */
.sw{position:relative;display:inline-block;width:34px;height:19px;flex:0 0 auto}
.sw input{opacity:0;width:0;height:0}
.sw span{position:absolute;inset:0;background:var(--line2);border-radius:20px;transition:.15s;cursor:pointer}
.sw span::before{content:"";position:absolute;width:15px;height:15px;left:2px;top:2px;background:#fff;border-radius:50%;transition:.15s}
.sw input:checked+span{background:var(--ok)}
.sw input:checked+span::before{transform:translateX(15px)}
/* 规则卡片 */
.rule{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--line);
 border-radius:var(--r2);background:var(--bg2);margin-bottom:8px}
.rule .ri{color:var(--tx3);font-size:12px;width:20px;text-align:center;flex:0 0 auto}
.rule .rb{flex:1;min-width:0;font-size:13px}
.rule .rb .c{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:6px;background:var(--card2);
 border:1px solid var(--line2);margin:2px 4px 2px 0;color:var(--tx2);max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle}
.rule .ra{white-space:nowrap;font-size:12.5px;font-weight:600}
.rule .ops{display:flex;gap:4px;flex:0 0 auto}
.ib{background:none;border:1px solid transparent;color:var(--tx2);padding:4px 7px;border-radius:7px;font-size:12px}
.ib:hover{background:var(--card2);color:var(--tx);border-color:var(--line2)}
.ib:disabled{opacity:.25}
.dirty{color:var(--warn);font-size:12px}
/* 标签页（弹窗内） */
.mtabs{display:flex;gap:2px;margin:14px 0 4px;background:var(--bg2);padding:4px;border-radius:var(--r);width:100%}
.mtab{flex:1;text-align:center;padding:7px 12px;border-radius:var(--r2);cursor:pointer;color:var(--tx2);
 font-size:13px;font-weight:500;user-select:none;transition:.15s}
.mtab:hover{color:var(--tx)}
.mtab.active{background:var(--card2);color:#fff;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.8);
 display:none;align-items:flex-start;justify-content:center;
 padding:4vh 20px 20px;z-index:99;overscroll-behavior:contain}
.modal.show{display:flex;animation:fade .18s ease}
@keyframes fade{from{opacity:0}to{opacity:1}}
.mbox{background:var(--card);border:1px solid var(--line2);border-radius:16px;
 padding:22px 24px;max-width:560px;width:100%;max-height:92vh;overflow-y:auto;
 box-shadow:var(--sh);animation:pop .2s cubic-bezier(.2,.9,.3,1.2);
 overscroll-behavior:contain;scrollbar-gutter:stable;transform:translateZ(0);contain:paint}
.mbox.wide{max-width:780px}
.mbox.scrolling *{pointer-events:none}
@keyframes pop{from{transform:translateY(12px) scale(.98);opacity:0}}
.mbox h2{font-size:16.5px;font-weight:650;margin-bottom:4px}
.toast{position:fixed;bottom:26px;left:50%;transform:translateX(-50%);
 background:var(--card2);border:1px solid var(--line2);padding:11px 20px;
 border-radius:11px;display:none;z-index:100;max-width:90%;font-size:13.5px;box-shadow:var(--sh);white-space:pre-wrap}
.toast.show{display:block;animation:up .22s cubic-bezier(.2,.9,.3,1.2)}
@keyframes up{from{transform:translate(-50%,14px);opacity:0}}
.toast.err{border-color:rgba(248,113,113,.4);color:#ffb4b4}
.toast.ok{border-color:rgba(52,211,153,.4);color:#8ff0c4}
.alert{background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.28);
 color:#f5d78e;border-radius:var(--r2);padding:11px 13px;font-size:12.5px;
 margin-bottom:10px;line-height:1.7}
.note{background:rgba(59,130,246,.06);border:1px solid rgba(59,130,246,.22);color:#a9c8f5;
 border-radius:var(--r2);padding:10px 13px;font-size:12.5px;margin-bottom:12px;line-height:1.7}
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
body.mopen{overflow:hidden}
.login{max-width:350px;margin:16vh auto;padding:0 20px}
.login .card{padding:24px}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:#3a4356}
</style></head><body>
<div id="login" class="login" style="display:none">
  <div class="card"><h3>sing-box 面板</h3>
    <label>用户名</label><input type="text" id="usr" autocomplete="username"
      onkeydown="if(event.key==='Enter')document.getElementById('pw').focus()">
    <label>密码</label><input type="password" id="pw" autocomplete="current-password"
      onkeydown="if(event.key==='Enter')doLogin()">
    <div class="acts"><button onclick="doLogin()">登录</button></div>
  </div>
</div>
<div id="app" style="display:none">
<aside class="side" id="side">
  <div class="brand"><i>S</i>sing-box 面板</div>
  <nav class="nav" id="nav"></nav>
  <div class="sidefoot" id="sidefoot">—</div>
</aside>
<div class="mask" id="mask" onclick="sideOpen(0)"></div>
<div class="main">
<header class="topbar">
  <button class="burger" onclick="sideOpen(1)" aria-label="菜单"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button>
  <h1 id="ptitle">首页</h1>
  <span id="hbadge" class="hbadge" title="系统健康" onclick="go('log')">检查中…</span>
  <div class="stat" id="stat"></div>
  <div style="display:flex;gap:8px">
    <button class="btn2" onclick="restart()">重启</button>
    <button class="btn2" onclick="logout()">退出</button>
  </div>
</header>
<div class="content">
<div id="p-home"></div>
<div id="p-in" style="display:none"><div class="bar"><button onclick="newNode()">+ 添加节点</button><span class="sp"></span><span class="mut" style="font-size:12px">流量为节点累计 · 首页可看实时速度</span></div><div id="inlist" class="grid"></div></div>
<div id="p-users" style="display:none"></div>
<div id="p-out" style="display:none"><div class="bar"><button onclick="newOut()">+ 添加出站</button>
 <button class="btn2" onclick="speedAll()">⚡ 全部测延迟</button></div><div id="outlist" class="grid"></div></div>
<div id="p-cert" style="display:none"><div class="bar"><button onclick="newCert()">+ 申请证书</button></div><div id="certlist" class="grid"></div></div>
<div id="p-route" style="display:none"></div>
<div id="p-dns" style="display:none"></div>
<div id="p-sub" style="display:none"><div class="card"><h3>订阅链接 <span class="badge">包含全部节点</span></h3>
 <div class="uri" id="suburl" onclick="cp(this.textContent)"></div>
 <div id="subinfo" style="margin-top:12px"></div></div>
 <div class="note">每个用户还有自己的订阅链接，只包含分配给他的节点，在「用户」页的「链接」里查看。</div></div>
<div id="p-ver" style="display:none"><div id="verbox"></div></div>
<div id="p-log" style="display:none">
 <div class="card"><h3>系统健康 <span id="hdetail" class="badge">…</span></h3>
  <div id="hbox"></div>
  <div class="acts"><button class="btn2" onclick="loadHealth()">刷新</button></div></div>
 <div class="card"><h3>面板运行日志 <span class="badge">自愈动作与异常</span></h3>
  <pre id="runlog" style="max-height:240px"></pre></div>
 <div class="card">
 <h3>sing-box 日志 <span id="log-badge" class="badge">…</span></h3>
 <div id="log-ctl"></div>
 <div class="acts" style="margin-bottom:10px"><button class="btn2" onclick="loadLog()">刷新</button></div>
 <pre id="logbox"></pre></div></div>
<div id="p-set" style="display:none"></div>
</div></div></div>
<div class="modal" id="modal"><div class="mbox" id="mbox"></div></div>
<div class="toast" id="toast"></div>
<script>
const BASE='__BASE__';
let TK=localStorage.getItem('tk')||'',PROTOS={},CERTS=[],OUTS=[],USERS=null;
const $=id=>document.getElementById(id);
function msg(t,ok){const e=$('toast');e.textContent=t;e.className='toast show '+(ok?'ok':'err');clearTimeout(msg._t);msg._t=setTimeout(()=>e.className='toast',ok?3000:6000)}
async function api(p,m,b){const r=await fetch(BASE+'/api'+p,{method:m||'GET',headers:{'Content-Type':'application/json','X-Token':TK},body:b?JSON.stringify(b):null});
 if(r.status===401){TK='';localStorage.removeItem('tk');show(0);throw new Error('未登录')}return r.json()}
function esc(s){return String(s==null?'':s).replace(/[<>&"']/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]))}
function cp(t){navigator.clipboard.writeText(t).then(()=>msg('已复制',1),()=>msg('复制失败，请手动选择'))}
function openM(html,wide){const b=$('mbox');b.className='mbox'+(wide?' wide':'');b.innerHTML=html;$('modal').classList.add('show')}
function closeM(){$('modal').classList.remove('show')}

// ── 格式化 ──
function fmtB(n){n=+n||0;const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(n<10?2:1):n)+' '+u[i]}
function fmtR(n){return fmtB(n)+'/s'}
function fmtDur(s){if(s==null)return '—';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
 return d?`${d}天${h}小时`:(h?`${h}小时${m}分`:`${m}分`)}
function fmtTs(ts){if(!ts)return '—';const d=new Date(ts*1000);const p=x=>String(x).padStart(2,'0');
 return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`}
function toLocalInput(ts){if(!ts)return '';const d=new Date(ts*1000);const p=x=>String(x).padStart(2,'0');
 return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`}
function expTxt(u){if(!u.expiry)return '<span class="mut">永久</span>';
 const left=u.expiry-Date.now()/1000;
 if(left<=0)return '<span class="badge r">已过期</span>';
 const d=Math.ceil(left/86400);return `<span class="${d<=3?'badge y':''}" title="${fmtTs(u.expiry)}">剩 ${d} 天</span>`}

// ── 导航 ──
const IC={
 home:'<path d="M3 11.5 12 4l9 7.5"/><path d="M5 10v10h5v-6h4v6h5V10"/>',
 in:'<path d="M7 18a5 5 0 1 1 .9-9.9A6 6 0 0 1 19 10a4 4 0 0 1-1 7.9"/><path d="M12 11v9m-3-3 3 3 3-3"/>',
 users:'<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6 6 0 0 1 3.5 6"/>',
 out:'<path d="M7 18a5 5 0 1 1 .9-9.9A6 6 0 0 1 19 10a4 4 0 0 1-1 7.9"/><path d="M12 20v-9m-3 3 3-3 3 3"/>',
 cert:'<rect x="4" y="3" width="16" height="13" rx="2"/><path d="M8 8h8M8 11h5"/><path d="m9 16-1 5 4-2 4 2-1-5"/>',
 route:'<circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><path d="M6 17V9a3 3 0 0 1 3-3h7M18 7v8a3 3 0 0 1-3 3H8"/>',
 dns:'<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
 sub:'<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
 ver:'<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/>',
 log:'<path d="M5 4h14v16H5z"/><path d="M8 8h8M8 12h8M8 16h5"/>',
 set:'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'};
const PAGES=[['home','首页'],['in','节点'],['users','用户'],['out','出站'],['cert','证书'],'|',['route','路由规则'],['dns','DNS'],['sub','订阅'],'|',['ver','版本'],['log','日志'],['set','设置']];
let CUR='home';
function renderNav(){$('nav').innerHTML=PAGES.map(p=>p==='|'?'<div class="sep"></div>':
 `<a data-p="${p[0]}" onclick="go('${p[0]}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${IC[p[0]]}</svg>${p[1]}</a>`).join('')}
function sideOpen(v){$('side').classList.toggle('open',!!v);$('mask').classList.toggle('show',!!v)}
function go(p){if(CUR==='route'&&p!=='route'&&RT&&RT.dirty&&!confirm('路由规则有未保存的修改，确定离开？'))return;
 if(CUR==='dns'&&p!=='dns'&&DN&&DN.dirty&&!confirm('DNS 有未保存的修改，确定离开？'))return;
 CUR=p;sideOpen(0);try{localStorage.setItem('pg',p)}catch(e){}
 document.querySelectorAll('.nav a').forEach(a=>a.classList.toggle('active',a.dataset.p===p));
 PAGES.forEach(x=>{if(x!=='|')$('p-'+x[0]).style.display=x[0]===p?'block':'none'});
 $('ptitle').textContent=(PAGES.find(x=>x[0]===p)||[0,''])[1];
 if(p==='home')loadHome();if(p==='in')loadIn();if(p==='users')loadUsers();if(p==='out')loadOut();
 if(p==='cert')loadCerts();if(p==='route')loadRoute();if(p==='dns')loadDns();if(p==='sub')loadSub();
 if(p==='ver')loadVer();if(p==='log'){loadLog();loadHealth()}if(p==='set')loadSet()}

function show(in_){$('login').style.display=in_?'none':'block';$('app').style.display=in_?'block':'none';
 if(in_){renderNav();refresh();startPoll();let pg='home';try{pg=localStorage.getItem('pg')||'home'}catch(e){}
  go(PAGES.some(x=>x[0]===pg)?pg:'home')}else stopPoll()}
async function doLogin(){const pw=$('pw').value,us=$('usr').value;
 const r=await(await fetch(BASE+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:us,password:pw})})).json();
 if(r.ok){TK=r.token;localStorage.setItem('tk',TK);show(1)}else msg('用户名或密码错误')}
function logout(){TK='';localStorage.removeItem('tk');show(0)}
async function refresh(){const s=await api('/status');
 $('stat').innerHTML=`<span><span class="dot ${s.running?'on':'off'}"></span>${s.running?'运行中':'已停止'}</span><span>版本 <b>${esc(s.version)}</b></span><span>IP <b>${esc(s.ip)}</b></span>`;
 $('sidefoot').innerHTML=`sing-box ${esc(s.version)} · 节点 ${s.inbounds} · 出站 ${s.outbounds}`;
 PROTOS=await api('/protocols');loadHealth()}
let _hTimer=null,_dTimer=null;
function startPoll(){stopPoll();_hTimer=setInterval(()=>{if(TK)loadHealth().catch(()=>{})},60000);
 _dTimer=setInterval(()=>{if(TK&&CUR==='home'&&!document.hidden)loadHome(1).catch(()=>{})},3000)}
function stopPoll(){if(_hTimer)clearInterval(_hTimer);if(_dTimer)clearInterval(_dTimer);_hTimer=_dTimer=null}

// ════════ 首页仪表盘 ════════
function gauge(label,pct,sub,color){pct=Math.max(0,Math.min(100,pct||0));const C=2*Math.PI*30,off=C*(1-pct/100);
 const col=color||(pct>=90?'var(--err)':pct>=70?'var(--warn)':'var(--pri)');
 return `<div class="card gauge"><svg viewBox="0 0 74 74"><circle cx="37" cy="37" r="30" fill="none" stroke="var(--line)" stroke-width="7"/>
  <circle cx="37" cy="37" r="30" fill="none" stroke="${col}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 37 37)" style="transition:stroke-dashoffset .6s"/>
  <text x="37" y="42" text-anchor="middle" fill="var(--tx)" font-size="15" font-weight="650">${Math.round(pct)}%</text></svg>
  <div class="gt"><b>${label}</b><span>${sub||''}</span></div></div>`}
function chart(series,colors,fmtMax){// series: [[v...],...]
 const W=600,H=120,n=Math.max(2,...series.map(s=>s.length));let mx=0;series.forEach(s=>s.forEach(v=>mx=Math.max(mx,v||0)));
 const top=mx>0?mx*1.15:1;const x=i=>(i/(n-1))*W,y=v=>H-6-((v||0)/top)*(H-14);
 let g='';for(let k=1;k<4;k++)g+=`<line x1="0" x2="${W}" y1="${k*H/4}" y2="${k*H/4}" stroke="var(--line)" stroke-width="1"/>`;
 const paths=series.map((s,j)=>{if(!s.length)return'';const off=n-s.length;const pts=s.map((v,i)=>`${x(i+off).toFixed(1)},${y(v).toFixed(1)}`);
  return `<path d="M${x(off)},${H} L${pts.join(' L')} L${x(n-1)},${H} Z" fill="${colors[j]}" opacity=".12"/><polyline points="${pts.join(' ')}" fill="none" stroke="${colors[j]}" stroke-width="2" stroke-linejoin="round"/>`}).join('');
 return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${g}${paths}<text x="6" y="14" fill="var(--tx3)" font-size="11">${fmtMax?fmtMax(mx):Math.round(mx)}</text></svg>`}
async function loadHome(silent){const box=$('p-home');
 if(!silent&&!box.innerHTML)box.innerHTML='<div class="card"><div class="scanning">加载中…</div></div>';
 let d;try{d=await api('/dashboard')}catch(e){return}
 if(CUR!=='home')return;
 const s=d.sys||{},sb=d.sb||{},st=d.stats||{};
 const mem=s.mem||{},dsk=s.disk||{},swp=s.swap||{};
 const pc=(o)=>o&&o.total?100*o.used/o.total:0;
 const h=d.hist||[],sh=st.hist||[];
 let mode='';
 if(st.disabled)mode='<span class="badge">已关闭</span>';
 else if(!st.ok)mode=`<span class="badge r" title="${esc(st.err)}">Clash API 不可用</span>`;
 else mode=st.mode==='iptables'?'<span class="badge g" title="内核按端口计数，不漏短连接">精确计数</span>':`<span class="badge y" title="${esc(st.acct_err||'')}：轮询连接估算，短连接可能漏算">估算</span>`;
 const nodes=d.nodes||[];
 box.innerHTML=`<div class="tiles">
   ${gauge('CPU',s.cpu,`${s.cores||'?'} 核 · 负载 ${(s.load||[]).join(' / ')||'—'}`)}
   ${gauge('内存',pc(mem),mem.total?`${fmtB(mem.used)} / ${fmtB(mem.total)}`:'—')}
   ${gauge('硬盘',pc(dsk),dsk.total?`${fmtB(dsk.used)} / ${fmtB(dsk.total)}`:'—')}
   ${gauge('交换区',pc(swp),swp.total?`${fmtB(swp.used)} / ${fmtB(swp.total)}`:'未启用','#8b5cf6')}
  </div>
  <div class="grid2">
   <div class="card"><h3>服务器网速<span class="sp"></span><span class="num" style="font-size:12.5px;color:var(--tx2)">↓ <b style="color:#60a5fa">${fmtR(s.rx||0)}</b> &nbsp; ↑ <b style="color:#34d399">${fmtR(s.tx||0)}</b></span></h3>
    ${chart([h.map(x=>x[3]),h.map(x=>x[4])],['#60a5fa','#34d399'],v=>fmtR(v))}
    <div class="legend"><span><i style="background:#60a5fa"></i>下行</span><span><i style="background:#34d399"></i>上行</span><span class="mut">开机以来 ↓ ${fmtB(s.rx_total)} · ↑ ${fmtB(s.tx_total)}</span></div></div>
   <div class="card"><h3>CPU / 内存<span class="sp"></span><span class="num" style="font-size:12.5px;color:var(--tx2)">CPU <b>${s.cpu==null?'—':s.cpu+'%'}</b> &nbsp; 内存 <b>${Math.round(pc(mem))}%</b></span></h3>
    ${chart([h.map(x=>x[1]),h.map(x=>x[2])],['#f59e0b','#a78bfa'],v=>Math.round(v)+'%')}
    <div class="legend"><span><i style="background:#f59e0b"></i>CPU</span><span><i style="background:#a78bfa"></i>内存</span><span class="mut">最近 ${h.length*3<60?h.length*3+' 秒':Math.round(h.length*3/60)+' 分钟'}</span></div></div>
  </div>
  <div class="grid2">
   <div class="card"><h3>系统信息</h3>
    <div class="row"><span>主机名</span><span>${esc(s.host||'—')}</span></div>
    <div class="row"><span>系统</span><span>${esc(s.os||'—')}</span></div>
    <div class="row"><span>内核 / 架构</span><span>${esc(s.kernel||'—')} · ${esc(s.arch||'')}</span></div>
    <div class="row"><span>CPU</span><span>${esc(s.cpu_model||'—')} · ${s.cores||'?'} 核</span></div>
    <div class="row"><span>公网 IP</span><span>${esc(s.ip||'—')}</span></div>
    <div class="row"><span>已运行</span><span>${fmtDur(s.uptime)}</span></div></div>
   <div class="card"><h3>sing-box <span class="badge ${sb.running?'g':'r'}">${sb.running?'运行中':'已停止'}</span><span class="sp"></span><button class="btn2 sm" onclick="restart()">重启</button></h3>
    <div class="row"><span>版本</span><span>${esc(sb.version||'—')}</span></div>
    <div class="row"><span>内存占用</span><span>${sb.rss?fmtB(sb.rss):'—'}</span></div>
    <div class="row"><span>已运行</span><span>${fmtDur(sb.uptime)}</span></div>
    <div class="row"><span>当前连接</span><span class="num">${sb.conns||0}</span></div>
    <div class="row"><span>用户</span><span>${(d.users||{}).active||0} 启用 / ${(d.users||{}).total||0} 总数</span></div>
    <div class="row"><span>代理网速</span><span class="num">↓ ${fmtR((st.rate||{}).down||0)} · ↑ ${fmtR((st.rate||{}).up||0)}</span></div></div>
  </div>
  <div class="card"><h3>节点流量 ${mode}<span class="sp"></span><button class="btn2 sm" onclick="resetStats('')">全部清零</button></h3>
   ${nodes.length?`<div class="tw"><table class="tbl"><tr><th>节点</th><th>协议</th><th>端口</th><th>用户</th><th>连接</th><th>在线 IP</th><th>实时 ↓ / ↑</th><th>累计 ↓ / ↑</th><th></th></tr>
   ${nodes.map(n=>`<tr><td>${esc(n.name)}<div class="mut" style="font-size:11.5px">${esc(n.tag)}</div></td><td>${esc(n.proto)}</td><td class="num">${n.port||''}</td>
    <td class="num">${n.users==null?'<span class="mut" title="该协议不支持多用户">—</span>':n.users}</td><td class="num">${n.conns}</td><td class="num">${n.ips}</td>
    <td class="num">${fmtR(n.down_rate)}<br><span class="mut">${fmtR(n.up_rate)}</span></td>
    <td class="num"><b>${fmtB(n.down)}</b><br><span class="mut">${fmtB(n.up)}</span></td>
    <td><button class="ib" title="清零" onclick="resetStats('${esc(n.tag)}')">清零</button></td></tr>`).join('')}</table></div>`
   :'<div class="empty">还没有节点</div>'}
   <p class="mut" style="font-size:12px;margin-top:10px">按节点统计。按用户统计需要把 sing-box 编译进面板（s-ui 的做法），那样就不能自选 sing-box 版本，所以这里不提供。</p></div>`}
async function resetStats(tag){if(!confirm(tag?`清零节点 ${tag} 的累计流量？`:'清零全部节点的累计流量？'))return;
 const r=await api('/stats-reset','POST',{tag});msg(r.msg,r.ok);loadHome()}

// ════════ 节点 ════════
async function loadIn(){const l=await api('/inbounds');OUTS=await api('/outbounds');
 $('inlist').innerHTML=l.length?l.map(n=>`<div class="card"><h3>${esc(n.name)}<span class="badge">${esc(n.proto||n.type)}</span>${n.conns?`<span class="badge g">${n.conns} 连接</span>`:''}</h3>
  <div class="row"><span>标签 / 端口</span><span>${esc(n.tag)} · ${n.port}</span></div>
  <div class="row"><span>出站</span><span>${n.bind==='direct'?'直连':esc(n.bind)}</span></div>
  <div class="row"><span>用户</span><span>${n.multi?(n.users.length?`${n.active_users} 启用 / ${n.users.length} 分配`:'<span class="mut">仅原有用户</span>'):'<span class="mut">不支持多用户</span>'}</span></div>
  <div class="row"><span>累计流量</span><span class="num">↓ ${fmtB(n.down)} · ↑ ${fmtB(n.up)}</span></div>
  ${n.uri?`<div class="uri" onclick="cp(this.textContent)" title="点击复制">${esc(n.uri)}</div>`:''}
  <div class="acts"><button class="btn2" onclick="editNode('${encodeURIComponent(n.tag)}')">编辑</button>
  <button class="btn2" onclick="bindDlg('${encodeURIComponent(n.tag)}','${encodeURIComponent(n.bind)}')">绑定出站</button>
  <button class="btnd" onclick="delIn('${encodeURIComponent(n.tag)}')">删除</button></div></div>`).join(''):'<div class="empty">还没有节点，点上方添加</div>'}

// 节点弹窗：按 s-ui 分「服务端 / 客户端」两页
const CLIENT_KEYS=['server','hop'];
const TRKEYS=['transport','tr_path','tr_host','tr_ed'];
function nodeModal(title,protoSel,nameVal,saveBtn){
 return `<h2>${title}</h2>
  <div class="f2"><div>${protoSel}</div><div><label>节点名称</label><input id="f-name" value="${esc(nameVal)}"></div></div>
  <div class="mtabs"><div class="mtab active" data-t="s" onclick="mtab('s')">服务端</div><div class="mtab" data-t="c" onclick="mtab('c')">客户端</div></div>
  <div id="mt-s"><div id="fs"></div><div id="fu"></div><div id="fa"></div></div>
  <div id="mt-c" style="display:none"><div id="fc"></div></div>
  <div class="acts">${saveBtn}<button class="btn2" onclick="closeM()">取消</button></div>`}
function mtab(t){document.querySelectorAll('.mtab').forEach(e=>e.classList.toggle('active',e.dataset.t===t));
 document.querySelectorAll('[id^="mt-"]').forEach(e=>e.style.display=e.id==='mt-'+t?'block':'none')}
async function fillNode(proto,gv,assigned,uri){const spec=PROTOS[proto];
 if(spec.needs_cert&&!CERTS.length){const cr=await api('/certs');CERTS=cr.certs||[]}
 const sf=spec.fields.filter(f=>f.k!=='name'&&CLIENT_KEYS.indexOf(f.k)<0),cf=spec.fields.filter(f=>CLIENT_KEYS.indexOf(f.k)>=0);
 $('fs').innerHTML=sf.map(f=>fld(f,gv(f))).join('');
 $('fa').innerHTML=advHTML(spec,gv);
 $('fc').innerHTML=(cf.length?cf.map(f=>fld(f,gv(f))).join(''):'')
  +`<div class="note" style="margin-top:14px">分享链接里的连接地址${spec.needs_cert?'使用证书域名':'使用上面填写的地址'}。每个用户的链接与此相同，只是凭据换成他自己的。</div>`
  +(uri?`<label>当前分享链接（原有用户）</label><div class="uri" onclick="cp(this.textContent)">${esc(uri)}</div>`:'');
 if(!USERS){try{USERS=await api('/users')}catch(e){USERS={users:[]}}}
 const multi=['hysteria2','vless','vless-tls','trojan','anytls','tuic','vmess','hysteria','naive','socks','mixed','http'].indexOf(proto)>=0;
 const us=USERS.users||[];
 $('fu').innerHTML=`<label>用户 <span class="hint">节点原有的用户始终保留；这里勾选面板里的其他用户</span></label>`+
  (!multi?`<div class="alert" style="margin:0">${esc(spec.label)} 不支持多用户：开启后原有链接会失效</div>`
  :us.length?`<div class="chkbox">${us.map(u=>`<label class="chk"><input type="checkbox" class="nu" value="${esc(u.name)}" ${assigned.indexOf(u.name)>=0?'checked':''}>
    <span>${esc(u.name)}</span><i>${u.group?esc(u.group)+' · ':''}${u.active?'启用':(u.expired?'已过期':'已停用')}</i></label>`).join('')}</div>`
  :`<div class="mut" style="font-size:12.5px">还没有用户，可在「用户」页添加</div>`)}
function pickedUsers(){const e=document.querySelectorAll('.nu');return e.length||document.querySelector('#fu .chkbox')?[...e].filter(x=>x.checked).map(x=>x.value):undefined}
async function newNode(){const opts=Object.entries(PROTOS).map(([k,v])=>`<option value="${k}">${esc(v.label)}</option>`).join('');
 USERS=null;
 openM(nodeModal('添加节点',`<label>协议</label><select id="proto" onchange="renderF()">${opts}</select>`,'',`<button onclick="saveNode(this)">创建</button>`),1);renderF()}
async function renderF(){const p=$('proto').value,spec=PROTOS[p];
 const a=await api('/autofill');const gv=f=>f.auto?(a[f.auto]||''):(f.d||'');
 $('f-name').value=(spec.fields.find(f=>f.k==='name')||{}).d||'';
 await fillNode(p,gv,[],'')}
async function editNode(t0){const t=decodeURIComponent(t0);
 const d=await api('/inbound-detail/'+encodeURIComponent(t));
 if(!d.ok)return msg(d.msg||'读取失败');
 const spec=PROTOS[d.proto];if(!spec)return msg('未知协议');
 USERS=null;
 openM(nodeModal(`编辑节点`,`<label>协议 <span class="hint">不可更改</span></label><input value="${esc(spec.label)}" disabled>`,d.name,
  `<button onclick="saveEdit(this,'${encodeURIComponent(t)}','${d.proto}')">保存</button>`),1);
 const gv=f=>d.fields[f.k]!==undefined?String(d.fields[f.k]):(f.d||'');
 const nodes=await api('/inbounds');const n=nodes.find(x=>x.tag===t)||{};
 await fillNode(d.proto,gv,d.users||[],n.uri||'')}
function fld(f,v){v=v===undefined?'':String(v);
 const h=f.h?`<span class="hint">${esc(f.h)}</span>`:'';
 if(f.t==='bool')return `<label class="chk"><input type="checkbox" id="f-${f.k}" ${v==='1'?'checked':''}><span>${esc(f.l)}</span>${f.h?`<i>${esc(f.h)}</i>`:''}</label>`;
 if(f.t==='cert'){const o=CERTS.map(c=>`<option value="${esc(c.domain)}" ${c.domain===v?'selected':''}>${esc(c.domain)}</option>`).join('');
  return `<label>${esc(f.l)}${h}</label>`+(CERTS.length?`<select id="f-${f.k}">${o}</select>`:`<div class="alert">无可用证书，请先到「证书」页申请</div>`)}
 if(f.t==='select')return `<label>${esc(f.l)}${h}</label><select id="f-${f.k}">${f.opts.map(o=>`<option ${o===v?'selected':''}>${esc(o)}</option>`).join('')}</select>`;
 if(f.t==='dest')return `<label>${esc(f.l)} <a href="javascript:;" onclick="scanDest()">⚡ 扫描可用目标</a></label>
  <input id="f-${f.k}" type="text" value="${esc(v)}"><div id="scanres"></div>`;
 return `<label>${esc(f.l)}${h}</label><input id="f-${f.k}" type="${f.t}" value="${esc(v)}">`}
function advHTML(spec,gv){const a=spec.adv||[];if(!a.length)return '';
 const perf=a.filter(f=>TRKEYS.indexOf(f.k)<0),tr=a.filter(f=>TRKEYS.indexOf(f.k)>=0);
 let out='';
 if(perf.length)out+=`<details><summary>高级选项 · 性能与抗封锁（${perf.length}）</summary><div class="dbody">${perf.map(f=>fld(f,gv(f))).join('')}</div></details>`;
 if(tr.length)out+=`<details><summary>传输层设置（可过 CDN）</summary><div class="dbody">${tr.map(f=>fld(f,gv(f))).join('')}</div></details>`;
 return out}
function collectF(spec){const fs={};
 (spec.fields||[]).concat(spec.adv||[]).forEach(f=>{const e=$('f-'+f.k);
  if(e)fs[f.k]=(f.t==='bool')?(e.checked?'1':'0'):e.value});
 return fs}
async function scanDest(){const box=$('scanres');
 box.innerHTML='<div class="scanning">扫描中，约 8 秒…</div>';
 const r=await api('/scan');
 box.innerHTML=`<div class="scanlist">`+r.map(x=>{const cls=x.ok?'sok':'sbad';
   const info=x.ok?`${x.ms}ms · TLS1.3 · H2${x.issuer?' · '+esc(x.issuer):''}`:esc(x.err||'不可用');
   return `<div class="scanrow ${cls}" ${x.ok?`onclick="pickDest('${esc(x.host)}')"`:''}><span>${esc(x.host)}</span><b>${info}</b></div>`}).join('')+`</div>
   <div class="mut" style="font-size:12px;margin-top:6px">点击绿色条目即可选用（需 TLS1.3 + H2 才合格）</div>`}
function pickDest(h){$('f-dest').value=h;$('scanres').innerHTML='';msg('已选用 '+h,1)}
async function saveNode(b){const p=$('proto').value;const fs=collectF(PROTOS[p]);
 b.disabled=true;b.textContent='创建中…';
 const r=await api('/inbounds','POST',{proto:p,fields:fs,users:pickedUsers()});
 b.disabled=false;b.textContent='创建';
 if(r.ok){closeM();msg('节点已创建',1);loadIn();refresh()}else msg(r.msg)}
async function saveEdit(b,t0,proto){const t=decodeURIComponent(t0);const fs=collectF(PROTOS[proto]);
 b.disabled=true;b.textContent='保存中…';
 const r=await api('/inbound-edit/'+encodeURIComponent(t),'POST',{proto,fields:fs,users:pickedUsers()});
 b.disabled=false;b.textContent='保存';
 if(r.ok){closeM();msg('已保存，客户端需重新拉订阅',1);loadIn();refresh()}else msg(r.msg)}
async function delIn(t0){const t=decodeURIComponent(t0);if(!confirm('删除节点 '+t+'？分配给它的用户会自动解除。'))return;
 const r=await api('/inbounds/'+encodeURIComponent(t),'DELETE');
 if(r.ok){msg('已删除',1);loadIn();refresh()}else msg(r.msg)}

// ════════ 用户（参照 s-ui Clients）════════
let UF={q:'',g:'-',s:''},USEL=new Set();
async function loadUsers(){USERS=await api('/users');renderUsers()}
function renderUsers(){const box=$('p-users'),d=USERS||{users:[]};const us=d.users;
 const groups=[...new Set(us.map(u=>u.group||''))].sort();
 const q=UF.q.toLowerCase();
 const list=us.filter(u=>(!q||u.name.toLowerCase().includes(q)||(u.remark||'').toLowerCase().includes(q))
  &&(UF.g==='-'||(u.group||'')===UF.g)
  &&(!UF.s||(UF.s==='on'&&u.active)||(UF.s==='off'&&!u.enable)||(UF.s==='exp'&&u.expired)));
 const nn=t=>{const n=(d.nodes||[]).find(x=>x.tag===t);return n?n.name:t};
 box.innerHTML=`<div class="bar"><button onclick="userDlg('')">+ 添加用户</button><button class="btn2" onclick="bulkDlg()">批量添加</button>
  <button class="btnd" ${USEL.size?'':'disabled'} onclick="bulkDel()">删除所选${USEL.size?` (${USEL.size})`:''}</button>
  <span class="sp"></span>
  <input placeholder="搜索用户名 / 备注" value="${esc(UF.q)}" oninput="UF.q=this.value;renderUsers();this.focus();this.setSelectionRange(this.value.length,this.value.length)" style="width:170px">
  <select onchange="UF.g=this.value;renderUsers()"><option value="-">全部分组</option>${groups.map(g=>`<option value="${esc(g)}" ${UF.g===g?'selected':''}>${g?esc(g):'(未分组)'}</option>`).join('')}</select>
  <select onchange="UF.s=this.value;renderUsers()"><option value="">全部状态</option><option value="on" ${UF.s==='on'?'selected':''}>生效中</option><option value="off" ${UF.s==='off'?'selected':''}>已停用</option><option value="exp" ${UF.s==='exp'?'selected':''}>已过期</option></select></div>
  <div class="card">${us.length?`<div class="tw"><table class="tbl"><tr><th><input type="checkbox" onchange="selAll(this.checked)" ${list.length&&list.every(u=>USEL.has(u.name))?'checked':''}></th><th>用户名</th><th>启用</th><th>分组</th><th>节点</th><th>到期</th><th>创建时间</th><th>备注</th><th></th></tr>
   ${list.map(u=>`<tr><td><input type="checkbox" ${USEL.has(u.name)?'checked':''} onchange="selU('${esc(u.name)}',this.checked)"></td>
    <td><b>${esc(u.name)}</b>${!u.active&&u.enable&&u.expired?'':''}</td>
    <td><label class="sw" title="${u.enable?'点击停用':'点击启用'}"><input type="checkbox" ${u.enable?'checked':''} onchange="toggleU('${esc(u.name)}',this.checked,this)"><span></span></label></td>
    <td>${u.group?`<span class="badge b">${esc(u.group)}</span>`:'<span class="mut">—</span>'}</td>
    <td title="${esc((u.inbounds||[]).map(nn).join('、'))}">${(u.inbounds||[]).length?`${u.inbounds.length} 个`:'<span class="mut">未分配</span>'}</td>
    <td>${expTxt(u)}</td><td class="mut num">${fmtTs(u.created)}</td>
    <td class="mut" style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(u.remark||'')}</td>
    <td style="white-space:nowrap"><button class="ib" onclick="userDlg('${esc(u.name)}','l')">链接</button><button class="ib" onclick="userDlg('${esc(u.name)}')">编辑</button><button class="ib" style="color:var(--err)" onclick="delUser('${esc(u.name)}')">删除</button></td></tr>`).join('')}
   </table></div>${list.length?'':'<div class="empty">没有符合筛选条件的用户</div>'}`
  :'<div class="empty">还没有用户。<br>用户可以分配到多个节点，每人一个独立的订阅链接，到期自动停用。</div>'}</div>
  <p class="mut" style="font-size:12px">停用或到期的用户会自动从节点里移除，他的订阅链接返回 404。节点建立时的原有用户不受影响。</p>`}
function selU(n,v){v?USEL.add(n):USEL.delete(n);renderUsers()}
function selAll(v){const q=UF.q.toLowerCase();(USERS.users||[]).forEach(u=>{if(v)USEL.add(u.name);else USEL.delete(u.name)});renderUsers()}
async function toggleU(n,on,el){const u=USERS.users.find(x=>x.name===n);if(!u)return;el.disabled=true;
 const r=await api('/user-edit/'+encodeURIComponent(n),'POST',Object.assign({},u,{enable:on}));
 msg(r.ok?(on?'已启用':'已停用'):r.msg,r.ok);loadUsers()}
async function delUser(n){if(!confirm(`删除用户 ${n}？他的订阅链接立即失效。`))return;
 const r=await api('/users/'+encodeURIComponent(n),'DELETE');msg(r.msg,r.ok);USEL.delete(n);loadUsers()}
async function bulkDel(){const ns=[...USEL];if(!ns.length)return;if(!confirm(`删除所选 ${ns.length} 个用户？`))return;
 const r=await api('/users-del','POST',{names:ns});msg(r.msg,r.ok);USEL.clear();loadUsers()}
function nodePicker(sel){const ns=(USERS.nodes||[]);
 if(!ns.length)return '<div class="mut" style="font-size:12.5px">还没有节点</div>';
 return `<div class="chkbox">${ns.map(n=>`<label class="chk ${n.multi?'':'dis'}"><input type="checkbox" class="un" value="${esc(n.tag)}" ${sel.indexOf(n.tag)>=0?'checked':''} ${n.multi?'':'disabled'}>
   <span>${esc(n.name)}</span><i>${esc(n.proto)}${n.multi?'':' · 不支持多用户'}</i></label>`).join('')}</div>
   <div style="font-size:12px;margin-top:4px"><a href="javascript:;" onclick="document.querySelectorAll('.un:not(:disabled)').forEach(e=>e.checked=true)">全选</a> / <a href="javascript:;" onclick="document.querySelectorAll('.un').forEach(e=>e.checked=false)">清空</a></div>`}
function expField(ts){return `<label>到期时间 <span class="hint">留空为永久</span></label>
 <input type="datetime-local" id="u-exp" value="${toLocalInput(ts)}">
 <div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">${[['永久',0],['7 天',7],['30 天',30],['90 天',90],['半年',182],['1 年',365]].map(([l,d])=>
  `<button class="btn2 sm" type="button" onclick="setExp(${d})">${l}</button>`).join('')}</div>`}
function setExp(days){$('u-exp').value=days?toLocalInput(Math.floor(Date.now()/1000)+days*86400):''}
function readExp(){const v=$('u-exp').value;return v?Math.floor(new Date(v).getTime()/1000):0}
async function userDlg(name,tab){if(!USERS)USERS=await api('/users');
 const u=name?USERS.users.find(x=>x.name===name):null;if(name&&!u)return msg('用户不存在');
 const x=u||{enable:true,inbounds:(USERS.nodes||[]).filter(n=>n.multi).map(n=>n.tag)};
 openM(`<h2>${u?'编辑用户 · '+esc(u.name):'添加用户'}</h2>
  ${u?`<div class="mtabs"><div class="mtab ${tab!=='l'?'active':''}" data-t="b" onclick="mtab('b')">基本</div><div class="mtab ${tab==='l'?'active':''}" data-t="l" onclick="mtab('l');userLinks('${esc(u.name)}')">链接</div></div>`:''}
  <div id="mt-b" style="${tab==='l'?'display:none':''}">
  <div class="f2"><div><label>用户名 <span class="hint">字母数字 . _ -</span></label><input id="u-name" value="${esc(x.name||'')}" maxlength="32"></div>
   <div><label>分组</label><input id="u-group" value="${esc(x.group||'')}" placeholder="可选" list="u-groups"><datalist id="u-groups">${[...new Set(USERS.users.map(v=>v.group).filter(Boolean))].map(g=>`<option value="${esc(g)}">`).join('')}</datalist></div></div>
  <label class="chk" style="margin-top:10px"><input type="checkbox" id="u-en" ${x.enable!==false?'checked':''}><span>启用</span><i>停用后立即从节点移除，订阅返回 404</i></label>
  ${expField(x.expiry)}
  <label>备注</label><input id="u-remark" value="${esc(x.remark||'')}" placeholder="可选">
  <label>分配节点</label>${nodePicker(x.inbounds||[])}
  <details ${u?'':''}><summary>凭据 · UUID 与密码（留空自动生成）</summary><div class="dbody">
   <label>UUID <span class="hint">VLESS / VMess / TUIC 使用</span></label><input id="u-uuid" value="${esc(x.uuid||'')}" placeholder="自动生成">
   <label>密码 <span class="hint">其余协议使用</span></label><input id="u-pass" value="${esc(x.password||'')}" placeholder="自动生成">
   ${u?`<div class="acts"><button class="btn2 sm" onclick="resetU('${esc(u.name)}','cred')">重新生成凭据</button></div>`:''}</div></details>
  <div class="acts"><button onclick="saveUser(this,'${esc(name||'')}')">${u?'保存':'添加'}</button><button class="btn2" onclick="closeM()">取消</button></div></div>
  ${u?`<div id="mt-l" style="${tab==='l'?'':'display:none'}"><div class="scanning">加载中…</div></div>`:''}`,1);
 if(u&&tab==='l')userLinks(u.name)}
async function userLinks(n){const r=await api('/user-links/'+encodeURIComponent(n));const box=$('mt-l');if(!box)return;
 if(!r.ok){box.innerHTML=`<div class="alert">${esc(r.msg)}</div>`;return}
 const u=USERS.users.find(x=>x.name===n)||{};
 box.innerHTML=`${u.active?'':'<div class="alert">该用户当前未生效（已停用或已过期），订阅会返回 404，节点也不接受他的连接</div>'}
  <label>订阅链接 <span class="hint">点击复制 · 只包含分配给他的节点</span></label>
  <div class="uri" onclick="cp(this.textContent)">${esc(r.sub)}</div>
  <div class="acts"><button class="btn2 sm" onclick="window.open('${esc(r.sub)}?plain=1')">查看明文</button><button class="btn2 sm" onclick="resetU('${esc(n)}','sub')">更换订阅地址</button></div>
  <label style="margin-top:16px">各节点链接（${r.links.length}）</label>
  ${r.links.length?r.links.map(l=>`<div style="margin-top:8px;font-size:12.5px;color:var(--tx2)">${esc(l.name)} <span class="mut">${esc(l.tag)}</span></div><div class="uri" style="margin-top:4px" onclick="cp(this.textContent)">${esc(l.uri)}</div>`).join('')
   :'<div class="mut" style="font-size:12.5px">没有分配支持多用户的节点</div>'}`}
async function saveUser(b,old){const ins=[...document.querySelectorAll('.un:checked')].map(e=>e.value);
 const body={name:$('u-name').value.trim(),group:$('u-group').value.trim(),enable:$('u-en').checked,expiry:readExp(),
  remark:$('u-remark').value.trim(),inbounds:ins,uuid:$('u-uuid').value.trim(),password:$('u-pass').value.trim()};
 b.disabled=true;
 const r=old?await api('/user-edit/'+encodeURIComponent(old),'POST',body):await api('/users','POST',body);
 b.disabled=false;
 if(r.ok){closeM();msg(r.msg,1);loadUsers()}else msg(r.msg)}
async function resetU(n,what){if(!confirm(what==='sub'?'更换订阅地址后旧地址立即失效，确定？':'重新生成 UUID 和密码？他需要重新拉订阅才能继续使用。'))return;
 const r=await api('/user-reset/'+encodeURIComponent(n),'POST',{what});msg(r.msg,r.ok);
 if(r.ok){USERS=await api('/users');if(what==='sub')userLinks(n);else{closeM();renderUsers()}}}
function bulkDlg(){openM(`<h2>批量添加用户</h2>
  <div class="f3"><div><label>数量</label><input id="b-n" type="number" min="1" max="200" value="10"></div>
   <div><label>用户名前缀</label><input id="b-p" value="user"></div><div><label>起始编号</label><input id="b-s" type="number" value="1"></div></div>
  <p class="mut" style="font-size:12px;margin-top:6px">将生成 user1、user2…，已存在的名字自动跳过</p>
  <label>分组</label><input id="u-group" placeholder="可选">
  ${expField(0)}
  <label>分配节点</label>${nodePicker((USERS.nodes||[]).filter(n=>n.multi).map(n=>n.tag))}
  <div class="acts"><button onclick="saveBulk(this)">添加</button><button class="btn2" onclick="closeM()">取消</button></div>`,1)}
async function saveBulk(b){b.disabled=true;
 const r=await api('/users-bulk','POST',{count:+$('b-n').value,prefix:$('b-p').value.trim(),start:+$('b-s').value,
  group:$('u-group').value.trim(),expiry:readExp(),inbounds:[...document.querySelectorAll('.un:checked')].map(e=>e.value)});
 b.disabled=false;if(r.ok){closeM();msg(r.msg,1);loadUsers()}else msg(r.msg)}

// ════════ 出站 / 证书 / 订阅 / 版本 / 日志（沿用原逻辑）════════
async function loadOut(){OUTS=await api('/outbounds');
 $('outlist').innerHTML=OUTS.length?OUTS.map(o=>`<div class="card"><h3>${esc(o.tag)}<span class="badge">${esc(o.type)}</span></h3>
  <div class="row"><span>地址</span><span>${esc(o.server)}</span></div>
  <div class="row"><span>端口</span><span>${esc(o.port)}</span></div>
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
   <div class="row"><span>当前</span><span>${cur?`<b style="color:var(--ok)">https://${esc(cur)}:${r.panel_port}</b>`:`http://127.0.0.1:${r.panel_port} <i class="mut" style="font-style:normal">(仅本机，需 SSH 隧道)</i>`}</span></div>
   <div class="acts"><button class="btn2" onclick="pathDlg()">更换访问路径</button>
   ${cur?`<button class="btnd" onclick="setPanelTls('')">关闭 HTTPS，改回仅本机</button>`:''}</div>
   ${cur?'':`<p class="mut" style="font-size:12px;margin-top:8px">下方证书点「用于面板」即可用域名 HTTPS 访问</p>`}</div>`;
 $('certlist').innerHTML=head+(CERTS.length?CERTS.map(c=>`<div class="card">
   <h3>${esc(c.domain)}${cur===c.domain?'<span class="badge g">面板使用中</span>':''}</h3>
   <div class="row"><span>到期</span><span>${esc(c.expire)}</span></div>
   ${cur!==c.domain?`<div class="acts"><button class="btn2" onclick="setPanelTls('${esc(c.domain)}')">用于面板 HTTPS</button></div>`:''}
   </div>`).join(''):'<div class="empty">暂无证书，点上方申请</div>')}
function pathDlg(){openM(`<h2>更换面板访问路径</h2>
 <p class="mut" style="font-size:13px;margin-bottom:8px">路径可防止面板被扫描器发现。更换后旧地址立即 404</p>
 <label>路径（留空=取消路径，4-64 位字母/数字/-/_）</label>
 <input id="pp-v" placeholder="留空则取消">
 <div class="acts"><button onclick="savePath(0)">保存</button>
 <button class="btn2" onclick="savePath(1)">随机生成</button>
 <button class="btn2" onclick="closeM()">取消</button></div>`)}
async function savePath(rand){
 const r=await api('/panel-path','POST',{path:rand?'':$('pp-v').value,random:!!rand});
 if(!r.ok)return msg(r.msg);
 $('mbox').innerHTML=`<h2>路径已更换</h2>
  <p class="mut" style="font-size:13px;margin:8px 0">请用新地址访问（当前页面已失效）：</p>
  <div class="uri" onclick="cp(this.textContent)">${esc(r.url)}</div>
  <div class="acts"><button onclick="location.href='${esc(r.url)}'">前往新地址</button></div>`}
async function setPanelTls(d){
 if(d&&!confirm(`将面板改为 https://${d}:端口 访问？\n\n注意：面板会监听公网，建议用防火墙限制来源 IP。`))return;
 if(!d&&!confirm('关闭 HTTPS？面板将只监听 127.0.0.1，需要 SSH 隧道才能访问。'))return;
 const r=await api('/panel-tls','POST',{domain:d});
 if(r.ok){openM(`<h2>面板正在重启</h2>
   <p class="mut" style="font-size:13px;margin:10px 0">请用新地址访问（含路径，点击可复制）：</p>
   <div class="uri" onclick="cp(this.textContent)">${esc(r.url)}</div>
   ${r.hint?`<p style="color:var(--warn);font-size:12px">${esc(r.hint.trim())}</p>`:''}
   <p class="mut" style="font-size:13px;margin:14px 0 6px">订阅链接同步更新为：</p>
   <div class="uri" onclick="cp(this.textContent)">${esc(r.suburl||'')}</div>
   <p style="color:var(--warn);font-size:12px;margin-top:6px">⚠ 客户端里的订阅地址需要改成新的</p>
   <div class="acts">${d?`<button onclick="location.href='${esc(r.url)}'">前往新地址</button>`:''}
   <button class="btn2" onclick="closeM()">关闭</button></div>`)}else msg(r.msg)}
async function loadSub(){let r;
 try{r=await api('/sub')}catch(e){$('subinfo').innerHTML=`<div class="alert">加载失败: ${esc(e.message||e)}</div>`;return}
 if(!r||!r.url){$('subinfo').innerHTML=`<div class="alert">接口异常${r&&r.msg?': '+esc(r.msg):''}<div class="cmd">journalctl -u singbox-panel -n 30 --no-pager</div></div>`;return}
 $('suburl').textContent=r.url;
 let h='';
 if(r.legacy)h+=`<div class="alert">⚠ 订阅服务仍在用旧版(http.server)，会导致订阅为空或被下载。<br>
   在服务器执行下面命令切换到新版：<div class="cmd">sed -i 's|ExecStart=.*|ExecStart=/usr/bin/python3 /etc/sing-box/panel.py --sub|;/WorkingDirectory/d' /etc/systemd/system/singbox-sub.service \&\& systemctl daemon-reload \&\& systemctl restart singbox-sub</div></div>`;
 if(!r.running)h+=`<div class="alert">⚠ 订阅端口未监听，可能被其他程序占用：<div class="cmd">ss -ltnp | grep :端口号  →  确认后 systemctl restart singbox-panel</div></div>`;
 h+=`<div class="row"><span>节点数</span><span><b>${r.count}</b></span></div>`;
 h+=`<div class="row"><span>地址类型</span><span>${r.domain?'<b style="color:var(--ok)">域名 HTTPS</b>':'IP + HTTP <i class="mut" style="font-style:normal;font-size:12px">（证书页启用 HTTPS 后自动改用域名）</i>'}</span></div>`;
 if(r.count)h+=`<div class="row"><span>包含</span><span>${r.names.map(esc).join('、')}</span></div>`;
 else h+=`<div class="alert">订阅内没有节点。请先到「节点」页创建节点。</div>`;
 h+=`<div class="acts"><button class="btn2" onclick="window.open($('suburl').textContent+'?plain=1')">查看明文内容</button>
   <button class="btn2" onclick="subTokenDlg()">更换订阅地址</button></div>`;
 h+=`<p class="mut" style="font-size:12px;margin-top:10px">点击链接可复制 · token 即密码，勿外泄</p>`;
 $('subinfo').innerHTML=h}
async function loadVer(){const box=$('verbox');
 box.innerHTML='<div class="card"><div class="scanning">检查更新中…</div></div>';
 const r=await api('/versions');
 const cur=r.current||'未知',pin=r.pinned||'';
 let banner='';
 if(r.has_update){banner=`<div class="alert" style="background:#16241c;border-color:#2d7f4f;color:#8ff0b5">
   🎉 有新版本 <b>${esc(r.latest)}</b> 可用（当前 ${esc(cur)}）
   ${r.note?`<div style="color:var(--tx2);font-size:12px;margin-top:6px;white-space:pre-wrap;max-height:80px;overflow:auto">${esc(r.note)}</div>`:''}
   <div class="acts"><button onclick="doInstall('${esc(r.latest)}')">立即升级</button></div></div>`}
 else if(r.latest){banner=`<div class="alert" style="background:var(--bg2);border-color:var(--line2);color:var(--tx2)">✓ 已是最新版本 ${esc(cur)}</div>`}
 const rows=(r.list||[]).map(v=>{const isCur=v.ver===cur;
   const tag=v.pre?'<span class="vtag pre">预发布</span>':'<span class="vtag rel">正式版</span>';
   return `<div class="scanrow${isCur?' vcur':''}"><span>${esc(v.ver)} ${tag} <i class="mut" style="font-style:normal;font-size:12px">${esc(v.date)}</i></span>
     ${isCur?'<b style="color:var(--ok)">使用中</b>':`<button class="btn2 sm" onclick="doInstall('${esc(v.ver)}')">切换</button>`}</div>`}).join('');
 const dk=await api('/disk').catch(()=>null);
 let disk='';
 if(dk){const root=dk['/']||{},t=dk['/tmp']||{};const low=(root.avail||999)<150;
  disk=`<div class="card"><h3>磁盘 ${low?'<span class="badge r">空间不足</span>':''}</h3>
   <div class="row"><span>根分区 /</span><span>可用 <b>${root.avail||'?'}MB</b> / ${root.total||'?'}MB</span></div>
   <div class="row"><span>/tmp</span><span>可用 ${t.avail||'?'}MB / ${t.total||'?'}MB ${dk.tmp_is_ram?'<i style="color:var(--warn);font-style:normal;font-size:12px">内存盘</i>':''}</span></div>
   <div class="acts"><button class="btn2" onclick="doClean(0)">清理残留</button><button class="btn2" onclick="doClean(1)">深度清理 (含apt/日志)</button></div>
   <p class="mut" style="font-size:12px;margin-top:8px">升级需要约 100MB。后台每 12 小时自动清理一次残留</p></div>`}
 box.innerHTML=banner+`<div class="grid2"><div class="card"><h3>当前版本</h3>
   <div class="row"><span>版本</span><span><b>${esc(cur)}</b></span></div>
   <div class="row"><span>锁定</span><span>${pin?`<b style="color:var(--warn)">${esc(pin)}</b>`:'未锁定'}</span></div>
   <div class="acts"><button class="btn2" onclick="loadVer()">🔄 检查更新</button>
     <button class="btn2" onclick="doPin(${pin?'false':'true'})">${pin?'解除锁定':'锁定当前版本'}</button>
     <button class="btn2" onclick="manualVer()">安装其他版本</button></div>
   <p class="mut" style="font-size:12px;margin-top:8px">锁定后切换版本会二次确认，防止误升级</p></div>
  <div class="card"><h3>自动更新 ${r.auto&&r.auto.enabled?'<span class="badge g">已开启</span>':'<span class="badge">已关闭</span>'}</h3>
   <label class="chk" style="margin:6px 0"><input type="checkbox" id="au-on" ${r.auto&&r.auto.enabled?'checked':''}><span>发现新版本时自动升级 <i>失败会自动回滚</i></span></label>
   <div class="f2"><div><label>更新通道</label><select id="au-ch">
     <option value="stable" ${(!r.auto||r.auto.channel==='stable')?'selected':''}>仅正式版（推荐）</option>
     <option value="all" ${r.auto&&r.auto.channel==='all'?'selected':''}>含预发布 beta/alpha</option></select></div>
    <div><label>检查间隔（小时）</label><input id="au-iv" type="number" min="1" value="${(r.auto&&r.auto.interval_hours)||12}"></div></div>
   <div class="acts"><button onclick="saveAuto()">保存</button></div>
   ${pin?`<p style="color:var(--warn);font-size:12px;margin-top:8px">⚠ 当前已锁定版本，自动更新不会执行</p>`:''}
   ${(r.auto_log&&r.auto_log.length)?`<p class="mut" style="font-size:12px;margin-top:10px">最近记录：</p><div class="mut" style="font-size:12px;line-height:1.8">${r.auto_log.slice().reverse().map(x=>`${esc(x.t)} · ${esc(x.msg)}`).join('<br>')}</div>`:''}
  </div></div>${disk}
  <div class="card"><h3>最近版本 <span class="badge">最新 ${(r.list||[]).length} 个</span></h3>
   <div class="scanlist">${rows||'<div class="empty">获取失败，检查服务器能否访问 GitHub</div>'}</div>
   <p class="mut" style="font-size:12px;margin-top:8px">需要更早的版本请用「安装其他版本」手动输入</p></div>`}
async function doInstall(v){const r0=await api('/versions');
 if(r0.pinned&&r0.pinned!==v&&!confirm(`当前锁定在 ${r0.pinned}，确定切换到 ${v}？`))return;
 if(!confirm(`切换到 sing-box ${v}？\n\n若新版本无法加载配置将自动回滚。`))return;
 const r=await api('/install-version','POST',{version:v});
 if(!r.ok){alert(r.msg);return}
 openM(`<h2>切换到 ${esc(v)}</h2><div id="vstat" class="alert" style="background:var(--bg2);border-color:var(--line2);color:var(--tx2)"><span class="spin"></span> 准备中…</div>
  <div class="acts"><button class="btn2" onclick="closeM()">后台运行，关闭窗口</button></div>`);
 pollVer()}
async function pollVer(){for(let i=0;i<120;i++){await new Promise(r=>setTimeout(r,2000));
   let s;try{s=await api('/version-status')}catch(e){return}
   const box=$('vstat');if(!box)return;
   if(s.running){box.innerHTML=`<span class="spin"></span> ${esc(s.step||'处理中')}… (${(i+1)*2}s)`;continue}
   if(s.ok===true){box.style.cssText='background:#16241c;border-color:#2d7f4f;color:#8ff0b5';box.textContent='✓ '+s.msg;loadVer();refresh();setTimeout(closeM,1500);return}
   if(s.ok===false){box.style.cssText='';box.innerHTML='✗ '+esc(s.msg).replace(/\n/g,'<br>');return}}
 const box=$('vstat');if(box)box.textContent='超时，请查看日志'}
function manualVer(){openM(`<h2>手动指定版本</h2><label>版本号（不带 v 前缀）</label><input id="mv" placeholder="1.14.0-beta.7">
 <div class="acts"><button onclick="(async()=>{const v=$('mv').value.trim();if(!v)return;closeM();doInstall(v)})()">安装</button><button class="btn2" onclick="closeM()">取消</button></div>`)}
async function saveAuto(){const en=$('au-on').checked,ch=$('au-ch').value,iv=parseInt($('au-iv').value)||12;
 if(en&&ch==='all'&&!confirm('含预发布通道会自动升到 beta/alpha 版本。\n\n预发布版可能引入不兼容变更，确定开启？'))return;
 const r=await api('/auto-update','POST',{enabled:en,channel:ch,interval_hours:iv});msg(r.msg,1);loadVer()}
async function doClean(deep){if(deep&&!confirm('深度清理会清空 apt 缓存并压缩系统日志，确定？'))return;
 msg('清理中…',1);const r=await api('/cleanup','POST',{deep:!!deep});msg(r.msg,1);loadVer()}
async function doPin(p){const r=await api('/pin-version','POST',{pin:p});msg(r.msg,1);loadVer()}
function subTokenDlg(){openM(`<h2>更换订阅地址</h2>
 <p style="color:var(--warn);font-size:13px;margin-bottom:8px">⚠ 更换后旧地址立即失效，所有客户端都要改成新地址</p>
 <label>自定义 token（留空则随机生成）</label><input id="st-tok" placeholder="8-64 位字母/数字/-/_">
 <div class="acts"><button onclick="saveSubToken()">更换</button><button class="btn2" onclick="closeM()">取消</button></div>`)}
async function saveSubToken(){const r=await api('/sub-token','POST',{token:$('st-tok').value});
 if(!r.ok)return msg(r.msg);
 $('mbox').innerHTML=`<h2>订阅地址已更换</h2><div class="uri" onclick="cp(this.textContent)">${esc(r.url)}</div>
  <p style="color:var(--warn);font-size:12px;margin-top:8px">旧地址已失效，请更新所有客户端</p>
  <div class="acts"><button onclick="closeM();loadSub()">完成</button></div>`}
async function loadHealth(){let h;try{h=await api('/health')}catch(e){return}
 const b=$('hbadge');const txt={green:'运行正常',yellow:'需要注意',red:'存在故障'}[h.level]||'未知';
 b.className='hbadge '+h.level;b.textContent=txt+(h.problems.length?` · ${h.problems.length}`:'');
 b.title=h.problems.join(' / ')||'所有子系统正常';
 const d=$('hdetail');
 if(d){d.textContent=txt;d.className='badge '+({green:'g',yellow:'y',red:'r'}[h.level]||'')}
 const box=$('hbox');if(!box)return;
 const th=Object.entries(h.threads||{}).map(([n,t])=>
   `<div class="hitem"><b>线程 ${esc(n)}</b><span>${t.alive?'<span style="color:var(--ok)">运行中</span>':'<span style="color:var(--err)">已停止</span>'}`
   +(t.restarts?` · 重启 ${t.restarts} 次`:'')+`</span>`
   +(t.last_error?`<div class="mut" style="font-size:11px;margin-top:3px">${esc(t.last_error)}</div>`:'')+`</div>`).join('');
 const cert=h.cert.days_left==null?'未启用':`${h.cert.days_left} 天`;
 const certColor=h.cert.days_left!=null&&h.cert.days_left<15?'var(--warn)':'var(--tx)';
 box.innerHTML=(h.problems.length?`<div class="alert">${h.problems.map(esc).join('<br>')}</div>`:'')
  +`<div class="hgrid">
   <div class="hitem"><b>订阅服务</b><span>${h.subscription.listening?'<span style="color:var(--ok)">监听中</span>':'<span style="color:var(--err)">未监听</span>'} · ${esc(h.subscription.scheme)}:${h.subscription.port}</span></div>
   <div class="hitem"><b>sing-box</b><span>${esc(h.singbox.state)} · ${h.singbox.inbounds} 个节点</span></div>
   <div class="hitem"><b>证书剩余</b><span style="color:${certColor}">${cert}</span></div>
   <div class="hitem"><b>面板内存</b><span>${h.rss_mb==null?'—':h.rss_mb+' MB'}</span></div>
   <div class="hitem"><b>已运行</b><span>${fmtDur(h.uptime_sec)}</span></div>
  </div><div class="hgrid">${th}</div>`;
 const rl=$('runlog');if(rl)rl.textContent=(h.runlog||[]).map(x=>`[${x.level}] ${x.t}  ${x.msg}`).join('\n')||'（暂无事件）'}
async function loadLog(){const r=await api('/logs');const st=r.state||await api('/log-state');renderLogCtl(st);
 $('logbox').textContent=st.enabled?(r.log||'（暂无日志）'):'日志已关闭。开启后 sing-box 才会写入 journald。'}
function renderLogCtl(st){
 $('log-badge').outerHTML=st.enabled?`<span id="log-badge" class="badge g">已开启 · ${esc(st.level)}</span>`:'<span id="log-badge" class="badge">已关闭</span>';
 $('log-ctl').innerHTML=st.enabled?`
  <label>日志级别 <span class="hint">越靠后越安静。warn / error 适合长期开着</span></label>
  <select id="log-lv">${(st.levels||[]).map(v=>`<option ${v===st.level?'selected':''}>${v}</option>`).join('')}</select>
  <div class="acts"><button class="btn2" onclick="setLog(1)">应用级别</button><button class="btnd" onclick="setLog(0)">关闭日志</button></div>
  <p class="mut" style="font-size:12px;margin-top:6px">改动会重启 sing-box，已连接的会话会断一下</p>`
  :`<div class="alert">日志已关闭，sing-box 不再写 journald —— 省磁盘和 IO，但出问题时也查不到原因。</div>
   <div class="acts"><button onclick="setLog(1)">开启日志</button></div>`}
async function setLog(on){const lv=$('log-lv');
 if(!on&&!confirm('关闭日志后 sing-box 不再记录任何信息，排查故障会很困难。\n\n会重启 sing-box，确定关闭？'))return;
 const r=await api('/set-log','POST',{enabled:!!on,level:lv?lv.value:undefined});msg(r.msg,r.ok?1:0);
 if(r.ok)setTimeout(()=>{loadLog();refresh()},1200)}
function obForm(d){d=d||{};const k=d.kind||'socks';
 return `<label>类型</label><select id="o-kind" onchange="onKindChange()">
   <option value="socks" ${k==='socks'?'selected':''}>SOCKS（支持 UDP，推荐）</option>
   <option value="http" ${k==='http'?'selected':''}>HTTP / HTTPS（仅 TCP）</option></select>
 <div class="f2"><div><label>标签</label><input id="o-tag" value="${esc(d.tag||'')}" placeholder="留空自动生成"></div>
  <div><label>服务器地址</label><input id="o-srv" value="${esc(d.server||'')}" placeholder="1.2.3.4"></div></div>
 <div class="f2"><div><label>服务器端口</label><input id="o-port" type="number" value="${esc(d.port||'')}" placeholder="1080"></div>
  <div id="o-verbox"><label>版本</label><select id="o-ver">
    <option value="5" ${String(d.version||'5')==='5'?'selected':''}>5</option><option value="4a" ${d.version==='4a'?'selected':''}>4a</option><option value="4" ${d.version==='4'?'selected':''}>4</option></select></div></div>
 <div class="f2"><div><label>用户名</label><input id="o-user" value="${esc(d.username||'')}" placeholder="留空=无认证"></div>
  <div><label>密码</label><input id="o-pass" value="${esc(d.password||'')}"></div></div>
 <div id="o-netbox"><label>网络</label><select id="o-net">
   <option value="" ${!d.network?'selected':''}>TCP/UDP（默认）</option><option value="tcp" ${d.network==='tcp'?'selected':''}>仅 TCP</option><option value="udp" ${d.network==='udp'?'selected':''}>仅 UDP</option></select></div>
 <label class="chk" id="o-tlsrow" style="display:${k==='http'?'flex':'none'};margin:8px 0"><input type="checkbox" id="o-tls" ${d.tls?'checked':''}><span>使用 HTTPS 连接落地 <i>落地需支持 TLS</i></span></label>
 <label class="chk" id="o-uotrow" style="display:${k==='http'?'none':'flex'};margin:4px 0"><input type="checkbox" id="o-uot" ${d.uot?'checked':''}><span>UDP over TCP <i>仅当落地支持 UoT 时勾选</i></span></label>`}
function onKindChange(){const k=$('o-kind').value,http=k==='http';
 ['o-tlsrow','o-uotrow','o-verbox','o-netbox','o-quicrow'].forEach(id=>{const e=$(id);if(!e)return;
  const showIt={'o-tlsrow':http,'o-uotrow':!http,'o-verbox':!http,'o-netbox':!http,'o-quicrow':!http}[id];
  e.style.display=showIt?(id.endsWith('row')?'flex':'block'):'none'})}
function obPayload(){const k=$('o-kind').value;
 return {kind:k,tag:$('o-tag').value.trim(),server:$('o-srv').value.trim(),port:$('o-port').value.trim(),
   username:$('o-user').value.trim(),password:$('o-pass').value,version:$('o-ver')?$('o-ver').value:'5',
   network:(k==='socks'&&$('o-net'))?$('o-net').value:'',tls:k==='http'&&$('o-tls')?$('o-tls').checked:false,uot:$('o-uot')?$('o-uot').checked:false}}
async function newOut(){const nodes=await api('/inbounds');
 const list=nodes.length?nodes.map(n=>`<label class="chk"><input type="checkbox" class="nd" value="${esc(n.tag)}"><span>${esc(n.name)} <i>${esc(n.type)} · ${n.port}</i>${n.bind!=='direct'?`<em>当前: ${esc(n.bind)}</em>`:''}</span></label>`).join('')
   :'<div class="mut" style="font-size:13px;padding:6px 0">还没有节点</div>';
 openM(`<h2>添加出站</h2>${obForm(null)}
 <label style="margin-top:14px">绑定节点 (可多选，选中的节点全部流量走此出站)
   ${nodes.length?'<a href="javascript:;" onclick="allNd(1)">全选</a> / <a href="javascript:;" onclick="allNd(0)">清空</a>':''}</label>
 <div class="chkbox">${list}</div>
 <label class="chk" id="o-quicrow" style="margin:8px 0"><input type="checkbox" id="o-blockquic" checked><span>拒绝 QUIC，强制走 TCP <i>推荐 · 多数落地不支持 UDP</i></span></label>
 <div class="acts"><button onclick="saveOut()">添加</button><button class="btn2" onclick="closeM()">取消</button></div>`);onKindChange()}
function allNd(v){document.querySelectorAll('.nd').forEach(e=>e.checked=!!v)}
async function saveOut(){const binds=[...document.querySelectorAll('.nd:checked')].map(e=>e.value);
 const p=obPayload();p.binds=binds;p.block_quic=$('o-blockquic')?$('o-blockquic').checked:true;
 const r=await api('/outbounds','POST',p);
 if(r.ok){closeM();msg('出站已添加'+(binds.length?`，已绑定 ${binds.length} 个节点`:''),1);loadOut();refresh()}else msg(r.msg)}
async function speedAll(){const l=await api('/outbounds');if(!l.length)return msg('暂无出站');
 msg(`开始测延迟 ${l.length} 个出站…`,1);for(const o of l)speedOut(encodeURIComponent(o.tag))}
async function speedOut(t0){const t=decodeURIComponent(t0);const box=$('sp-'+t);
 if(box)box.innerHTML='<span class="spin"></span> 启动…';
 await api('/speedtest/'+encodeURIComponent(t));
 for(let i=0;i<20;i++){await new Promise(r=>setTimeout(r,1500));
   let s;try{s=await api('/speed-status/'+encodeURIComponent(t))}catch(e){return}
   const b=$('sp-'+t);if(!b)return;
   if(s.running){b.innerHTML=`<span class="spin"></span> ${esc(s.step||'测试中')}`;continue}
   if(s.ok===true){const col=s.latency<=100?'var(--ok)':(s.latency<=250?'var(--warn)':'var(--err)');
     b.innerHTML=`<b style="color:${col}">${s.latency}ms</b>`+(s.best!==s.latency?` <i class="mut" style="font-style:normal;font-size:12px">最快 ${s.best}ms</i>`:'')
       +(s.total?` <i class="mut" style="font-style:normal;font-size:12px">· 完整往返 ${s.total}ms</i>`:'')+(s.loss?` <span style="color:var(--err);font-size:12px">丢包 ${s.loss}%</span>`:'')
       +(s.ip?` <i class="mut" style="font-style:normal;font-size:12px">${esc(s.ip)}</i>`:'');return}
   if(s.ok===false){b.innerHTML=`<span style="color:var(--err)">${esc(s.msg)}</span>`;return}}
 const b=$('sp-'+t);if(b)b.textContent='超时'}
async function editOut(t0){const t=decodeURIComponent(t0);const d=await api('/outbound-detail/'+encodeURIComponent(t));
 if(!d.ok)return msg(d.msg||'读取失败');
 openM(`<h2>编辑出站 · ${esc(t)}</h2><p class="mut" style="font-size:12px;margin-bottom:6px">改名后节点绑定会自动跟随</p>${obForm(d)}
  <div class="acts"><button onclick="saveEditOut('${encodeURIComponent(t)}')">保存</button><button class="btn2" onclick="closeM()">取消</button></div>`);onKindChange()}
async function saveEditOut(t0){const t=decodeURIComponent(t0);const r=await api('/outbound-edit/'+encodeURIComponent(t),'POST',obPayload());
 if(r.ok){closeM();msg('已保存',1);loadOut()}else msg(r.msg)}
async function delOut(t0){const t=decodeURIComponent(t0);if(!confirm('删除出站 '+t+'?'))return;
 const r=await api('/outbounds/'+encodeURIComponent(t),'DELETE');if(r.ok){msg('已删除',1);loadOut()}else msg(r.msg)}
async function testOut(t0){const t=decodeURIComponent(t0);const e=$('t-'+t);if(e)e.textContent='测试中…';
 const r=await api('/test/'+encodeURIComponent(t));const e2=$('t-'+t);if(e2)e2.textContent=r.msg}
function bindDlg(tag0,cur0){const tag=decodeURIComponent(tag0),cur=decodeURIComponent(cur0);
 const o=OUTS.map(x=>`<option value="${esc(x.tag)}" ${x.tag===cur?'selected':''}>${esc(x.tag)}</option>`).join('');
 openM(`<h2>绑定出站</h2><p class="mut" style="font-size:13px">节点 <b>${esc(tag)}</b> 的全部流量将走所选出站</p>
 <label>出站</label><select id="b-out"><option value="direct" ${cur==='direct'?'selected':''}>direct (本机直连)</option>${o}</select>
 <div class="acts"><button onclick="saveBind('${encodeURIComponent(tag)}')">保存</button><button class="btn2" onclick="closeM()">取消</button></div>`)}
async function saveBind(tag0){const tag=decodeURIComponent(tag0);const r=await api('/bind','POST',{inbound:tag,outbound:$('b-out').value});
 if(r.ok){closeM();msg('已更新',1);loadIn()}else msg(r.msg)}
function newCert(){openM(`<h2>申请证书</h2><p class="mut" style="font-size:13px">域名需已解析到本机；80 端口被 nginx 等占用时会临时停用，签发完自动恢复</p>
 <label>域名</label><input id="c-domain" placeholder="example.com">
 <div class="acts"><button onclick="saveCert(this)">申请</button><button class="btn2" onclick="closeM()">取消</button></div>`)}
async function saveCert(b){const d=$('c-domain').value.trim();if(!d)return msg('请填域名');
 b.disabled=true;b.textContent='提交中…';const r=await api('/certs','POST',{domain:d});
 if(!r.ok){msg(r.msg);b.disabled=false;b.textContent='申请';return}
 $('mbox').innerHTML=`<h2>申请证书 · ${esc(d)}</h2><div id="cstat" class="alert" style="background:var(--bg2);border-color:var(--line2);color:var(--tx2)"><span class="spin"></span> 正在预检…</div>
  <div class="acts"><button class="btn2" onclick="closeM()">后台运行，关闭窗口</button></div>`;pollCert()}
async function pollCert(){for(let i=0;i<90;i++){await new Promise(r=>setTimeout(r,2000));
   let s;try{s=await api('/cert-status')}catch(e){return}
   const box=$('cstat');if(!box)return;
   if(s.running){box.innerHTML=`<span class="spin"></span> ${esc(s.step||'处理中')}… (${(i+1)*2}s)`;continue}
   if(s.ok===true){box.style.cssText='background:#16241c;border-color:#2d7f4f;color:#8ff0b5';box.textContent='✓ '+s.msg;CERTS=[];loadCerts();setTimeout(closeM,1500);return}
   if(s.ok===false){box.style.cssText='';box.innerHTML='✗ '+esc(s.msg).replace(/\n/g,'<br>');return}}
 const box=$('cstat');if(box)box.textContent='超时，请查看服务器日志'}
async function restart(){const r=await api('/restart','POST');msg(r.ok?'已重启':'失败',r.ok);refresh()}

// ════════ 路由规则（参照 s-ui Rules）════════
let RT=null;
const ACTS={route:'走出站',reject:'拒绝','hijack-dns':'劫持 DNS',sniff:'嗅探',resolve:'解析域名','route-options':'路由选项'};
const RS_PRESETS=[
 ['geosite-category-ads-all','广告域名','https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs'],
 ['geosite-cn','中国域名','https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs'],
 ['geoip-cn','中国 IP','https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs'],
 ['geosite-openai','OpenAI','https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs'],
 ['geosite-netflix','Netflix','https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs'],
 ['geosite-google','Google','https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google.srs'],
 ['geosite-category-porn','成人网站','https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-porn.srs']];
async function loadRoute(){const r=await api('/route');RT=Object.assign(r,{dirty:false});renderRoute()}
function arr(v){return v==null?[]:(Array.isArray(v)?v:[v])}
function ruleSummary(r){const c=[];const add=(l,v)=>{v=arr(v);if(v.length)c.push(`<span class="c" title="${esc(v.join(', '))}">${l}: ${esc(v.slice(0,3).join(', '))}${v.length>3?' …+'+(v.length-3):''}</span>`)};
 if(r.type==='logical')c.push(`<span class="c">逻辑 ${esc(r.mode||'and')} · ${arr(r.rules).length} 条子规则</span>`);
 add('入站',r.inbound);add('网络',r.network);add('协议',r.protocol);add('域名',r.domain);add('后缀',r.domain_suffix);
 add('关键词',r.domain_keyword);add('正则',r.domain_regex);add('IP',r.ip_cidr);add('源IP',r.source_ip_cidr);
 add('端口',r.port);add('端口范围',r.port_range);add('规则集',r.rule_set);
 if(r.ip_is_private)c.push('<span class="c">非公开 IP</span>');if(r.clash_mode)add('模式',r.clash_mode);
 if(r.invert)c.push('<span class="c" style="color:var(--warn)">反选</span>');
 const known=['inbound','network','protocol','domain','domain_suffix','domain_keyword','domain_regex','ip_cidr','source_ip_cidr','port','port_range','rule_set','ip_is_private','invert','action','outbound','type','mode','rules','clash_mode','method','no_drop','sniffer','timeout','server','strategy'];
 const other=Object.keys(r).filter(k=>known.indexOf(k)<0);if(other.length)c.push(`<span class="c">${esc(other.join(', '))}</span>`);
 return c.join('')||'<span class="mut">所有流量</span>'}
function ruleAct(r){const a=r.action||(r.outbound?'route':'route');
 if(a==='route')return `<span style="color:var(--pri)">→ ${esc(r.outbound||'?')}</span>`;
 if(a==='reject')return '<span style="color:var(--err)">拒绝</span>';
 return `<span style="color:var(--tx2)">${esc(ACTS[a]||a)}</span>`}
function renderRoute(){const R=RT;const box=$('p-route');
 const rs=R.rule_set||[];
 box.innerHTML=`<div class="bar"><button onclick="saveRoute(this)" ${R.dirty?'':'disabled'}>保存并应用</button>
  ${R.dirty?'<span class="dirty">● 有未保存的修改</span>':''}<span class="sp"></span>
  <button class="btn2" onclick="loadRoute()">撤销修改</button></div>
  <div class="note">规则按顺序匹配，命中第一条就停止；都不命中走「默认出站」。保存前会用 sing-box 校验，失败自动回滚。<br>「节点 → 绑定出站」生成的也是这里的规则，两边改动互相可见。</div>
  <div class="card"><h3>路由规则 <span class="badge">${R.rules.length} 条</span><span class="sp"></span>
   <select onchange="if(this.value){tplRule(this.value);this.value=''}" style="width:auto;padding:5px 8px;font-size:12.5px">
    <option value="">快捷模板…</option><option value="ads">屏蔽广告</option><option value="bt">屏蔽 BT 下载</option><option value="cn">屏蔽回国流量（中国 IP）</option><option value="private">屏蔽访问内网</option></select>
   <button class="btn2 sm" onclick="ruleDlg(-1)">+ 添加规则</button></h3>
   ${R.rules.length?R.rules.map((r,i)=>`<div class="rule"><span class="ri">${i+1}</span><div class="rb">${ruleSummary(r)}</div><span class="ra">${ruleAct(r)}</span>
    <div class="ops"><button class="ib" ${i?'':'disabled'} onclick="mvRule(${i},-1)" title="上移">↑</button><button class="ib" ${i<R.rules.length-1?'':'disabled'} onclick="mvRule(${i},1)" title="下移">↓</button>
    <button class="ib" onclick="ruleDlg(${i})">编辑</button><button class="ib" style="color:var(--err)" onclick="rmRule(${i})">删除</button></div></div>`).join('')
   :'<div class="empty">没有规则，所有流量走默认出站</div>'}
   <div class="f2" style="margin-top:6px"><div><label>默认出站 <span class="hint">都不匹配时</span></label>
    <select onchange="RT.final=this.value;RT.dirty=true;renderRoute()">${R.outbounds.map(o=>`<option ${o===R.final?'selected':''}>${esc(o)}</option>`).join('')}</select></div></div></div>
  <div class="card"><h3>规则集 <span class="badge">${rs.length} 个</span><span class="sp"></span>
   <select onchange="if(this.value){addPreset(+this.value);this.value=''}" style="width:auto;padding:5px 8px;font-size:12.5px"><option value="">添加常用规则集…</option>
    ${RS_PRESETS.map((p,i)=>`<option value="${i}" ${rs.some(x=>x.tag===p[0])?'disabled':''}>${p[1]} (${p[0]})</option>`).join('')}</select>
   <button class="btn2 sm" onclick="rsDlg(-1)">+ 自定义</button></h3>
   ${rs.length?`<div class="tw"><table class="tbl"><tr><th>标签</th><th>类型</th><th>来源</th><th>被引用</th><th></th></tr>
    ${rs.map((x,i)=>{const used=R.rules.filter(r=>arr(r.rule_set).indexOf(x.tag)>=0).length;
     return `<tr><td><b>${esc(x.tag)}</b></td><td>${esc(x.type||'')} ${x.format?`<span class="mut">· ${esc(x.format)}</span>`:''}</td>
     <td class="mut" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.url||x.path||'')}">${esc(x.url||x.path||(x.rules?'内联 '+x.rules.length+' 条':''))}</td>
     <td>${used?used+' 条规则':'<span class="mut">未使用</span>'}</td>
     <td style="white-space:nowrap"><button class="ib" onclick="rsDlg(${i})">编辑</button><button class="ib" style="color:var(--err)" onclick="rmRs(${i})">删除</button></td></tr>`}).join('')}</table></div>`
   :'<div class="mut" style="font-size:12.5px">规则集是可远程更新的域名 / IP 列表，在规则里按标签引用</div>'}</div>`}
function mvRule(i,d){const a=RT.rules;[a[i],a[i+d]]=[a[i+d],a[i]];RT.dirty=true;renderRoute()}
function rmRule(i){if(!confirm('删除第 '+(i+1)+' 条规则？'))return;RT.rules.splice(i,1);RT.dirty=true;renderRoute()}
function rmRs(i){const t=RT.rule_set[i].tag;const used=RT.rules.filter(r=>arr(r.rule_set).indexOf(t)>=0).length;
 if(used&&!confirm(`规则集 ${t} 被 ${used} 条规则引用，删除后这些规则会校验失败。确定删除？`))return;
 RT.rule_set.splice(i,1);RT.dirty=true;renderRoute()}
function addPreset(i){const p=RS_PRESETS[i];if(RT.rule_set.some(x=>x.tag===p[0]))return;
 RT.rule_set.push({tag:p[0],type:'remote',format:'binary',url:p[2]});RT.dirty=true;renderRoute();msg('已添加规则集 '+p[0]+'，在规则里引用它即可',1)}
function tplRule(k){const ensure=i=>{const p=RS_PRESETS[i];if(!RT.rule_set.some(x=>x.tag===p[0]))RT.rule_set.push({tag:p[0],type:'remote',format:'binary',url:p[2]})};
 let r;if(k==='ads'){ensure(0);r={rule_set:['geosite-category-ads-all'],action:'reject'}}
 if(k==='bt')r={protocol:['bittorrent'],action:'reject'};
 if(k==='cn'){ensure(2);r={rule_set:['geoip-cn'],action:'reject'}}
 if(k==='private')r={ip_is_private:true,action:'reject'};
 const at=RT.rules.findIndex(x=>x.action==='sniff')+1;RT.rules.splice(at,0,r);RT.dirty=true;renderRoute();msg('已添加，记得点「保存并应用」',1)}
async function saveRoute(b){b.disabled=true;b.textContent='应用中…';
 const r=await api('/route','POST',{rules:RT.rules,rule_set:RT.rule_set,final:RT.final});
 b.textContent='保存并应用';if(r.ok){msg(r.msg,1);loadRoute()}else{b.disabled=false;msg(r.msg)}}
// 规则编辑：表单 + JSON，两边可切换；表单不认识的字段原样保留
const RF_LIST=[['domain','完整域名'],['domain_suffix','域名后缀'],['domain_keyword','域名关键词'],['domain_regex','域名正则'],['ip_cidr','目标 IP / CIDR'],['source_ip_cidr','来源 IP / CIDR'],['port','目标端口'],['port_range','端口范围 (如 1000:2000)']];
const PROTO_OPTS=['http','tls','quic','dns','bittorrent','stun','dtls','ssh','rdp'];
let RE=null;
function ruleDlg(i){const r=i>=0?JSON.parse(JSON.stringify(RT.rules[i])):{action:'route',outbound:RT.final||'direct'};
 RE={i,r};const logical=r.type==='logical';
 openM(`<h2>${i>=0?'编辑规则 #'+(i+1):'添加规则'}</h2>
  <div class="mtabs"><div class="mtab ${logical?'':'active'}" data-t="f" onclick="ruleTab('f')">表单</div><div class="mtab ${logical?'active':''}" data-t="j" onclick="ruleTab('j')">JSON</div></div>
  <div id="mt-f" style="${logical?'display:none':''}"></div>
  <div id="mt-j" style="${logical?'':'display:none'}"><label>规则 JSON <span class="hint">逻辑规则等高级写法在这里改</span></label><textarea id="rj" rows="14"></textarea></div>
  <div class="acts"><button onclick="saveRule()">确定</button><button class="btn2" onclick="closeM()">取消</button><span class="mut" style="font-size:12px">确定后还需「保存并应用」</span></div>`,1);
 if(logical){$('rj').value=JSON.stringify(r,null,2);RE.tab='j'}else{RE.tab='f';ruleForm()}}
function ruleForm(){const r=RE.r;const a=r.action||'route';
 const ins=RT.inbounds.map(t=>`<label class="chk"><input type="checkbox" class="ri-in" value="${esc(t)}" ${arr(r.inbound).indexOf(t)>=0?'checked':''}><span>${esc(t)}</span></label>`).join('');
 const rss=(RT.rule_set||[]).map(x=>`<label class="chk"><input type="checkbox" class="ri-rs" value="${esc(x.tag)}" ${arr(r.rule_set).indexOf(x.tag)>=0?'checked':''}><span>${esc(x.tag)}</span></label>`).join('');
 $('mt-f').innerHTML=`<div class="f2"><div><label>动作</label><select id="ri-act" onchange="RE.r.action=this.value;ruleRead();ruleForm()">
   ${Object.entries(ACTS).map(([k,v])=>`<option value="${k}" ${k===a?'selected':''}>${v} (${k})</option>`).join('')}</select></div>
  <div>${a==='route'?`<label>出站</label><select id="ri-out">${RT.outbounds.map(o=>`<option ${o===r.outbound?'selected':''}>${esc(o)}</option>`).join('')}</select>`:''}</div></div>
  <p class="mut" style="font-size:12px;margin-top:8px">下面的条件全部留空 = 匹配所有流量。同一类里多项是「或」，不同类之间是「且」。</p>
  <div class="f2"><div><label>入站（节点）</label><div class="chkbox" style="max-height:150px">${ins||'<span class="mut" style="font-size:12px">无</span>'}</div></div>
   <div><label>规则集</label><div class="chkbox" style="max-height:150px">${rss||'<span class="mut" style="font-size:12px;padding:6px;display:block">还没有规则集，先在页面上添加</span>'}</div></div></div>
  <div class="f2"><div><label>网络</label><select id="ri-net"><option value="">不限</option><option value="tcp" ${r.network==='tcp'?'selected':''}>TCP</option><option value="udp" ${r.network==='udp'?'selected':''}>UDP</option></select></div>
   <div><label>协议 <span class="hint">需要嗅探</span></label><div class="chkbox" style="max-height:110px;display:flex;flex-wrap:wrap">${PROTO_OPTS.map(p=>`<label class="chk" style="padding:4px 8px"><input type="checkbox" class="ri-pr" value="${p}" ${arr(r.protocol).indexOf(p)>=0?'checked':''}><span>${p}</span></label>`).join('')}</div></div></div>
  <div class="f2">${RF_LIST.map(([k,l])=>`<div><label>${l} <span class="hint">每行一项</span></label><textarea id="ri-${k}" rows="2">${esc(arr(r[k]).join('\n'))}</textarea></div>`).join('')}</div>
  <label class="chk" style="margin-top:8px"><input type="checkbox" id="ri-priv" ${r.ip_is_private?'checked':''}><span>匹配非公开 IP</span><i>内网 / 本机地址</i></label>
  <label class="chk"><input type="checkbox" id="ri-inv" ${r.invert?'checked':''}><span>反选结果</span><i>条件不满足时才命中</i></label>`}
function ruleRead(){if(RE.tab!=='f'||!$('ri-act'))return;const r=RE.r;const set=(k,v)=>{if(v==null||v===''||(Array.isArray(v)&&!v.length)||v===false)delete r[k];else r[k]=v};
 const chk=c=>[...document.querySelectorAll('.'+c+':checked')].map(e=>e.value);
 r.action=$('ri-act').value;
 if(r.action==='route'&&$('ri-out'))r.outbound=$('ri-out').value;else delete r.outbound;
 set('inbound',chk('ri-in'));set('rule_set',chk('ri-rs'));set('network',$('ri-net').value);set('protocol',chk('ri-pr'));
 RF_LIST.forEach(([k])=>{let v=$('ri-'+k).value.split('\n').map(s=>s.trim()).filter(Boolean);
  if(k==='port')v=v.map(x=>+x).filter(x=>x>0&&x<65536);set(k,v)});
 set('ip_is_private',$('ri-priv').checked);set('invert',$('ri-inv').checked);
 if(r.action==='route'&&!r.outbound)r.outbound='direct'}
function ruleTab(t){if(t===RE.tab)return;
 if(t==='j'){ruleRead();$('rj').value=JSON.stringify(RE.r,null,2)}
 else{let o;try{o=JSON.parse($('rj').value)}catch(e){return msg('JSON 格式错误：'+e.message)}
  if(o.type==='logical')return msg('逻辑规则只能用 JSON 编辑');RE.r=o;ruleForm()}
 RE.tab=t;document.querySelectorAll('.mtab').forEach(e=>e.classList.toggle('active',e.dataset.t===t));
 $('mt-f').style.display=t==='f'?'':'none';$('mt-j').style.display=t==='j'?'':'none'}
function saveRule(){let r;if(RE.tab==='j'){try{r=JSON.parse($('rj').value)}catch(e){return msg('JSON 格式错误：'+e.message)}}
 else{ruleRead();r=RE.r}
 if(typeof r!=='object'||Array.isArray(r))return msg('规则必须是一个 JSON 对象');
 if(r.action==='route'||(!r.action&&r.outbound)){if(r.action==='route'&&!r.outbound)return msg('请选择出站')}
 if(RE.i>=0)RT.rules[RE.i]=r;else{const at=RT.rules.length;RT.rules.splice(at,0,r)}
 RT.dirty=true;closeM();renderRoute()}
function rsDlg(i){const x=i>=0?RT.rule_set[i]:{type:'remote',format:'binary'};
 openM(`<h2>${i>=0?'编辑规则集':'添加规则集'}</h2>
  <div class="f2"><div><label>标签</label><input id="rs-tag" value="${esc(x.tag||'')}" placeholder="如 geosite-openai"></div>
   <div><label>类型</label><select id="rs-type" onchange="$('rs-r').style.display=this.value==='remote'?'':'none';$('rs-l').style.display=this.value==='local'?'':'none'">
    <option value="remote" ${x.type==='remote'?'selected':''}>远程 (remote)</option><option value="local" ${x.type==='local'?'selected':''}>本地文件 (local)</option></select></div></div>
  <div class="f2"><div><label>格式</label><select id="rs-fmt"><option value="binary" ${x.format!=='source'?'selected':''}>binary (.srs)</option><option value="source" ${x.format==='source'?'selected':''}>source (.json)</option></select></div>
   <div id="rs-r2"><label>更新间隔 <span class="hint">默认 1d</span></label><input id="rs-iv" value="${esc(x.update_interval||'')}" placeholder="1d"></div></div>
  <div id="rs-r" style="${x.type==='remote'?'':'display:none'}"><label>下载地址</label><input id="rs-url" value="${esc(x.url||'')}" placeholder="https://…/geosite-xxx.srs"></div>
  <div id="rs-l" style="${x.type==='local'?'':'display:none'}"><label>文件路径</label><input id="rs-path" value="${esc(x.path||'')}" placeholder="/etc/sing-box/xxx.srs"></div>
  <div class="acts"><button onclick="saveRs(${i})">确定</button><button class="btn2" onclick="closeM()">取消</button></div>`)}
function saveRs(i){const tag=$('rs-tag').value.trim(),type=$('rs-type').value;if(!tag)return msg('请填标签');
 if(RT.rule_set.some((x,j)=>x.tag===tag&&j!==i))return msg('标签已存在');
 const o=i>=0?Object.assign({},RT.rule_set[i]):{};o.tag=tag;o.type=type;o.format=$('rs-fmt').value;
 if(type==='remote'){o.url=$('rs-url').value.trim();if(!o.url)return msg('请填下载地址');delete o.path;const iv=$('rs-iv').value.trim();if(iv)o.update_interval=iv;else delete o.update_interval}
 else{o.path=$('rs-path').value.trim();if(!o.path)return msg('请填文件路径');delete o.url;delete o.update_interval}
 const old=i>=0?RT.rule_set[i].tag:null;
 if(i>=0){RT.rule_set[i]=o;if(old!==tag)RT.rules.forEach(r=>{if(r.rule_set){r.rule_set=arr(r.rule_set).map(t=>t===old?tag:t)}})}else RT.rule_set.push(o);
 RT.dirty=true;closeM();renderRoute()}

// ════════ DNS（参照 s-ui DNS）════════
let DN=null;
const DNS_TYPES=[['local','系统 DNS'],['udp','UDP'],['tcp','TCP'],['tls','DNS over TLS'],['https','DNS over HTTPS'],['h3','DNS over HTTP/3'],['quic','DNS over QUIC']];
async function loadDns(){const r=await api('/dns');DN=Object.assign(r,{dirty:false});DN.dns=DN.dns||{};renderDns()}
function renderDns(){const D=DN.dns;const sv=D.servers||[],ru=D.rules||[];const box=$('p-dns');const tags=sv.map(s=>s.tag);
 box.innerHTML=`<div class="bar"><button onclick="saveDns(this)" ${DN.dirty?'':'disabled'}>保存并应用</button>
  ${DN.dirty?'<span class="dirty">● 有未保存的修改</span>':''}<span class="sp"></span><button class="btn2" onclick="loadDns()">撤销修改</button></div>
  <div class="note">服务端的 DNS 决定 sing-box 解析目标域名时找谁。不配置时用系统 DNS，大多数情况不用改。<br>配置了多个服务器时，必须指定「出站解析服务器」（sing-box 1.12 起的要求），保存时会自动补上。</div>
  <div class="card"><h3>基本设置</h3>
   <div class="f3"><div><label>默认服务器 <span class="hint">都不匹配时</span></label><select onchange="dnsSet('final',this.value)"><option value="">第一个服务器</option>${tags.map(t=>`<option ${t===D.final?'selected':''}>${esc(t)}</option>`).join('')}</select></div>
    <div><label>出站解析服务器 <span class="hint">节点连目标时用</span></label><select onchange="DN.resolver=this.value;DN.dirty=true;renderDns()"><option value="">自动</option>${tags.map(t=>`<option ${t===DN.resolver?'selected':''}>${esc(t)}</option>`).join('')}</select></div>
    <div><label>解析策略</label><select onchange="dnsSet('strategy',this.value)">${[['','默认'],['prefer_ipv4','优先 IPv4'],['prefer_ipv6','优先 IPv6'],['ipv4_only','仅 IPv4'],['ipv6_only','仅 IPv6']].map(([v,l])=>`<option value="${v}" ${(D.strategy||'')===v?'selected':''}>${l}</option>`).join('')}</select></div></div>
   <div class="f2"><div><label>缓存容量 <span class="hint">条，小于 1024 无效</span></label><input type="number" value="${D.cache_capacity||''}" placeholder="默认" onchange="dnsSet('cache_capacity',this.value?+this.value:'')"></div>
    <div><label>&nbsp;</label><label class="chk"><input type="checkbox" ${D.disable_cache?'checked':''} onchange="dnsSet('disable_cache',this.checked)"><span>禁用缓存</span></label></div></div></div>
  <div class="card"><h3>服务器 <span class="badge">${sv.length} 个</span><span class="sp"></span><button class="btn2 sm" onclick="dsDlg(-1)">+ 添加服务器</button></h3>
   ${sv.length?`<div class="tw"><table class="tbl"><tr><th>标签</th><th>类型</th><th>地址</th><th>经由出站</th><th></th></tr>
    ${sv.map((s,i)=>`<tr><td><b>${esc(s.tag)}</b>${s.tag===(D.final||tags[0])?' <span class="badge b">默认</span>':''}</td><td>${esc(s.type||'')}</td>
     <td class="mut">${esc(s.server||'')}${s.server_port?':'+s.server_port:''}</td><td class="mut">${esc(s.detour||'直连')}</td>
     <td style="white-space:nowrap"><button class="ib" ${i?'':'disabled'} onclick="mvDs(${i},-1)">↑</button><button class="ib" onclick="dsDlg(${i})">编辑</button><button class="ib" style="color:var(--err)" onclick="rmDs(${i})">删除</button></td></tr>`).join('')}</table></div>`
   :'<div class="mut" style="font-size:12.5px">未配置，使用系统 DNS</div>'}</div>
  <div class="card"><h3>DNS 规则 <span class="badge">${ru.length} 条</span><span class="sp"></span><button class="btn2 sm" ${sv.length?'':'disabled'} onclick="drDlg(-1)">+ 添加规则</button></h3>
   ${ru.length?ru.map((r,i)=>`<div class="rule"><span class="ri">${i+1}</span><div class="rb">${ruleSummary(r)}${r.query_type?`<span class="c">类型: ${esc(arr(r.query_type).join(', '))}</span>`:''}</div>
    <span class="ra">${r.action==='reject'?'<span style="color:var(--err)">拒绝</span>':`<span style="color:var(--pri)">→ ${esc(r.server||'?')}</span>`}</span>
    <div class="ops"><button class="ib" ${i?'':'disabled'} onclick="mvDr(${i},-1)">↑</button><button class="ib" ${i<ru.length-1?'':'disabled'} onclick="mvDr(${i},1)">↓</button>
    <button class="ib" onclick="drDlg(${i})">编辑</button><button class="ib" style="color:var(--err)" onclick="rmDr(${i})">删除</button></div></div>`).join('')
   :'<div class="mut" style="font-size:12.5px">没有规则，所有查询走默认服务器</div>'}</div>`}
function dnsSet(k,v){if(v===''||v==null||v===false)delete DN.dns[k];else DN.dns[k]=v;DN.dirty=true;renderDns()}
function mvDs(i,d){const a=DN.dns.servers;[a[i],a[i+d]]=[a[i+d],a[i]];DN.dirty=true;renderDns()}
function rmDs(i){const t=DN.dns.servers[i].tag;if(!confirm('删除 DNS 服务器 '+t+'？'))return;DN.dns.servers.splice(i,1);
 if(DN.dns.final===t)delete DN.dns.final;if(DN.resolver===t)DN.resolver='';DN.dirty=true;renderDns()}
function mvDr(i,d){const a=DN.dns.rules;[a[i],a[i+d]]=[a[i+d],a[i]];DN.dirty=true;renderDns()}
function rmDr(i){if(!confirm('删除第 '+(i+1)+' 条 DNS 规则？'))return;DN.dns.rules.splice(i,1);DN.dirty=true;renderDns()}
function dsDlg(i){const s=i>=0?DN.dns.servers[i]:{type:'https'};
 openM(`<h2>${i>=0?'编辑 DNS 服务器':'添加 DNS 服务器'}</h2>
  <div class="f2"><div><label>标签</label><input id="ds-tag" value="${esc(s.tag||'')}" placeholder="如 cloudflare"></div>
   <div><label>类型</label><select id="ds-type" onchange="$('ds-addr').style.display=this.value==='local'?'none':''">${DNS_TYPES.map(([v,l])=>`<option value="${v}" ${s.type===v?'selected':''}>${l} (${v})</option>`).join('')}</select></div></div>
  <div id="ds-addr" style="${s.type==='local'?'display:none':''}"><div class="f2"><div><label>服务器地址</label><input id="ds-srv" value="${esc(s.server||'')}" placeholder="1.1.1.1"></div>
   <div><label>端口 <span class="hint">留空用默认</span></label><input id="ds-port" type="number" value="${s.server_port||''}"></div></div>
   <label>经由出站 <span class="hint">留空直连</span></label><select id="ds-det"><option value="">直连</option>${DN.outbounds.filter(o=>o!=='direct').map(o=>`<option ${o===s.detour?'selected':''}>${esc(o)}</option>`).join('')}</select></div>
  <div class="acts"><button onclick="saveDs(${i})">确定</button><button class="btn2" onclick="closeM()">取消</button></div>`)}
function saveDs(i){const tag=$('ds-tag').value.trim();if(!tag)return msg('请填标签');
 const sv=DN.dns.servers=DN.dns.servers||[];if(sv.some((x,j)=>x.tag===tag&&j!==i))return msg('标签已存在');
 const o=i>=0?Object.assign({},sv[i]):{};const old=i>=0?sv[i].tag:null;o.tag=tag;o.type=$('ds-type').value;
 if(o.type==='local'){delete o.server;delete o.server_port;delete o.detour}
 else{o.server=$('ds-srv').value.trim();if(!o.server)return msg('请填服务器地址');const p=+$('ds-port').value;if(p)o.server_port=p;else delete o.server_port;
  const d=$('ds-det').value;if(d)o.detour=d;else delete o.detour}
 if(i>=0){sv[i]=o;if(old!==tag){(DN.dns.rules||[]).forEach(r=>{if(r.server===old)r.server=tag});if(DN.dns.final===old)DN.dns.final=tag;if(DN.resolver===old)DN.resolver=tag}}else sv.push(o);
 DN.dirty=true;closeM();renderDns()}
let DRE=null;
function drDlg(i){const r=i>=0?JSON.parse(JSON.stringify(DN.dns.rules[i])):{server:(DN.dns.servers[0]||{}).tag};DRE={i,r};
 const tags=(DN.dns.servers||[]).map(s=>s.tag);
 openM(`<h2>${i>=0?'编辑 DNS 规则 #'+(i+1):'添加 DNS 规则'}</h2>
  <div class="mtabs"><div class="mtab active" data-t="f" onclick="drTab('f')">表单</div><div class="mtab" data-t="j" onclick="drTab('j')">JSON</div></div>
  <div id="mt-f"><div class="f2"><div><label>动作</label><select id="dr-act"><option value="route" ${r.action!=='reject'?'selected':''}>交给服务器</option><option value="reject" ${r.action==='reject'?'selected':''}>拒绝</option></select></div>
   <div><label>服务器</label><select id="dr-srv">${tags.map(t=>`<option ${t===r.server?'selected':''}>${esc(t)}</option>`).join('')}</select></div></div>
   <div class="f2">${[['domain','完整域名'],['domain_suffix','域名后缀'],['domain_keyword','域名关键词'],['domain_regex','域名正则']].map(([k,l])=>`<div><label>${l} <span class="hint">每行一项</span></label><textarea id="dr-${k}" rows="2">${esc(arr(r[k]).join('\n'))}</textarea></div>`).join('')}</div>
   <div class="f2"><div><label>查询类型 <span class="hint">如 A、AAAA、HTTPS，逗号分隔</span></label><input id="dr-qt" value="${esc(arr(r.query_type).join(', '))}"></div>
    <div><label>规则集</label><select id="dr-rs" multiple style="height:72px">${(DN.rule_sets||[]).map(t=>`<option ${arr(r.rule_set).indexOf(t)>=0?'selected':''}>${esc(t)}</option>`).join('')}</select></div></div>
   <label class="chk" style="margin-top:8px"><input type="checkbox" id="dr-inv" ${r.invert?'checked':''}><span>反选结果</span></label></div>
  <div id="mt-j" style="display:none"><textarea id="drj" rows="12"></textarea></div>
  <div class="acts"><button onclick="saveDr()">确定</button><button class="btn2" onclick="closeM()">取消</button><span class="mut" style="font-size:12px">确定后还需「保存并应用」</span></div>`,1);DRE.tab='f'}
function drRead(){if(DRE.tab!=='f')return;const r=DRE.r;const set=(k,v)=>{if(v==null||v===''||(Array.isArray(v)&&!v.length)||v===false)delete r[k];else r[k]=v};
 const a=$('dr-act').value;if(a==='reject'){r.action='reject';delete r.server}else{delete r.action;r.server=$('dr-srv').value}
 ['domain','domain_suffix','domain_keyword','domain_regex'].forEach(k=>set(k,$('dr-'+k).value.split('\n').map(s=>s.trim()).filter(Boolean)));
 set('query_type',$('dr-qt').value.split(/[,，\s]+/).map(s=>s.trim().toUpperCase()).filter(Boolean));
 set('rule_set',[...$('dr-rs').selectedOptions].map(o=>o.value));set('invert',$('dr-inv').checked)}
function drTab(t){if(t===DRE.tab)return;
 if(t==='j'){drRead();$('drj').value=JSON.stringify(DRE.r,null,2)}else{try{DRE.r=JSON.parse($('drj').value)}catch(e){return msg('JSON 格式错误：'+e.message)}drDlg2()}
 DRE.tab=t;document.querySelectorAll('.mtab').forEach(e=>e.classList.toggle('active',e.dataset.t===t));
 $('mt-f').style.display=t==='f'?'':'none';$('mt-j').style.display=t==='j'?'':'none'}
function drDlg2(){const keep=DRE.r,i=DRE.i;drDlg(i);DRE.r=keep;const r=keep;
 $('dr-act').value=r.action==='reject'?'reject':'route';if(r.server)$('dr-srv').value=r.server;
 ['domain','domain_suffix','domain_keyword','domain_regex'].forEach(k=>$('dr-'+k).value=arr(r[k]).join('\n'));
 $('dr-qt').value=arr(r.query_type).join(', ');$('dr-inv').checked=!!r.invert}
function saveDr(){let r;if(DRE.tab==='j'){try{r=JSON.parse($('drj').value)}catch(e){return msg('JSON 格式错误：'+e.message)}}else{drRead();r=DRE.r}
 const ru=DN.dns.rules=DN.dns.rules||[];if(DRE.i>=0)ru[DRE.i]=r;else ru.push(r);DN.dirty=true;closeM();renderDns()}
async function saveDns(b){b.disabled=true;b.textContent='应用中…';
 const r=await api('/dns','POST',{dns:DN.dns,resolver:DN.resolver||''});
 b.textContent='保存并应用';if(r.ok){msg(r.msg,1);loadDns()}else{b.disabled=false;msg(r.msg)}}

// ════════ 设置 ════════
async function loadSet(){let d={};try{d=await api('/dashboard')}catch(e){}
 const st=d.stats||{};
 $('p-set').innerHTML=`<div class="grid2">
  <div class="card"><h3>备份与恢复</h3>
   <p class="mut" style="font-size:12.5px;margin-bottom:6px">备份包含 sing-box 配置、节点信息、用户和订阅地址；不含面板登录密码和证书文件。</p>
   <div class="acts"><button onclick="doBackup()">下载备份</button>
    <label class="btn2" style="display:inline-block;margin:0;padding:8px 15px;border-radius:var(--r2);cursor:pointer;font-size:13.5px;color:var(--tx)">从文件恢复…<input type="file" accept=".json,application/json" style="display:none" onchange="doRestore(this)"></label></div></div>
  <div class="card"><h3>流量统计 ${st.disabled?'<span class="badge">已关闭</span>':'<span class="badge g">已开启</span>'}</h3>
   <p class="mut" style="font-size:12.5px">累计流量用 iptables 按端口精确计数（只计数、不拦截）；当前连接数和在线 IP 读取 sing-box 只监听本机的 Clash API。</p>
   <div class="row"><span>计数方式</span><span>${st.mode==='iptables'?'<span class="badge g">iptables 精确计数</span>':`<span class="badge y">Clash API 估算</span>`}</span></div>
   ${st.acct_err&&st.mode!=='iptables'?`<div class="row"><span>原因</span><span class="mut">${esc(st.acct_err)}</span></div>`:''}
   <div class="acts"><button class="${st.disabled?'':'btnd'}" onclick="toggleStats(${st.disabled?1:0})">${st.disabled?'开启流量统计':'关闭流量统计'}</button></div>
   <p class="mut" style="font-size:12px;margin-top:8px">开关会重启一次 sing-box</p></div>
  <div class="card"><h3>面板访问</h3><p class="mut" style="font-size:12.5px">访问路径和 HTTPS 在「证书」页设置。</p>
   <div class="acts"><button class="btn2" onclick="pathDlg()">更换访问路径</button><button class="btn2" onclick="go('cert')">前往证书页</button></div></div>
 </div>`}
async function doBackup(){const r=await fetch(BASE+'/api/backup',{headers:{'X-Token':TK}});if(!r.ok)return msg('备份失败');
 const blob=await r.blob();const a=document.createElement('a');a.href=URL.createObjectURL(blob);
 a.download=(r.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)?.[1]||'sb-panel-backup.json';
 document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},1000);msg('已下载备份',1)}
async function doRestore(inp){const f=inp.files[0];inp.value='';if(!f)return;let bk;
 try{bk=JSON.parse(await f.text())}catch(e){return msg('文件不是有效的 JSON')}
 if(!bk||bk.app!=='sb-panel')return msg('不是本面板导出的备份文件');
 if(!confirm(`用 ${bk.time||'该'} 的备份覆盖当前配置？\n\n节点 ${(bk.config.inbounds||[]).length} 个，用户 ${((bk.users||{}).users||[]).length} 个。会重启 sing-box，失败自动回滚。`))return;
 msg('恢复中…',1);const r=await api('/restore','POST',{backup:bk});msg(r.msg,r.ok);if(r.ok){refresh();loadSet()}}
async function toggleStats(on){if(!on&&!confirm('关闭后首页不再显示节点流量和连接数，确定？'))return;
 const r=await api('/stats-toggle','POST',{on:!!on});msg(r.msg,r.ok);loadSet()}

// ── 弹窗通用行为 ──
(function(){let t=null;document.addEventListener('scroll',e=>{const el=e.target;if(!el||el.nodeType!==1||el.id!=='mbox')return;
 el.classList.add('scrolling');clearTimeout(t);t=setTimeout(()=>el.classList.remove('scrolling'),120)},true)})();
(function(){const md=$('modal');new MutationObserver(()=>{const open=md.classList.contains('show');
 document.body.classList.toggle('mopen',open);const bx=$('mbox');if(open&&bx)bx.scrollTop=0}).observe(md,{attributes:true,attributeFilter:['class']})})();
let _mdOnMask=false;
$('modal').addEventListener('mousedown',e=>{_mdOnMask=(e.target.id==='modal')});
$('modal').addEventListener('click',e=>{if(e.target.id==='modal'&&_mdOnMask)closeM();_mdOnMask=false});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&$('modal').classList.contains('show'))closeM()});
window.addEventListener('beforeunload',e=>{if((RT&&RT.dirty)||(DN&&DN.dirty)){e.preventDefault();e.returnValue=''}});
(async()=>{if(TK){try{await api('/status');show(1)}catch(e){show(0)}}else show(0)})();
</script></body></html>"""


class PanelHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128      # 默认只有 5，堆积时会直接拒绝连接
    allow_reuse_address = True
    tls_ctx = None                # 由 use_tls() 挂上

    def use_tls(self, ctx):
        """挂 TLS —— 但绝不包装监听套接字。

        `srv.socket = ctx.wrap_socket(srv.socket, server_side=True)` 是个陷阱：
        SSLSocket.accept() 会在 accept 循环里**同步完成 TLS 握手**，只要有一个
        客户端连上后不发 ClientHello（端口扫描器、半开的移动网络连接都会），
        serve_forever 就永久卡在那里；后续连接堆满内核 accept 队列之后，
        端口对外表现为「不监听」，而线程本身还活着 —— 外部完全看不出是死是活。
        这里改成 accept 立刻返回明文 socket，握手放到每连接的工作线程里做。"""
        self.tls_ctx = ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(30)       # 握手 / 首行 / keep-alive 空闲统一 30s 上限
        return sock, addr

    def process_request_thread(self, request, client_address):
        try:
            if self.tls_ctx is not None:
                request = self.tls_ctx.wrap_socket(request, server_side=True)
            self.finish_request(request, client_address)
        except Exception:
            pass                  # 握手失败 / 明文连 https 端口，静默丢弃
        finally:
            self.shutdown_request(request)

    def force_stop(self):
        """打断监听套接字，让任何卡在 accept 的 serve_forever 立即抛错退出。
        给看门狗兜底用 —— shutdown() 是无限期等待，卡住的服务它叫不醒。"""
        import socket as _sk
        try:
            self.socket.shutdown(_sk.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.socket.close()
        except Exception:
            pass


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
        HEARTBEAT["t"] = HEARTBEAT["panel"] = time.time()
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

        # 健康检查免鉴权：出问题时往往正是登录不进去的时候
        if self._strip_base(urllib.parse.urlparse(self.path).path) == "/api/health":
            return self._send(200, api_health())
        raw = urllib.parse.urlparse(self.path).path
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
            if p == "/api/health":
                return self._send(200, api_health())
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
                info = meta().get(t, {})
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
                                        "fields": fields,
                                        "port": ib.get("listen_port"),
                                        "name": info.get("name", t),
                                        "users": [u["name"] for u in load_users()["users"]
                                                  if t in (u.get("inbounds") or [])]})
            if p == "/api/dashboard":
                return self._send(200, api_dashboard())
            if p == "/api/users":
                return self._send(200, api_users())
            if p.startswith("/api/user-links/"):
                n = urllib.parse.unquote(p[len("/api/user-links/"):])
                u = next((x for x in load_users()["users"] if x["name"] == n), None)
                if not u:
                    return self._send(200, {"ok": False, "msg": "用户不存在"})
                return self._send(200, {"ok": True, "links": user_links(u),
                                        "sub": sub_base_url() + u["sub"]})
            if p == "/api/route":
                return self._send(200, api_route_get())
            if p == "/api/dns":
                return self._send(200, api_dns_get())
            if p == "/api/backup":
                body = json.dumps(api_backup(), ensure_ascii=False, indent=2).encode()
                self._sent = True
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="sb-panel-{time.strftime("%Y%m%d-%H%M")}.json"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
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
                st = api_log_state()
                if not st["enabled"]:
                    return self._send(200, {"log": "", "state": st})
                _, log, _ = sh("journalctl -u sing-box -n 80 --no-pager")
                return self._send(200, {"log": log, "state": st})
            if p == "/api/log-state":
                return self._send(200, api_log_state())
            if p.startswith("/api/test/"):
                tag = urllib.parse.unquote(p[len("/api/test/"):])
                return self._send(200, api_test_outbound(tag))
            if p == "/api/scan":
                return self._send(200, scan_dests())
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
            if p == "/api/users":
                okk, r = api_user_save("", b, True)
                return self._send(200, {"ok": okk, "msg": r})
            if p.startswith("/api/user-edit/"):
                n = urllib.parse.unquote(p[len("/api/user-edit/"):])
                okk, r = api_user_save(n, b, False)
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/users-bulk":
                okk, r = api_users_bulk(b)
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/users-del":
                okk, r = api_user_del(b.get("names") or [])
                return self._send(200, {"ok": okk, "msg": r})
            if p.startswith("/api/user-reset/"):
                n = urllib.parse.unquote(p[len("/api/user-reset/"):])
                okk, r = api_user_reset(n, b.get("what", "sub"))
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/route":
                okk, r = api_route_set(b)
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/dns":
                okk, r = api_dns_set(b)
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/restore":
                okk, r = api_restore(b)
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/stats-reset":
                okk, r = api_stats_reset(b.get("tag") or "")
                return self._send(200, {"ok": okk, "msg": r})
            if p == "/api/stats-toggle":
                okk, r = api_stats_toggle(bool(b.get("on")))
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
            if p == "/api/set-log":
                okk, m2 = api_set_log(bool(b.get("enabled")), b.get("level"))
                return self._send(200, {"ok": okk, "msg": m2})
            if p == "/api/restart":
                c, _, _ = sh("systemctl restart sing-box")
                return self._send(200, {"ok": c == 0})
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
            if p.startswith("/api/users/"):
                n = urllib.parse.unquote(p[len("/api/users/"):])
                okk, m = api_user_del([n])
                return self._send(200, {"ok": okk, "msg": m})
        return self._send(404, {"ok": False})


class SubHandler(QuietMixin, BaseHTTPRequestHandler):
    """订阅服务：以 text/plain 返回，浏览器内联显示而非下载"""
    server_version = "sb-sub"
    protocol_version = "HTTP/1.1"
    timeout = 30

    def log_message(self, *a):
        pass

    def handle_one_request(self):
        HEARTBEAT["t"] = HEARTBEAT["sub"] = time.time()
        super().handle_one_request()

    def do_GET(self):
        try:
            return self._do_GET()
        except Exception as e:
            runlog(f"订阅请求异常: {type(e).__name__}: {e}", "error")
            try:
                body = b"Internal Error"
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                pass

    def _do_GET(self):
        u = urllib.parse.urlparse(self.path)
        token = u.path.lstrip("/")
        qs = urllib.parse.parse_qs(u.query)
        real = sub_token()
        user = None if token == real else find_user_by_sub(token)
        # 停用或到期的用户和不存在的 token 一样返回 404，不泄露它曾经存在
        if not token or (token != real and not (user and user_active(user))):
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if user:
            uris = [x["uri"] for x in user_links(user)]
        else:
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
        title = f"sing-box · {user['name']}" if user else "sing-box"
        self.send_header("Profile-Title", "base64:" + base64.b64encode(title.encode()).decode())
        self.send_header("Subscription-Userinfo",
                         f"upload=0; download=0; total=0; expire={int((user or {}).get('expiry') or 0)}")
        self.end_headers()
        self.wfile.write(body)


SUB_STATE = {"port": 0, "scheme": "http", "listening": False, "server": None}


def sub_serve_forever(sub_port):
    """订阅监听器。异常抛出后由 supervisor 退避重启 —— 以前它是裸线程，
    崩了端口就永久没了，而面板还活着，外部完全发现不了。"""
    pc = load_json(PANEL_CFG, {})
    srv = PanelHTTPServer(("0.0.0.0", sub_port), SubHandler)
    scheme = "http"
    dom = pc.get("tls_domain", "")
    if dom:
        sc, sk = f"{CERT_DIR}/{dom}/fullchain.pem", f"{CERT_DIR}/{dom}/privkey.pem"
        if os.path.exists(sc) and os.path.exists(sk):
            import ssl as _s
            ctx = _s.SSLContext(_s.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(sc, sk)
            srv.use_tls(ctx)
            register_tls("subscription", ctx, sc, sk)   # 交给 cert_reload_loop 热更新
            scheme = "https"
    SUB_STATE.update(scheme=scheme, listening=True, server=srv)
    runlog(f"订阅服务已监听 {scheme}://{dom or '0.0.0.0'}:{sub_port}")
    try:
        srv.serve_forever(poll_interval=0.5)
    finally:
        SUB_STATE.update(listening=False, server=None)
        try:
            srv.server_close()               # 释放端口，否则重启时会 Address already in use
        except Exception:
            pass


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
    preflight(host, port, int(pc.get("sub_port", 8080) or 0), pc.get("tls_domain", ""))
    supervise("janitor", janitor_loop)
    supervise("auto_update", auto_update_loop)
    _wd_tls = bool(pc.get("tls_domain")) and os.path.exists(
        f"{CERT_DIR}/{pc.get('tls_domain', '')}/fullchain.pem")
    supervise("watchdog", watchdog_loop, host, port, _wd_tls)
    supervise("sub_watchdog", sub_watchdog_loop)
    supervise("cert_reload", cert_reload_loop)
    supervise("cert_renew", cert_renew_loop)
    supervise("users", users_loop)
    supervise("stats", stats_loop)
    supervise("sysmon", sys_loop)

    # 订阅服务与面板同进程（省一个 Python 解释器约 20MB），由 supervisor 看着
    sub_port = int(pc.get("sub_port", 8080))
    if sub_port and sub_port != port:
        SUB_STATE["port"] = sub_port
        supervise("subscription", sub_serve_forever, sub_port)

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
            httpd.use_tls(ctx)
            register_tls("panel", ctx, cert, key)
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
