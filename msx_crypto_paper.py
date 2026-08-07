#!/usr/bin/env python3
"""
MSX 加密合约延迟套利 —— 纸面模拟交易（DRY_RUN，绝不下真单）

用真实价格跑【完整】开/平/风控逻辑，把每一笔"假设成交"记下来，
一天后直接回答：这套策略（含收敛出场）到底赚不赚。零风险。

价格源（全部公开，不需要 token）：
  - MSX 现价（成交基准）: POST /co/spot/product/page 一次拿全部标的的 price
  - 币安标记价          : GET  /fapi/v1/premiumIndex 一次拿全部
  dev = (MSX现价 − 币安标记) / 币安标记

策略逻辑：
  开仓  |dev| ≥ ENTRY_DEV 且连续确认 → 开在"会被标记拉过去"的方向
        dev<0(现价低于标记) → 做多 LONG   dev>0 → 做空 SHORT
  平仓  ① |dev|≤EXIT_DEV 缺口收敛 → 止盈   ② 反向 STOP_MOVE → 止损
        ③ 超过 MAX_HOLD_SEC 未收敛 → 超时平
  盈亏  = (平仓现价 − 开仓现价) × 方向 − 手续费 − 滑点，× 名义
        （开平都按 MSX 现价成交，这是真实机制；标记价只影响未实现盈亏/强平）

⚠️ 模拟的乐观之处：按现价(≈中间价)成交，真实市价单会吃点差；
   PAPER_SLIPPAGE 就是对此的保守补偿，跑之前可按实际点差调大。

用法：
  python3 msx_crypto_paper.py                # 正常跑（平仓/统计发 TG）
  python3 msx_crypto_paper.py --quiet        # 只控制台
  python3 msx_crypto_paper.py --duration 600 # 跑 600 秒退出（测试）
"""

import argparse
import csv
import os
import time
from datetime import datetime

import requests

from crypto_config import (
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, MSX_API_BASE, BINANCE_FAPI,
    PAPER_WATCHLIST, PAPER_TRADE_SYMBOLS, PAPER_POLL_INTERVAL,
    PAPER_HTTP_TIMEOUT, PAPER_HTTP_RETRY, PAPER_LEVERAGE, PAPER_MARGIN,
    PAPER_FEE_RATE, PAPER_SLIPPAGE, PAPER_SLIPPAGE_DEFAULT,
    PAPER_ENTRY_DEV, PAPER_CONFIRM_TICKS,
    PAPER_MAX_POSITIONS, PAPER_COOLDOWN_SEC, PAPER_EXIT_DEV, PAPER_STOP_MOVE,
    PAPER_MAX_HOLD_SEC, PAPER_REPORT_INTERVAL, PAPER_TRADES_CSV,
    PAPER_DEV_LOG_MIN, PAPER_DEV_CSV,
)

QUIET = False
NOTIONAL = PAPER_MARGIN * PAPER_LEVERAGE          # 每笔名义价值(USDT)


def round_trip_cost(sym):
    """该标的开+平的手续费+滑点(名义占比)。BTC/ETH 滑点更小。"""
    slip = PAPER_SLIPPAGE.get(sym, PAPER_SLIPPAGE_DEFAULT)
    return 2 * (PAPER_FEE_RATE + slip)

positions = {}    # sym -> {side, entry_trade, entry_mark, entry_dev, open_mono, open_dt}
cooldown = {}     # sym -> mono 截止
_streak = {}      # sym -> {'n': int, 'last': (trade, mark)}

# 偏差观测：即使 0 成交，也要知道缺口实际能到多大（用于校准阈值）
DEV_BUCKETS = [0.0005, 0.001, 0.0015, 0.002, 0.003]   # 0.05/0.1/0.15/0.2/0.3%
dev_stats = {}    # sym -> {'max': float, 'n': int, 'buckets': {b: count}}
_last_dev_pair = {}

# 运行时标的：配置 PAPER_WATCHLIST 为空则启动时自动填（MSX∩币安 全部可对比合约）
WATCHLIST = list(PAPER_WATCHLIST)
TRADE_SET = set()   # 允许模拟"下单"的标的（观测覆盖全部，交易只在这个可信子集）
stats = {'trades': 0, 'wins': 0, 'pnl': 0.0, 'cost': 0.0,
         'by_reason': {}, 'start': None}


def _ts():
    return datetime.now().strftime('%H:%M:%S')


def send_tg(text):
    if QUIET or not text:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text,
                  "parse_mode": "HTML", "disable_web_page_preview": True},
            timeout=10)
    except Exception as e:
        print(f"[{_ts()}] ⚠️ TG 失败: {e}")


# 复用连接（keep-alive），减少 TLS 握手、抗偶发抽风
_session = requests.Session()
_session.headers.update({"Accept": "application/json, text/plain, */*"})


def _req(method, url, **kw):
    """带重试的请求：超时/连接错误退避重试，其它错误直接抛。"""
    kw.setdefault('timeout', PAPER_HTTP_TIMEOUT)
    last = None
    for attempt in range(PAPER_HTTP_RETRY + 1):
        try:
            return _session.request(method, url, **kw)
        except (requests.Timeout, requests.ConnectionError) as e:
            last = e
            if attempt < PAPER_HTTP_RETRY:
                time.sleep(0.3 * (attempt + 1))
    raise last


def fetch_msx_prices():
    """一次拿全部 MSX 加密现价 {sym: price}"""
    d = _req("POST", f"{MSX_API_BASE}/co/spot/product/page",
             json={"pageIndex": 1, "pageSize": 100}).json()
    if d.get('code') != 0:
        raise RuntimeError(f"page code={d.get('code')}")
    return {x['symbol']: float(x['price']) for x in d['data']['list'] if x.get('price')}


def fetch_binance_marks():
    """一次拿全部币安标记价 {sym: mark}"""
    arr = _req("GET", f"{BINANCE_FAPI}/fapi/v1/premiumIndex").json()
    if not isinstance(arr, list):
        raise RuntimeError("premiumIndex 非列表")
    return {x['symbol']: float(x['markPrice']) for x in arr}


def _csv_init():
    if not os.path.exists(PAPER_TRADES_CSV):
        with open(PAPER_TRADES_CSV, 'w', newline='') as f:
            csv.writer(f).writerow([
                'open_time', 'symbol', 'side', 'entry_dev_pct', 'entry_trade', 'entry_mark',
                'close_time', 'close_trade', 'close_dev_pct', 'reason', 'hold_s',
                'gross_pct', 'net_pct', 'pnl_usdt', 'cum_pnl'])


def _log_trade(row):
    try:
        with open(PAPER_TRADES_CSV, 'a', newline='') as f:
            csv.writer(f).writerow(row)
    except Exception:
        pass


def _devcsv_init():
    if not os.path.exists(PAPER_DEV_CSV):
        with open(PAPER_DEV_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(['time', 'symbol', 'dev_pct', 'msx_trade', 'binance_mark'])


def track_dev(sym, dev, trade, mark):
    """记录偏差峰值/分布 + 超阈值样本。纯观测，不影响开仓判断。"""
    s = dev_stats.setdefault(sym, {'max': 0.0, 'n': 0,
                                   'buckets': {b: 0 for b in DEV_BUCKETS}})
    a = abs(dev)
    s['n'] += 1
    if a > s['max']:
        s['max'] = a
    for b in DEV_BUCKETS:
        if a >= b:
            s['buckets'][b] += 1
    # 超过记录阈值、且价格对有变化才写（避免同一报价重复记）
    if a >= PAPER_DEV_LOG_MIN and _last_dev_pair.get(sym) != (trade, mark):
        _last_dev_pair[sym] = (trade, mark)
        try:
            with open(PAPER_DEV_CSV, 'a', newline='') as f:
                csv.writer(f).writerow([
                    datetime.now().isoformat(timespec='milliseconds'), sym,
                    round(dev * 100, 4), trade, mark])
        except Exception:
            pass


def try_open(sym, trade, mark, dev, now):
    if cooldown.get(sym, 0) > now:
        return
    if len(positions) >= PAPER_MAX_POSITIONS:
        return
    if abs(dev) < PAPER_ENTRY_DEV:
        _streak.pop(sym, None)
        return
    # 连续确认（价格对有变化才计入，滤冻结帧）
    st = _streak.get(sym) or {'n': 0, 'last': None}
    _streak[sym] = st
    pair = (trade, mark)
    if pair != st['last']:
        st['n'] += 1
        st['last'] = pair
    if st['n'] < PAPER_CONFIRM_TICKS:
        return

    side = 'LONG' if dev < 0 else 'SHORT'
    positions[sym] = {'side': side, 'entry_trade': trade, 'entry_mark': mark,
                      'entry_dev': dev, 'open_mono': now, 'open_dt': datetime.now()}
    _streak.pop(sym, None)
    arrow = '做多↑' if side == 'LONG' else '做空↓'
    print(f"[{_ts()}] 🟢 模拟开仓 {sym} {arrow} @现价{trade} (标记{mark}, dev{dev*100:+.3f}%, 名义{NOTIONAL}U)")


def try_close(sym, trade, mark, dev, now):
    p = positions[sym]
    direction = 1 if p['side'] == 'LONG' else -1
    move = (trade - p['entry_trade']) / p['entry_trade']   # 现价相对变化(带符号)
    gross_pct = move * direction                           # 名义毛收益率
    hold = now - p['open_mono']

    reason = None
    if abs(dev) <= PAPER_EXIT_DEV:
        reason = '收敛止盈'
    elif gross_pct <= -PAPER_STOP_MOVE:
        reason = '止损'
    elif hold >= PAPER_MAX_HOLD_SEC:
        reason = '超时'
    if not reason:
        return

    cost_rate = round_trip_cost(sym)
    net_pct = gross_pct - cost_rate
    pnl = net_pct * NOTIONAL
    stats['trades'] += 1
    stats['pnl'] += pnl
    stats['cost'] += cost_rate * NOTIONAL
    if pnl > 0:
        stats['wins'] += 1
    stats['by_reason'][reason] = stats['by_reason'].get(reason, 0) + 1

    _log_trade([
        p['open_dt'].isoformat(timespec='seconds'), sym, p['side'],
        round(p['entry_dev'] * 100, 4), p['entry_trade'], p['entry_mark'],
        datetime.now().isoformat(timespec='seconds'), trade, round(dev * 100, 4),
        reason, round(hold, 1), round(gross_pct * 100, 4), round(net_pct * 100, 4),
        round(pnl, 4), round(stats['pnl'], 4)])

    del positions[sym]
    cooldown[sym] = now + PAPER_COOLDOWN_SEC
    emoji = '✅' if pnl > 0 else '❌'
    msg = (f"{emoji} 模拟平仓 {sym} {p['side']} [{reason}]\n"
           f"开{p['entry_trade']} → 平{trade} | 持{hold:.1f}s | "
           f"净{net_pct*100:+.3f}% → <b>{pnl:+.4f}U</b> | 累计 {stats['pnl']:+.4f}U")
    print(f"[{_ts()}] {msg.replace(chr(10),' ').replace('<b>','').replace('</b>','')}")
    send_tg(msg)


def report(to_tg=True):
    n = stats['trades']
    wr = (stats['wins'] / n * 100) if n else 0
    dur = (time.monotonic() - stats['start']) / 60 if stats['start'] else 0
    reasons = ', '.join(f"{k}{v}" for k, v in stats['by_reason'].items()) or '无'
    msg = (f"📊 模拟统计（{dur:.0f}分钟）\n"
           f"成交 {n} 笔 | 胜率 {wr:.0f}% | 净盈亏 <b>{stats['pnl']:+.4f}U</b>\n"
           f"手续费+滑点成本 {stats['cost']:.4f}U | 持仓中 {len(positions)}\n"
           f"出场分布: {reasons}")
    # 缺口观测：0 成交时这才是关键信息——缺口到底能到多大
    ranked = sorted(
        [(sym, dev_stats[sym]) for sym in WATCHLIST
         if dev_stats.get(sym) and dev_stats[sym]['n']],
        key=lambda kv: kv[1]['max'], reverse=True)
    dev_lines = []
    for sym, s in ranked:
        bk = ' '.join(f"≥{b*100:g}%×{s['buckets'][b]}" for b in DEV_BUCKETS)
        dev_lines.append(f"  {sym} 峰值 {s['max']*100:.3f}% | {bk}")
    if dev_lines:
        total = sum(dev_stats[s]['n'] for s in dev_stats)
        msg += "\n缺口观测（按峰值排序，采样 %d）:\n" % total + "\n".join(dev_lines)
    print(f"[{_ts()}] {msg.replace(chr(10),' ').replace('<b>','').replace('</b>','')}")
    # 周期统计 to_tg=False 只进控制台（避免平静时段刷屏）；开跑/最终结算才推 TG
    if to_tg:
        send_tg(msg)


def main():
    global QUIET
    ap = argparse.ArgumentParser(description="MSX 加密延迟套利 纸面模拟")
    ap.add_argument('--quiet', action='store_true', help='不发 TG，只控制台')
    ap.add_argument('--duration', type=int, default=0, help='跑 N 秒后退出(0=一直跑)')
    args = ap.parse_args()
    QUIET = args.quiet

    _csv_init()
    _devcsv_init()
    stats['start'] = time.monotonic()

    # 确定标的：配置留空 = MSX 与币安都有的全部合约（启动时求交集，就地填充）
    if not WATCHLIST:
        try:
            msx0, bn0 = fetch_msx_prices(), fetch_binance_marks()
            WATCHLIST[:] = sorted(set(msx0) & set(bn0))
            skip = sorted(set(msx0) - set(bn0))
            print(f"[{_ts()}] 自动全量: MSX {len(msx0)} 个 ∩ 币安 = {len(WATCHLIST)} 个可对比"
                  + (f"；跳过币安无对应 {len(skip)} 个: {', '.join(skip)}" if skip else ""))
        except Exception as e:
            WATCHLIST[:] = ["BTCUSDT", "ETHUSDT", "SOLUSDT"]
            print(f"[{_ts()}] ⚠️ 自动取标的失败({e})，回退 {WATCHLIST}")

    # 模拟交易子集（观测覆盖全部 watchlist，下单只在可信标的）
    TRADE_SET.update(set(PAPER_TRADE_SYMBOLS or WATCHLIST) & set(WATCHLIST))

    startup = (
        f"📝 <b>MSX 加密延迟套利 · 纸面模拟</b>（不下真单）\n"
        f"观测 {len(WATCHLIST)} 个 | 模拟交易 {len(TRADE_SET)} 个: {', '.join(sorted(TRADE_SET))}\n"
        f"开仓 |dev|≥{PAPER_ENTRY_DEV*100:.2f}% 确认{PAPER_CONFIRM_TICKS}t | "
        f"止盈|dev|≤{PAPER_EXIT_DEV*100:.2f}% 止损{PAPER_STOP_MOVE*100:.1f}% 超时{PAPER_MAX_HOLD_SEC}s\n"
        f"每笔 {PAPER_MARGIN}U×{PAPER_LEVERAGE}={NOTIONAL}U名义\n"
        f"费{PAPER_FEE_RATE*100:.3f}%/边 | 滑点 BTC/ETH "
        f"{PAPER_SLIPPAGE.get('BTCUSDT', PAPER_SLIPPAGE_DEFAULT)*100:.2f}%、"
        f"其余{PAPER_SLIPPAGE_DEFAULT*100:.2f}%/边"
    )
    print(startup.replace('<b>', '').replace('</b>', ''))
    send_tg(startup)

    last_report = time.monotonic()
    err_streak = 0
    first_ok = False
    try:
        while True:
            t0 = time.monotonic()
            try:
                msx = fetch_msx_prices()
                marks = fetch_binance_marks()
                err_streak = 0
                now = time.monotonic()

                # 首次取价成功 → 明确报活，便于确认"启动成功"
                if not first_ok:
                    first_ok = True
                    sample = [s for s in ("BTCUSDT", "ETHUSDT", "SOLUSDT")
                              if s in msx and s in marks][:3]
                    lines = [f"{s} MSX {msx[s]} vs 标记 {marks[s]} "
                             f"(dev{(msx[s]-marks[s])/marks[s]*100:+.3f}%)" for s in sample]
                    ok_msg = (f"✅ <b>数据源已连通，监控 {len(WATCHLIST)} 个标的</b>\n"
                              + "\n".join(lines))
                    print(ok_msg.replace('<b>', '').replace('</b>', ''))
                    send_tg(ok_msg)

                for sym in WATCHLIST:
                    trade, mark = msx.get(sym), marks.get(sym)
                    if not trade or not mark:
                        continue
                    dev = (trade - mark) / mark
                    track_dev(sym, dev, trade, mark)     # 观测：覆盖全部
                    if sym in positions:
                        try_close(sym, trade, mark, dev, now)
                    elif sym in TRADE_SET:               # 下单：只在可信子集
                        try_open(sym, trade, mark, dev, now)
            except Exception as e:
                err_streak += 1
                if err_streak == 1 or err_streak % 20 == 0:
                    print(f"[{_ts()}] ⚠️ 取价失败({err_streak}): {e}")

            if time.monotonic() - last_report >= PAPER_REPORT_INTERVAL:
                report(to_tg=False)
                last_report = time.monotonic()

            if args.duration and time.monotonic() - stats['start'] >= args.duration:
                break
            time.sleep(max(0.05, PAPER_POLL_INTERVAL - (time.monotonic() - t0)))
    except KeyboardInterrupt:
        print("\n⏹️ 手动停止")
    finally:
        print(f"\n[{_ts()}] === 最终结算 ===")
        report()


if __name__ == "__main__":
    main()
