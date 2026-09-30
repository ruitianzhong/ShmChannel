#!/usr/bin/env python3
"""拓扑可视化: 读 gen_config 产出的 frr_overlay.json + partition.json, 生成自包含 HTML+SVG。

着色按分区状态/分组(分类身份, 每个直标节点名 -> 第二编码):
  - 常在线(partition.always_online) -> 蓝(slot1)
  - 每个轮换分区(partition.sets 的一项) -> 独立颜色(slot2 起; 超过 7 个折入灰)
  - 其余(罕有, 未调度) -> 灰

布局 `--layout`:
  - auto: 优先 线(line, 路径) -> 双层(spine, 完全二分) -> 三层(fatree, 按度数/邻接判别)
          -> 圆形兜底
  - line / spine / fatree / circle 可强制指定。

用法:
  python3 scripts/vis_topology.py --frr-overlay cfg/frr_overlay.json --partition cfg/partition.json \
      --out topo.html [--layout auto|line|spine|fatree|circle] [--title ...]
"""
import argparse
import json
import math

# 8 slot 分类调色板(参考 palette); 常在线取 slot1, 各轮换分组依次 slot2..; 超 7 组折灰。
SLOTS = [
    ("#2a78d6", "#3987e5"),   # 1 blue
    ("#eb6834", "#d95926"),   # 2 orange
    ("#1baf7a", "#199e70"),   # 3 aqua
    ("#eda100", "#c98500"),   # 4 yellow
    ("#e87ba4", "#d55181"),   # 5 magenta
    ("#008300", "#008300"),   # 6 green
    ("#4a3aa7", "#9085e9"),   # 7 violet
    ("#e34948", "#e66767"),   # 8 red
]
OTHER = ("#8a8882", "#8a8882")
SURFACE = {"page": ("#f9f9f7", "#0d0d0d"), "chart": ("#fcfcfb", "#1a1a19")}
INK = {"primary": ("#0b0b0b", "#ffffff"), "secondary": ("#52514e", "#c3c2b7"),
       "muted": ("#898781", "#898781")}
EDGE = {"light": "#c9c7bf", "dark": "#383835"}


# ---------------------------------------------------------------- 图构建
def build_graph(frr_overlay):
    nodes = sorted(frr_overlay, key=lambda n: int(n[2:]))
    edges, seen = [], set()
    for a in nodes:
        for p in frr_overlay[a].get("peers", []):
            key = frozenset((a, p["name"]))
            if p["name"] in nodes and key not in seen:
                seen.add(key)
                edges.append((a, p["name"]))
    deg = {n: 0 for n in nodes}
    for u, v in edges:
        deg[u] += 1
        deg[v] += 1
    adj = {n: set() for n in nodes}
    for u, v in edges:
        adj[u].add(v)
        adj[v].add(u)
    return nodes, edges, deg, adj


def classify_group(nodes, partition):
    """每个节点 -> 分组 id: 'A'=常在线, 'R{i}'=第 i 个轮换分区, 'O'=未调度。"""
    always = set(partition.get("always_online", []))
    sets = partition.get("sets", [])
    set_of = {}
    for i, s in enumerate(sets):
        for x in s:
            if x in nodes:
                set_of[x] = i
    group = {}
    for n in nodes:
        if n in always:
            group[n] = "A"
        elif n in set_of:
            group[n] = f"R{set_of[n]}"
        else:
            group[n] = "O"
    return group, len(sets)


def build_series(len_sets, has_other):
    """有序 series: [(group_id, label, light, dark)]。R{i} 用 SLOTS[1+i], 超出折 OTHER。"""
    order = ["A"] + [f"R{i}" for i in range(len_sets)]
    series = [("A", "常在线", *SLOTS[0])]
    for i in range(len_sets):
        if i + 1 < len(SLOTS):
            series.append((f"R{i}", f"轮换组 {i + 1}", *SLOTS[1 + i]))
        else:
            series.append((f"R{i}", f"轮换组 {i + 1}", *OTHER))   # 超量折灰
    if has_other:
        order.append("O")
        series.append(("O", "未调度", *OTHER))
    # 按 order 重排(常在线最前、未调度最后)
    return [s for g in order for s in series if s[0] == g]


# ---------------------------------------------------------------- 布局
def _is_path(nodes, deg):
    return all(d <= 2 for d in deg.values()) and \
           sum(deg.values()) == 2 * (len(nodes) - 1)


def _bipartition(nodes, adj):
    color = {}
    for n in nodes:
        if n in color:
            continue
        color[n] = 0
        st = [n]
        while st:
            cur = st.pop()
            for nb in adj[cur]:
                if nb not in color:
                    color[nb] = color[cur] ^ 1
                    st.append(nb)
                elif color[nb] == color[cur]:
                    return None
    a = [n for n in nodes if color[n] == 0]
    b = [n for n in nodes if color[n] == 1]
    if not a or not b:
        return None
    if all(len(adj[n]) == len(b) for n in a) and all(len(adj[n]) == len(a) for n in b):
        return a, b
    return None


def _fatree_tiers(nodes, adj, deg):
    """按度数 + 邻接判别 3 层 fat-tree; 不合规则返回 None。"""
    if len(nodes) < 5:
        return None
    min_deg = min(deg[n] for n in nodes)
    tier = {}
    for n in nodes:
        d = deg[n]
        if d == min_deg:
            tier[n] = "edge"
        elif any(deg[nb] == min_deg for nb in adj[n]):
            tier[n] = "agg"
        else:
            tier[n] = "core"
    core = [n for n, t in tier.items() if t == "core"]
    agg = [n for n, t in tier.items() if t == "agg"]
    edge = [n for n, t in tier.items() if t == "edge"]
    if not (core and agg and edge):
        return None
    for n in core:
        if not all(tier[nb] == "agg" for nb in adj[n]):
            return None
    for n in edge:
        if not all(tier[nb] == "agg" for nb in adj[n]):
            return None
    for n in agg:
        if any(tier[nb] not in ("edge", "core") for nb in adj[n]):
            return None
    return tier


def layout(nodes, edges, adj, deg, group, mode="auto"):
    W, H, m = 900, 620, 70
    n = len(nodes)
    if mode in ("auto", "line") and (mode == "line" or _is_path(nodes, deg)):
        pos = {}
        for i, nd in enumerate(nodes):
            x = m + (W - 2 * m) * (i / max(n - 1, 1))
            pos[nd] = {"x": round(x, 1), "y": round(H / 2, 1)}
        return pos, W, H
    if mode in ("auto", "spine"):
        bp = _bipartition(nodes, adj)
        if bp:
            top, bottom = bp
            if min(int(x[2:]) for x in top) > min(int(x[2:]) for x in bottom):
                top, bottom = bottom, top
            pos = {}
            for row, ys in ((top, m), (bottom, H - m)):
                for i, nd in enumerate(row):
                    x = m + (W - 2 * m) * (i / max(len(row) - 1, 1))
                    pos[nd] = {"x": round(x, 1), "y": round(ys, 1)}
            return pos, W, H
    if mode in ("auto", "fatree"):
        tier = _fatree_tiers(nodes, adj, deg)
        if tier:
            return _layout_fatree(nodes, tier, group, W, H, m)
    cx, cy, r = W / 2, H / 2, min(W, H) / 2 - m
    pos = {}
    for i, nd in enumerate(nodes):
        ang = 2 * math.pi * i / n - math.pi / 2
        pos[nd] = {"x": round(cx + r * math.cos(ang), 1), "y": round(cy + r * math.sin(ang), 1)}
    return pos, W, H


def _layout_fatree(nodes, tier, group, W, H, m):
    def pod_idx(n):
        g = group[n]
        return int(g[1:]) if g.startswith("R") else None
    pos = {}
    core = sorted(n for n in nodes if tier[n] == "core")
    nc = len(core)
    for i, nd in enumerate(core):
        x = m + (W - 2 * m) * (i / max(nc - 1, 1))
        pos[nd] = {"x": round(x, 1), "y": round(m, 1)}
    bypod = {}
    for n in nodes:
        if tier[n] == "agg" or tier[n] == "edge":
            i = pod_idx(n)
            if i is None:
                i = max((pod_idx(x) for x in nodes if pod_idx(x) is not None), default=0) + 1
            bypod.setdefault(i, {"agg": [], "edge": []})
            bypod[i][tier[n]].append(n)
    pods = len(bypod)
    for i, grp in sorted(bypod.items()):
        x0 = m + (W - 2 * m) * (i / pods)
        x1 = m + (W - 2 * m) * ((i + 1) / pods)
        for tier_row, ys in (("agg", H / 2), ("edge", H - m)):
            items = sorted(grp[tier_row])
            cnt = len(items)
            for j, nd in enumerate(items):
                x = x0 + (x1 - x0) * (j + 1) / (cnt + 1)
                pos[nd] = {"x": round(x, 1), "y": round(ys, 1)}
    return pos, W, H


# ---------------------------------------------------------------- HTML
def render(nodes, edges, group, series, pos, W, H, title):
    n = len(nodes)
    e = len(edges)
    edge_lines = "\n".join(
        f'<line x1="{pos[u]["x"]}" y1="{pos[u]["y"]}" x2="{pos[v]["x"]}" '
        f'y2="{pos[v]["y"]}" class="edge"/>' for u, v in edges)
    # 每个分组动态生成 class `n-<i>` + 图例 swatch 色; 深浅色各给一遍
    gdefs_l, gdefs_d, legends = [], [], []
    gmap = {gid: f"{idx}" for idx, (gid, *_r) in enumerate(series)}
    for gid, label, lx, dx in series:
        i = gmap[gid]
        gdefs_l.append(f'.n-{i} {{ fill:{lx}; }}')
        gdefs_d.append(f'.n-{i} {{ fill:{dx}; }}')
        legends.append(
            f'<span class="lg"><i class="sw" style="background:{lx}"></i>{label}</span>')

    circs = []
    for nd in nodes:
        x, y = pos[nd]["x"], pos[nd]["y"]
        ci = gmap[group[nd]]
        deg = sum(1 for u, v in edges if nd in (u, v))
        label = next(lb for gid, lb, *_ in series if gid == group[nd])
        circs.append(
            f'<g class="node" tabindex="0" data-name="{nd}" data-state="{label}" '
            f'data-degree="{deg}"><title>{nd} · {label} · 度 {deg}</title>'
            f'<circle cx="{x}" cy="{y}" r="11" class="n-{ci} ring"/>'
            f'<text class="nl" x="{x}" y="{y + 4}" text-anchor="middle">{nd}</text></g>')

    table_rows = "\n".join(
        f"<tr><td>{nd}</td><td>{next(lb for gid, lb, *_ in series if gid == group[nd])}</td>"
        f"<td>{sum(1 for u, v in edges if nd in (u, v))}</td></tr>" for nd in nodes)

    tooltip = """
    <div id="tip" class="tip" hidden></div>
    <script>
      var tip = document.getElementById('tip');
      document.querySelectorAll('.node').forEach(function (g) {
        g.addEventListener('mouseenter', function (e) { var d=g.dataset;
          tip.textContent = d.name + ' · ' + d.state + ' · 度 ' + d.degree;
          tip.hidden=false; move(e); g.classList.add('hover'); });
        g.addEventListener('mousemove', move);
        g.addEventListener('mouseleave', function(){ tip.hidden=true; g.classList.remove('hover'); });
        g.addEventListener('focus', function(){ tip.textContent=g.dataset.name; tip.hidden=false; });
        g.addEventListener('blur', function(){ tip.hidden=true; });
      });
      function move(e){ var r=document.getElementById('svg').getBoundingClientRect();
        tip.style.left=(e.clientX-r.left+12)+'px'; tip.style.top=(e.clientY-r.top-8)+'px'; }
    </script>"""

    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<style>
  :root {{ color-scheme: light; }}
  .viz-root {{
    --surface-page:{SURFACE['page'][0]}; --surface:{SURFACE['chart'][0]};
    --ink:{INK['primary'][0]}; --ink-2:{INK['secondary'][0]}; --ink-3:{INK['muted'][0]};
    --edge:{EDGE['light']};
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background:{SURFACE['page'][0]}; color:{INK['primary'][0]}; margin:0; padding:24px;
  }}
  .viz-root h1 {{ font-size:18px; margin:0 0 12px; font-weight:600; }}
  .controls {{ display:flex; gap:16px; align-items:center; margin-bottom:10px; font-size:13px; }}
  .legend {{ display:flex; gap:14px; flex-wrap:wrap; }}
  .lg {{ display:inline-flex; align-items:center; gap:6px; }}
  .sw {{ width:14px; height:14px; border-radius:4px; display:inline-block; }}
  button.toggle {{ font:inherit; border:1px solid var(--ink-3); background:transparent; color:inherit;
    border-radius:6px; padding:4px 10px; cursor:pointer; }}
  #svg {{ background:var(--surface); border:1px solid var(--ink-3); border-radius:10px; width:100%;
    height:auto; display:block; }}
  .edge {{ stroke:var(--edge); stroke-width:2; }}
  .ring {{ stroke:var(--surface); stroke-width:2.5; }}
  .node.hover circle {{ stroke-width:4; }}
  {"".join(gdefs_l)}
  .nl {{ font:12px system-ui, sans-serif; fill:var(--ink-2); text-anchor:middle;
    pointer-events:none; dy:.35em; }}
  .tip {{ position:absolute; background:#111; color:#fff; padding:4px 8px; border-radius:6px;
    font-size:12px; pointer-events:none; box-shadow:0 2px 6px rgba(0,0,0,.3); z-index:10; }}
  table {{ border-collapse:collapse; margin-top:16px; font-size:13px; width:100%; }}
  caption {{ text-align:left; font-size:13px; color:var(--ink-2); margin-bottom:6px; }}
  th,td {{ text-align:left; padding:6px 10px; border-bottom:1px solid var(--ink-3); }}
  th {{ color:var(--ink-2); font-weight:600; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) .viz-root {{
      color-scheme: dark;
      --surface-page:{SURFACE['page'][1]}; --surface:{SURFACE['chart'][1]};
      --ink:{INK['primary'][1]}; --ink-2:{INK['secondary'][1]}; --ink-3:{INK['muted'][1]};
      --edge:{EDGE['dark']};
      {"".join(gdefs_d)}
    }}
  }}
  :root[data-theme="dark"] .viz-root {{
    color-scheme: dark;
    --surface-page:{SURFACE['page'][1]}; --surface:{SURFACE['chart'][1]};
    --ink:{INK['primary'][1]}; --ink-2:{INK['secondary'][1]}; --ink-3:{INK['muted'][1]};
    --edge:{EDGE['dark']};
    {"".join(gdefs_d)}
  }}
</style></head>
<body class="viz-root">
  <h1>{title}</h1>
  <div class="controls">
    <div class="legend">{''.join(legends)}</div>
    <button class="toggle" onclick="toggleTheme()">🌓 深浅色</button>
  </div>
  <svg id="svg" viewBox="0 0 {W} {H}" role="img"
       aria-label="拓扑图: {n} 节点 {e} 链路, 按分区着色">
    <defs><style>.node{{cursor:pointer}}</style></defs>
    {edge_lines}
    {''.join(circs)}
  </svg>
  {tooltip}
  <table><caption>节点清单</caption>
    <tr><th>节点</th><th>分区/轮换组</th><th>度</th></tr>
    {table_rows}
  </table>
  <script>function toggleTheme(){{
    var r=document.documentElement;
    if(r.getAttribute('data-theme')==='dark') r.removeAttribute('data-theme');
    else r.setAttribute('data-theme','dark');}}</script>
</body></html>"""


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="拓扑可视化(常在线蓝, 每轮换分区一色; fat-tree 分层)")
    ap.add_argument("--frr-overlay", required=True)
    ap.add_argument("--partition", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--layout", default="auto", choices=["auto", "line", "spine", "fatree", "circle"])
    ap.add_argument("--title", default=None)
    args = ap.parse_args()

    frr = json.load(open(args.frr_overlay))
    part = json.load(open(args.partition))
    nodes, edges, deg, adj = build_graph(frr)
    group, len_sets = classify_group(nodes, part)
    series = build_series(len_sets, "O" in group.values())
    pos, W, H = layout(nodes, edges, adj, deg, group, args.layout)
    title = args.title or f"拓扑 {args.layout if args.layout != 'auto' else 'auto'} · {len(nodes)} 节点 / {len(edges)} 链路"
    with open(args.out, "w") as f:
        f.write(render(nodes, edges, group, series, pos, W, H, title))
    cnt = {lb: sum(1 for g in group.values() if g == gid) for gid, lb, *_ in series}
    print(f"[vis] 写出 {args.out} ({len(nodes)} 节点 / {len(edges)} 链路)")
    print(f"[vis] 分组: " + ", ".join(f"{lb}={cnt[lb]}" for gid, lb, *_ in series))


if __name__ == "__main__":
    main()