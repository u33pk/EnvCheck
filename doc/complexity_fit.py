import re
import math
import numpy as np
import matplotlib.pyplot as plt


def parse_kv(text: str) -> dict:
    """解析 key=value 配置，忽略空行和 # 注释。"""
    cfg = {}
    for line in text.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^([^=:]+?)\s*[:=]\s*(.*)$', line)
        if m:
            cfg[m.group(1).strip()] = m.group(2).strip()
    return cfg


def shannon_entropy(s: str) -> float:
    """计算字符串的 Shannon 熵（bits），衡量字符分布的不确定性。"""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    n = len(s)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def infer_type(val: str) -> str:
    if val.lower() in ('true', 'false'):
        return 'boolean'
    try:
        float(val)
        return 'number'
    except ValueError:
        return 'string'


def calc_complexity_scores(cfg: dict):
    """
    为每个 key-value item 计算综合复杂度（熵）。
    维度：
      - value 的 Shannon 熵（信息密度）
      - key 的 Shannon 熵（命名复杂度）
      - key 的层级深度（点号数量，结构复杂度）
    返回：有序 keys 列表，综合分数数组，以及各维度原始值数组。
    """
    keys = sorted(cfg.keys())
    scores = []
    v_ents = []
    k_ents = []
    depths = []

    for k in keys:
        v = cfg[k]
        v_ent = shannon_entropy(v)
        k_ent = shannon_entropy(k)
        depth = k.count('.')

        # 综合分：value 熵权重最高，key 熵和深度作为结构加成
        score = v_ent + 0.3 * k_ent + 0.5 * depth

        scores.append(score)
        v_ents.append(v_ent)
        k_ents.append(k_ent)
        depths.append(depth)

    return keys, np.array(scores), np.array(v_ents), np.array(k_ents), np.array(depths)


def bin_smooth(y: np.ndarray, n_bins: int = 80, smooth_rounds: int = 3):
    """分箱聚合 + 移动平均平滑 + 插值。纯 numpy 实现。"""
    n = len(y)
    bin_size = n / n_bins
    x_bin = np.arange(n_bins, dtype=float)
    y_bin_raw = np.empty(n_bins, dtype=float)

    for i in range(n_bins):
        start = int(i * bin_size)
        end = int((i + 1) * bin_size) if i < n_bins - 1 else n
        y_bin_raw[i] = y[start:end].mean()

    y_smooth = y_bin_raw.copy()
    kernel = np.ones(3) / 3
    for _ in range(smooth_rounds):
        y_smooth = np.convolve(y_smooth, kernel, mode='same')

    x_fine = np.linspace(0, n_bins - 1, 400)
    y_fine = np.interp(x_fine, x_bin, y_smooth)
    return x_fine, y_fine, x_bin, y_bin_raw


def plot_complexity_fit(keys, scores, v_ents, k_ents, depths, title, out_path):
    """
    单文件复杂度拟合折线图。
    主图：综合复杂度（熵）的拟合曲线。
    子图（右侧小图）：三个维度的均值参考线。
    """
    x_fine, y_fine, x_bin, y_bin_raw = bin_smooth(scores, n_bins=80)

    fig = plt.figure(figsize=(14, 4.5), dpi=150)
    gs = fig.add_gridspec(1, 2, width_ratios=[4, 1], wspace=0.25)
    ax_main = fig.add_subplot(gs[0])
    ax_side = fig.add_subplot(gs[1])

    # ── 主图：拟合曲线 ──
    n = len(scores)
    x_all = np.linspace(0, 79, n)
    ax_main.scatter(x_all, scores, c='lightgray', s=1, alpha=0.15, zorder=1)
    ax_main.scatter(x_bin, y_bin_raw, c=y_bin_raw, cmap='plasma',
                    s=30, zorder=3, edgecolors='white', linewidths=0.3)
    ax_main.fill_between(x_fine, y_fine, alpha=0.25, color='darkviolet', zorder=2)
    ax_main.plot(x_fine, y_fine, color='darkviolet', linewidth=2.2, zorder=4)

    ax_main.set_xlim(-1, 80)
    ax_main.set_ylabel('Complexity Score (Entropy)', fontsize=10)
    ax_main.set_xlabel('Key Index (binned & fitted)', fontsize=10)
    ax_main.set_title(title, fontsize=13, fontweight='bold')
    ax_main.spines['top'].set_visible(False)
    ax_main.spines['right'].set_visible(False)
    ax_main.text(0.99, 0.95, f'n_keys={n}  bins={len(x_bin)}',
                 transform=ax_main.transAxes, ha='right', va='top',
                 fontsize=8, color='gray', alpha=0.8)

    # ── 右侧小图：三个维度的箱线图 ──
    data_for_box = [v_ents, k_ents, depths]
    labels = ['Value\nEntropy', 'Key\nEntropy', 'Depth']
    bp = ax_side.boxplot(data_for_box, tick_labels=labels, patch_artist=True,
                         widths=0.5, showfliers=False)
    colors = ['#AB63FA', '#636EFA', '#00CC96']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    for median in bp['medians']:
        median.set_color('white')
        median.set_linewidth(2)
    ax_side.set_ylabel('Raw Score', fontsize=9)
    ax_side.set_title('Decomposition', fontsize=11, fontweight='bold')
    ax_side.spines['top'].set_visible(False)
    ax_side.spines['right'].set_visible(False)

    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out_path}')


if __name__ == '__main__':
    import sys
    files = sys.argv[1:] if len(sys.argv) > 1 else ['huoji.prop', 'cvd.prop']

    for path in files:
        with open(path) as f:
            cfg = parse_kv(f.read())

        keys, scores, v_ents, k_ents, depths = calc_complexity_scores(cfg)
        base = path.rsplit('.', 1)[0]

        print(f'\n=== {path} ===')
        print(f'Keys: {len(keys)}')
        print(f'  Value entropy  mean={v_ents.mean():.2f}  max={v_ents.max():.2f}')
        print(f'  Key entropy    mean={k_ents.mean():.2f}  max={k_ents.max():.2f}')
        print(f'  Depth          mean={depths.mean():.2f}  max={depths.max():.2f}')

        plot_complexity_fit(
            keys, scores, v_ents, k_ents, depths,
            title=f'{path} – Complexity Trend (Fitted)',
            out_path=f'{base}_complexity.png'
        )
