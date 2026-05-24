import re
import numpy as np
import matplotlib.pyplot as plt
from difflib import SequenceMatcher


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


def sim(v1: str, v2: str) -> float:
    """返回相似度 0~1，1 为完全相同。"""
    try:
        n1, n2 = float(v1), float(v2)
        return 1 - min(abs(n1 - n2) / (abs(n1) + abs(n2) + 1e-9), 1.0)
    except Exception:
        pass
    if v1.lower() in ('true', 'false') and v2.lower() in ('true', 'false'):
        return 1.0 if v1.lower() == v2.lower() else 0.0
    return SequenceMatcher(None, v1, v2).ratio()


def calc_diffs(c1: dict, c2: dict):
    """返回有序 key 列表和对应的差异分数数组（0=相同，1=最大差异）。"""
    keys = sorted(set(c1) | set(c2))
    diffs = []
    for k in keys:
        if k in c1 and k in c2:
            diffs.append(1.0 - sim(c1[k], c2[k]))
        else:
            diffs.append(1.0)
    return keys, np.array(diffs, dtype=float)


def plot_pixel_matrix(keys, diffs, out_path='diff_pixel.png', width=64, cmap='RdYlGn_r'):
    """
    将每个 key 的差异分映射成一个像素，排成矩形网格。

    Parameters
    ----------
    keys : list[str]
        有序 key 列表（仅用于统计数量，不显示在图上）。
    diffs : np.ndarray
        与 keys 一一对应的差异分数，范围 [0, 1]。
    out_path : str
        输出图片路径。
    width : int
        每行像素数，决定矩阵宽度；高度自动计算。
    cmap : str
        matplotlib colormap 名称；默认红-黄-绿反转（红=差异大，绿=差异小）。
    """
    n = len(diffs)
    height = int(np.ceil(n / width))
    matrix = np.full((height, width), np.nan)

    for i, d in enumerate(diffs):
        matrix[i // width, i % width] = d

    fig, ax = plt.subplots(figsize=(10, max(2, height * 0.18)), dpi=150)

    _cmap = plt.get_cmap(cmap).copy()
    _cmap.set_bad(color='#f0f0f0')  # 空白像素用浅灰

    im = ax.imshow(matrix, aspect='auto', cmap=_cmap, vmin=0, vmax=1,
                   interpolation='nearest')

    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)

    cbar = plt.colorbar(im, ax=ax, fraction=0.02, pad=0.01)
    cbar.set_label('Diff', fontsize=8)
    cbar.ax.tick_params(labelsize=7)

    ax.set_title(f'Config Diff Pixel Map  ({n} keys → {width}×{height})',
                 fontsize=13, fontweight='bold', pad=8)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'[saved] {out_path}')


if __name__ == '__main__':
    with open('huoji.prop') as f:
        c1 = parse_kv(f.read())
    with open('cvd.prop') as f:
        c2 = parse_kv(f.read())

    keys, diffs = calc_diffs(c1, c2)
    print(f'Keys total: {len(keys)} | '
          f'Only huoji: {len(set(c1)-set(c2))} | '
          f'Only cvd: {len(set(c2)-set(c1))} | '
          f'Common: {len(set(c1)&set(c2))}')

    plot_pixel_matrix(keys, diffs)
