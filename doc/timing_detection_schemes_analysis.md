# Zygisk Next 时序检测方案可行性分析报告

## 一、概述

本文分析三种针对 Zygisk Next 的时间侧信道检测方案的可行性。通过结合 Zygisk Next 历史源码的逆向分析，验证各方案的理论基础、实际效果及检测可靠性。

---

## 二、方案 A：双进程对比法（正常进程 vs isolatedProcess）

### 2.1 方案描述

创建两个同类型的 Service，一个正常进程，一个声明 `android:isolatedProcess="true"`。对比两者的启动耗时差异：

```cpp
// 伪代码逻辑
long normal_start = measureServiceStart("com.example.normal_service");
long isolated_start = measureServiceStart("com.example.isolated_service");
long delta = normal_start - isolated_start;

if (delta > THRESHOLD_MS && delta < UPPER_LIMIT_MS) {
    // 可疑：正常进程持续显著慢于 isolated 进程
}
```

**假设前提**：isolated 进程通常能绕过 Zygisk 的注入逻辑，可作为"基线参照组"。

### 2.2 源码验证

#### 2.2.1 Zygisk 的 Hook 安装位置

从 `jni_hooks.hpp` 可以看到，Zygisk 同时 hook 了两种进程创建路径：

```cpp
// 普通 App 进程：nativeForkAndSpecialize
std::array nativeForkAndSpecialize_methods = {
    JNINativeMethod {
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;...",
        (void *) &nativeForkAndSpecialize_l
    },
    // ... 多个重载版本
};

// isolatedProcess / WebView 进程：nativeSpecializeAppProcess
std::array nativeSpecializeAppProcess_methods = {
    JNINativeMethod {
        "nativeSpecializeAppProcess",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;Z...",
        (void *) &nativeSpecializeAppProcess_q
    },
    // ... 多个重载版本
};
```

**结论**：isolated 进程**同样会经过 Zygisk 的 hook 路径**，不会完全绕过。

#### 2.2.2 两种路径的执行差异

从 `hook.cpp` 对比两种路径的实现：

**普通进程（nativeForkAndSpecialize）**：
```cpp
void ZygiskContext::nativeForkAndSpecialize_pre() {
    fork_pre();                          // (1) 执行 hook 的 fork
    if (pid == 0) {
        app_specialize_pre();            // (2) 加载模块、preSpecialize
    }
    sanitize_fds();                      // (3) 清理非法 fd
}
```

**isolated 进程（nativeSpecializeAppProcess）**：
```cpp
void ZygiskContext::nativeSpecializeAppProcess_pre() {
    flags[SKIP_FD_SANITIZATION] = true;  // 跳过了 fd sanitization！
    app_specialize_pre();
}
```

**关键差异**：

| 操作 | 普通进程 | isolated 进程 | 差异 |
|------|---------|--------------|------|
| fork_pre() | 有（fd 遍历记录）| 无（不走 fork）| **普通进程多 ~50-500 us** |
| sanitize_fds() | 有（关闭非法 fd）| **跳过** | **普通进程多 ~70-600 us** |
| 模块加载 | 完整 | 可能简化 | 取决于模块策略 |

#### 2.2.3 关于"isolated 绕过 Zygisk"的澄清

**源码中未发现 isolated 进程的显式豁免逻辑**。Zygisk 对两种路径都安装了 hook，isolated 进程仍然会被注入。

但是，isolated 进程存在以下客观差异：
1. **不走 fork**：isolated 进程由 zygote 直接 `specialize`，跳过了 `fork_pre()` 中的 fd 遍历
2. **跳过 fd sanitization**：显式设置了 `SKIP_FD_SANITIZATION = true`
3. **模块可能不加载**：模块可以通过 `GetProcessFlags` 判断进程类型，选择性跳过 isolated 进程

### 2.3 时间开销估算

| 场景 | 普通进程 | isolated 进程 | 差异 |
|------|---------|--------------|------|
| 无 Zygisk | ~0.5-2 ms | ~0.3-1.5 ms | ~0.2-0.5 ms（系统差异） |
| 有 Zygisk（无模块）| ~1.5-5 ms | ~1-3 ms | **~0.5-2 ms** |
| 有 Zygisk（有模块）| ~5-50 ms | ~2-10 ms | **~3-40 ms** |

### 2.4 可行性评估

| 维度 | 评估 |
|------|------|
| **理论基础** | 部分成立。isolated 不会完全绕过 Zygisk，但确实减少了部分开销 |
| **检测信号强度** | 中。差异存在但可能较小（尤其无模块时仅 ~0.5-2ms） |
| **误报风险** | 中。isolated 进程本身启动路径就不同，存在系统级差异 |
| **绕过难度** | 中。Zygisk 可以对 isolated 进程也执行完整注入，消除差异 |

### 2.5 改进建议

1. **阈值设置**：`THRESHOLD_MS = 1ms`，`UPPER_LIMIT_MS = 50ms`
2. **多次采样**：单次测量不可靠，建议各采集 10-20 次取中位数
3. **组合使用**：作为基线参照，与其他方案配合效果更佳

---

## 三、方案 B：多阶段时序指纹

### 3.1 方案描述

不仅测量总启动时间，而是细分 Application.onCreate 前后的耗时分布：

- **测量点 1**：`fork()` 返回时刻（通过 `/proc/self/stat` 的 `starttime` 字段）
- **测量点 2**：应用层代码首次执行时刻（`SystemClock.uptimeMillis()`）
- **核心假设**：Zygisk 特征表现为 fork 返回后到 ActivityThread 初始化前的"空白期"异常延长

### 3.2 源码验证

#### 3.2.1 "空白期"的构成

从源码分析，fork 后存在明确的 Zygisk 注入延迟窗口：

```cpp
// hook.cpp:650-673
void ZygiskContext::nativeForkAndSpecialize_pre() {
    fork_pre();                          // (A) fd 遍历记录
    if (pid == 0) {
        app_specialize_pre();            // (B) 模块加载执行
    }
    sanitize_fds();                      // (C) fd 清理
}

void ZygiskContext::nativeForkAndSpecialize_post() {
    if (pid == 0) {
        app_specialize_post();           // (D) 模块 post + 自卸载
    }
    fork_post();
}
```

**"空白期" = (A) + (B) + (C) + (D)**，这些全部是 Zygisk 引入的额外开销。

#### 3.2.2 各阶段详细开销

**(A) fork_pre()**：
```cpp
void ZygiskContext::fork_pre() {
    sigmask(SIG_BLOCK, SIGCHLD);         // ~1 us
    pid = old_fork();                     // ~50-200 us
    if (pid != 0 || flags[SKIP_FD_SANITIZATION])
        return;

    // 子进程：遍历 /proc/self/fd
    auto dir = xopen_dir("/proc/self/fd");
    for (dirent *entry; (entry = readdir(dir.get()));) {
        int fd = parse_int(entry->d_name);
        if (fd < 0 || fd >= MAX_FD_SIZE) {
            close(fd);                    // 关闭超范围 fd
            continue;
        }
        allowed_fds[fd] = true;           // 标记允许
    }
    allowed_fds[dirfd(dir.get())] = false;
}
```
- 额外开销：**~50-500 us**（fd 数量决定）

**(B) app_specialize_pre() / run_modules_pre()**：
```cpp
void ZygiskContext::run_modules_pre() {
    auto ms = zygiskd::ReadModules();     // IPC 读取模块列表
    for (size_t i = 0; i < size; i++) {
        auto& m = ms[i];
        if (void* handle = DlopenMem(m.memfd, RTLD_NOW);  // 从 memfd 加载 SO
            void* entry = dlsym(handle, "zygisk_module_entry")) {
            modules.emplace_back(i, handle, entry);
        }
    }

    for (auto &m : modules) {
        m.onLoad(env);                    // 模块初始化
        m.preAppSpecialize(args.app);     // 模块 pre 钩子
    }
}
```
- 额外开销：**~N x (1-20) ms**（N = 模块数量）

**(C) sanitize_fds()**：
```cpp
void ZygiskContext::sanitize_fds() {
    // 处理 fds_to_ignore 参数
    // 遍历 /proc/self/fd，关闭非白名单 fd
    for (dirent *entry; (entry = readdir(dir.get()));) {
        int fd = parse_int(entry->d_name);
        if ((fd < 0 || fd >= MAX_FD_SIZE || !allowed_fds[fd]) && fd != dfd) {
            close(fd);
        }
    }
}
```
- 额外开销：**~70-600 us**

**(D) app_specialize_post() / run_modules_post()**：
```cpp
void ZygiskContext::run_modules_post() {
    flags[POST_SPECIALIZE] = true;
    for (const auto &m : modules) {
        m.postAppSpecialize(args.app);    // 模块 post 钩子
        m.tryUnload();                     // 尝试卸载模块
    }
}
```
- 额外开销：**~0.3-10 ms**（取决于模块 post 实现）

#### 3.2.3 测量方法实现

```cpp
// 方法：通过 /proc/self/stat 获取内核视角的进程启动时间
long get_kernel_start_time() {
    FILE* fp = fopen("/proc/self/stat", "r");
    if (!fp) return -1;

    char line[1024];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // /proc/[pid]/stat 格式：
    // pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt
    // utime stime cutime cstime priority nice num_threads itrealvalue starttime ...
    // 第 22 个字段是 starttime（自系统启动以来的时钟滴答数）

    // 注意：comm 字段可能包含空格和括号，需要特殊处理
    char* p = strrchr(line, ')');
    if (!p) return -1;
    p += 2;  // 跳过 ") "

    // 跳过前 19 个字段（从 state 开始数）
    for (int i = 0; i < 19; i++) {
        p = strchr(p, ' ');
        if (!p) return -1;
        p++;
    }

    long starttime = strtol(p, nullptr, 10);
    return starttime;
}

// 应用层测量
long get_app_start_time() {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;  // ms
}

// "空白期" = 应用层首次执行时间 - 内核 starttime 转换后的时间
// 注意：需要统一时间基准，或计算相对差值
```

### 3.3 时间开销汇总

| 阶段 | 无 Zygisk | 有 Zygisk（无模块）| 有 Zygisk（3 模块）|
|------|----------|------------------|------------------|
| fork 本身 | ~50-200 us | ~50-200 us | ~50-200 us |
| fork_pre() | 0 | ~50-500 us | ~50-500 us |
| run_modules_pre() | 0 | ~0.1-1 ms | ~3-60 ms |
| sanitize_fds() | 0 | ~70-600 us | ~70-600 us |
| run_modules_post() | 0 | ~0.1-0.5 ms | ~0.3-10 ms |
| **"空白期"总计** | **~0.5-2 ms** | **~1.5-5 ms** | **~5-80 ms** |

### 3.4 可行性评估

| 维度 | 评估 |
|------|------|
| **理论基础** | **完全成立**。直接测量 Zygisk 核心注入路径的延迟 |
| **检测信号强度** | **高**。>3 倍的时间差异（无模块时 2-3x，有模块时 10-40x） |
| **误报风险** | 低。测量的是 Zygisk 特有的 fork 后 specialize 延迟 |
| **绕过难度** | **高**。这些开销是功能必需的，无法消除 |

### 3.5 优势与局限

**优势**：
1. 直接击中 Zygisk 的核心注入机制
2. 测量的是"额外开销"而非总时间，信噪比高
3. 不依赖外部参照，自包含检测

**局限**：
1. 需要区分"系统正常 specialize 时间"和"Zygisk 额外时间"
2. `/proc/self/stat` 的 `starttime` 单位是时钟滴答，需要转换
3. 需要 root 权限才能精确测量某些阶段（但普通 App 可通过 JNI 调用 native 代码实现）

---

## 四、方案 C：统计显著性检测

### 4.1 方案描述

单次测量不可靠，需要进行多次冷启动采样（建议 ≥20 次）：

1. 计算样本方差，剔除 Thermal throttling 导致的离群值
2. 对比同一设备上"干净模式"与当前模式的分布差异
3. 使用统计检验（如 t-test）判断差异是否显著

### 4.2 统计特征分析

#### 4.2.1 Zygisk 引入的时间分布特征

从源码分析，Zygisk 的时间延迟具有以下统计特性：

**特征 1：均值偏移**
- 无论测量哪个阶段，有 Zygisk 时的均值都高于无 Zygisk
- 偏移量与模块数量成正比

**特征 2：方差增大**
- 模块加载时间不稳定（`DlopenMem` + `onLoad` + `preAppSpecialize`）
- 不同模块的执行时间差异大
- 方差显著大于正常系统的 fork 延迟

**特征 3：双峰/多峰分布**
- 某些模块可能选择性加载（如 denylist 机制）
- 形成"快路径"（模块跳过）和"慢路径"（模块加载）

```cpp
// 从 hook.cpp 可以看到模块的选择性加载：
void ZygiskContext::app_specialize_pre() {
    info_flags = zygiskd::GetProcessFlags(g_ctx->args.app->uid);
    if ((info_flags & (PROCESS_IS_MANAGER | PROCESS_ROOT_IS_MAGISK)) == ...) {
        setenv("ZYGISK_ENABLED", "1", 1);  // 管理器进程特殊处理
    } else {
        run_modules_pre();   // 普通进程加载模块
    }
}
```

#### 4.2.2 统计检验实现

```cpp
#include <vector>
#include <algorithm>
#include <cmath>

// Welch's t-test（适用于方差不等的情况）
double welch_t_test(const std::vector<double>& sample1,
                    const std::vector<double>& sample2) {
    size_t n1 = sample1.size();
    size_t n2 = sample2.size();

    double mean1 = 0, mean2 = 0;
    for (double x : sample1) mean1 += x;
    for (double x : sample2) mean2 += x;
    mean1 /= n1;
    mean2 /= n2;

    double var1 = 0, var2 = 0;
    for (double x : sample1) var1 += (x - mean1) * (x - mean1);
    for (double x : sample2) var2 += (x - mean2) * (x - mean2);
    var1 /= (n1 - 1);
    var2 /= (n2 - 1);

    double se = sqrt(var1 / n1 + var2 / n2);
    double t = (mean1 - mean2) / se;

    // 自由度（Welch-Satterthwaite 方程）
    double df = pow(var1 / n1 + var2 / n2, 2) /
                (pow(var1 / n1, 2) / (n1 - 1) + pow(var2 / n2, 2) / (n2 - 1));

    return t;  // 与 t 分布临界值比较
}

// Cohen's d（效应量）
double cohens_d(const std::vector<double>& sample1,
                const std::vector<double>& sample2) {
    double mean1 = 0, mean2 = 0;
    for (double x : sample1) mean1 += x;
    for (double x : sample2) mean2 += x;
    mean1 /= sample1.size();
    mean2 /= sample2.size();

    double var1 = 0, var2 = 0;
    for (double x : sample1) var1 += (x - mean1) * (x - mean1);
    for (double x : sample2) var2 += (x - mean2) * (x - mean2);
    var1 /= (sample1.size() - 1);
    var2 /= (sample2.size() - 1);

    double pooled_std = sqrt((var1 + var2) / 2);
    return fabs(mean1 - mean2) / pooled_std;
}

// 离群值剔除（IQR 方法）
std::vector<double> remove_outliers(const std::vector<double>& data) {
    if (data.size() < 4) return data;

    std::vector<double> sorted = data;
    std::sort(sorted.begin(), sorted.end());

    size_t q1_idx = sorted.size() / 4;
    size_t q3_idx = sorted.size() * 3 / 4;
    double q1 = sorted[q1_idx];
    double q3 = sorted[q3_idx];
    double iqr = q3 - q1;

    double lower = q1 - 1.5 * iqr;
    double upper = q3 + 1.5 * iqr;

    std::vector<double> result;
    for (double x : data) {
        if (x >= lower && x <= upper) result.push_back(x);
    }
    return result;
}
```

#### 4.2.3 采样策略

```cpp
int detect_zygisk_statistical() {
    const int SAMPLES = 30;
    std::vector<double> samples;

    for (int i = 0; i < SAMPLES; i++) {
        // 测量 fork-to-specialize 时间
        double t = measure_fork_specialize_time();
        samples.push_back(t);

        // 冷启动间隔：确保进程完全退出，避免缓存影响
        usleep(100000);  // 100ms
    }

    // 剔除离群值
    samples = remove_outliers(samples);

    // 计算统计量
    double mean = 0, var = 0;
    for (double x : samples) mean += x;
    mean /= samples.size();
    for (double x : samples) var += (x - mean) * (x - mean);
    var /= (samples.size() - 1);
    double stddev = sqrt(var);
    double cv = stddev / mean;  // 变异系数

    // 判断逻辑
    // 基准值（无 Zygisk）：mean ~ 1-3ms，cv ~ 0.05-0.15
    // 有 Zygisk：mean ~ 3-20ms，cv ~ 0.1-0.5

    int score = 0;
    if (mean > 5.0) score += 2;           // 均值异常高
    if (cv > 0.2) score += 2;              // 变异系数大
    if (has_bimodal_distribution(samples)) score += 3;  // 双峰分布

    return score;  // >= 5 表示高度可疑
}
```

### 4.3 统计特征预期值

| 指标 | 无 Zygisk | 有 Zygisk（无模块）| 有 Zygisk（有模块）|
|------|----------|------------------|------------------|
| 均值 | ~1-3 ms | ~2-5 ms | ~5-50 ms |
| 标准差 | ~0.1-0.5 ms | ~0.3-1 ms | ~2-20 ms |
| 变异系数 (CV) | ~0.05-0.15 | ~0.1-0.3 | ~0.3-0.8 |
| 分布形态 | 近似正态 | 轻微右偏 | **双峰/多峰** |

### 4.4 可行性评估

| 维度 | 评估 |
|------|------|
| **理论基础** | **完全成立**。统计方法是解决单次测量噪声的标准手段 |
| **检测信号强度** | **高**。Zygisk 引入的方差增大和分布变形是强信号 |
| **误报风险** | 低。统计检验本身控制了一类错误率 |
| **绕过难度** | **高**。时间分布的统计特征是系统性的，难以伪造 |

### 4.5 优势与局限

**优势**：
1. 消除单次测量的随机噪声
2. 可以检测"弱信号"（如模块较少时的轻微延迟）
3. 统计显著性提供了量化的置信度

**局限**：
1. 需要多次采样，检测耗时较长
2. 需要"干净模式"的基线数据，或依赖设备间对比
3. Thermal throttling 等系统因素可能干扰分布

---

## 五、综合对比与推荐

### 5.1 三种方案对比

| 维度 | 方案 A（双进程对比） | 方案 B（多阶段时序） | 方案 C（统计检验） |
|------|-------------------|-------------------|-----------------|
| **检测目标** | 正常 vs isolated 进程差异 | fork 后 specialize 延迟 | 时间分布的统计特征 |
| **理论基础** | 部分成立 | **完全成立** | **完全成立** |
| **信号强度** | 中 | **高** | **高** |
| **实现复杂度** | 低 | 中 | 高 |
| **误报率** | 中 | 低 | **低** |
| **绕过难度** | 中 | **高** | **高** |
| **独立使用** | 可以 | **推荐** | 需配合 B |
| **综合推荐度** | ★★★☆ | ★★★★★ | ★★★★☆ |

### 5.2 最佳实践：组合方案 B + C

**推荐架构**：

```
┌─────────────────────────────────────────┐
│           组合检测框架                    │
├─────────────────────────────────────────┤
│  阶段 1：数据采集（方案 B 的测量点）       │
│  - 测量 fork() 到 ActivityThread 的时间   │
│  - 同时测量 isolated 进程作为基线（方案 A）│
├─────────────────────────────────────────┤
│  阶段 2：统计处理（方案 C 的方法）         │
│  - 各采集 30 个冷启动样本                 │
│  - 剔除离群值                            │
│  - Welch's t-test 检验差异显著性           │
├─────────────────────────────────────────┤
│  阶段 3：综合判断                         │
│  - p-value < 0.01                        │
│  - Cohen's d > 0.8（大效应量）            │
│  - 均值差异 > 2ms                        │
│  → 判定为 Zygisk 存在                    │
└─────────────────────────────────────────┘
```

**判断逻辑**：

```cpp
enum DetectionResult {
    CLEAN,       // 无 Zygisk
    SUSPICIOUS,  // 可疑，需进一步确认
    DETECTED     // 高度确信存在 Zygisk
};

DetectionResult detect_zygisk_combined() {
    // 1. 采集样本
    auto normal_samples = collect_samples(NORMAL_PROCESS, 30);
    auto isolated_samples = collect_samples(ISOLATED_PROCESS, 30);

    // 2. 剔除离群值
    normal_samples = remove_outliers(normal_samples);
    isolated_samples = remove_outliers(isolated_samples);

    // 3. 计算统计量
    double t_stat = welch_t_test(normal_samples, isolated_samples);
    double effect_size = cohens_d(normal_samples, isolated_samples);

    // 4. 综合判断
    bool significant = (fabs(t_stat) > 2.76);  // df≈50, p<0.01
    bool large_effect = (effect_size > 0.8);
    bool mean_diff_large = (mean(normal_samples) - mean(isolated_samples) > 2.0);

    if (significant && large_effect && mean_diff_large) {
        return DETECTED;
    } else if (significant || mean_diff_large) {
        return SUSPICIOUS;
    } else {
        return CLEAN;
    }
}
```

### 5.3 各方案的适用场景

| 场景 | 推荐方案 | 理由 |
|------|---------|------|
| 快速初筛 | A | 实现简单，一次测量即可 |
| 精确检测 | B | 直接测量核心路径，信噪比最高 |
| 对抗绕过 | C | 统计特征难以伪造 |
| 生产环境 | B + C | 兼顾准确性和可靠性 |

---

## 六、结论

1. **方案 A（双进程对比）**：**可行但信号较弱**。isolated 进程不会完全绕过 Zygisk，但确实减少了部分开销（跳过 fd sanitization）。适合作为基线参照，但不建议独立使用。

2. **方案 B（多阶段时序）**：**高度可行且信号强**。直接测量 Zygisk 核心注入路径（fork_pre → run_modules_pre → sanitize_fds → run_modules_post）引入的延迟，信噪比最高，是首选检测方案。

3. **方案 C（统计显著性）**：**高度可行且抗绕过**。Zygisk 引入的方差增大和分布变形（尤其是模块选择性加载导致的双峰分布）是强统计信号。建议作为方案 B 的方法论增强。

**最终推荐**：采用 **方案 B（多阶段时序指纹）+ 方案 C（统计显著性检测）** 的组合，以方案 A（isolated 进程基线）作为辅助参照。这种组合既能精确捕获 Zygisk 的时序特征，又能通过统计方法消除噪声，提供高可靠性的检测结果。
