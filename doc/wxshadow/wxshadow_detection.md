# WXShadow 模块检测方案

## 1. 模块原理与检测切入点

WXShadow 通过**Shadow Page**技术实现无痕 Hook：为被 Hook 的代码页分配一份私有副本（Shadow 页），在用户态**读取**时返回原始页（`r--`），**执行**时映射到 Shadow 页（`--x`，含 BRK 断点或 Patch）。通过动态改写 PTE（页表项）完成切换。

**核心弱点**：同一物理页在任一时刻**不能同时可读可执行**。当代码在执行 Shadow 页时读取自身所在页，或两个线程分别读/执行同一页，必然触发页权限异常，内核需要介入切换 PTE。这个介入过程留下可检测的侧信道。

| wxshadow 页面状态 | PTE 权限 | 读操作 | 执行操作 |
|------------------|---------|--------|---------|
| SHADOW_X | `--x` | 触发 data abort | 执行含 BRK 的 shadow |
| ORIGINAL | `r--` | 读取原始代码 | 触发 instruction abort |
| STEPPING | `r-x` | 读取原始代码 | 单步执行原始指令 |

---

## 2. 检测方法

### 2.1 自读代码页 + Page Fault 统计（无需 root，推荐）

**原理**：正常代码页权限为 `r-x`，代码读取自身所在页不会触发 page fault。wxshadow shadow 页为 `--x`，任何读取都会触发 data abort，内核介入切换 PTE 到 `r--`。

**检测逻辑**：
1. 在疑似被 Hook 的函数附近，执行一个**主动读取自己代码页**的操作
2. 对比操作前后的 `/proc/self/stat` 的 `minflt`（minor page fault）计数
3. 异常增量 = wxshadow 介入次数

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static uint64_t read_minflt(void) {
    FILE *fp = fopen("/proc/self/stat", "r");
    if (!fp) return 0;
    uint64_t minflt = 0;
    // pid comm state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt
    fscanf(fp, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %lu", &minflt);
    fclose(fp);
    return minflt;
}

// 这段代码的关键：它读取自己所在的页
// 如果该页被 wxshadow shadow (--x)，读取会触发 page fault
__attribute__((noinline, aligned(4096)))
void self_read_probe(void) {
    void *page = (void*)((uintptr_t)&self_read_probe & ~0xFFF);
    volatile uint32_t val = *(volatile uint32_t*)page;
    (void)val;
}

// 将探针函数放到一个独立的代码页，避免被其他代码干扰
__attribute__((section(".wxshadow.probe")))
static void probe_trigger(void) {
    self_read_probe();
}

int detect_by_page_fault(void) {
    uint64_t before = read_minflt();

    // 多次调用以放大信号
    for (int i = 0; i < 100; i++) {
        self_read_probe();
    }

    uint64_t after = read_minflt();
    uint64_t delta = after - before;

    printf("[*] minflt before=%lu after=%lu delta=%lu\n", before, after, delta);

    // 正常情况下自读代码页 delta 应为 0（或极低，如 < 5）
    // wxshadow shadow 状态下，每次读取触发一次额外 page fault
    return delta > 50 ? 1 : 0;
}
```

**增强方案**：将探针函数编译到独立的 `.o` 文件并链接，确保它独占一页。在探针函数中插入多条读取指令（跨 cache line），增加触发概率。

**误报控制**：某些内核配置下（如 THP、KSM）自读也可能触发 minor fault，建议设置阈值并根据设备校准。

---

### 2.2 双线程并发读执行竞争（无需 root）

**原理**：一个线程持续执行被测代码页上的函数，另一个线程持续读取同一页。正常 `r-x` 页无竞争；wxshadow 页上读线程触发 read fault（切到 ORIGINAL），执行线程触发 exec fault（切回 SHADOW_X），产生大量交叉 page fault。

```c
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile int g_running = 1;
static void *g_target_page = NULL;

__attribute__((noinline, aligned(4096)))
void target_func_loop(void) {
    for (volatile int i = 0; i < 100; i++);  // 在此页上执行
}

static void *exec_thread(void *arg) {
    (void)arg;
    while (g_running) {
        target_func_loop();
    }
    return NULL;
}

static void *read_thread(void *arg) {
    (void)arg;
    while (g_running) {
        volatile uint32_t val = *(volatile uint32_t*)g_target_page;
        (void)val;
    }
    return NULL;
}

int detect_by_race(void) {
    uint64_t before = read_minflt();  // 复用 2.1 的函数

    g_target_page = (void*)((uintptr_t)&target_func_loop & ~0xFFF);
    g_running = 1;

    pthread_t t1, t2;
    pthread_create(&t1, NULL, exec_thread, NULL);
    pthread_create(&t2, NULL, read_thread, NULL);

    usleep(50000);  // 竞争 50ms

    g_running = 0;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    uint64_t after = read_minflt();
    uint64_t delta = after - before;

    printf("[*] Race minflt delta=%lu\n", delta);

    // 正常情况下并发读执行同一 r-x 页，delta 应 < 100
    // wxshadow 竞争下，delta 可达数千甚至上万
    return delta > 500 ? 1 : 0;
}
```

**优势**：不需要知道具体被 Hook 的地址，只要目标代码页被 shadow，任何并发读执行都会产生信号。

---

### 2.3 BRK + 单步时延指纹（无需 root，高精度计时）

**原理**：wxshadow 命中 BRK 后，完整路径包括：陷入 EL1 → 遍历 page_list → 切换 PTE → TLB flush → 启用单步 → 返回 EL0 执行一条指令 → 再次陷入 → 切回 shadow → 禁用单步 → 返回。单次延迟约 **5-20 µs**，远高于普通函数调用（~ns 级）。

```c
#include <time.h>
#include <stdint.h>
#include <stdio.h>

static inline uint64_t nanos(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 目标函数：如果被 wxshadow 设置 BRK，每次调用多消耗 ~10us
__attribute__((noinline))
int target_canary(void) {
    return 0x12345678;
}

int detect_by_timing(void) {
    // 预热缓存
    for (int i = 0; i < 100; i++) target_canary();

    uint64_t start = nanos();
    for (int i = 0; i < 10000; i++) {
        target_canary();
    }
    uint64_t total = nanos() - start;
    uint64_t avg_ns = total / 10000;

    printf("[*] target_canary avg latency: %lu ns\n", avg_ns);

    // 正常空函数 ~20-50ns
    // wxshadow BRK 路径 ~5000-20000ns
    return avg_ns > 500 ? 1 : 0;
}
```

**增强方案**：
1. **比值法**：同时测量 `target_canary()` 和另一个未被 hook 的函数（如 `getpid()`），消除 CPU 频率波动
2. **方差分析**：BRK 路径的延迟分布集中在一个固定区间（~5-20us），正常调用延迟分布集中在低值区间。统计分布的**双峰特征**可以区分
3. **冷启动 vs 热启动**：首次调用可能触发 TLB miss，延迟更高。对比冷/热调用的增量比

```c
int detect_by_timing_ratio(void) {
    uint64_t t1 = nanos();
    for (int i = 0; i < 10000; i++) target_canary();
    uint64_t lat_hooked = (nanos() - t1) / 10000;

    uint64_t t2 = nanos();
    for (int i = 0; i < 10000; i++) getpid();  // 未被 hook 的参考
    uint64_t lat_ref = (nanos() - t2) / 10000;

    uint64_t ratio = lat_hooked / (lat_ref + 1);
    printf("[*] ratio=%lu (hooked=%lu ref=%lu)\n", ratio, lat_hooked, lat_ref);
    return ratio > 10 ? 1 : 0;
}
```

---

### 2.4 跨页边界时序分析

**原理**：如果一个函数跨越两个页边界（如入口在页 A 末尾，主体在页 B），只有被 Hook 的页 A 会触发 BRK 开销。测量函数内部不同段的执行时间，可以定位"入口段异常慢"的特征。

```c
__attribute__((noinline, aligned(4096)))
void cross_page_func(void) {
    // 这段代码靠近页边界
    // 如果 wxshadow 只在入口设置了 BRK，只有前几条指令有延迟
    asm volatile("nop" :::);
    asm volatile("nop" :::);
    asm volatile("nop" :::);
}

// 需要确保 cross_page_func 的 BRK 位于页 A 的末尾
// 主体（nop 序列）在页 B
```

**实现复杂度高**，但可用于精确定位被 Hook 的页。

---

### 2.5 Fork 行为差异（无需 root）

**原理**：wxshadow 在 `dup_mmap` 前后会暂停/恢复 shadow。fork 前父进程 shadow 页切回原始页（DORMANT），fork 后恢复。子进程复制的页表指向原始页，不含 shadow。

```c
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

__attribute__((noinline, aligned(4096)))
int canary_func(void) {
    return 0xABCD1234;
}

int detect_by_fork(void) {
    uint64_t parent_before = read_minflt();

    pid_t pid = fork();
    if (pid == 0) {
        // 子进程：此时页表是原始的
        uint64_t child_after = read_minflt();
        printf("[child] minflt=%lu\n", child_after);

        // 子进程调用 canary_func，如果父进程被 hook
        // 子进程执行的是原始代码（无 BRK）
        // 执行时间应显著快于父进程
        uint64_t t0 = nanos();
        for (int i = 0; i < 10000; i++) canary_func();
        uint64_t child_time = nanos() - t0;
        printf("[child] exec time: %lu ns\n", child_time);
        exit(0);
    }

    waitpid(pid, NULL, 0);

    uint64_t parent_after = read_minflt();
    uint64_t parent_delta = parent_after - parent_before;
    printf("[parent] minflt delta=%lu\n", parent_delta);

    // 父进程 fork 后恢复 shadow，但 fork 本身会触发 page fault
    // 重点是比较父子进程的 canary_func 执行时间
    return 0;  // 需要 IPC 获取子进程时间做对比
}
```

**局限性**：fork 本身引入大量 page fault（COW），需要精细的基线校准。

---

### 2.6 利用 /proc/self/pagemap 监控 PFN 变化（需要 root）

**原理**：wxshadow shadow 状态下，PTE 指向新分配的物理页（shadow 页），原始页的 PFN 被替换。通过 `/proc/pid/pagemap` 可以读取虚拟页对应的物理页号。

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

// 需要 root 权限读取 /proc/self/pagemap
static uint64_t read_pfn(void *va) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;

    uintptr_t offset = ((uintptr_t)va / 4096) * 8;
    lseek(fd, offset, SEEK_SET);

    uint64_t entry;
    read(fd, &entry, sizeof(entry));
    close(fd);

    if (!(entry & (1ULL << 63))) return 0;  // not present
    return entry & ((1ULL << 55) - 1);       // PFN
}

__attribute__((noinline, aligned(4096)))
void probe_pfn(void) {}

int detect_by_pfn(void) {
    void *page = (void*)((uintptr_t)&probe_pfn & ~0xFFF);
    uint64_t pfn_before = read_pfn(page);
    printf("[*] PFN before: %lu\n", pfn_before);

    // 运行一段时间，让 wxshadow 有机会设置 shadow
    sleep(1);

    uint64_t pfn_after = read_pfn(page);
    printf("[*] PFN after:  %lu\n", pfn_after);

    // PFN 变化 = 页表被改写 = 可能处于 shadow 状态
    return pfn_before != 0 && pfn_after != 0 && pfn_before != pfn_after;
}
```

**限制**：Android 上 `/proc/pid/pagemap` 通常需要 `CAP_SYS_ADMIN`。但某些厂商系统或特定 SELinux 配置下可能可读。

---

### 2.7 PMU 性能计数器（需要 perf 权限或 debuggable）

**原理**：ARM64 PMU 可以统计 BRK 指令执行次数和异常陷入次数。wxshadow 每次 BRK 命中产生 2 次异常（BRK handler + single-step handler）。

```c
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>
#include <stdint.h>
#include <stdio.h>

// ARM64 PMU event codes（具体值因 CPU 型号而异）
#define ARMV8_PMU_INST_BRK 0x0C   // BRK instruction retired
#define ARMV8_PMU_EXC_TAKEN 0x0A  // Exception taken

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int detect_by_pmu(void) {
    struct perf_event_attr pe = {
        .type = PERF_TYPE_RAW,
        .size = sizeof(struct perf_event_attr),
        .config = ARMV8_PMU_INST_BRK,
        .disabled = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1,
    };

    int fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd < 0) {
        perror("perf_event_open");
        return -1;  // 无权限
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // 执行可能被 hook 的函数
    for (int i = 0; i < 10000; i++) {
        target_canary();  // 如果被 hook，每次触发 BRK
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t count;
    read(fd, &count, sizeof(count));
    close(fd);

    printf("[*] BRK instruction count: %lu\n", count);
    return count > 0 ? 1 : 0;
}
```

**现实限制**：现代 Android 对 `perf_event_open` 限制严格，通常需要 root 或 debuggable app。

---

### 2.8 内核日志扫描（需要 dmesg 权限）

**原理**：wxshadow 大量使用 `pr_info()` 输出日志，如 `wxshadow: BRK handler ENTER pc=%lx`。

```c
#include <stdio.h>
#include <string.h>

int detect_by_kmsg(void) {
    FILE *fp = fopen("/dev/kmsg", "r");
    if (!fp) fp = popen("dmesg 2>/dev/null", "r");
    if (!fp) return -1;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "wxshadow")) {
            printf("[!] wxshadow log: %s", line);
            found++;
        }
    }
    fclose(fp);
    return found > 0 ? 1 : 0;
}
```

**注意**：`dmesg` 通常需要 root。但某些 Android 版本允许普通 App 读取 `/dev/kmsg` 的部分内容。日志也可能被 `logd` 缓存到 `kmsg` 的 ring buffer 中。

---

### 2.9 prctl 选项探测

**原理**：wxshadow 注册了自定义 prctl 选项 `0x57580001 - 0x57580008`。

```c
#include <sys/prctl.h>
#include <errno.h>
#include <stdio.h>

int detect_by_prctl_probe(void) {
    // wxshadow 使用 0x57580001 - 0x57580008
    // 如果模块已加载，非法参数调用不会返回 -EINVAL
    // 而是返回模块内部错误码（如 -ENOENT）

    int ret = prctl(0x57580001, 0, 0, 0, 0);
    printf("[*] prctl(0x57580001) = %d (errno=%d)\n", ret, errno);

    if (ret == -1 && errno == EINVAL) {
        // 内核不认识这个 option → wxshadow 未加载
        return 0;
    }

    // 返回其他错误码（如 -3, -2, -14）→ wxshadow 已加载并处理了请求
    return 1;
}
```

**局限性**：只能检测模块是否加载，不能检测"当前进程是否被 hook"。而且如果 wxshadow 作者更换通信通道（如改用 ioctl），此检测失效。

---

## 3. 检测方案对比

| 方法 | 所需权限 | 可靠性 | 信号强度 | 实现复杂度 | 对抗难度 |
|------|---------|--------|---------|-----------|---------|
| **自读代码页 + minflt** | 无 | ⭐⭐⭐⭐⭐ | 高 | 低 | ❌ 无法根本对抗 |
| **双线程读执行竞争** | 无 | ⭐⭐⭐⭐⭐ | 极高 | 低 | ❌ 无法根本对抗 |
| **BRK 时延指纹** | 无 | ⭐⭐⭐⭐ | 高 | 低 | 难（可优化不能消除）|
| **跨页时序分析** | 无 | ⭐⭐⭐⭐ | 中 | 高 | 难 |
| **Fork 行为差异** | 无 | ⭐⭐⭐ | 中 | 中 | 中等 |
| **pagemap PFN 监控** | root | ⭐⭐⭐⭐⭐ | 极高 | 低 | 不可能对抗 |
| **PMU BRK 计数** | perf/debug | ⭐⭐⭐⭐⭐ | 极高 | 中 | 需换异常类型 |
| **内核日志扫描** | dmesg | ⭐⭐⭐⭐⭐ | 极高 | 低 | 关闭日志即可 |
| **prctl 探测** | 无 | ⭐⭐ | 低 | 低 | 换通信通道 |

---

## 4. 实战建议

### 4.1 综合检测评分框架

```c
#include <stdio.h>
#include <stdint.h>

int detect_wxshadow(void) {
    int score = 0;

    // 方法1：自读代码页 page fault（最强无权限检测）
    if (detect_by_page_fault()) {
        printf("[+] Page fault anomaly: self-read triggered faults\n");
        score += 10;
    }

    // 方法2：双线程竞争（更强信号）
    if (detect_by_race()) {
        printf("[+] Race condition: concurrent read/exec anomalies\n");
        score += 10;
    }

    // 方法3：时延指纹
    if (detect_by_timing()) {
        printf("[+] Timing anomaly: BRK-like latency detected\n");
        score += 8;
    }

    // 方法4：时延比值（消除频率波动）
    if (detect_by_timing_ratio()) {
        printf("[+] Timing ratio anomaly\n");
        score += 8;
    }

    // 方法5：prctl 探测（仅作为辅助）
    if (detect_by_prctl_probe()) {
        printf("[+] prctl probe: wxshadow prctl options active\n");
        score += 3;
    }

    // 方法6：pagemap（如果有权限）
    if (detect_by_pfn()) {
        printf("[+] PFN changed: page table was rewritten\n");
        score += 10;
    }

    // 方法7：PMU（如果有权限）
    if (detect_by_pmu() > 0) {
        printf("[+] PMU: BRK instructions detected\n");
        score += 10;
    }

    // 方法8：内核日志
    if (detect_by_kmsg() > 0) {
        printf("[+] Kernel logs contain wxshadow traces\n");
        score += 10;
    }

    printf("\n=== WXShadow Detection Score: %d ===\n", score);

    if (score >= 20)
        printf("VERDICT: WXShadow hook detected with high confidence\n");
    else if (score >= 10)
        printf("VERDICT: Suspicious - possible WXShadow or other hook\n");
    else if (score >= 5)
        printf("VERDICT: Weak signals, inconclusive\n");
    else
        printf("VERDICT: No WXShadow indicators found\n");

    return score;
}
```

### 4.2 基线校准

首次运行时应在**干净环境**（未加载 wxshadow）下执行：

```c
void calibrate_baseline(void) {
    printf("[*] Calibrating on clean device...\n");

    // 运行 10 轮取中位数
    int pf[10], race[10], timing[10];
    for (int i = 0; i < 10; i++) {
        pf[i]    = detect_by_page_fault();
        race[i]  = detect_by_race();
        timing[i]= detect_by_timing();
    }

    // 存储基线到私有文件或 memory
    // 后续检测与基线对比，而非硬编码阈值
}
```

### 4.3 误报控制

| 潜在误报源 | 处理方法 |
|-----------|---------|
| THP 透明大页 | 首次自读 THP 可能触发 split，建议预热后再测量 |
| CPU 频率波动 | 使用时延比值法，或绑定大核固定频率 |
| 正常 page fault | 代码页通常是 `r-x`，自读不应触发 fault |
| `mprotect` 调用 | 检测前检查近期是否有 `mprotect` 系统调用 |
| KSM / 内存去重 | 罕见，可通过连续多次测量取最小值过滤 |

### 4.4 对抗 wxshadow 的可能改进

如果 wxshadow 作者尝试对抗检测：

| 检测向量 | wxshadow 可能的对抗 | 效果 |
|---------|-------------------|------|
| 自读 page fault | 将 shadow 页权限改为 `r-x`（放弃隐藏） | 失去核心隐藏能力 |
| 时延指纹 | 批量指令模拟代替单步 | 复杂度高，可能引入新异常 |
| pagemap PFN | 无（需要 root 权限才能读取） | 无法对抗 |
| PMU 计数 | 用未对齐访问替代 BRK | 可行但实现复杂 |

**核心结论**：自读代码页检测是 wxshadow 架构层面的死穴——W^X Shadow 的本质就是读和执行分离，无法让一页同时可读可执行。

---

## 5. 结论

WXShadow 的隐藏能力是针对**外部读取视角**（如 `/proc/pid/mem`、ptrace、CRC32 校验）设计的，但其页表切换机制在以下层面留下不可避免的侧信道：

1. **页权限层面**：`--x` shadow 页读取必然触发 page fault，这是最稳定、最可靠、最无法对抗的检测入口
2. **时序层面**：BRK + 单步的两次陷入 + 两次 TLB flush 引入固定延迟，可通过高精度计时检测
3. **物理页层面**：PTE 指向的 PFN 发生变化，root 权限下可直接观测

**最有效的单一无权限检测**：在关键代码页中插入自读探针，统计 `/proc/self/stat` 的 `minflt` 增量。代码简洁、零依赖、无法在内核层被拦截（除非 wxshadow 放弃隐藏能力）。

**最可靠的 root 权限检测**：`/proc/self/pagemap` PFN 监控，直接观测页表物理映射变化，100% 准确。
