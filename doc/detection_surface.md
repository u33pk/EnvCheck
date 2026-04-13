# APatch Root 后的检测面分析

本文档从源码层面分析 APatch（及其核心 KernelPatch）在成功获取 root 权限后，会在系统中留下哪些可被普通 App 检测到的特征。分析维度包括：**网络端口**、**静态文件系统痕迹**、**系统调用侧信道** 以及**时间侧信道**。

---

## 1. 端口开放情况：无网络服务端

**结论：APatch / KernelPatch 不会主动开放任何 TCP / UDP / Netlink 服务端端口。**

在 KernelPatch 内核代码（`kernel/patch/`）和 APatch 用户空间代码（`apd/`、`app/src/`）中，均不存在创建监听端口的网络服务端逻辑（无 `socket()` → `bind()` → `listen()` → `accept()` 的调用链）。

KernelPatch 提供的所有特权接口（`SU`、`KPM` 加载、`KSTORAGE` 等）均通过 **系统调用 `syscall(45)`**（即 SuperCall）直接完成，不经过任何网络协议栈。

> **检测 implication**：基于端口扫描（扫描本地端口、分析 `/proc/net/tcp` 等）**无法直接检测** APatch 的存在。

---

## 2. 静态文件系统痕迹（普通 App 可直接探测）

APatch 和 APD 守护进程在 `/data` 分区留下了大量固定路径的痕迹。普通 App（即使未获取 root）可以通过 Java/Kotlin 的文件 API 或 `Runtime.exec("ls ...")` 等方式探测这些路径。

### 2.1 APatch 核心目录与文件

| 路径 | 来源/用途 |
|------|----------|
| `/data/adb/ap/` | `APATCH_FOLDER`，APatch 根目录 |
| `/data/adb/ap/bin/` | BusyBox 及 APatch 工具链 |
| `/data/adb/ap/log/` | APatch 日志目录 |
| `/data/adb/ap/package_config` | 包权限配置文件 |
| `/data/adb/ap/su_path` | 自定义 su 路径配置文件 |
| `/data/adb/ap/version` | 已安装的 APatch 版本 |
| `/data/adb/ap/kpms/` | KPM 模块存放目录 |
| `/data/adb/ap/ori.img` | 原始 boot.img 备份 |
| `/data/adb/apd` | APD 守护进程二进制 |

### 2.2 APM (APatch Module) 目录

| 路径 | 来源/用途 |
|------|----------|
| `/data/adb/modules/` | 已安装模块目录 |
| `/data/adb/modules_update/` | 待更新模块目录 |
| `/data/adb/metamodule` | 指向当前激活元模块的符号链接 |

### 2.3 启动脚本目录

| 路径 | 来源/用途 |
|------|----------|
| `/data/adb/post-fs-data.d/` | post-fs-data 阶段脚本 |
| `/data/adb/post-mount.d/` | post-mount 阶段脚本 |
| `/data/adb/service.d/` | late_start 服务脚本 |
| `/data/adb/boot-completed.d/` | 开机完成脚本 |

### 2.4 su 二进制

APatch 支持动态修改 su 路径（通过 `sc_su_reset_path`）。默认或常见配置下，su 可能出现在 `/system/bin/su`、`/data/adb/ap/bin/su` 等位置。普通 App 可直接探测这些路径是否存在且可执行。

> **注意**：部分 root 隐藏工具可能通过 mount 命名空间隔离或 bind mount 隐藏上述文件，但在默认配置下，这些路径对普通 App 是可见的。

---

## 3. 可被侧信道检测到的特征

### 3.1 系统调用号 45 被劫持（核心侧信道）

KernelPatch 硬编码使用了系统调用号 **45** 作为 SuperCall 后门，定义在：
- `kernel/patch/include/uapi/scdefs.h`
- `app/src/main/cpp/uapi/scdefs.h`

```c
#define __NR_supercall 45
```

`supercall_install()` 通过 `hook_syscalln(__NR_supercall, 6, before, 0, 0)` 对 45 号系统调用进行了劫持（优先 `sys_call_table` 函数指针替换，其次 inline hook）。

**侧信道原理：**
- 在未 Patch 的 Android 内核上，调用 `syscall(45, ...)` 通常会迅速返回 `-ENOSYS`（系统调用未实现），走内核默认的快速失败路径。
- 在 APatch 设备上，任何对 45 号系统调用的调用都会先进入 KernelPatch 的 hook 跳板代码（保存寄存器、跳转、校验等），即使参数非法，也不会走原本的 "系统调用不存在" 快速路径。

**可观测差异：**
- 如果传入的 `cmd` 超出 `SUPERCALL_HELLO` ~ `SUPERCALL_MAX` 范围，`before` 钩子直接 `return`，由于未设置 `args->skip_origin`，hook 框架会继续调用原始系统调用处理函数，最终返回 `-ENOSYS`。
- 如果传入的 `cmd` 在有效范围内（如 `0x1000 = SUPERCALL_HELLO`）但 key 为空或无效，`before` 钩子同样会在 `compat_strncpy_from_user` 或 `auth_superkey()` 失败后直接 `return`，`skip_origin` 未被置位，最终仍然返回 `-ENOSYS`。

这意味着：**仅通过观测 `syscall(45)` 的返回码，无法在不拥有 root 的情况下探测 APatch**（除非持有正确的 superkey）。返回值侧信道并不可行。

### 3.2 vmalloc 区域异常

`prot_myself()` 在 `kernel/base/start.c` 中将 KernelPatch 的内存区域注册到内核的 `vmalloc` 列表：

```c
vm_area_add_early(&kp_vm);
```

如果某个 App 能够读取 `/proc/vmallocinfo`（通常需要 root，但部分 OEM 设备权限较松），可能会发现一段大小异常、caller 地址固定、flags 为 `0x00000044` 的连续内存区域。

### 3.3 SELinux 审计日志缺失

KernelPatch 通过 inline hook `avc_denied`（`kernel/patch/patch.c` 中的 `patch_config.avc_denied`）来绕过 SELinux 权限检查。如果一个 App 能够触发某些**理应被 SELinux 拒绝**的操作，并观察到 `dmesg` 或 `logcat` 中完全没有 `avc: denied` 日志，这可能间接证明 `avc_denied` 被 hook。但普通 App 通常无法稳定、重复地控制这一点。

---

## 4. 特别关注：时间侧信道（Timing Side-Channel）

时间侧信道是普通 App 在不具备 root 权限的情况下，**最有可能检测到 APatch 存在的高级手段**。以下是可以通过高精度计时器观测到的特征。

### 4.1 `syscall(45)` 的执行时间异常（高可行性）

**检测方法：**
App 可以通过 `clock_gettime(CLOCK_MONOTONIC_RAW)` 或 `perf_event_open` 等高精度计时器，大量测量以下系统调用的执行时间：

1. `syscall(45, "", 0x1000)` — `cmd` 在有效范围内（`SUPERCALL_HELLO`），key 为空
2. `syscall(45, "", 0x1)` — `cmd` 在有效范围外
3. `syscall(9999, "", 0)` — 一个肯定不存在的系统调用号，作为基线

**时间差异来源：**
- **基线（9999 号）**：内核直接走 `do_ni_syscall` 或 `sys_ni_syscall`，路径极短，通常在 **几十到一百纳秒级**。
- **APatch 上的 45 号（cmd 有效）**：即使 key 错误，`before` 钩子也会被触发。内核需要执行：
  - hook 框架的入口跳板（保存寄存器、调整栈帧）
  - `compat_strncpy_from_user(key, ukey, MAX_KEY_LEN)` 从用户空间拷贝 key
  - `auth_superkey(key)` 进行哈希/字符串比对
  - 最终返回 `-EINVAL` 或 `-EPERM`
  - **总耗时通常比基线长出数百纳秒到微秒级**。
- **APatch 上的 45 号（cmd 无效）**：`before` 钩子在前几行就 `return` 了，但仍然已经经过了 hook 的入口跳板代码，因此仍然比 9999 号的纯基线要慢。

**检测逻辑示例：**

```cpp
// 测量 N 次（如 10000 次），取中位数
int64_t t_invalid = measure([&]() {
    syscall(45, "", 0x1);  // cmd out of range
});

int64_t t_valid = measure([&]() {
    syscall(45, "", 0x1000); // cmd = SUPERCALL_HELLO
});

int64_t t_baseline = measure([&]() {
    syscall(9999, "", 0);    // non-existent syscall
});

// 如果 t_invalid 显著 > t_baseline，说明 45 号被 hook
// 如果 t_valid 显著 > t_invalid，说明边界内 cmd 触发了更多校验逻辑
```

**为什么对 APatch 特别有效？**
因为 `__NR_supercall = 45` 是**硬编码**的。在所有 APatch/KernelPatch 版本中都使用 45 号（早期版本曾复用 `__NR_truncate`，但源码中已固定为 45）。这意味着检测代码可以针对性地、高信噪比地扫描这一个系统调用号。

### 4.2 高频 fork/exec 的耗时偏移（中等可行性）

KernelPatch inline hook 了多个高频内核函数，特别是：
- `copy_process`（`fork`/`clone` 的核心）
- `avc_denied`（每次 SELinux 检查）
- `input_handle_event`（输入事件处理）

**检测方法：**
App 可以通过高频创建/销毁子进程（如每秒数千次 `fork` + `exit`），并用 `clock_gettime` 测量 `clone()` / `fork()` 的系统调用耗时。

**时间差异来源：**
- 被 hook 的函数会额外执行 hook 入口的指令修补/恢复逻辑、回调函数调用前导等。
- 对于 `copy_process`，KernelPatch 的 `task_observer` 可能还会附加额外的 per-task 数据结构初始化。
- 单次调用的额外开销可能只有 **10~100 纳秒**，但通过对数万个样本做均值或中位数对比，可以观测到统计学上的偏移。

**局限性：**
- 需要规避 Android 的 `fd` 限制和进程数限制（`rlimit`）。
- CPU 调度、频率缩放、缓存状态会引入噪声，需要统计滤波（如剔除异常值、绑定大核）。

### 4.3 缓存侧信道（Cache Side-Channel）

虽然严格来说属于缓存侧信道，但普通 App 可以通过**时间测量**间接观测：

- 调用 `syscall(45, ...)` 会访问内核中特定的 hook 代码页和数据页（如 `before` 函数、`auth_superkey` 的常量表）。
- 如果 App 在调用前后通过 ARM64 性能计数器测量用户态内存的访问延迟（Flush+Reload / Prime+Probe 的简化版），理论上可能观测到缓存被内核代码驱逐的痕迹。
- 但在 Android 用户态实现难度较高，稳定性和信噪比不如直接测量系统调用时间。

---

## 5. 检测特征矩阵总结

| 特征类型 | 具体特征 | 检测难度（普通 App） | 是否时间侧信道 |
|---------|---------|---------------------|---------------|
| **网络端口** | 无开放端口 | — | — |
| **文件系统** | `/data/adb/ap/` 存在 | 极低 | 否 |
| **文件系统** | `/data/adb/modules/` 存在 | 极低 | 否 |
| **文件系统** | 自定义 `su` 路径存在 | 低 | 否 |
| **系统调用** | `syscall(45)` 返回码侧信道 | — | 否（**不可行**） |
| **系统调用** | `syscall(45)` 执行时间显著长于不存在的 syscall | 中 | **是（最可靠）** |
| **系统调用** | `syscall(45)` 有效 cmd 与无效 cmd 耗时差异 | 中 | **是** |
| **内核行为** | 高频 `clone()` 平均耗时微增 | 高 | 是 |
| **内存** | `/proc/vmallocinfo` 异常区域 | 高（通常需 root） | 否 |
| **日志** | `avc: denied` 日志缺失 | 中 | 否 |

### 降低检测面的建议

- **文件系统痕迹**：通过 mount 命名空间隔离或 bind mount 隐藏 `/data/adb/ap/` 和 `/data/adb/modules/`（需 APD 额外实现）。
- **su 路径**：避免使用常见的 `/system/bin/su`，使用随机路径并频繁更换。
- **syscall(45) 侧信道**：这是目前最难防御的硬编码特征。防御方向可能包括：
  - 不劫持 45 号，改用更隐蔽的通信机制（但这需要大幅修改 KernelPatch 架构）。
  - 在 `before` 钩子中对非法调用走最短路径快速返回，尽量弥合与 `-ENOSYS` 的时间差（只能增加检测样本量，无法完全消除）。


---

## 附录：一段 KernelSU 时间侧信道检测代码的拆解与对 APatch 的适用性分析

下面拆解一段在实际样本中发现的 KernelSU 侧信道检测代码（ARM64，NEON 优化），分析其工作原理，并评估其对 APatch 的检测效果。

### 检测代码结构

该代码的核心逻辑可分为六个阶段：

#### 阶段 1：环境初始化
- 获取 CPU 核心数，识别并绑定到高性能大核，确保计时稳定。

#### 阶段 2：内存分配
- 为两组时间样本各分配 `80000 * 8` 字节的缓冲区，并清零。

#### 阶段 3：采集执行时间
- **样本 A**：循环调用 `syscall(__NR_faccessat, -1, NULL, 0, ...)`，使用 `CNTVCT_EL0`（虚拟计数器）配合 `ISB` 指令屏障采集纳秒级耗时。
- **样本 B**：循环调用 `syscall(__NR_fchownat, -1, NULL, 0, 0, -1)`，同样采集耗时。

计时函数伪代码：
```c
unsigned __int64 get_time() {
    __isb(0xF);
    unsigned __int64 result = _ReadStatusReg(CNTVCT_EL0);
    __isb(0xF);
    return result;
}
```

#### 阶段 4：排序稳定化
- 对两组各 10000 个有效样本（取前 10000 个或排序后）进行 `qsort`，消除极值干扰，取稳定分位数进行比较。

#### 阶段 5：NEON 向量化比较
- 使用 NEON 指令并行比较排序后的两组样本：
  - 若 `faccessat_time[i] > fchownat_time[i] + 1`，则记为一次异常。
- NEON 的作用纯粹是提升比较性能，逻辑上等价于：

```c
uint32_t anomaly = 0;
for (int i = 0; i < NUM_SAMPLES; i++) {
    if (faccessat[i] > fchownat[i] + 1) {
        anomaly++;
    }
}
```

#### 阶段 6：阈值判定
- 若异常数 `anomaly > 0x1B58`（即 7000），则判定存在 KernelSU，触发后续处理。

---

### 为什么这段代码对 KernelSU 有效？

KernelSU 在内核中 inline-hook 了 `faccessat`（syscall 48），用于拦截文件访问权限检查（例如判断 App 是否能访问模块挂载点、或用于 Manager 身份校验）。

因此：
- **`faccessat`** 被 hook → 每次调用都要走 KernelSU 的跳板代码（保存寄存器、执行回调、权限判断等）→ **耗时明显变长**。
- **`fchownat`** 没有被 hook → 走正常的内核快速失败路径（参数非法时直接返回 `-EBADF`/`-EFAULT`）→ **耗时很短**。

在 KernelSU 设备上，排序后的 `faccessat` 样本会有大量分位数显著大于 `fchownat`，异常数轻松突破 7000 阈值。

---

### 为什么这段代码对 APatch 基本无效？

APatch / KernelPatch 的 hook 策略与 KernelSU 有显著差异。从源码分析可知，KernelPatch hook 的目标列表如下（包含文档主文未完全列出的 syscall）：

| 被 Hook 的目标 | 用途 |
|---------------|------|
| `__NR_supercall (45)` | SuperCall 后门通信 |
| `rest_init` / `kernel_init` | 内核初始化时启动 KernelPatch 运行时 |
| `panic` | 调试/日志输出 |
| `copy_process` | 进程创建监控（task observer） |
| `avc_denied` | SELinux 绕过 |
| `slow_avc_audit` | SELinux 审计绕过 |
| `input_handle_event` | 输入事件处理 |
| `__NR_execve` / `__NR_execveat` | su / APD 执行兼容 |
| `__NR_openat` | 用户空间守护进程相关 |
| `__NR3264_fstatat` / `__NR_faccessat` | su 路径替换 |

**关键修正：**
- **`faccessat` (syscall 48) 确实被 hook 了**（`kernel/patch/common/sucompat.c:392`），其 `before` 钩子 `su_handler_arg1_ufilename_before` 用于 su 路径替换。
- **`fchownat` 没有被 hook**。

然而，APatch 的 `faccessat` hook 对普通 App 走的是快速路径：先检查 `is_su_allow_uid(uid)`，对未被允许的普通 App 直接 `return`。虽然仍会经历 hook 框架的入口跳板和 `before` 函数前几句（`current_uid()` 和 kstorage 查找），但额外开销**远小于 KernelSU**（KernelSU 对所有 App 都做完整的权限检查和模块挂载判断）。因此：
- 在 APatch 设备上，`faccessat` 和 `fchownat` 之间**不存在像 KernelSU 那样稳定的、大分位数的显著耗时差异**。
- 该检测代码的异常数通常会在随机噪声范围内波动，**难以突破 7000 的高阈值**。
- 该检测器仍**很可能将 APatch 设备误判为“干净设备”**，但原因不是“`faccessat` 未被 hook”，而是“APatch 的 `faccessat` hook 对普通 App 开销过小”。

#### 间接时间差异是否存在？

KernelPatch 确实 hook 了 `avc_denied`，而 `faccessat` / `fchownat` 理论上都会触发 SELinux 检查。但：
- 由于参数非法，这两个 syscall 可能在内核早期路径（如 `fdget` 或 `getname`）就直接返回错误了，**根本走不到 `avc_denied`**。
- 即使走到了 SELinux 检查，两个 syscall 都会经过 `avc_denied`，额外开销是**对称的**，不会产生稳定的 `faccessat > fchownat` 模式。

所以，**不存在可靠的间接时间侧信道**。

---

### 如何将该方法论改编为 APatch 检测器？

这段代码的检测框架非常优秀：大核绑定、`CNTVCT_EL0` 高精度计时、`ISB` 屏障消除乱序执行影响、大样本量 + qsort + NEON 向量化比较。这些工程细节完全可以复用。

要检测 APatch，核心是把 **被 hook 的 syscall** 从 `faccessat` 替换为 **`syscall(45)`**。

#### 改编方案 A：`syscall(45)` vs 不存在的 syscall

```c
// 数组1: syscall(45, "", 0x1)   -- cmd 超出范围，但会进入 hook 跳板
// 数组2: syscall(9999, "", 0)   -- 完全未实现的 syscall，走最短路径

for (int i = 0; i < NUM_SAMPLES; i++) {
    t1 = get_time();
    syscall(45, "", 0x1);
    t2 = get_time();
    arr1[i] = t2 - t1;

    t1 = get_time();
    syscall(9999, "", 0);
    t2 = get_time();
    arr2[i] = t2 - t1;
}

qsort(arr1, NUM_SAMPLES, ...);
qsort(arr2, NUM_SAMPLES, ...);

uint32_t anomaly = 0;
for (int i = 0; i < NUM_SAMPLES; i++) {
    if (arr1[i] > arr2[i] + THRESHOLD_NS) {
        anomaly++;
    }
}

if (anomaly > DETECTION_THRESHOLD) {
    // 判定为 APatch / KernelPatch
}
```

**预期结果：**
- 未 Patch 设备：`syscall(45)` 和 `syscall(9999)` 都会快速返回 `-ENOSYS`，时间相近。
- APatch 设备：`syscall(45)` 会进入 KernelPatch 的 hook 跳板（保存寄存器、cmd 范围检查、快速返回），比 `syscall(9999)` 慢 **数百纳秒到微秒级**。在 10000 次样本中，异常数会显著高于阈值。

#### 改编方案 B：`syscall(45)` 有效 cmd vs 无效 cmd

更进一步，可以利用 `before` 钩子内部的逻辑差异：

```c
// 数组1: syscall(45, "", 0x1000)  -- SUPERCALL_HELLO，会执行 auth_superkey
// 数组2: syscall(45, "", 0x1)      -- cmd 超出范围，在 hook 入口处快速返回
```

在 APatch 设备上：
- `0x1000` 会触发 `compat_strncpy_from_user` + `auth_superkey()`，路径更长。
- `0x1` 会在 `before` 函数的前几行就 `return`，路径更短。

因此 `arr1[i] > arr2[i] + THRESHOLD` 的异常数也会非常显著。这个方法甚至可以**区分“单纯被 hook 了 syscall 45”和“确实是 KernelPatch/APatch”**。

#### 改编方案 C：返回值侧信道（不可行）

> **注意：该方案不可行。**

如前所述，`before` 钩子仅在 key 验证通过时才会设置 `args->skip_origin = 1`。对于空 key 或错误 key，钩子直接 `return` 后，hook 框架会调用原始系统调用处理函数，返回值仍然是 `-ENOSYS`。因此：
- 未 Patch 设备：`syscall(45, "", 0x1000)` 返回 `-ENOSYS`。
- APatch 设备（未持有正确 superkey）：同样返回 `-ENOSYS`。

**无法通过返回值区分 APatch 是否存在。**

---

### 总结

| 问题 | 结论 |
|------|------|
| **这段 KernelSU 检测代码对 APatch 有效吗？** | **基本无效**。原因不是 `faccessat` 未被 hook，而是 APatch 的 `faccessat` hook 对普通 App 走的是快速失败路径，耗时差异远小于 KernelSU，难以突破高阈值。 |
| **为什么对 KernelSU 有效？** | KernelSU hook 了 `faccessat` 做权限/模块挂载拦截，导致其执行时间显著长于未被 hook 的 `fchownat`。 |
| **这段代码的检测框架有价值吗？** | **非常有价值**。大核绑定、CNTVCT 计时、ISB 屏障、qsort 稳定化、NEON 批量比较都是高质量的工程实践。 |
| **如何改编检测 APatch？** | 将 `faccessat` 替换为 **`syscall(45, ..., cmd)`**，将 `fchownat` 替换为**不存在的 syscall（如 9999）**或 `syscall(45, ..., 无效cmd)`，复用相同的比较逻辑。 |
| **APatch 能防御这种改编检测吗？** | 很难。`__NR_supercall = 45` 是硬编码的，hook 必然存在。唯一的防御方向是让非法调用的 `before` 钩子走最短路径，尽量缩小与 `-ENOSYS` 的时间差，但这只能提高检测所需的样本量，无法消除统计显著性。 |
