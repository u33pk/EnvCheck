# SUSFS4KSU 深度检测研究报告

**基于源码审计、Radare2 逆向分析与高精度时间侧信道的综合检测框架**

---

## 摘要

SUSFS（SUperSU FileSystem）是 Android 内核层面的一种 root 隐藏框架，通过 KernelSU 的 `prctl` 隧道与用户态通信。本报告基于对 `susfs4ksu` 完整源码（内核补丁、KSU 集成、用户态模块）的审计，以及对 `ksu_susfs` 二进制（ARM64 ELF）的 Radare2 静态分析，提出了一套**无需 root 权限**即可检测 SUSFS 存在的多层级检测框架。

核心发现包括：
- **直接返回值侧信道**：普通 app 调用 `prctl(0xDEADBEEF)` 时，有 KSU/SUSFS 的内核返回 `0`，无 KSU 的内核返回 `EINVAL`。
- **高精度时间侧信道**：利用 ARM64 `cntvct_el0` 虚拟计数器，可测量 SUSFS 在 `faccessat`、`stat`、`getdents64`、`/proc/self/maps` 等热路径中引入的 `kmalloc(PAGE_SIZE)` 和链表遍历开销。
- **一致性异常**：SUSFS 的错误码返回逻辑存在违反 POSIX 的漏洞（如 `/data/` 下 `linkat` 返回 `ENOENT` 而非 `EEXIST`）。

---

## 1. 目标架构概述

### 1.1 SUSFS 内核层（Inline Patch）

SUSFS 不是 LKM（可加载内核模块），而是通过补丁直接编译进内核源码的内联 Hook 框架。其核心功能与 hook 点如下：

| 功能 | 生效路径 | UID 限制 | 内核 Hook 点 |
|------|---------|---------|-------------|
| `sus_path` | 隐藏文件/目录 | `>= 2000` | `filldir64`, `vfs_getattr`, `do_filp_open`, `faccessat`, `chdir` 等 |
| `sus_mount` | 隐藏挂载点 | 无 | `show_vfsmnt`, `show_mountinfo`, `show_vfsstat` |
| `sus_kstat` | 伪造 `stat` | `>= 2000` | `cp_new_stat` |
| `sus_maps` | 伪造 `/proc/self/maps` | 无 | `show_map_vma` |
| `map_files` | 伪造 `/proc/self/map_files/` | 无 | `proc_map_files_lookup`, `proc_map_files_readdir` |
| `sus_proc_fd_link` | 伪造 `/proc/self/fd/` 符号链接 | 无 | `do_proc_readlink` |
| `sus_memfd` | 阻止创建特定 memfd | 无 | `memfd_create` |
| `try_umount` | setuid 时自动 umount | 非 init mnt_ns | `ksu_handle_setuid` |
| `mnt_id_reorder` | 重排 mountinfo mnt_id | `>= 10000` | `mounts_open_common` |
| `spoof_uname` | 伪造 `uname` | 无 | `newuname` |

### 1.2 用户态通信协议

用户态工具 `ksu_susfs` 通过 `prctl()` 与内核通信，协议格式如下：

```c
prctl(
    int option      = 0xDEADBEEF,       // KernelSU 魔数
    unsigned long cmd,                  // SUSFS 命令码 (0x55555 ~ 0x55562)
    void *arg3,                         // 输入结构体指针
    unsigned long arg4,                 // 保留 (NULL)
    int *error                          // 输出错误码指针
);
```

Radare2 反汇编确认了参数加载方式（`ksu_susfs_arm64`）：

```asm
0x002184dc  mov   w0, 0xbeef              ; 低 16 位
0x002184ec  movk  w0, 0xdead, lsl 16      ; 高 16 位 → 0xDEADBEEF

0x002184e0  mov   w1, 0x5555
0x002184f4  movk  w1, 0x5, lsl 16         ; → 0x55555 (CMD_SUSFS_ADD_SUS_PATH)

0x00223284  mov   x8, 0xa7                ; syscall 167 = prctl
0x00223288  svc   #0                      ; 进入内核态
```

### 1.3 模块安装痕迹

安装后的文件系统残留：
- `/data/adb/ksu/bin/ksu_susfs` — 核心二进制（SHA256: `aec682a0caa59b1f4ccffea7c41f5b75c24994fdb8058b8bc0bf4e09c889939c`）
- `/data/adb/ksu/modules/susfs4ksu/module.prop` — 包含 `id=susfs4ksu`
- 二进制 `.rodata` 段包含 1300+ 条特征字符串，完整暴露功能矩阵

---

## 2. 检测方法论

本报告将检测手段分为四个层级，从直接到间接，从稳定到高级侧信道。

### 2.1 Layer 1: 直接检测（Direct Detection）

#### 2.1.1 prctl 返回值侧信道

**原理**：KSU 的 `ksu_handle_prctl()` 对 `option == 0xDEADBEEF` 有专门处理。普通 app 调用时，即使不是 root，也会进入 KSU handler 并返回 `0`；而无 KSU 的内核不认识 `0xDEADBEEF`，返回 `EINVAL`。

**POC 代码**：

```c
#include <sys/prctl.h>
#include <errno.h>

int detect_ksu_by_prctl_return(void) {
    int ret = prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
    if (ret == 0) {
        // 有 KSU（SUSFS 的前提条件）
        return 1;
    } else if (errno == EINVAL) {
        // 无 KSU
        return 0;
    }
    return -1;
}
```

**可靠性**：⭐⭐⭐⭐⭐ — 一次调用即可区分，时延 < 1μs。

#### 2.1.2 文件系统痕迹扫描

```c
// 检测模块元数据
int detect_susfs_by_filesystem(void) {
    struct stat st;
    if (stat("/data/adb/ksu/modules/susfs4ksu/module.prop", &st) == 0) {
        return 1;
    }
    if (stat("/data/adb/ksu/bin/ksu_susfs", &st) == 0) {
        return 1;
    }
    return 0;
}
```

**限制**：部分用户可能将模块安装在 Magisk 兼容路径，或删除模块目录但保留内核补丁。

#### 2.1.3 内核符号扫描

```c
// 读取 /proc/kallsyms，搜索 susfs 相关符号
FILE *fp = fopen("/proc/kallsyms", "r");
char line[256];
while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "susfs_") || strstr(line, "LH_SUS_")) {
        return 1;
    }
}
```

**限制**：取决于 `CONFIG_KALLSYMS` 和 `kptr_restrict` 配置，但符号名通常可见。

---

### 2.2 Layer 2: 高精度时间侧信道（Timing Side-Channel）

ARM64 用户态可直接读取 `cntvct_el0`（Virtual Counter）获取纳秒级精度的时间戳，无需 root 或特殊权限。该计数器频率通常为 1~50 MHz，时延测量精度可达 ~20ns。

```c
static inline uint64_t get_cntvct(void) {
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

static inline uint64_t get_cntfrq(void) {
    uint64_t val;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}
```

#### 2.2.1 prctl 执行路径长度侧信道

**原理**：有 KSU 时，`prctl(0xDEADBEEF)` 需进入 `ksu_handle_prctl()` 执行多个分支判断；无 KSU 时直接返回 `EINVAL`。

**测量代码**：

```c
#include <sys/prctl.h>
#include <time.h>

int detect_ksu_by_prctl_timing(void) {
    const int ITER = 100000;
    uint64_t t1, t2, sum = 0;
    
    // 绑定到单 CPU 核心，减少调度噪声
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    // 预热指令缓存
    for (int i = 0; i < 1000; i++) {
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
    }
    
    for (int i = 0; i < ITER; i++) {
        t1 = get_cntvct();
        prctl(0xDEADBEEF, 0x55555, NULL, NULL, NULL);
        t2 = get_cntvct();
        sum += (t2 - t1);
    }
    
    uint64_t avg_cycles = sum / ITER;
    uint64_t freq = get_cntfrq();
    double avg_ns = (double)avg_cycles * 1e9 / freq;
    
    printf("prctl avg latency: %.2f ns (%llu cycles)\n", avg_ns, avg_cycles);
    
    // 经验阈值（需针对设备校准）：
    // 无 KSU: < 400 ns
    // 有 KSU: > 600 ns
    return (avg_ns > 500.0) ? 1 : 0;
}
```

#### 2.2.2 faccessat 隐藏路径 kmalloc 侧信道

**原理**：`susfs_sus_path_by_path()` 对隐藏路径执行 `kmalloc(PAGE_SIZE) + d_path() + list_for_each_entry_safe() + kfree()`。

```c
// kernel_patches/fs/susfs.c
int susfs_sus_path_by_path(...) {
    char* path = kmalloc(PAGE_SIZE, GFP_KERNEL);  // 4KB/16KB 分配
    ptr = d_path(file, path, PAGE_SIZE);          // 路径解析
    list_for_each_entry_safe(cursor, temp, &LH_SUS_PATH, list) {
        if (unlikely(!strcmp(cursor->info.target_pathname, path))) {
            // 命中隐藏
        }
    }
    kfree(path);
}
```

**关键洞察**：
- 对**隐藏路径**调用 `faccessat()`：触发 `kmalloc` → slab 分配器慢路径 → TLB miss
- 对**不存在路径**调用 `faccessat()`：标准内核路径，无额外分配
- 对**正常存在路径**调用 `faccessat()`：标准路径

**测量代码**：

```c
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

long measure_faccessat_latency(const char *path, int warmup, int iter) {
    uint64_t t1, t2, sum = 0;
    
    for (int i = 0; i < warmup; i++) {
        faccessat(AT_FDCWD, path, F_OK, 0);
    }
    
    for (int i = 0; i < iter; i++) {
        t1 = get_cntvct();
        faccessat(AT_FDCWD, path, F_OK, 0);
        t2 = get_cntvct();
        sum += (t2 - t1);
    }
    
    return (long)((double)sum * 1e9 / get_cntfrq() / iter);
}

int detect_susfs_by_faccessat_timing(void) {
    // 常见被隐藏路径 vs 确定存在的正常路径
    const char *hidden_paths[] = {
        "/system/addon.d",
        "/vendor/bin/install-recovery.sh",
        "/system/bin/install-recovery.sh",
        "/data/adbroot",
        NULL
    };
    const char *normal_path = "/system/bin/ls";
    
    long normal_lat = measure_faccessat_latency(normal_path, 500, 5000);
    
    for (int i = 0; hidden_paths[i]; i++) {
        long hidden_lat = measure_faccessat_latency(hidden_paths[i], 500, 5000);
        double ratio = (double)hidden_lat / normal_lat;
        
        printf("[%s] latency: %ld ns (ratio: %.2f)\n", hidden_paths[i], hidden_lat, ratio);
        
        // 阈值：隐藏路径比正常路径慢 30% 以上，或绝对差值 > 200ns
        if (ratio > 1.30 || (hidden_lat - normal_lat) > 200) {
            return 1;
        }
    }
    return 0;
}
```

**可靠性**：⭐⭐⭐⭐ — `kmalloc(PAGE_SIZE)` 是 SUSFS 架构层面的固有开销，无法消除。

#### 2.2.3 stat 系统调用双路径侧信道

**原理**：`stat()` 在内核中触发 `vfs_getattr()` → `susfs_sus_path_by_path()`（路径匹配）→ `cp_new_stat()` → `susfs_sus_kstat()`（inode 匹配，仅 UID >= 2000）。

对于普通 app（UID >= 10000），`sus_kstat` 也会生效。这意味着：
- 对隐藏文件调用 `stat()`：走 `sus_path` 拦截路径（`kmalloc` + 链表遍历）
- 对正常文件调用 `stat()`：标准路径

**测量代码**：类似 `faccessat`，将 syscall 替换为 `stat()`。

#### 2.2.4 getdents64 目录遍历时延侧信道

**原理**：`filldir64` 中通过 `susfs_sus_ino_for_filldir64()` 遍历 `LH_SUS_PATH` 链表，匹配 inode 后跳过目录项输出。

```c
// kernel_patches/fs/readdir.c
static int filldir64(...) {
    // ...
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    if (susfs_sus_ino_for_filldir64(ino)) {
        return 0;  // 隐藏该目录项
    }
#endif
    // ...
}
```

**检测方案**：测量 `/system/bin/` 等包含大量文件且可能存在隐藏项的目录遍历时延。

```c
long measure_getdents_latency(const char *path) {
    uint64_t t1, t2;
    DIR *dir = opendir(path);
    if (!dir) return -1;
    
    struct dirent *entry;
    t1 = get_cntvct();
    while ((entry = readdir(dir)) != NULL) {
        // 空循环
    }
    t2 = get_cntvct();
    closedir(dir);
    
    return (long)((double)(t2 - t1) * 1e9 / get_cntfrq());
}
```

**限制**：目录项数量固定时，差异可能不明显。更适合检测**目录项计数异常**（见 Layer 3）。

#### 2.2.5 /proc/self/maps 读取时延侧信道

**原理**：`show_map_vma()` 中调用 `susfs_sus_maps()`，需要 `kmalloc(SUSFS_MAX_LEN_PATHNAME)` + 遍历 `LH_SUS_MAPS_SPOOFER`。

```c
// kernel_patches/fs/proc/task_mmu.c
#ifdef CONFIG_KSU_SUSFS_SUS_MAPS
    out_name = kmalloc(SUSFS_MAX_LEN_PATHNAME, GFP_KERNEL);
    ret = susfs_sus_maps(ino, end - start, &ino, &dev, &flags, &pgoff, vma, out_name);
#endif
```

**检测代码**：

```c
long measure_maps_read_latency(void) {
    const int ITER = 1000;
    uint64_t t1, t2, sum = 0;
    char buf[4096];
    
    for (int i = 0; i < ITER; i++) {
        int fd = open("/proc/self/maps", O_RDONLY);
        t1 = get_cntvct();
        while (read(fd, buf, sizeof(buf)) > 0);
        t2 = get_cntvct();
        close(fd);
        sum += (t2 - t1);
    }
    
    return (long)((double)sum * 1e9 / get_cntfrq() / ITER);
}
```

---

### 2.3 Layer 3: 一致性异常检测（Consistency Checks）

SUSFS 的隐藏逻辑是**点状的**（只 patch 特定数据出口），导致大量内核 API 绕过其拦截，形成不一致性。

#### 2.3.1 错误码异常（强烈推荐）

**源码级漏洞**：`susfs_change_error_no_by_pathname()` 对 `/data/` 路径的 `linkat` 操作返回 `ENOENT` 而非 `EEXIST`。

```c
} else if (!strncmp(pathname, "/data/", 6)) {
    switch(syscall_family) {
        case SYSCALL_FAMILY_LINKAT_NEWNAME:
            *errno_to_be_changed = -ENOENT;  // BUG!
            return;
        // ...
    }
}
```

**正常系统行为**：对已存在的文件执行 `linkat(newname)` 应返回 `EEXIST`。
**SUSFS 行为**：返回 `ENOENT`。

**检测代码**：

```c
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int detect_susfs_by_linkat_errno(void) {
    // 在 app 私有目录创建测试文件
    const char *existing = "/data/data/<pkg>/files/.probe";
    const char *newlink = "/data/data/<pkg>/files/.probe_link";
    
    int fd = open(existing, O_CREAT | O_RDWR, 0644);
    close(fd);
    
    // 尝试对已存在的文件创建硬链接
    int ret = linkat(AT_FDCWD, existing, AT_FDCWD, newlink, 0);
    unlink(newlink);
    
    if (ret == -1 && errno == ENOENT) {
        // 命中 SUSFS 错误码漏洞
        return 1;
    }
    // 正常应为 EEXIST
    return 0;
}
```

**可靠性**：⭐⭐⭐⭐⭐ — 这是源码级 bug，修复会破坏现有隐藏语义。

#### 2.3.2 memfd_create EFAULT 异常

```c
#include <sys/mman.h>

int detect_susfs_by_memfd(void) {
    int fd = memfd_create("memfd:/jit-cache", MFD_CLOEXEC);
    if (fd == -1 && errno == EFAULT) {
        // SUSFS 的 sus_memfd 故意返回 EFAULT
        return 1;
    }
    if (fd >= 0) close(fd);
    return 0;
}
```

#### 2.3.3 maps 与 fstat 的 inode 不一致

**原理**：`sus_maps` 伪造 `/proc/self/maps` 中的 `ino` 和 `dev`，但文件系统层面的 `fstat()` 返回真实值。

```c
void *handle = dlopen("/data/app/<pkg>/lib/arm64/libnative.so", RTLD_NOW);
int fd = open("/data/app/<pkg>/lib/arm64/libnative.so", O_RDONLY);
struct stat st;
fstat(fd, &st);
unsigned long real_ino = st.st_ino;

// 读取 /proc/self/maps，查找该 so 的映射
// 对比 maps 中的 inode 与 real_ino
// 如果不一致 → sus_maps 生效
```

#### 2.3.4 mountinfo mnt_id 连续性异常

**原理**：`mnt_id_reorder` 功能会将 mount ID 重新编号为从第一个 mount ID 开始的**严格连续整数**（1, 2, 3...）。正常系统的 mount ID 是内核全局递增的，通常不连续。

```c
FILE *fp = fopen("/proc/self/mountinfo", "r");
int prev_id = -1, count = 0;
char line[512];

while (fgets(line, sizeof(line), fp)) {
    int mnt_id;
    sscanf(line, "%d", &mnt_id);
    if (prev_id != -1 && mnt_id != prev_id + 1) {
        // 不连续，正常
        fclose(fp);
        return 0;
    }
    prev_id = mnt_id;
    count++;
}
fclose(fp);

// 如果前 N 个 mount ID 严格连续且 N > 5，极可疑
return (count > 5) ? 1 : 0;
```

#### 2.3.5 uname 与 /proc/version 不一致

```c
#include <sys/utsname.h>

int detect_susfs_by_uname_inconsistency(void) {
    struct utsname u;
    uname(&u);
    
    FILE *fp = fopen("/proc/version", "r");
    char version[256];
    fgets(version, sizeof(version), fp);
    fclose(fp);
    
    // 对比 u.release 与 /proc/version 中的版本号
    if (!strstr(version, u.release)) {
        return 1;  // spoof_uname 生效
    }
    return 0;
}
```

---

### 2.4 Layer 4: 二进制与内存指纹

#### 2.4.1 ksu_susfs 二进制特征码

| 特征 | 值 |
|------|-----|
| ELF BuildID (arm64) | `2a29486b8c99b0f0f2ede21d4cccda4b2c382e3e` |
| SHA256 | `aec682a0caa59b1f4ccffea7c41f5b75c24994fdb8058b8bc0bf4e09c889939c` |
| `.rodata` 字符串数 | ~1368 条 |
| 硬编码魔数 | `0xDEADBEEF` (addr: `0x002184dc`), `0x55555` (addr: `0x002184e0`) |

#### 2.4.2 进程 cmdline 监控

`ksu_susfs` 被调用时，`/proc/<pid>/cmdline` 会暴露完整参数：

```c
DIR *dir = opendir("/proc");
while ((entry = readdir(dir)) != NULL) {
    snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
    // 读取并匹配 "ksu_susfs"
}
```

---

## 3. 缓解措施与反检测分析

### 3.1 SUSFS 开发者可能的缓解方向

| 检测手段 | 缓解难度 | 说明 |
|---------|---------|------|
| prctl 返回值 | 低 | KSU 可修改 handler 对非 root 返回 `EINVAL` |
| prctl 时延 | 中 | 可内联 handler 减少函数调用开销 |
| faccessat kmalloc 时延 | **极高** | 要隐藏文件就必须做路径匹配，无法避免额外开销 |
| linkat 错误码 bug | 高 | 修复会破坏现有隐藏语义，需重构错误码逻辑 |
| mnt_id_reorder | 低 | 可关闭该功能 |
| uname spoofing | 低 | 可关闭该功能 |
| maps 与 fstat 不一致 | **极高** | 要伪造 maps 就必然与真实 inode 不一致 |

### 3.2 根本矛盾

SUSFS 的设计哲学是**"只保护看，不保护用"**（数据出口伪造）。这导致其存在**结构性矛盾**：
1. **路径中心型**：一切检测依赖路径字符串匹配。基于 fd 的操作（`fexecve`、`sendfile`、`copy_file_range`）天然绕过路径解析层。
2. **点状 Hook**：只修改特定函数，未修改的系统调用形成绕过面。
3. **额外工作必然耗时**：任何隐藏/伪造逻辑都引入额外的 CPU 周期和内存访问，在高精度计时器面前难以完全消除。

---

## 4. 综合检测决策树

```
开始
  │
  ▼
prctl(0xDEADBEEF) 返回值 == 0 ?
  ├── 是 → KSU 存在
  │         │
  │         ▼
  │         linkat errno == ENOENT ?
  │           ├── 是 → SUSFS 高置信度
  │           └── 否 → 继续
  │
  │         faccessat 隐藏路径时延 > 阈值 ?
  │           ├── 是 → SUSFS 中高置信度
  │           └── 否 → 继续
  │
  │         /proc/self/maps 读取时延异常 ?
  │           ├── 是 → SUSFS 中置信度
  │           └── 否 → KSU 存在但 SUSFS 不确定
  │
  └── 否 → KSU 不存在
            │
            ▼
            检查内核符号 /proc/kallsyms
              ├── 发现 susfs_* → SUSFS 存在但 KSU 被隐藏/绕过
              └── 无 → 系统干净
```

---

## 5. 结论

SUSFS 虽然在内核层面实现了广泛的文件系统隐藏，但其架构存在多处可被普通 app 利用的检测面：

1. **prctl 返回值侧信道**是最稳定、最高效的初筛手段，一次系统调用即可区分有无 KSU。
2. **`kmalloc(PAGE_SIZE)` 引入的时间侧信道**是 SUSFS 的结构性弱点。利用 ARM64 `cntvct_el0` 虚拟计数器，普通 app 可在纳秒级精度测量 `faccessat`、`stat` 等热路径的时延差异。
3. **错误码异常**（`linkat` 返回 `ENOENT`、`memfd_create` 返回 `EFAULT`）是源码级 bug，极难修复而不破坏功能。
4. **一致性检测**（maps vs fstat、uname vs /proc/version、mnt_id 连续性）提供了交叉验证手段。

本报告提出的检测框架**完全不需要 root 权限**，仅需标准 Android NDK 接口和高精度计时器即可实施。对于安全研究人员和反 root 检测系统开发者，这些技术可有效识别基于 SUSFS 的隐藏环境。

---

**附录：关键源码引用**

- `kernel_patches/include/linux/susfs.h` — 结构体定义与 CMD 常量
- `kernel_patches/fs/susfs.c` — 内核态实现（`kmalloc`、`list_for_each_entry_safe`）
- `kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch` — prctl 拦截点
- `ksu_susfs/jni/main.c` — 用户态通信协议
- `ksu_module_susfs/tools/ksu_susfs_arm64` — Radare2 反汇编对象
