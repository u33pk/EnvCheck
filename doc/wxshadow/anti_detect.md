# Anti-Detect 模块突破与检测方案

## 第一部分：检测 Anti-Detect 模块本身

anti-detect 是一个运行时加载的内核模块，其防护机制建立在 Inline Hook 之上。Hook 本身会留下可检测的痕迹，且其防护范围存在明确的边界。

---

### 1.1 Syscall 时序侧信道

Inline Hook 在目标函数入口处插入跳转指令（通常改写为 `b <trampoline>`），这会引入额外的指令缓存刷新、分支预测失效和 trampoline 执行开销。通过大量采样 syscall 延迟，可以检测出 hook 的存在。

```c
#include <time.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>

#define SAMPLES 10000

static inline uint64_t nanos() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 测量 faccessat 的延迟分布
long measure_faccessat_latency(void) {
    uint64_t start = nanos();
    for (int i = 0; i < SAMPLES; i++) {
        syscall(__NR_faccessat, AT_FDCWD, "/dev/null", F_OK, 0);
    }
    uint64_t end = nanos();
    return (long)((end - start) / SAMPLES);
}

// 对比：faccessat 通常 ~50-100ns，被 hook 后可能增加 100-500ns
int detect_by_timing(void) {
    long lat = measure_faccessat_latency();
    printf("[*] faccessat avg latency: %ld ns\n", lat);
    return lat > 200 ? 1 : 0;  // 阈值根据设备调整
}
```

**增强方案**：对比被 hook syscall（faccessat）和未被 hook syscall（如 getpid）的延迟比值。hook 引入的额外开销是固定的，比值法可以消除 CPU 频率波动的影响。

---

### 1.2 直接 Syscall vs Libc Wrapper 对比

anti-detect hook 的是 syscall 层面。glibc 的 `access()` 会调用 `faccessat2`（已被 hook），但如果应用直接通过 `syscall()` 调用底层 syscall，或者调用 anti-detect 未 hook 的 syscall（如 `openat`），返回值会出现矛盾。

```c
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

// 检测逻辑：libc wrapper 被 hook，但直接 openat 未被 hook
// 如果 access("/dev/goldfish_pipe") 返回 ENOENT，但 openat 成功
// → 确认存在 anti-detect 类 syscall hook
int detect_hook_inconsistency(void) {
    // glibc access() → faccessat2 (hooked → ENOENT)
    int ret_access = access("/dev/goldfish_pipe", F_OK);
    int err_access = errno;

    // 直接 syscall openat (NOT hooked → may succeed)
    int fd = syscall(__NR_openat, AT_FDCWD, "/dev/goldfish_pipe", O_RDONLY);
    int has_open = (fd >= 0);
    if (has_open) close(fd);

    // 矛盾检测
    if (ret_access == -1 && err_access == ENOENT && has_open) {
        printf("[!] DETECTED: faccessat returns ENOENT but openat succeeds\n");
        printf("    → syscall hook layer confirmed (anti-detect-like)\n");
        return 1;
    }
    return 0;
}
```

**更通用的变体**：对任意路径进行此检测。hook 的 syscall 返回 ENOENT，但未 hook 的 openat 返回成功 → 100% 确认存在文件隐藏 hook。

---

### 1.3 Kallsyms 符号扫描

KernelPatch 的 hook 机制和模块本身会在内核符号表中留下痕迹。

```c
#include <stdio.h>
#include <string.h>

// 扫描 /proc/kallsyms 中的 KP/anti-detect 相关符号
int detect_by_kallsyms(void) {
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) return -1;

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        // KP hook 框架的链式结构符号
        if (strstr(line, "hook_chain") ||
            strstr(line, "hook_wrap") ||
            strstr(line, "hook_syscalln")) {
            printf("[!] KP hook symbol: %s", line);
            found++;
        }
        // anti-detect 模块自身的函数
        if (strstr(line, "anti_detect") ||
            strstr(line, "before_stat_syscall") ||
            strstr(line, "after_getdents64") ||
            strstr(line, "supercall_guard")) {
            printf("[!] anti-detect symbol: %s", line);
            found++;
        }
        // KernelPatch 内核模块标识
        if (strstr(line, "kpm_") || strstr(line, "kernelpatch")) {
            printf("[!] KP module symbol: %s", line);
            found++;
        }
    }
    fclose(fp);
    return found;
}
```

**注意**：某些内核配置会隐藏 kallsyms（`/proc/sys/kernel/kptr_restrict`），但 Android 设备通常保持可读。

---

### 1.4 KernelPatch Supercall 枚举已加载模块

如果 anti-detect 的 supercall guard 未启用（或已知 superkey），可以通过 KP 自身的 supercall 接口枚举已加载的 KPM 模块。

```c
// 伪代码：通过 SUPERCALL_KPM_LIST / SUPERCALL_KPM_INFO
// 获取已加载模块列表，检查是否包含 "anti-detect"

#include <stdio.h>
#include <string.h>

// 需要链接 KernelPatch 的 supercall 用户态库
// 或直接使用 syscall(__NR_supercall, ...) 手动构造调用

void detect_via_kpm_list(const char *superkey) {
    // 1. SUPERCALL_KPM_NUMS → 获取模块数量
    // 2. SUPERCALL_KPM_LIST → 获取模块名列表
    // 3. 遍历检查是否包含 "anti-detect"

    // 如果 supercall guard 启用且不知道 key：
    // → 调用返回 -ENOENT，这本身也是 KP 存在的信号
    // （普通设备上 syscall 45 是 truncate，返回 -ENOENT 表示文件不存在，
    //  但重复返回 -ENOENT 对于各种参数组合暗示了 hook）
}
```

**逆向信号**：即使不知道 superkey，连续用不同 cmd 调用 syscall 45 都返回 -ENOENT（而非 -EINVAL/EFAULT），本身就是 KP 存在的强信号。真实内核的 truncate syscall 对非法参数会返回不同的 errno。

---

### 1.5 通过 /proc/modules 检查

虽然 KPM 是 KP 框架的动态模块（不是标准的 .ko），但某些 KP 版本可能会在 `/proc/modules` 中留下记录。此外，KP 内核补丁本身加载后会修改内核代码段，可通过检查模块列表中的异常项来发现。

```c
FILE *fp = fopen("/proc/modules", "r");
char line[256];
while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "kernelpatch") || strstr(line, "kp_"))
        printf("[!] KernelPatch module in /proc/modules\n");
}
fclose(fp);
```

---

### 1.6 Syscall Table 完整性校验

通过读取内核内存中的 syscall table，对比已知的标准 syscall handler 地址，可以发现被 hook 的条目。

```c
// 高级方法：通过 /dev/mem 或 kernel exploit 读取 syscall table
// 或利用已知的信息泄露漏洞获取内核地址

// 简化版本：通过 kallsyms 获取 sys_call_table 符号地址
// 然后读取其中 faccessat/getdents64 的 handler 地址
// 如果地址不在内核代码段范围内（不以 0xffff 开头）→ 被 hook
```

---

## 第二部分：突破文件隐藏检测模拟器

anti-detect 只拦截了 `stat/access/readlinkat/getdents64` 四条路径且只匹配 `goldfish_` 前缀。以下方法完全不经过这些 hook，可以直接发现模拟器特征。

---

### 2.1 procfs / sysfs 中的模拟器特征（read 路径完全开放）

anti-detect 没有 hook `read`，所有通过 `read()` 读取的 proc/sys 文件都**完全暴露**。

#### /proc/devices

```bash
$ cat /proc/devices
...
250 goldfish_pipe
251 goldfish_sync
```

```c
FILE *fp = fopen("/proc/devices", "r");
char line[256];
while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "goldfish"))
        printf("[DETECT] Emulator via /proc/devices: %s", line);
}
fclose(fp);
```

#### /proc/interrupts

```bash
$ cat /proc/interrupts | grep goldfish
  3:     123456     0  goldfish   goldfish_pipe
```

#### /proc/iomem

```bash
$ cat /proc/iomem | grep goldfish
  00000000-00000fff : goldfish_timer
```

#### /proc/mtd

```bash
$ cat /proc/mtd
dev:    size   erasesize  name
mtd0: 00400000 00001000 "goldfish_nand"
```

#### /sys/bus/platform/devices/goldfish*

```c
DIR *dir = opendir("/sys/bus/platform/devices");
struct dirent *ent;
while ((ent = readdir(dir))) {
    if (strncmp(ent->d_name, "goldfish", 8) == 0)
        printf("[DETECT] goldfish in sysfs: %s\n", ent->d_name);
}
closedir(dir);
```

#### /sys/class/input/input*/name

```bash
$ cat /sys/class/input/input0/name
goldfish_rotary
```

#### /sys/class/drm/card*/device/

```c
FILE *fp = fopen("/sys/class/drm/card0/device/vendor", "r");
// 模拟器通常为 0x1af4 (VirtIO) 或 SwiftShader ID
```

---

### 2.2 间接发现隐藏文件（通过其他进程）

即使当前进程的 `getdents64` 被过滤，系统中**其他进程**打开的文件不受此模块影响。

#### 扫描 /proc/<pid>/fd/

surfaceflinger、audioserver 等系统服务会打开 goldfish 设备。遍历所有进程的 fd：

```c
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void scan_all_proc_fds(void) {
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    char path[256], linkbuf[256];
    ssize_t len;

    while ((ent = readdir(proc))) {
        if (!isdigit(ent->d_name[0])) continue;
        snprintf(path, sizeof(path), "/proc/%s/fd", ent->d_name);
        DIR *fd_dir = opendir(path);
        if (!fd_dir) continue;

        struct dirent *fd_ent;
        while ((fd_ent = readdir(fd_dir))) {
            if (fd_ent->d_name[0] == '.') continue;
            snprintf(path, sizeof(path), "/proc/%s/fd/%s",
                     ent->d_name, fd_ent->d_name);
            len = readlink(path, linkbuf, sizeof(linkbuf)-1);
            if (len > 0) {
                linkbuf[len] = 0;
                if (strstr(linkbuf, "goldfish"))
                    printf("[DETECT] %s (pid=%s)\n", linkbuf, ent->d_name);
            }
        }
        closedir(fd_dir);
    }
    closedir(proc);
}
```

**关键**：`readlink` 读取 `/proc/<pid>/fd/<n>` 时，内核返回的是真实路径，不走 anti-detect 的用户路径过滤逻辑。

#### /proc/<pid>/maps

```c
// surfaceflinger 等进程 mmap("/dev/goldfish_pipe") 会留下路径
FILE *fp = fopen("/proc/<pid>/maps", "r");
// 搜索 goldfish
```

---

### 2.3 未 Hook 的系统调用

| 系统调用 | 如何利用 |
|---------|---------|
| `openat` / `openat2` | **故意未 hook**，可直接打开 goldfish 设备文件并获取有效 fd |
| `readlink`（非 `readlinkat`） | 老内核/静态链接库可能直接调用 `readlink`，不经过 `readlinkat` |
| `getdents`（32bit 旧版） | 只 hook 了 `getdents64`，32bit dirent 可绕过 |
| `name_to_handle_at` | 获取文件句柄，不经过 stat/getdents |
| `open_by_handle_at` | 通过已获取的句柄打开文件 |
| `inotify_add_watch` | 对 `/dev` 设置监控，文件创建事件不受过滤 |
| `fanotify_mark` | 文件系统监控 |
| `listxattr/getxattr` | 查询文件扩展属性 |
| `ioctl` | 直接向设备发送控制命令 |

**最直接的 bypass**：

```c
// anti-detect 未 hook openat
int fd = open("/dev/goldfish_pipe", O_RDONLY);
if (fd >= 0) {
    printf("[DETECT] /dev/goldfish_pipe exists and can be opened!\n");
    close(fd);
}
```

---

### 2.4 Build.prop & 系统属性

anti-detect 完全不涉及属性系统：

```bash
$ getprop ro.hardware          # goldfish
$ getprop ro.kernel.qemu       # 1
$ getprop ro.boot.hardware     # goldfish
```

```c
#include <sys/system_properties.h>

char buf[PROP_VALUE_MAX];
__system_property_get("ro.hardware", buf);
if (strcmp(buf, "goldfish") == 0)
    printf("[DETECT] Emulator property: ro.hardware=%s\n", buf);
```

---

### 2.5 Boot Log / Kmsg

内核启动日志在 boot 时就已经写入 ring buffer，anti-detect 是运行时加载的模块，**无法修改历史日志**。

```bash
$ dmesg | grep -i goldfish
[    0.123456] goldfish_pipe: loaded
[    0.234567] goldfish_sync: loaded
```

```c
FILE *fp = fopen("/dev/kmsg", "r");
char line[512];
for (int i = 0; i < 200 && fgets(line, sizeof(line), fp); i++) {
    if (strstr(line, "goldfish"))
        printf("[DETECT] kmsg: %s", line);
}
fclose(fp);
```

---

### 2.6 Binder / ServiceManager

模拟器的 binder 服务名称通常包含 emulator 特征（如 `qemu_pipe`、`goldfish` 等专属服务）。通过 ServiceManager 查询可获得设备类型信息。

---

## 第三部分：综合检测代码

```c
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/system_properties.h>

// ========== 第一部分：检测 anti-detect 本身 ==========

static inline uint64_t nanos(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 1.1 时序侧信道
int detect_by_timing(void) {
    uint64_t start = nanos();
    for (int i = 0; i < 5000; i++)
        syscall(__NR_faccessat, AT_FDCWD, "/dev/null", F_OK, 0);
    uint64_t lat = (nanos() - start) / 5000;
    return lat > 200 ? 1 : 0;
}

// 1.2 hook 不一致性检测
int detect_hook_inconsistency(void) {
    int ret1 = access("/dev/goldfish_pipe", F_OK);
    int err1 = errno;
    int fd = syscall(__NR_openat, AT_FDCWD, "/dev/goldfish_pipe", O_RDONLY);
    int has_open = (fd >= 0);
    if (has_open) close(fd);
    return (ret1 == -1 && err1 == ENOENT && has_open);
}

// 1.3 kallsyms 扫描
int detect_by_kallsyms(void) {
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "anti_detect") ||
            strstr(line, "before_stat_syscall") ||
            strstr(line, "after_getdents64")) {
            found++;
        }
    }
    fclose(fp);
    return found;
}

// ========== 第二部分：检测模拟器特征 ==========

// 2.1 /proc/devices
int detect_proc_devices(void) {
    FILE *fp = fopen("/proc/devices", "r");
    if (!fp) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), fp))
        if (strstr(line, "goldfish")) found++;
    fclose(fp);
    return found;
}

// 2.2 sysfs 平台设备
int detect_sysfs_platform(void) {
    DIR *dir = opendir("/sys/bus/platform/devices");
    if (!dir) return 0;
    struct dirent *ent;
    int found = 0;
    while ((ent = readdir(dir)))
        if (strncmp(ent->d_name, "goldfish", 8) == 0) found++;
    closedir(dir);
    return found;
}

// 2.3 系统属性
int detect_system_props(void) {
    char buf[PROP_VALUE_MAX];
    __system_property_get("ro.hardware", buf);
    return strcmp(buf, "goldfish") == 0;
}

// 2.4 openat bypass
int detect_openat_bypass(void) {
    int fd = syscall(__NR_openat, AT_FDCWD, "/dev/goldfish_pipe", O_RDONLY);
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

// 2.5 扫描所有进程的 fd
int detect_via_proc_fds(void) {
    DIR *proc = opendir("/proc");
    struct dirent *ent;
    char path[256], linkbuf[256];
    int found = 0;

    while ((ent = readdir(proc))) {
        if (!isdigit(ent->d_name[0])) continue;
        snprintf(path, sizeof(path), "/proc/%s/fd", ent->d_name);
        DIR *fd_dir = opendir(path);
        if (!fd_dir) continue;
        struct dirent *fd_ent;
        while ((fd_ent = readdir(fd_dir))) {
            if (fd_ent->d_name[0] == '.') continue;
            snprintf(path, sizeof(path), "/proc/%s/fd/%s", ent->d_name, fd_ent->d_name);
            ssize_t len = readlink(path, linkbuf, sizeof(linkbuf)-1);
            if (len > 0 && strstr(linkbuf, "goldfish")) {
                found++;
                break;
            }
        }
        closedir(fd_dir);
    }
    closedir(proc);
    return found;
}

// ========== 主检测入口 ==========

int main() {
    int score = 0;

    printf("=== Part 1: Detecting anti-detect module ===\n");

    if (detect_by_timing()) {
        printf("[+] Timing side-channel: suspicious latency\n");
        score += 5;
    }
    if (detect_hook_inconsistency()) {
        printf("[+] Hook inconsistency: faccessat ENOENT but openat OK\n");
        score += 10;
    }
    int ksym = detect_by_kallsyms();
    if (ksym) {
        printf("[+] Kallsyms: %d anti-detect symbols found\n", ksym);
        score += 10;
    }

    printf("\n=== Part 2: Detecting emulator environment ===\n");

    if (detect_proc_devices()) {
        printf("[+] /proc/devices contains goldfish\n");
        score += 10;
    }
    if (detect_sysfs_platform()) {
        printf("[+] /sys/bus/platform/devices contains goldfish\n");
        score += 10;
    }
    if (detect_system_props()) {
        printf("[+] ro.hardware=goldfish\n");
        score += 10;
    }
    if (detect_openat_bypass()) {
        printf("[+] openat bypass: /dev/goldfish_pipe exists\n");
        score += 10;
    }
    if (detect_via_proc_fds()) {
        printf("[+] Found goldfish fds in other processes\n");
        score += 5;
    }

    printf("\n=== Result ===\n");
    printf("Total score: %d\n", score);
    if (score >= 20)
        printf("VERDICT: Anti-detect detected + Emulator environment confirmed\n");
    else if (score >= 10)
        printf("VERDICT: Emulator environment confirmed (anti-detect may be absent)\n");
    else if (score >= 5)
        printf("VERDICT: Suspicious - possible anti-detect or weak emulator signals\n");
    else
        printf("VERDICT: Likely real device\n");

    return score >= 10 ? 1 : 0;
}
```

---

## 总结

| 检测目标 | 方法 | 可靠性 |
|---------|------|--------|
| **anti-detect 本身** | Syscall 时序侧信道 | ⭐⭐⭐ |
| **anti-detect 本身** | faccessat vs openat 不一致 | ⭐⭐⭐⭐⭐ |
| **anti-detect 本身** | Kallsyms 符号扫描 | ⭐⭐⭐⭐⭐ |
| **anti-detect 本身** | Supercall 返回值异常 | ⭐⭐⭐⭐ |
| 模拟器环境 | `/proc/devices` 中的 goldfish | ⭐⭐⭐⭐⭐ |
| 模拟器环境 | `/sys/bus/platform/devices/goldfish*` | ⭐⭐⭐⭐⭐ |
| 模拟器环境 | `openat` bypass | ⭐⭐⭐⭐⭐ |
| 模拟器环境 | 扫描 `/proc/<pid>/fd/` | ⭐⭐⭐⭐ |
| 模拟器环境 | `/dev/kmsg` boot log | ⭐⭐⭐⭐⭐ |

anti-detect 本质上是一个**单点防御**，只解决"通过 libc 的 stat/readdir 检测 goldfish 文件"这一个攻击面。任何**多维度交叉验证**或**不走 libc wrapper 的直接 syscall** 都能轻易突破。
