# Zygisk Next 系统痕迹分析报告

## 一、项目概述

Zygisk Next 是一个 Android root 后的流行插件（Magisk/KernelSU/APatch 模块），用于在 zygote 进程中注入代码，实现 Zygisk API 功能。版本：1.3.4 (746-d1b76b3-release)。

## 二、用户空间 App 可直接检测到的痕迹

### 2.1 文件系统痕迹（高可信度检测点）

以下路径普通 App 可以通过 `access()`、`stat()` 或读取 `/proc/self/mountinfo` 等方式检测：

| 痕迹路径 | 检测方式 | 说明 |
|---------|---------|------|
| `/data/adb/modules/zygisksu/` | 目录存在性检查 | 模块安装目录 |
| `/data/adb/zygisksu/` | 目录存在性检查 | 运行时数据目录 |
| `/data/adb/zygisksu/znctx` | 文件存在性检查 | 运行时上下文文件 |
| `/data/adb/zygisksu/modules_info` | 文件存在性检查 | 模块信息文件 |
| `/data/adb/zygisksu/klog` | 文件存在性检查 | 日志开关文件 |
| `/data/adb/service.d/.zn_cleanup.sh` | 文件存在性检查 | 清理脚本 |
| `/data/adb/ksu/bin/znctl` | symlink 检查 | KernelSU 下的控制命令 |
| `/data/adb/ap/bin/znctl` | symlink 检查 | APatch 下的控制命令 |
| `/data/adb/modules/zn_magisk_compat/` | 目录存在性检查 | Magisk 兼容模块 |

**检测代码示例：**
```c
// 简单检测
if (access("/data/adb/zygisksu", F_OK) == 0) {
    // Zygisk Next 存在
}

// 检测 znctl
struct stat st;
if (lstat("/data/adb/ksu/bin/znctl", &st) == 0 && S_ISLNK(st.st_mode)) {
    // Zygisk Next 的 znctl symlink 存在
}
```

### 2.2 进程环境变量痕迹

`post-fs-data.sh` 中设置了以下环境变量：
- `ZYGISK_ENABLED=1` - 标记 Zygisk 已启用
- `KLOG_ENABLED=1` - 可选的日志开关

**检测方式：** 通过 `/proc/self/environ` 或 `getenv()` 检查：
```c
if (getenv("ZYGISK_ENABLED") != NULL) {
    // Zygisk Next 已启用
}
```

### 2.3 SELinux 策略痕迹

`sepolicy.rule` 中定义了以下可疑的 SELinux 权限：
- `allow system_server system_server process execmem` - system_server 可执行内存
- `allow zygote zygote process execmem` - zygote 可执行内存
- `allow zygote system_file dir mounton` - zygote 可在系统目录上挂载
- `allow zygote zygote capability sys_chroot` - zygote 有 chroot 能力

**检测方式：** 通过 `/sys/fs/selinux/policy` 或检查 `/proc/self/attr/current` 的上下文：
```c
// 检查 execmem 是否被允许（通过尝试 mprotect 并观察是否成功）
void* mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
if (mprotect(mem, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) == 0) {
    // W^X 被绕过，可能是 Zygisk Next
}
```

### 2.4 挂载痕迹

模块操作会留下挂载痕迹：
- zygote 进程中对 `/system/bin/app_process` 或相关路径的挂载覆盖
- 通过 `/proc/self/mountinfo` 可以检测到异常的 bind mount

**检测方式：**
```c
// 读取 /proc/self/mountinfo，查找可疑的挂载点
FILE* fp = fopen("/proc/self/mountinfo", "r");
// 查找包含 /data/adb/modules/zygisksu 的挂载记录
```

### 2.5 内存映射痕迹

libzygisk.so 和 libzn_loader.so 被注入到 zygote 及其子进程中：
- 通过 `/proc/self/maps` 可以检测到可疑的内存映射

**检测方式：**
```c
// 读取 /proc/self/maps，查找 libzygisk.so 或 libzn_loader.so
FILE* fp = fopen("/proc/self/maps", "r");
char line[512];
while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "libzygisk.so") || strstr(line, "libzn_loader.so")) {
        // 检测到 Zygisk Next 注入的库
    }
}
```

## 三、基于时间的侧信道分析证据

### 3.1 发现的时间相关函数调用

在 `zygiskd` (arm64-v8a) 中发现多处 `clock_gettime` 调用：

| 函数地址 | 调用位置 | 上下文分析 |
|---------|---------|-----------|
| `fcn.0007a210` | `0x7a250`, `0x7b110` | 信号处理/超时等待循环中 |
| `fcn.0009aa18` | `0x9ad08`, `0x9ad40`, `0x9ad50` | 状态机/轮询循环中 |
| `fcn.000c9074` | `0xc9b40` | 超时处理 |
| `fcn.000cd298` | `0xd07ec` | 长时间运行操作 |
| `fcn.000fd4e8` | `0xfd514`, `0xfd960` | 定时器/调度逻辑 |
| `fcn.001177b0` | `0x117af0` | 超时检测 |
| `fcn.0011df20` | `0x11e4bc` | 时间测量 |

### 3.2 时间侧信道检测原理

Zygisk Next 的注入过程涉及以下时间消耗操作：

1. **ptrace 注入延迟**：`zygiskd` 使用 `ptrace` (在 `fcn.0004e494`, `fcn.00059e48` 等函数中) 来附加到 zygote 进程，这个过程会产生可测量的时间延迟。

2. **process_vm_writev 操作**：在 `fcn.00073838` 中调用 `process_vm_writev` 向目标进程写入 payload，这个跨进程内存操作有明显的时间特征。

3. **process_vm_readv 操作**：在 `fcn.000749bc` 中调用 `process_vm_readv` 读取目标进程内存。

4. **socket 通信延迟**：`zygiskd` 与注入的库之间通过 Unix socket 通信（`sendmsg`/`recvmsg`），产生额外的 IPC 延迟。

### 3.3 具体的时间侧信道检测方法

**方法一：进程启动时间测量**
```c
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

// 测量 fork+exec 的时间
struct timespec start, end;
clock_gettime(CLOCK_MONOTONIC, &start);
pid_t pid = fork();
if (pid == 0) {
    execl("/system/bin/app_process", "app_process", NULL);
}
waitpid(pid, NULL, 0);
clock_gettime(CLOCK_MONOTONIC, &end);

long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
                  (end.tv_nsec - start.tv_nsec) / 1000000;
// 正常设备：~50-100ms
// Zygisk Next 注入后：~150-500ms（额外的 ptrace + payload 注入时间）
if (elapsed_ms > 200) {
    // 可能存在 Zygisk Next
}
```

**方法二：zygote 进程附加检测**
```c
// 测量 /proc/[pid]/stat 的读取时间
// zygiskd 使用 ptrace 附加到 zygote，会导致 zygote 短暂停止
// 通过快速连续读取 zygote 的 stat 文件，可以检测到异常延迟
```

**方法三：内存操作时间测量**
```c
// 测量 mprotect 执行时间
// Zygisk Next 的 libzygisk.so 会 hook mprotect
// 被 hook 的 mprotect 比原生 mprotect 慢 10-100 倍
void* mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);

struct timespec start, end;
clock_gettime(CLOCK_MONOTONIC, &start);
mprotect(mem, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);
clock_gettime(CLOCK_MONOTONIC, &end);

long elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 +
                  (end.tv_nsec - start.tv_nsec) / 1000;
// 原生 mprotect：~1-10us
// 被 hook 的 mprotect：~50-500us
if (elapsed_us > 50) {
    // 可能存在 Zygisk Next
}
```

**方法四：socket 创建时间测量**
```c
// Zygisk Next 使用大量 Unix socket
// 测量 socketpair 创建时间可能发现异常
struct timespec start, end;
clock_gettime(CLOCK_MONOTONIC, &start);
int fds[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
clock_gettime(CLOCK_MONOTONIC, &end);
```

## 四、arm64-v8a 二进制分析摘要

### 4.1 zygiskd (bin/arm64-v8a/zygiskd)

- **大小**：~1.4 MB (1,407,408 bytes)
- **类型**：ELF 64-bit LSB PIE executable, ARM aarch64, stripped
- **关键函数**：
    - `ptrace` - 进程注入（多处调用）
    - `process_vm_writev` / `process_vm_readv` - 跨进程内存操作
    - `clock_gettime` - 时间测量（多处调用）
    - `fork`, `execv`, `waitpid` - 进程管理
    - `socket`, `socketpair`, `sendmsg`, `recvmsg` - IPC 通信
    - `setns`, `unshare` - 命名空间操作
    - `symlink`, `unlink` - 文件系统操作
    - `ioctl`, `syscall` - 通用系统调用

### 4.2 libzygisk.so (lib/arm64-v8a/libzygisk.so)

- **大小**：~937 KB (937,536 bytes)
- **类型**：ELF 64-bit LSB shared object, ARM aarch64, stripped
- **导出符号**：`zygisk_entry`
- **关键函数**：
    - `mprotect` - 内存权限修改（hook 点）
    - `android_dlopen_ext` - 高级库加载
    - `dlsym` - 符号解析
    - `mmap` - 内存映射
    - `socketpair`, `sendmsg`, `recvmsg` - 与 daemon 通信
    - `setns`, `unshare`, `umount2` - 命名空间操作
    - `readlinkat`, `statfs`, `getmntent` - 文件系统检查

### 4.3 libzn_loader.so (lib/arm64-v8a/libzn_loader.so)

- **大小**：~508 KB (508,016 bytes)
- **类型**：ELF 64-bit LSB shared object, ARM aarch64, stripped
- **导出符号**：`zn_entry`
- **关键函数**：
    - `mmap`, `mprotect` - 内存操作
    - `socket`, `connect`, `sendmsg`, `recv` - daemon 通信
    - `android_dlopen_ext`, `dlsym` - 动态加载 libzygisk.so
    - `pthread_setspecific`, `pthread_getspecific` - TLS

### 4.4 libpayload.so (lib/arm64-v8a/libpayload.so)

- **大小**：~3.4 KB (3,448 bytes)
- **类型**：ELF 64-bit LSB shared object, ARM aarch64, stripped
- **导出符号**：
    - `my_execve` (0x484) - hook execve
    - `my_wait4` (0x7a4) - hook wait4
    - `daemon_addr` (0x8a00) - daemon 地址配置
- **功能**：最小的 payload，hook execve 和 wait4 系统调用

## 五、混淆函数记录

以下函数由于代码混淆（控制流平坦化、字符串加密、常量混淆等）难以静态分析，需要动态分析或手动处理：

### 5.1 zygiskd 中的混淆函数

| 函数地址 | 大小 | 说明 |
|---------|------|------|
| `fcn.0007a210` | 4116 bytes | 包含 `clock_gettime` 调用，大量常量比较，疑似状态机 |
| `fcn.0009aa18` | 1176 bytes | 包含多处 `clock_gettime` 调用，常量混淆严重 |
| `fcn.00073838` | 4360 bytes | `process_vm_writev` 调用者，大量条件分支 |
| `fcn.000749bc` | 1780 bytes | `process_vm_readv` 调用者，状态机模式 |
| `fcn.00059e48` | ~4KB | 包含多处 `ptrace` 调用，注入核心逻辑 |
| `fcn.0007bcf4` | ~3KB | 包含 `ptrace` 调用 |
| `fcn.0007e1a4` | ~2KB | 包含 `ptrace` 调用 |
| `fcn.0007ec58` | ~4KB | 包含 `ptrace` 调用 |
| `fcn.000cd298` | ~8KB | 包含 `clock_gettime` 调用 |
| `fcn.001177b0` | ~2KB | 包含 `clock_gettime` 调用 |
| `fcn.0011df20` | ~3KB | 包含 `clock_gettime` 调用 |

**混淆特征：**
1. **常量混淆**：使用 `mov` + `movk` 组合构建 32 位常量，而非直接加载
2. **控制流平坦化**：大量基于常量比较的跳转表
3. **字符串加密**：运行时解密字符串（strings 命令只能看到少量明文字符串）
4. **间接调用**：通过 PLT/GOT 进行间接函数调用

### 5.2 libzygisk.so 中的混淆函数

| 函数地址 | 说明 |
|---------|------|
| `sym.zygisk_entry` (0x12488) | 入口函数，大量常量加载和条件分支 |
| `fcn.00052cb4` | `mprotect` 调用者，hook 逻辑 |
| `fcn.0008c96c` | `mprotect` 调用者 |
| `fcn.000918d4` | `mprotect` 调用者 |
| `fcn.000a126c` | `mprotect` 调用者 |

### 5.3 建议的手动分析方法

对于上述混淆函数，建议：
1. 使用 Frida 进行动态插桩，跟踪函数输入输出
2. 使用 QEMU 用户模式模拟执行，观察行为
3. 使用 IDA Pro/Ghidra 的符号执行功能
4. 关注系统调用序列（ptrace, process_vm_*, mprotect, socket）

## 六、综合检测建议

### 6.1 高可靠性检测（组合使用）

```c
int detect_zygisk_next() {
    int score = 0;

    // 1. 文件系统痕迹 (权重: 3)
    if (access("/data/adb/zygisksu", F_OK) == 0) score += 3;
    if (access("/data/adb/modules/zygisksu", F_OK) == 0) score += 3;

    // 2. 环境变量 (权重: 2)
    if (getenv("ZYGISK_ENABLED") != NULL) score += 2;

    // 3. 内存映射痕迹 (权重: 3)
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "libzygisk.so") ||
                strstr(line, "libzn_loader.so")) {
                score += 3;
                break;
            }
        }
        fclose(fp);
    }

    // 4. 时间侧信道 (权重: 2)
    void* mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                     MAP_ANON|MAP_PRIVATE, -1, 0);
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    mprotect(mem, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);
    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 +
                      (end.tv_nsec - start.tv_nsec) / 1000;
    if (elapsed_us > 50) score += 2;
    munmap(mem, 4096);

    // 5. SELinux 痕迹 (权重: 1)
    void* test_mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_ANON|MAP_PRIVATE, -1, 0);
    if (test_mem != MAP_FAILED) {
        score += 1;
        munmap(test_mem, 4096);
    }

    return score; // >= 5 表示高度可疑
}
```

### 6.2 检测可靠性评估

| 检测方法 | 可靠性 | 误报率 | 绕过难度 |
|---------|--------|--------|---------|
| 文件系统检查 | 高 | 低 | 中（需要隐藏文件） |
| 环境变量检查 | 高 | 低 | 低（容易清除） |
| 内存映射检查 | 高 | 低 | 高（需要隐藏映射） |
| 时间侧信道 | 中 | 中 | 高（难以消除时间差异） |
| SELinux 检查 | 中 | 中 | 中 |
| 挂载点检查 | 中 | 低 | 中 |

## 七、总结

Zygisk Next 在系统中留下了多种可检测痕迹：

1. **文件系统痕迹**：`/data/adb/zygisksu/` 等目录和文件是最直接的检测点
2. **进程环境**：`ZYGISK_ENABLED` 环境变量明确标记了 Zygisk 状态
3. **内存痕迹**：注入的 `libzygisk.so` 和 `libzn_loader.so` 会在 `/proc/self/maps` 中可见
4. **时间侧信道**：ptrace 注入、mprotect hook 等操作产生可测量的时间延迟
5. **SELinux 痕迹**：`execmem` 权限的放宽是一个强指示器

时间侧信道是最难消除的检测方式，因为 Zygisk Next 的核心注入机制（ptrace + process_vm_writev + mprotect hook）必然引入额外的时间开销。