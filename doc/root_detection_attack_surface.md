# KernelSU Root 后可检测特征与侧信道分析

本文档系统分析使用 KernelSU 方案获取 root 权限后，系统层面暴露的**可检测特征**和**侧信道攻击面**。涵盖普通 App 可直接观测的静态特征，以及需要通过高精度测量或异常行为对比才能发现的动态侧信道。

---

## 一、核心结论

KernelSU 作为内核级 root 方案，虽然比传统的 `/system` 分区修补更隐蔽，但由于其架构设计（内核模块/内联代码 + 用户态守护进程 `ksud` + SELinux 策略注入 + 系统调用 hook），仍然在**文件系统、进程空间、SELinux 上下文、系统调用行为、内核元数据**五个维度留下了可检测痕迹。

特别需要注意的是，KernelSU 的 **`sucompat` 兼容层**和 **`kernel_umount` 模块卸载层**在处理不同 UID 的进程时引入了**差异化的时间开销和行为差异**，这构成了稳定的时间侧信道和异常行为侧信道。

---

## 二、静态特征：普通 App 可直接检测

### 2.1 文件系统痕迹（最易检测）

KernelSU 的用户态组件在 `/data/adb/` 下创建了大量固定路径的文件和目录。普通 App 通过 `stat()` 或 `access()` 即可探测其存在性。

| 路径 | 说明 | 检测难度 |
|------|------|----------|
| `/data/adb/ksud` | `ksud` 二进制本体 | 极低 |
| `/data/adb/ksu/` | KernelSU 工作目录 | 极低 |
| `/data/adb/ksu/bin/` | 附加工具目录 | 极低 |
| `/data/adb/ksu/.allowlist` | 持久化的授权列表（存在性可 stat） | 中 |
| `/data/adb/modules/` | 模块挂载目录 | 极低 |
| `/data/adb/modules_update/` | 模块更新缓存目录 | 极低 |
| `/data/adb/metamodule/` | 元模块符号链接 | 极低 |

**检测代码示例**：

```java
// Java 层面即可检测
new File("/data/adb/ksud").exists();
new File("/data/adb/modules").exists();
```

### 2.2 进程特征

`ksud` 作为 init 的直接子进程在多个生命周期阶段运行：

- `/data/adb/ksud post-fs-data`
- `/data/adb/ksud services`
- `/data/adb/ksud boot-completed`

这些进程具有以下可扫描特征：
- **UID/GID = 0**（root）
- **SELinux Domain = `u:r:ksu:s0`**
- **父进程 PID = 1**（init）

普通 App 可以通过遍历 `/proc/<pid>/cmdline` 和 `/proc/<pid>/attr/current` 来发现它们。

### 2.3 SELinux 上下文痕迹（最强特征）

KernelSU 将被 root 的进程、ksud 进程以及 root shell 统一切换到 **`u:r:ksu:s0`**。

**直接检测点**：

```bash
$ cat /proc/self/attr/current
u:r:ksu:s0
```

这是一个**几乎无法掩盖**的强特征。任何被 root 的 App，其自身进程的安全上下文都会从正常的 `u:r:untrusted_app:s0` 变为 `u:r:ksu:s0`。高级检测框架（如银行 App、游戏反作弊）会例行检查自身进程的 SELinux domain，一旦发现非预期的 domain，即可判定存在内核级 root。

**政策数据库痕迹**：

KernelSU 在内核中动态向 SELinux policy 注册了 `ksu` domain：

```c
ksu_type(db, KERNEL_SU_DOMAIN, "domain");
ksu_permissive(db, KERNEL_SU_DOMAIN);
ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL);
```

即使 `/sys/module/kernelsu` 被隐藏，高级检测仍可通过解析 sepolicy 数据库或观察 `servicemanager` 对 `ksu` domain 的 AVC 允许规则来推断 KernelSU 的存在。

### 2.4 内核 / proc / sysfs 痕迹

#### `/proc/modules` 中的条目

即使 LKM 模式下调用了 `kobject_del(&THIS_MODULE->mkobj.kobj)` 删除了 sysfs 入口，`/proc/modules` 中仍然保留着 `kernelsu` 的条目。`lsmod` 和 `cat /proc/modules` 都能发现它。

> **例外**：GKI 静态编译模式下没有独立的 `kernelsu.ko`，因此 `/proc/modules` 中不存在该条目。

#### 内核日志 (dmesg / last_kmsg)

KernelSU 初始化时会打印大量包含明确标识的日志：

```
reboot kprobe registered successfully
hook_manager: sys_enter tracepoint registered
sys_call_table=0x%lx
dispatcher installed at slot %d
Cached su SID: %u
```

这些日志可能存在于：
- 当前 `dmesg` 环形缓冲区
- `last_kmsg`（重启前的日志）
- `pstore`（崩溃保留存储）

#### kprobe 注册痕迹

KernelSU 注册了以下 kprobe：
- `reboot`：用于安装 `[ksu_driver]` fd
- `input_event`：用于安全模式检测（监听音量下键）
- `syscall_regfunc` / `syscall_unregfunc`：tracepoint 管理

如果设备开启了 `/sys/kernel/debug/kprobes/list` 的可读权限，可以直接枚举到这些 kprobe。

#### 系统调用表修改

`kernel/hook/arm64/syscall_hook.c` 会查找 `sys_call_table`，并将一个 `ni_syscall` 空闲槽位替换为 `ksu_syscall_dispatcher`：

```c
ksu_syscall_table = (syscall_fn_t *)ksu_lookup_symbol("sys_call_table");
ksu_syscall_table_hook(ksu_dispatcher_nr, (syscall_fn_t)ksu_syscall_dispatcher, NULL);
```

通过内核内存读取（如利用已知漏洞或驱动）dump 系统调用表，可以发现某个槽位指向了非标准的内核函数。

### 2.5 系统调用行为异常

#### seccomp 状态突变

`escape_with_root_profile()` 会调用 `disable_seccomp()` 将被 root 进程的 seccomp 完全关闭：

```c
current->seccomp.mode = 0;
current->seccomp.filter = NULL;
```

App 可以通过 `prctl(PR_GET_SECCOMP)` 或读取 `/proc/self/status` 中的 `Seccomp` 字段来发现：提权前可能是 `2`（filter mode），提权后突变为 `0`。

#### `[ksu_driver]` FD 扫描

KernelSU 会创建名为 `[ksu_driver]` 的匿名 inode fd。Manager App 或被 root 的进程可能持有该 fd。扫描 `/proc/self/fd/` 的符号链接目标：

```rust
// ksud 中的扫描逻辑
if target.to_string_lossy().contains("[ksu_driver]") {
    return Some(fd_num);
}
```

普通 App 用同样的逻辑扫描自己的 fd 表，如果发现 `[ksu_driver]` 或 `[ksu_fdwrapper]`，即可判定 KernelSU 正在运行。

---

## 三、侧信道检测（重点）

侧信道检测的核心在于：**KernelSU 为了提供 root 能力和模块隔离，在不同 UID、不同系统调用路径上引入了差异化的处理逻辑，这些差异在时间上或行为上是可以被高精度测量的。**

### 3.1 时间侧信道

#### 3.1.1 sucompat 对 `faccessat` / `stat` 的延迟差异

**调用链**：

```
sys_faccessat
  └─ ksu_hook_faccessat
       └─ ksu_handle_faccessat
            ├─ ksu_is_allow_uid_for_current()  [bitmap / array 查询]
            └─ 若 allowlist + 路径为 "/system/bin/su"：
                 *filename_user = sh_user_path()  [重定向到 /system/bin/sh]
```

**时间差异分析**：
- **非 allowlist App**：路径不是 `/system/bin/su` 时，只经历一次 `__ksu_is_allow_uid()` 的 bitmap 查询和 `strncpy_from_user_nofault`，额外开销极小（~10-50 ns）。
- **allowlist App**：命中 `/system/bin/su` 后，除了 allowlist 查询，还要执行 `memcmp`、路径重定向等额外分支，开销略大（~50-200 ns）。

**攻击模型**：

App 可以高频调用 `faccessat("/system/bin/su")` 和 `faccessat("/system/bin/xyz")`，使用 `CLOCK_MONOTONIC` 或 `rdtsc`（在支持的情况下）精确测量系统调用耗时。如果两个路径的耗时存在统计显著的差异，且 `/system/bin/su` 的耗时略高，可推断存在 sucompat hook。

#### 3.1.2 `execve("/system/bin/su")` 的显著延迟峰值

`ksu_handle_execve_sucompat` 在匹配到 `/system/bin/su` 后，会执行 `escape_with_root_profile()`，这是一系列极重的内核操作：

```c
escape_with_root_profile()
    ├─ prepare_creds()
    ├─ ksu_get_root_profile()          // allowlist 链表遍历
    ├─ 设置 uid/gid/capabilities
    ├─ setup_selinux()                  // 切换 domain
    ├─ commit_creds()
    ├─ disable_seccomp()                // 分配 fake task_struct
    ├─ for_each_thread 设置 tracepoint flag
    └─ setup_mount_ns()
```

**总耗时在微秒到毫秒级**，远超普通 `execve("/system/bin/sh")` 的系统调用开销（通常为几十微秒）。

**攻击模型**：

如果 allowlist App 测量 `execve("/system/bin/su")` 的返回时间，并与 `execve("/system/bin/sh")` 对比，会发现一个**显著的延迟峰值**（可能高出 10-100 倍）。这个峰值是内核态执行 cred 重构和 SELinux 切换的直接证据，极难通过优化消除。

#### 3.1.3 `setresuid` + `kernel_umount` 导致的 App 启动延迟差异

`ksu_handle_setresuid` 中的 `ksu_handle_umount()` 对**非 allowlist 的普通 App** 执行：

```c
down_read(&mount_list_lock);
list_for_each_entry (entry, &mount_list, list) {
    try_umount(entry->umountable, entry->flags);
}
up_read(&mount_list_lock);
```

**时间差异分析**：
- **非 allowlist App**：zygote fork 后调用 `setresuid` 时，会遍历 `mount_list` 并逐个 umount 模块挂载点。如果用户安装了大量模块，`mount_list` 可能很长，导致**启动延迟增加数微秒到数毫秒**。
- **allowlist App 或 Manager App**：`ksu_is_allow_uid_for_current()` 返回 true，`kernel_umount` 逻辑可能跳过或执行路径不同，启动更快。

**攻击模型**：

通过精确测量 App **冷启动时间**（从 `fork` 到 `Activity.onCreate`），或直接在 native 层测量 `setresuid` 系统调用耗时，可以发现：
- 被 root 的 App 启动更快（跳过了 umount）
- 未被 root 的 App 启动更慢（经历了 umount 遍历）

这种**同一设备上不同 App 启动速度的差异**是 KernelSU 模块隔离机制带来的稳定时间侧信道。

#### 3.1.4 Tracepoint 标记进程的全局 syscall 延迟

`ksu_mark_running_process_locked()` 会对以下进程设置 `TIF_SYSCALL_TRACEPOINT` 标记：
- `ksu_root_process` (uid==0, ksu domain)
- `zygote_process`
- `shell` (uid 2000)
- `init` (pid 1)
- `ksu_is_allow_uid(uid)` 返回 true 的进程

**关键影响**：

被标记的进程在**每次系统调用进入时**，都会触发 `sys_enter` tracepoint 回调 `ksu_sys_enter_handler`：

```c
ksu_sys_enter_handler(struct trace_event_raw_sys_enter *entry)
    ├─ 检查 ksu_dispatcher_nr < 0
    ├─ ksu_has_syscall_hook(id)       // 查询路由表
    └─ 若是 hooked syscall：修改 pt_regs->syscallno
```

这意味着被标记进程的每个 syscall 都额外多了：**tracepoint 触发 + 路由表查询 + 条件分支**。单次开销约为 **20-100 ns**，但高频系统调用（如 `getpid`、`getuid`、`read`、`write`）会累积出可观的性能差异。

**攻击模型**：

App 可以在被 root 前后（或通过与另一个未被 root 的进程对比），执行以下循环：

```c
for (int i = 0; i < 1000000; i++) {
    syscall(__NR_getpid);
}
```

被 root 的进程（已被标记）会比普通进程慢 **1%-5%**。虽然这个差异很小，但在高精度计时和统计平均下是可区分的。

> **注意**：由于 zygote 本身也被标记，所有从 zygote fork 出来的 App 在 fork 瞬间都继承了标记。但普通 App 的 UID 不在 allowlist 中时，后续 `setresuid` 会调用 `ksu_clear_task_tracepoint_flag_if_needed()` 清除标记。因此，**标记的生命周期本身**也可以作为检测信号——如果某个进程在 `setresuid` 前后 syscall 性能发生突变，说明 KernelSU 正在跟踪它。

---

### 3.2 异常行为侧信道

#### 3.2.1 `access("/system/bin/su")` 的返回值差异

`ksu_handle_faccessat` 的逻辑：

```c
if (!ksu_is_allow_uid_for_current(current_uid().val)) {
    return 0;  // 不干预
}
if (memcmp(path, su, sizeof(su)) == 0) {
    *filename_user = sh_user_path();  // 重定向到 /system/bin/sh
}
```

**行为差异**：
- **非 allowlist App**：如果设备上没有 `/system/bin/su` 实体文件，`access("/system/bin/su")` 返回 `ENOENT`（-1）。
- **allowlist App**：`access("/system/bin/su")` 被内核重定向为 `access("/system/bin/sh")`，返回 `0`（成功）。

**攻击模型**：

如果一个检测框架能够**以不同 UID 执行相同的系统调用**（例如通过多用户、工作资料、或利用 zygote 创建子进程），对比两者 `access("/system/bin/su")` 的结果：
- 某个 UID 返回 `0`
- 另一个 UID 返回 `-1`

即可证明内核正在按 UID 对 `/system/bin/su` 进行差异化处理，这是 KernelSU `sucompat` 层的独特指纹。

进一步地，如果设备开启了 `allow_shell`（debug 模式或用户手动启用），普通 shell (uid 2000) 也会被 allowlist。App 如果能以 shell uid 执行代码（虽然通常做不到，但某些漏洞可能实现），`access("/system/bin/su")` 会突然返回成功，这也是强烈信号。

#### 3.2.2 `init.rc` 的 stat 大小异常

`kernel/runtime/ksud_integration.c` 中的 `ksu_sys_fstat` 会人为增加 `init.rc` 的 `st_size`：

```c
new_size = size + ksu_rc_len;
copy_to_user_nofault(st_size_ptr, &new_size, sizeof(long));
```

这是因为 KernelSU 通过 read hook 向 `init.rc` 的读取结果中追加了额外的启动脚本（用于启动 `ksud`）。为了让 `init` 进程读取完整内容，fstat 返回的大小也被虚增了。

**检测方法**：

对 `/system/etc/init/hw/init.rc` 执行 `stat()` 获取 `st_size`，然后打开文件直接读取到物理 EOF（绕过 read hook），比较实际读取的字节数与 `st_size`。如果 `st_size > 实际大小`，则证明存在 fstat/read hook。

#### 3.2.3 seccomp 状态突变侧信道

如 2.5 节所述，普通 App 在获得 root 前通常运行在 seccomp filter mode（`Seccomp: 2`），获得 root 后突变为 `Seccomp: 0`。

App 可以在 JNI 层读取 `/proc/self/status`：

```
Seccomp:	2
```

调用 `grant_root()` 后再读取：

```
Seccomp:	0
```

这种**从 2 到 0 的突变**是普通 root 方案很少见的特征（大多数 root 不会动 seccomp），可以作为 KernelSU 的指纹之一。

---

## 四、检测特征汇总表

| 类别 | 检测目标 | 检测方法 | 隐蔽性 |
|------|----------|----------|--------|
| **文件系统** | `/data/adb/ksud`, `/data/adb/modules/` | `stat()` / `access()` | 极低 |
| **文件系统** | `init.rc` size 虚增 | `stat()` vs 实际读取 | 中 |
| **进程** | `ksud` 进程 (root, `u:r:ksu:s0`) | 扫描 `/proc` | 极低 |
| **SELinux** | `u:r:ksu:s0` | `/proc/self/attr/current` | 极低 |
| **SELinux** | `ksu` domain 在 policy 中 | sepolicy 分析 | 高 |
| **Syscall** | `access("/system/bin/su")` 返回值差异 | 系统调用返回值对比 | 中 |
| **Syscall** | seccomp 从 2 变为 0 | `/proc/self/status` | 中 |
| **Syscall** | syscall table 异常 | 内核内存 dump | 高 |
| **内核痕迹** | `/proc/modules` 中的 `kernelsu` | `cat /proc/modules` | 低 |
| **内核痕迹** | kprobe 注册 | `/sys/kernel/debug/kprobes/list` | 中 |
| **内核痕迹** | dmesg / last_kmsg | 日志读取 | 中 |
| **侧信道-T** | `faccessat("/system/bin/su")` 延迟差异 | 高精度 syscall 计时 | 中 |
| **侧信道-T** | `execve("/system/bin/su")` 显著延迟 | 高精度 execve 计时 | 中 |
| **侧信道-T** | 非 allowlist App 启动更慢 (umount) | 冷启动计时 | 中 |
| **侧信道-T** | tracepoint 标记进程的 syscall 开销 | syscall 循环计时 | 高 |
| **侧信道-B** | `/proc/self/fd` 中存在 `[ksu_driver]` | 扫描 fd 符号链接 | 低 |
| **侧信道-B** | `init.rc` stat size 与实际不一致 | 文件元数据对比 | 中 |

> **侧信道-T** = 时间侧信道（Timing Side-channel）  
> **侧信道-B** = 行为侧信道（Behavioral Side-channel）

---

## 五、攻防思考：为什么这些特征难以完全消除

1. **用户态守护进程不可少**：`ksud` 需要持续运行以执行模块生命周期脚本（`post-fs-data`、`service`、`boot-completed`），这意味着 `/data/adb/ksud` 和 ksud 进程必须存在。

2. **SELinux domain 必须区分**：内核必须将被 root 的进程切换到一个独立的、高权限的 SELinux domain（`u:r:ksu:s0`），否则无法在 enforcing SELinux 下执行特权操作。这个 domain 本身就成了强特征。

3. **系统调用 hook 必然引入开销**：为了拦截 `execve`、`faccessat`、`setresuid` 等关键调用，KernelSU 必须通过 tracepoint 或 syscall table patch 介入每次系统调用，这不可避免地带来了纳秒到微秒级的额外延迟。

4. **sucompat 的行为差异是功能决定的**：`sucompat` 的设计目标就是“让 allowlist 中的 App 能执行 su，非 allowlist 的不能”。这种**按 UID 差异化处理**天然构成了行为侧信道。

5. **kernel_umount 的遍历开销与模块数量成正比**：模块越多，`mount_list` 越长，非 allowlist App 的启动延迟越明显。这个侧信道与功能设计强绑定。

---

## 六、结语

KernelSU 提供了比传统 root 方案更强的隐蔽性（无 `/system` 分区修改、无持久化的 `su` 二进制），但其内核级架构也引入了新的检测面。

对于防御方（检测框架开发者）而言，最有效的检测策略是**多维度联合判断**：
- **静态特征**作为快速筛选（`stat("/data/adb/ksud")`）
- **SELinux 上下文**作为强确认信号（`u:r:ksu:s0`）
- **时间侧信道**作为无权限探测手段（syscall 延迟分析、启动时间对比）
- **行为侧信道**作为异常验证（`access("/system/bin/su")` 的 UID 差异化响应）

对于攻击方（试图隐藏 KernelSU 的用户）而言，想要完全消除上述特征，需要对内核源码进行深度 patch（如重命名 `ksu` domain、修改 `ksud` 路径、从 `modules` 链表中摘除、消除 sucompat 的时间差异等），这已超出普通用户的能力范围，且维护成本极高。
