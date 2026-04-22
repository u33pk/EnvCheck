# Zygisk Next 对 Zygote 孵化时间的影响分析

## 一、核心结论

**Zygisk Next 注入后，zygote 进程的 App 孵化时间会显著变长。** 这种时间延迟来源于两个层面：

1. **初始化注入阶段**（一次性）：ptrace 远程注入 libzygisk.so 到 zygote 进程
2. **每次 fork 阶段**（持续性）：hook 的 fork/unshare/sanitize_fds 以及模块加载执行

这些时间开销是功能必需的，无法被完全消除，因此构成了一个稳定的时间侧信道检测面。

---

## 二、初始化注入阶段的时间开销

### 2.1 注入流程

当系统启动 zygote 进程时，`zygiskd` 通过 `ptrace` 进行远程注入（`ptracer.cpp`）：

```cpp
bool trace_zygote(int pid) {
    ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL);
    // 等待 zygote 进入 STOP 状态
    inject_on_main(pid, lib_path);  // 核心注入
    kill(pid, SIGCONT);
    // 等待 SIGCONT 确认后 detach
}
```

### 2.2 inject_on_main 的详细步骤

```cpp
bool inject_on_main(int pid, const char *lib_path) {
    // 1. 读取寄存器，解析 auxv 找到 AT_ENTRY
    get_regs(pid, regs);
    // 多次 read_proc 读取目标进程内存
    read_proc(pid, arg, &argc, sizeof(argc));
    // 遍历 envp 找到 auxv 位置
    // 遍历 auxv 找到 AT_ENTRY

    // 2. 篡改入口地址触发 SIGSEGV
    write_proc(pid, addr_of_entry_addr, &break_addr, sizeof(break_addr));
    ptrace(PTRACE_CONT, pid, 0, 0);
    wait_for_trace(pid, &status, __WALL);  // 阻塞等待

    // 3. 恢复入口地址
    write_proc(pid, addr_of_entry_addr, &entry_addr, sizeof(entry_addr));

    // 4. 远程调用 dlopen(libzygisk.so)
    push_string(pid, regs, lib_path);       // process_vm_writev 写字符串
    remote_call(pid, regs, dlopen_addr, ...);  // ptrace 单步执行

    // 5. 远程调用 dlsym(handle, "entry")
    push_string(pid, regs, "entry");
    remote_call(pid, regs, dlsym_addr, ...);

    // 6. 调用注入器入口
    push_string(pid, regs, tmp_path);
    remote_call(pid, regs, injector_entry, ...);

    // 7. 恢复寄存器，让 zygote 继续运行
    set_regs(pid, backup);
}
```

### 2.3 时间开销估算

| 步骤 | 操作 | 预估耗时 |
|------|------|---------|
| 1 | 读取寄存器 + 解析 auxv（~10 次跨进程内存读取）| 5-15 ms |
| 2 | 写入口地址 + CONT + wait（上下文切换）| 5-20 ms |
| 3 | 恢复入口地址 | 1-3 ms |
| 4 | 远程 dlopen（参数写入 + 多次 ptrace 单步）| 20-80 ms |
| 5 | 远程 dlsym | 10-30 ms |
| 6 | 调用 entry 函数 | 10-40 ms |
| 7 | 恢复寄存器 | 1-3 ms |
| **总计** | | **~50-200 ms** |

> 注：实际耗时取决于 CPU 性能、系统负载和 ptrace 的上下文切换开销。

---

## 三、每次 App 孵化（fork）的持续性时间开销

### 3.1 Hook 安装位置

注入成功后，`libzygisk.so` 在 zygote 进程中永久安装了以下 PLT hooks（`hook.cpp:731-756`）：

```cpp
void hook_functions() {
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, fork);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, unshare);
    PLT_HOOK_REGISTER(android_runtime_dev, android_runtime_inode, strdup);
    PLT_HOOK_REGISTER_SYM(..., __android_log_close);
    hook_commit();
}
```

**关键点**：这些 hooks 在 zygote 进程中是永久存在的。子进程会卸载 `libzygisk.so`，但 zygote 本身保留 hooks。

### 3.2 Fork 调用链的时间开销

当系统请求孵化新 App 时，zygote 执行 `nativeForkAndSpecialize`，触发以下 hook 链：

```cpp
void ZygiskContext::nativeForkAndSpecialize_pre() {
    // 1. fork_pre()
    fork_pre();

    // 2. 子进程：app_specialize_pre()
    if (pid == 0) {
        app_specialize_pre();   // 加载模块、执行 preSpecialize
    }

    // 3. sanitize_fds()
    sanitize_fds();
}
```

#### 3.2.1 fork_pre() 开销

```cpp
void ZygiskContext::fork_pre() {
    sigmask(SIG_BLOCK, SIGCHLD);     // 1. 阻塞 SIGCHLD
    pid = old_fork();                 // 2. 实际 fork
    if (pid != 0 || flags[SKIP_FD_SANITIZATION])
        return;

    // 3. 子进程：遍历 /proc/self/fd 记录所有 fd
    auto dir = xopen_dir("/proc/self/fd");
    for (dirent *entry; (entry = readdir(dir.get()));) {
        int fd = parse_int(entry->d_name);
        if (fd < 0 || fd >= MAX_FD_SIZE) {
            close(fd);                // 关闭超出范围的 fd
            continue;
        }
        allowed_fds[fd] = true;       // 标记为允许
    }
    allowed_fds[dirfd(dir.get())] = false;  // dirfd 不允许
}
```

| 操作 | 开销来源 | 预估耗时 |
|------|---------|---------|
| `sigmask` | 系统调用 | ~1 us |
| `old_fork()` | 原生 fork | ~50-200 us |
| 遍历 `/proc/self/fd` | 目录读取 + 字符串解析（通常 50-200 个 fd）| ~50-500 us |
| 关闭超范围 fd | 系统调用 | ~1-10 us |
| **fork_pre 额外开销** | | **~50-500 us** |

#### 3.2.2 app_specialize_pre() 开销

```cpp
void ZygiskContext::app_specialize_pre() {
    flags[APP_SPECIALIZE] = true;
    info_flags = zygiskd::GetProcessFlags(g_ctx->args.app->uid);

    // 如果是管理器进程，设置环境变量
    if ((info_flags & (PROCESS_IS_MANAGER | PROCESS_ROOT_IS_MAGISK)) == ...) {
        setenv("ZYGISK_ENABLED", "1", 1);
    } else {
        run_modules_pre();   // 加载并执行模块
    }
}
```

#### 3.2.3 run_modules_pre() 开销

```cpp
void ZygiskContext::run_modules_pre() {
    auto ms = zygiskd::ReadModules();     // IPC 读取模块列表
    auto size = ms.size();
    for (size_t i = 0; i < size; i++) {
        auto& m = ms[i];
        // 从 memfd 加载模块 SO
        if (void* handle = DlopenMem(m.memfd, RTLD_NOW);
            void* entry = dlsym(handle, "zygisk_module_entry")) {
            modules.emplace_back(i, handle, entry);
        }
    }

    for (auto &m : modules) {
        m.onLoad(env);                    // 模块初始化（JNI 注册等）
        if (flags[APP_SPECIALIZE]) {
            m.preAppSpecialize(args.app); // 模块 pre 钩子
        }
    }
}
```

| 操作 | 开销来源 | 预估耗时 |
|------|---------|---------|
| `ReadModules()` | Unix socket IPC | ~100-500 us |
| `DlopenMem` (每个模块) | 从 memfd 加载 ELF + 重定位 + 符号解析 | ~1-10 ms |
| `dlsym` | 符号表遍历 | ~10-100 us |
| `onLoad()` | 模块自定义初始化 | ~0.1-10 ms |
| `preAppSpecialize()` | 模块自定义逻辑 | ~0.1-10 ms |
| **模块加载总开销** | | **~N x (1-20) ms**（N = 模块数量）|

#### 3.2.4 sanitize_fds() 开销

```cpp
void ZygiskContext::sanitize_fds() {
    if (flags[SKIP_FD_SANITIZATION])
        return;

    // 1. 处理 fds_to_ignore 参数
    if (jintArray fdsToIgnore = *args.app->fds_to_ignore) {
        // 读取并合并 fd 白名单
    }

    if (pid != 0)
        return;

    // 2. 子进程：关闭所有非白名单 fd
    auto dir = open_dir("/proc/self/fd");
    int dfd = dirfd(dir.get());
    for (dirent *entry; (entry = readdir(dir.get()));) {
        int fd = parse_int(entry->d_name);
        if ((fd < 0 || fd >= MAX_FD_SIZE || !allowed_fds[fd]) && fd != dfd) {
            close(fd);    // 逐个关闭
        }
    }
}
```

| 操作 | 开销来源 | 预估耗时 |
|------|---------|---------|
| 处理 `fds_to_ignore` | JNI 数组操作 | ~10-100 us |
| 遍历 `/proc/self/fd` | 目录读取（第二次）| ~50-300 us |
| `close()` 非白名单 fd | 系统调用（通常关闭 0-20 个）| ~10-200 us |
| **sanitize_fds 开销** | | **~70-600 us** |

### 3.3 单次 fork 总开销汇总

| 阶段 | 无 Zygisk | 有 Zygisk Next（无模块）| 有 Zygisk Next（3 个模块）|
|------|----------|----------------------|------------------------|
| 原生 fork | ~50-200 us | ~50-200 us | ~50-200 us |
| fork_pre() | 0 | ~50-500 us | ~50-500 us |
| app_specialize_pre() | 0 | ~0.1-1 ms | ~3-60 ms |
| sanitize_fds() | 0 | ~70-600 us | ~70-600 us |
| app_specialize_post() | 0 | ~0.1-0.5 ms | ~0.3-10 ms |
| **总计** | **~50-200 us** | **~0.3-2.3 ms** | **~3.5-71.3 ms** |

> 注：实际耗时高度依赖模块数量和模块自身的 pre/postSpecialize 实现。

---

## 四、时间侧信道检测方法

### 4.1 方法：测量 Activity 启动时间

```cpp
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

// 方法 1：通过 fork + exec 测量
long measure_fork_exec_time() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    pid_t pid = fork();
    if (pid == 0) {
        // 执行一个极轻量的程序
        execl("/system/bin/true", "true", nullptr);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);

    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - start.tv_sec) * 1000000 +
           (end.tv_nsec - start.tv_nsec) / 1000;  // 微秒
}

// 方法 2：通过 Binder 调用测量 am start 延迟
long measure_activity_start_time() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // 启动一个已预加载的 Activity
    // ... Intent 启动代码 ...

    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - start.tv_sec) * 1000000 +
           (end.tv_nsec - start.tv_nsec) / 1000;
}
```

### 4.2 方法：多次采样统计

```cpp
int detect_zygisk_by_fork_timing() {
    const int SAMPLES = 50;
    long times[SAMPLES];
    long sum = 0, sum_sq = 0;

    for (int i = 0; i < SAMPLES; i++) {
        times[i] = measure_fork_exec_time();
        sum += times[i];
        sum_sq += times[i] * times[i];
        usleep(10000);  // 10ms 间隔，避免缓存影响
    }

    double mean = (double)sum / SAMPLES;
    double variance = (double)sum_sq / SAMPLES - mean * mean;
    double stddev = sqrt(variance);

    // 基准值（无 Zygisk）：mean ~ 500-2000 us，stddev ~ 100-500 us
    // 有 Zygisk：mean ~ 2000-10000+ us，stddev 增大

    if (mean > 3000) {           // 均值显著偏高
        return 1;  // 可疑
    }
    if (stddev > mean * 0.5) {   // 方差异常大（模块加载不稳定）
        return 1;  // 可疑
    }
    return 0;
}
```

### 4.3 方法：fork 延迟分布分析

Zygisk Next 的 fork 延迟具有特定的时间分布特征：

- **无 Zygisk**：fork 时间近似正态分布，集中在 0.5-2 ms
- **有 Zygisk 无模块**：fork 时间右移，集中在 1-5 ms
- **有 Zygisk 有模块**：fork 时间呈现双峰或多峰分布
  - 第一峰：无模块匹配时的快速路径（~1-3 ms）
  - 第二峰：模块加载执行时的慢速路径（~10-50+ ms）

```cpp
// 通过直方图分析检测双峰分布
int detect_bimodal_distribution(long *times, int n) {
    // 将时间分为快/慢两组
    int fast_count = 0, slow_count = 0;
    long threshold = 5000;  // 5ms 阈值

    for (int i = 0; i < n; i++) {
        if (times[i] < threshold) fast_count++;
        else slow_count++;
    }

    // 如果慢路径占比 10%-90%，可能是模块选择性加载
    if (slow_count > n * 0.1 && slow_count < n * 0.9) {
        return 1;  // 可疑
    }
    return 0;
}
```

---

## 五、检测可靠性评估

| 检测方法 | 可靠性 | 误报率 | 绕过难度 | 说明 |
|---------|--------|--------|---------|------|
| fork+exec 时间测量 | 高 | 低 | 高 | 直接测量核心路径，难以隐藏 |
| Activity 启动时间 | 中 | 中 | 高 | 受系统服务影响，需多次采样 |
| 时间分布分析 | 高 | 低 | 极高 | 模块加载的模式特征难以伪造 |
| zygote 进程 CPU 时间 | 中 | 低 | 高 | 通过 `/proc/[zygote_pid]/stat` 读取 |

### 为什么难以绕过

1. **功能必需开销**：fd sanitization 是防止崩溃必需的；模块加载是核心功能
2. **zygote 特殊性**：zygote 进程不能卸载 hooks，否则新 App 无法被注入
3. **跨进程操作**：ptrace/process_vm_writev 的上下文切换开销是硬件级别的
4. **模块多样性**：不同模块的 pre/postSpecialize 执行时间差异形成了独特的指纹

---

## 六、总结

Zygisk Next 在 zygote 注入后，通过以下机制导致 App 孵化时间变长：

1. **初始化注入**：ptrace 远程注入增加 50-200 ms 的 zygote 启动延迟
2. **fork hook**：每次 fork 增加 fd 遍历记录开销（~50-500 us）
3. **fd sanitization**：每次 fork 增加两次 `/proc/self/fd` 遍历（~70-600 us）
4. **模块加载**：每个模块增加 1-20 ms 的加载和执行开销，与模块数量成正比

这些时间开销构成了一个**高可靠性、低误报率、难以绕过**的时间侧信道。用户态 App 可以通过测量 fork 延迟、Activity 启动时间或分析延迟分布来检测 Zygisk Next 的存在。
