# Vector (LSPosed) 框架可检测痕迹分析

> 基于源码分析，总结 Vector 框架在 Android 系统中留下的可被 App 检测到的痕迹。
> 分析版本：基于 Zygisk 的 Vector 框架（兼容 Android 8.1 - Android 17 Beta）

---

## 一、文件系统痕迹

### 1.1 核心数据目录

Vector 守护进程在 `/data/adb/lspd/` 目录下存储所有运行时数据，这是**最稳定、最直接的检测点**。

| 路径 | 说明 | 检测方式 |
|------|------|----------|
| `/data/adb/lspd/` | 守护进程基础路径 | `stat()` / `access(F_OK)` |
| `/data/adb/lspd/log/` | 日志目录 | 目录存在性检测 |
| `/data/adb/lspd/log.old/` | 旧日志备份目录 | 目录存在性检测 |
| `/data/adb/lspd/modules/` | 模块数据目录 | 目录存在性检测 |
| `/data/adb/lspd/config/` | 配置文件目录 | 目录存在性检测 |
| `/data/adb/lspd/config/modules_config.db` | SQLite 模块配置数据库 | 文件存在性检测 |
| `/data/adb/lspd/.cli_sock` | CLI Unix Domain Socket | 文件存在性检测 |
| `/data/adb/lspd/lock` | 守护进程锁文件 | 文件存在性检测 |

**代码位置**：`daemon/src/main/kotlin/org/matrix/vector/daemon/data/FileSystem.kt:42-55`

### 1.2 Magisk/KernelSU 模块目录

| 路径 | 说明 | 检测方式 |
|------|------|----------|
| `/data/adb/modules/zygisk_vector/` | Magisk 模块安装目录 | `access(F_OK)` |
| `/data/adb/modules/zygisk_vector/module.prop` | 模块配置文件，包含 `id=zygisk_vector` | 读取内容检测 |
| `/data/adb/modules/zygisk_vector/bin/dex2oat32` | dex2oat 包装器（32位） | 文件存在性检测 |
| `/data/adb/modules/zygisk_vector/bin/dex2oat64` | dex2oat 包装器（64位） | 文件存在性检测 |
| `/data/adb/modules/zygisk_vector/bin/liboat_hook32.so` | dex2oat hook 库（32位） | 文件存在性检测 |
| `/data/adb/modules/zygisk_vector/bin/liboat_hook64.so` | dex2oat hook 库（64位） | 文件存在性检测 |
| `/data/adb/modules/zygisk_vector/framework/lspd.dex` | 框架 DEX 文件 | 文件存在性检测 |

**代码位置**：
- `daemon/src/main/kotlin/org/matrix/vector/daemon/env/Dex2OatServer.kt:111-112`
- `zygisk/module/customize.sh:60-66`

### 1.3 SELinux 上下文标签

Vector 创建了自定义的 SELinux 类型，可通过检查文件安全上下文检测。

| 标签 | 用途 | 检测方式 |
|------|------|----------|
| `u:object_r:xposed_data:s0` | 模块数据目录标签 | `getxattr()` / `ls -Z` |
| `u:object_r:xposed_file:s0` | 框架文件标签 | `getxattr()` / `ls -Z` |

**代码位置**：
- `daemon/src/main/kotlin/org/matrix/vector/daemon/data/FileSystem.kt:328-330`
- `zygisk/module/sepolicy.rule`

### 1.4 系统属性修改

| 属性名 | 修改内容 | 检测方式 |
|--------|----------|----------|
| `dalvik.vm.dex2oat-flags` | 注入 `--inline-max-code-units=0` | `System.getProperty()` / `__system_property_get()` |

**代码位置**：`daemon/src/main/jni/dex2oat.cpp:71,78`

---

## 二、进程与运行时痕迹

### 2.1 进程名 / App Name

| 进程名 | 设置位置 | 检测方式 |
|--------|----------|----------|
| `org.matrix.vector.daemon` | 守护进程 DDM 名称 | `ActivityManager.getRunningAppProcesses()` |
| `lspd` | 守护进程 nice-name | `/proc/[pid]/cmdline` |
| `VectorCli` | CLI 工具 nice-name | `/proc/[pid]/cmdline` |
| `system_server`（ZTE 设备）| ZTE workaround 修改 argv[0] | `/proc/[pid]/cmdline` |

**代码位置**：
- `daemon/src/main/kotlin/org/matrix/vector/daemon/VectorDaemon.kt:90`
- `zygisk/src/main/cpp/module.cpp:376-391`

### 2.2 GID/UID 异常

**Manager App 被额外添加 GID_INET (3003)**：

当 `org.lsposed.manager` 运行时，其 gids 数组会比正常多出一个 `3003`。

```cpp
// zygisk/src/main/cpp/module.cpp:241-265
if (args->uid == kHostPackageUid) {
    // ...
    jint inet_gid = GID_INET;
    env_->SetIntArrayRegion(new_gids, original_gids_count, 1, &inet_gid);
    args->gids = new_gids;
}
```

**检测方式**：`Os.getgroups()` 或读取 `/proc/self/status` 中的 `Groups:`

### 2.3 环境变量（dex2oat 子进程）

| 变量 | 值 | 说明 |
|------|-----|------|
| `LD_PRELOAD` | `/proc/self/fd/[fd]` | 指向 memfd 中的 hook 库 |
| `DEX2OAT_CMD` | 原始 dex2oat 路径 | 传递原始命令 |

**代码位置**：`dex2oat/src/main/cpp/dex2oat.cpp:199-212`

---

## 三、Binder IPC 痕迹

### 3.1 异常 Binder 服务名

Vector 在 system_server 中注册了代理服务，这是**高可靠性的检测点**。

| 服务名 | 说明 | 检测方式 |
|--------|------|----------|
| `serial_vector` | 晚注入代理服务 | `ServiceManager.getService("serial_vector")` |

正常 Android 系统只有 `serial` 服务，不存在 `serial_vector`。

**代码位置**：
- `daemon/src/main/kotlin/org/matrix/vector/daemon/VectorDaemon.kt:60`
- `zygisk/src/main/cpp/module.cpp:395-397`

### 3.2 特殊 Binder Transaction Code

Vector 使用硬编码的 transaction code 进行内部通信。

| Code | 十六进制值 | 说明 |
|------|-----------|------|
| `_VEC` | `0x5F564543` | Bridge 事务码 |
| `_DEX` | `0x5F444558` | DEX 传输事务码 |
| `_OBF` | `0x5F4F4246` | 混淆映射事务码 |

**代码位置**：
- `zygisk/src/main/cpp/ipc_bridge.cpp:89-91`
- `daemon/src/main/kotlin/org/matrix/vector/daemon/ipc/ApplicationService.kt:20-25`

### 3.3 JNI 函数表覆盖

Vector 通过 `SetTableOverride` 替换 `CallBooleanMethodV` 来拦截 Binder IPC。

**检测思路**：检查 JNI 函数表中 `CallBooleanMethodV` 指针是否指向 `libart.so` 内的原始地址，或是否指向 `libzygisk.so` / `libvector.so` 的内存区域。

**代码位置**：`zygisk/src/main/cpp/ipc_bridge.cpp:511-570`

---

## 四、内存与 /proc 痕迹

### 4.1 /proc/self/maps 可检测特征

通过读取 `/proc/self/maps` 可以检测以下内存中的代码痕迹：

| 特征字符串 | 来源 | 说明 |
|-----------|------|------|
| `liboat_hook.so` | dex2oat wrapper | 通过 LD_PRELOAD 加载 |
| `liboat_hook_memfd` | memfd 匿名文件 | hook 库的内存副本 |
| `Vector_` | 生成类名前缀 | ART 动态生成的类 |
| `Dobby` | 生成类 source name | inline hook 引擎标识 |
| `xposed/dummy/XResourcesSuperClass` | 资源 hook 虚拟类 | 运行时生成的 DEX |
| `xposed/dummy/XTypedArraySuperClass` | 资源 hook 虚拟类 | 运行时生成的 DEX |
| `InMemoryDexClassLoader` | 内存 DEX 加载器 | 无文件路径的 DEX 段 |
| `org.matrix.vector` | 框架包名 | 内存中的类路径 |
| `de.robv.android.xposed` | Xposed 包名 | Legacy API 类路径 |

**代码位置**：
- `native/src/elf/elf_image.cpp:301-380`
- `native/src/jni/resources_hook.cpp:182-189`
- `zygisk/src/main/cpp/module.cpp:129-130`

### 4.2 ClassLoader 链异常

被注入的进程中，ClassLoader 链会出现以下异常：

| ClassLoader 类型 | 说明 |
|-----------------|------|
| `dalvik.system.InMemoryDexClassLoader` | 框架 DEX 加载器 |
| `org.matrix.vector.impl.utils.VectorModuleClassLoader` | 模块隔离加载器 |
| `dalvik.system.ByteBufferDexClassLoader` | 模块 DEX 加载器 |
| `xposed.dummy.XResourcesSuperClass` | 资源 hook 虚拟类加载器 |

**检测方式**：
```java
ClassLoader cl = getClassLoader();
while (cl != null) {
    String name = cl.getClass().getName();
    // 检查是否包含异常 ClassLoader
    cl = cl.getParent();
}
```

**代码位置**：
- `xposed/src/main/kotlin/org/matrix/vector/impl/utils/VectorModuleClassLoader.kt`
- `legacy/src/main/java/de/robv/android/xposed/XposedBridge.java:100-105`

### 4.3 堆栈跟踪中的特征类名

App 触发异常后，堆栈中可能出现以下特征类名：

```
org.matrix.vector.impl.hooks.VectorChain
org.matrix.vector.impl.hooks.VectorNativeHooker
org.matrix.vector.impl.VectorLifecycleManager
org.matrix.vector.impl.utils.VectorModuleClassLoader
org.matrix.vector.impl.core.VectorStartup
org.matrix.vector.impl.core.VectorModuleManager
org.matrix.vector.service.BridgeService
de.robv.android.xposed.XposedBridge
de.robv.android.xposed.XposedHelpers
de.robv.android.xposed.XResources
de.robv.android.xposed.XposedInit
```

**检测方式**：主动触发一个异常并检查堆栈，或检查 `Thread.getAllStackTraces()`。

---

## 五、Logcat 痕迹

### 5.1 日志标签

Vector 在 logcat 中输出大量日志，可通过标签过滤检测。

**Native 层标签**：
| 标签 | 来源 |
|------|------|
| `VectorNative` | Native 通用库 |
| `VectorNativeDaemon` | Daemon native 层 |
| `VectorDex2Oat` | dex2oat 包装器 |

**Java/Kotlin 层标签**：
| 标签 | 来源 |
|------|------|
| `VectorDaemon` | Daemon 主入口 |
| `VectorService` | 主服务实现 |
| `VectorZygiskBridge` | Zygisk Bridge 服务 |
| `VectorLogcat` | 日志监控 |
| `VectorLifecycle` | 生命周期管理 |
| `VectorModuleClassLoader` | 模块类加载器 |
| `VectorLegacyBridge` | Legacy Xposed 桥接 |
| `VectorContext` | 上下文管理 |
| `XSharedPreferences` | 跨进程 SharedPreferences |
| `LSPosedManager` | 管理器应用 |

**代码位置**：`daemon/src/main/jni/logcat.cpp:37-45`

### 5.2 日志内容特征字符串

| 特征日志内容 | 说明 |
|-------------|------|
| `Version x.x.x (xxx)` | Daemon 启动时输出版本 |
| `Successfully injected Vector IPC binder for applications.` | system_server 注入成功 |
| `system_server restarted...` | system_server 重启检测 |
| `Applying ZTE-specific workaround: setting argv[0] to system_server.` | ZTE 设备 workaround |
| `!!start_verbose!!` / `!!stop_verbose!!` / `!!refresh_modules!!` | 日志控制指令 |

### 5.3 Logcat 监控机制

Daemon 会监控 logcat 输出，并将特定标签的日志路由到模块日志文件。这本身也会在 logcat 中留下活动痕迹。

**被监控的标签**：
- `VectorContext`, `VectorLegacyBridge`, `VectorModuleManager`, `XSharedPreferences`
- `APatchD`, `Dobby`, `KernelSU`, `LSPlant`, `LSPlt`, `Magisk`, `SELinux`, `TEESimulator`
- `LSPosed`, `Vector`, `dex2oat`, `zygisk`

---

## 六、ART 运行时痕迹

### 6.1 方法 Hook 痕迹

Vector 使用 LSPlant 引擎进行 ART 方法替换，被 hook 的方法具有以下特征：

- `ArtMethod` 的 `entry_point_from_quick_compiled_code_` 被替换为 trampoline
- 原始方法被备份为 `backup` 对象
- 可通过 ART 内部结构检测方法是否被替换

**代码位置**：`native/src/jni/hook_bridge.cpp:14-72, 138-148`

### 6.2 DEX 信任提升痕迹

Vector 调用 `MakeDexFileTrusted` 提升框架 DEX 的信任级别，绕过 Hidden API 限制。

**检测思路**：检查进程中是否存在信任级别异常的 DEX 文件。

**代码位置**：
- `native/src/core/context.cpp:89-96`
- `native/src/jni/hook_bridge.cpp:499`

### 6.3 AOT 反优化痕迹

`VectorDeopter` 强制方法回退到解释器执行，确保 hook 生效。

**检测思路**：检查方法的执行模式（解释器 vs AOT 编译代码）。

**代码位置**：`xposed/src/main/kotlin/org/matrix/vector/impl/core/VectorDeopter.kt`

### 6.4 do_dlopen Hook

Vector hook 了 `do_dlopen` 来拦截动态库加载，触发 native 模块初始化。

```cpp
inline static auto do_dlopen_hook =
    "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv"_sym.hook->*
    [](const char *name, int flags, const void *extinfo, const void *caller_addr) {
        // 拦截 so 加载，查找 native_init 符号
    };
```

**代码位置**：`native/src/core/native_api.cpp:157-195`

---

## 七、其他可检测痕迹

### 7.1 共享内存 / memfd

| 名称 | 说明 | 检测方式 |
|------|------|----------|
| `liboat_hook_memfd` | dex2oat hook 库的 memfd | `/proc/self/fd/` 遍历 |

**代码位置**：`dex2oat/src/main/cpp/dex2oat.cpp:152`

### 7.2 Unix Socket

| Socket 名 | 类型 | 说明 |
|----------|------|------|
| `5291374ceda0aef7c5d86cd2a4f6a3ac` | 抽象命名空间 | dex2oat wrapper 通信 socket |

**代码位置**：
- `dex2oat/src/main/cpp/dex2oat.cpp:28`
- `daemon/src/main/jni/dex2oat.cpp:116`

### 7.3 包名存在性

| 包名 | 说明 | 检测方式 |
|------|------|----------|
| `org.lsposed.manager` | 管理器应用 | `getPackageManager().getPackageInfo()` |
| `com.android.shell` | 寄生管理器宿主 | 检查该包是否出现异常 Activity/Service |

### 7.4 通知渠道

Daemon 创建了特定的通知渠道：
- `STATUS_CHANNEL_ID`
- `SCOPE_CHANNEL_ID`
- `UPDATED_CHANNEL_ID`

**检测方式**：`NotificationManager.getNotificationChannels()`

**代码位置**：`daemon/src/main/kotlin/org/matrix/vector/daemon/system/NotificationManager.kt`

---

## 八、被排除 Package 的检测能力分析

### 8.1 注入决策流程

```
preAppSpecialize
├── Manager App 特殊处理（添加 GID_INET）
├── 检查 app_data_dir（无则跳过）
├── 检查 is_child_zygote（是则跳过）
├── 检查 isolated UID（是则跳过）
└── 标记 should_inject = true

postAppSpecialize
├── if !should_inject: 允许卸载模块
└── if should_inject: 请求 Binder -> 加载 DEX -> 初始化 Hook
```

**代码位置**：`zygisk/src/main/cpp/module.cpp:233-354`

### 8.2 被排除 Package 能检测到的痕迹

| 检测方法 | 能否检测 | 原因 |
|----------|---------|------|
| `/data/adb/lspd/` 存在性 | ✅ 能 | 完全无关，全局存在 |
| `/data/adb/modules/zygisk_vector/` 存在性 | ✅ 能 | 完全无关，全局存在 |
| `serial_vector` 服务查询 | ✅ 能 | system_server 始终注入 |
| Binder.execTransact 拦截检测 | ✅ 能 | system_server 始终注入 |
| `dalvik.vm.dex2oat-flags` 检查 | ✅ 能 | 全局属性修改 |
| Logcat 中 Vector 标签 | ✅ 能 | Daemon 全局日志 |
| 其他被注入 App 的异常 | ✅ 能 | 旁证 |
| 自身进程 ClassLoader 检查 | ❌ 不能 | 未被注入 |
| 自身堆栈中的 Vector 类名 | ❌ 不能 | 未被注入 |
| 自身 `/proc/self/maps` 检查 | ❌ 不能 | 未被注入 |
| 自身 heartbeat binder | ❌ 不能 | 未注册到 daemon |

---

## 九、检测优先级建议

### 高可靠性（推荐优先使用）

1. **文件系统路径检测**
   - `/data/adb/lspd/` 目录存在性
   - `/data/adb/modules/zygisk_vector/` 目录存在性
   - 优点：直接、稳定、难以隐藏
   - 缺点：需要 `READ_EXTERNAL_STORAGE` 或利用路径遍历

2. **system_server Binder 服务检测**
   - `ServiceManager.getService("serial_vector")`
   - 优点：system_server 始终被注入，不受单个 package 排除影响
   - 缺点：需要反射调用隐藏 API

3. **系统属性检测**
   - `dalvik.vm.dex2oat-flags` 包含 `--inline-max-code-units=0`
   - 优点：全局修改，所有 App 可见
   - 缺点：需要 `android.permission.READ_DEVICE_CONFIG` 或反射

### 中等可靠性

4. **Logcat 标签检测**
   - 搜索 `Vector`、`LSPosed`、`zygisk` 等标签
   - 优点：运行时活跃证据
   - 缺点：需要 `READ_LOGS` 权限，且日志可能被清理

5. **Manager App GID 检测**
   - 检查 `org.lsposed.manager` 的 groups 是否包含 3003
   - 优点：特异性强
   - 缺点：需要 Manager App 正在运行

6. **ClassLoader 链检测**
   - 遍历 `ClassLoader.getParent()` 检查异常
   - 优点：直接证据
   - 缺点：仅对被注入的进程有效

### 低可靠性（辅助验证）

7. **堆栈跟踪检测**
   - 触发异常检查堆栈中的特征类名
   - 优点：直接证据
   - 缺点：需要特定触发条件

8. **/proc/self/maps 检测**
   - 搜索内存中的特征字符串
   - 优点：详细
   - 缺点：需要解析 maps 文件，可能被伪造

---

## 十、代码位置速查表

| 痕迹类别 | 关键文件 |
|----------|----------|
| Zygisk 模块入口 | `zygisk/src/main/cpp/module.cpp` |
| IPC Bridge / Binder 拦截 | `zygisk/src/main/cpp/ipc_bridge.cpp` |
| Native Hook 引擎 | `native/src/jni/hook_bridge.cpp` |
| ART 初始化 / DEX 信任 | `native/src/core/context.cpp` |
| Native API (do_dlopen hook) | `native/src/core/native_api.cpp` |
| 资源 Hook | `native/src/jni/resources_hook.cpp` |
| Daemon 主入口 | `daemon/src/main/kotlin/org/matrix/vector/daemon/VectorDaemon.kt` |
| Application Service | `daemon/src/main/kotlin/org/matrix/vector/daemon/ipc/ApplicationService.kt` |
| SystemServer Service | `daemon/src/main/kotlin/org/matrix/vector/daemon/ipc/SystemServerService.kt` |
| 文件系统操作 | `daemon/src/main/kotlin/org/matrix/vector/daemon/data/FileSystem.kt` |
| dex2oat 包装器 | `dex2oat/src/main/cpp/dex2oat.cpp` |
| dex2oat Hook | `dex2oat/src/main/cpp/oat_hook.cpp` |
| 模块生命周期 | `xposed/src/main/kotlin/org/matrix/vector/impl/VectorLifecycleManager.kt` |
| 模块类加载器 | `xposed/src/main/kotlin/org/matrix/vector/impl/utils/VectorModuleClassLoader.kt` |
| Legacy Xposed Bridge | `legacy/src/main/java/de/robv/android/xposed/XposedBridge.java` |
| 日志监控 | `daemon/src/main/jni/logcat.cpp` |

---

*本文档基于 Vector 框架开源代码分析生成，仅供安全研究和防御性检测参考。*
