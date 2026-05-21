# EnvCheck - AI Coding Agent Guide

## Project Overview

**EnvCheck** 是一款 Android 环境安全检测应用，包名为 `qpdb.env.check`。该应用用于检测 Android 设备的安全状态和环境配置，包括开发者模式、ADB 状态、网络环境、SIM 卡信息、Root 框架（KernelSU/APatch/ZygiskNext）、WXShadow 关联模块等。

- **项目类型**: Android 应用（单模块项目）
- **开发语言**: Kotlin（Java 11 目标），C++（JNI 原生代码）
- **构建系统**: Gradle Kotlin DSL
- **架构模式**: 基于管理器的插件式架构

## Technology Stack

| 组件 | 版本 |
|------|------|
| Kotlin | 2.0.21 |
| Android Gradle Plugin | 8.13.2 |
| Compile SDK | 36 |
| Min SDK | 29 (Android 10) |
| Target SDK | 36 |
| CMake | 3.22.1 |
| JVM Target | 11 |

### 关键依赖

- AndroidX Core KTX
- AndroidX AppCompat
- Material Design Components
- ConstraintLayout
- Kotlin Coroutines (1.7.3)
- Lifecycle Runtime KTX (2.7.0)

### 原生代码

应用包含 C++ 原生代码，位于 `app/src/main/cpp/`：
- `native-lib.cpp` - JNI 桥接代码
- `properties/system_properties.cpp` - 直接读取 Android 系统属性
- `properties/property_info.cpp` - 属性名称处理
- `jni/wxshadow_detection.cpp` - WXShadow / Anti-Detect / Hide-Maps 综合检测
- `jni/apatch_detection.cpp` - APatch 检测
- `jni/ksu_detection.cpp` - KernelSU 检测
- `jni/zygisk_next_detection.cpp` - ZygiskNext 检测
- `jni/xplike_detection.cpp` - XPLike 检测
- `jni/susfs_detection.cpp` - SUSFS 检测
- `jni/soc_detection.cpp` - SoC 信息检测
- `jni/file_util.cpp` - JNI 文件工具
- `jni/property_util.cpp` - JNI 属性访问
- `gpu/vulkan_info.cpp` - GPU Vulkan 信息
- `utils/time_util.h` - 时间工具

原生库名称为 "check"，通过 `System.loadLibrary("check")` 加载。

## Project Structure

```
app/src/main/
├── AndroidManifest.xml          # 应用清单（包含权限声明）
├── cpp/                         # C++ 原生代码
│   ├── CMakeLists.txt
│   ├── native-lib.cpp
│   ├── gpu/
│   ├── jni/
│   ├── properties/
│   └── utils/
├── java/qpdb/env/check/
│   ├── EnvCheckApp.kt           # Application 类，提供全局 Context
│   ├── MainActivity.kt          # 主界面，使用 RecyclerView 显示可展开的分类
│   ├── adapter/                 # UI 适配器
│   │   └── CategoryAdapter.kt
│   ├── checkers/                # 检测器实现
│   │   ├── APatchChecker.kt     # APatch 检测
│   │   ├── BatteryChecker.kt    # 电池信息检测
│   │   ├── BootloaderLockChecker.kt  # Bootloader 锁定状态检测
│   │   ├── CameraChecker.kt     # 摄像头检测
│   │   ├── DeveloperChecker.kt  # 开发者模式/ADB 检测
│   │   ├── GpuChecker.kt        # GPU 信息检测
│   │   ├── InputDeviceChecker.kt  # 输入设备检测
│   │   ├── KernelInfoChecker.kt # 内核信息检测
│   │   ├── KernelSUChecker.kt   # KernelSU 检测
│   │   ├── NetworkChecker.kt    # 网络环境检测
│   │   ├── OEMChecker.kt        # OEM 服务检测
│   │   ├── PackageChecker.kt    # 包名列表检测
│   │   ├── SensorChecker.kt     # 传感器信息检测
│   │   ├── SimCardChecker.kt    # SIM 卡信息
│   │   ├── SoCChecker.kt        # SoC 信息检测
│   │   ├── SusfsChecker.kt      # SUSFS 检测
│   │   ├── WebViewFingerPrintChecker.kt  # WebView 指纹检测
│   │   ├── WxShadowChecker.kt   # WXShadow / Anti-Detect / Hide-Maps 检测
│   │   ├── XPLikeChecker.kt     # XPLike 检测
│   │   └── ZygiskNextChecker.kt # ZygiskNext 检测
│   ├── manager/                 # 管理器层
│   │   ├── CheckerManager.kt    # 检测器注册与执行（单例）
│   │   ├── DataManager.kt       # 数据更新与统计
│   │   └── UIManager.kt         # UI 消息显示（Snackbar）
│   ├── model/                   # 数据模型
│   │   ├── Category.kt          # 检测分类
│   │   ├── Checkable.kt         # 检测器接口
│   │   ├── CheckerRegistry.kt   # 检测器注册表
│   │   ├── CheckItem.kt         # 检测项数据类
│   │   ├── CheckResult.kt       # 检测结果
│   │   └── CheckStatus.kt       # 检测状态枚举（PASS/FAIL/INFO）
│   └── utils/                   # 工具类
│       ├── ApatchDetectionUtil.kt
│       ├── EmulatorDetector.kt
│       ├── FileUtil.kt          # JNI 文件检查
│       ├── GpuInfoUtil.kt
│       ├── GpuNativeUtil.kt
│       ├── HttpUtil.kt          # HTTP 请求
│       ├── KeyStoreUtil.kt      # 证书枚举
│       ├── KsuDetectionUtil.kt
│       ├── NetworkUtil.kt       # 网络工具
│       ├── OpenWrtUtil.kt       # OpenWrt 网关检测
│       ├── PackageUtil.kt
│       ├── PermissionUtil.kt    # 运行时权限处理
│       ├── PropertyUtil.kt      # JNI 属性访问
│       ├── SoCDetectionUtil.kt
│       ├── SusfsDetectionUtil.kt
│       ├── SystemPropertyUtil.kt
│       ├── WxShadowDetectionUtil.kt
│       ├── XPLikeUtil.kt
│       └── ZygiskNextUtil.kt
├── res/                         # Android 资源文件
│   ├── drawable/
│   │   └── dialog_background.xml
│   └── layout/
│       ├── activity_main.xml    # 主界面布局
│       ├── dialog_check_detail.xml  # 检测详情对话框
│       ├── item_category.xml    # 分类项布局
│       └── item_check.xml       # 检测项布局
└── test/                        # 单元测试
```

## Build Commands

```bash
# 构建项目
./gradlew build

# 构建 Debug APK
./gradlew assembleDebug

# 构建 Release APK
./gradlew assembleRelease

# 运行单元测试
./gradlew test

# 运行仪器测试（需要连接设备/模拟器）
./gradlew connectedAndroidTest

# 清理构建产物
./gradlew clean

# 安装 Debug APK 到已连接设备
./gradlew installDebug
```

## Architecture Details

### 检测器架构

所有检测器必须实现 `Checkable` 接口：

```kotlin
interface Checkable {
    val categoryName: String                    // 分类名称
    fun checkList(): List<CheckItem>            // 获取检测项列表
    fun runCheck(): List<CheckItem>             // 执行检测（默认调用 checkList()）
    suspend fun runCheckWithProgress(
        onProgress: suspend (CheckItem) -> Unit
    ): List<CheckItem>                          // 实时进度回调（默认一次性返回）
}
```

**实时进度**：`runCheckWithProgress` 允许每个检测项完成后立即回调，UI 实时更新对应 item 的状态，无需等待所有检测结束。

### 检测状态定义

- `PASS` - 检测通过（安全状态）
- `FAIL` - 检测失败（发现问题）
- `INFO` - 信息状态（等待检测或中性信息）

状态显示在 UI 上：绿色（PASS）、红色（FAIL）、黄色（INFO）。点击 item 色块可弹出详情对话框，对话框头部颜色与状态一致。

### 检测器注册

检测器在 `CheckerManager.registerDefaultCheckers()` 中注册。当前启用的检测器：

```kotlin
CheckerRegistry.registerAll(
    APatchChecker(),       // APatch 检测
    SoCChecker(),          // SoC 信息检测
    CameraChecker(),       // 摄像头检测
    SensorChecker(),       // 传感器信息检测
    OEMChecker(),          // OEM 服务检测
    PackageChecker(),      // 包名列表检测
    WxShadowChecker(),     // WXShadow / Anti-Detect / Hide-Maps 检测
)
```

当前已注释掉的检测器：`BootloaderLockChecker`、`BatteryChecker`、`DeveloperChecker`、`SimCardChecker`、`WebViewFingerPrintChecker`、`InputDeviceChecker`、`NetworkChecker`、`GpuChecker`、`KernelSUChecker`、`ZygiskNextChecker`、`XPLikeChecker`、`SusfsChecker`、`KernelInfoChecker`。

### 模块结构

- 单模块项目（`:app`），在 `settings.gradle.kts` 中配置
- 根目录 `build.gradle.kts` 应用 Android 应用和 Kotlin 插件
- App 级 `build.gradle.kts` 包含所有依赖和构建配置
- 依赖版本通过 `gradle/libs.versions.toml` 管理

## Development Guidelines

### 添加新检测器

1. 在 `checkers/` 目录下创建实现 `Checkable` 接口的类
2. 重写 `categoryName` 属性定义分类名称
3. 实现 `checkList()` 返回检测项列表
4. 重写 `runCheck()` 执行实际检测逻辑
5. 如需实时进度，重写 `runCheckWithProgress()`
6. 在 `CheckerManager.registerDefaultCheckers()` 中注册检测器

### 代码风格

- 使用 **官方 Kotlin 代码风格**（在 `gradle.properties` 中配置 `kotlin.code.style=official`）
- 使用 **ViewBinding** 访问视图（已在 `build.gradle.kts` 中启用）
- 异步操作使用 **Kotlin Coroutines** 和 `lifecycleScope`
- 日志使用 Android `Log` 类，TAG 格式为类名

### 权限管理

应用需要以下权限（在 `AndroidManifest.xml` 中声明）：

```xml
<uses-feature android:glEsVersion="0x00020000" android:required="true" />
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.READ_PHONE_STATE" />
<uses-permission android:name="android.permission.READ_PRIVILEGED_PHONE_STATE" />
```

运行时权限（如 `READ_PHONE_STATE`）需要在代码中动态申请。

### JNI 使用规范

- 属性读取优先使用 `PropertyUtil.getProp()`（JNI 方式）
- JNI 失败时回退到 shell 命令方式
- 文件存在性检查使用 `FileUtil.fileExists()`（使用 stat 系统调用）
- 新增 JNI 方法需在 `WxShadowDetectionUtil` 或对应 Util 类中声明 `external` 方法，并在 C++ 中实现对应签名的 JNI 函数

## Testing Strategy

### 单元测试

- 框架: JUnit 4
- 位置: `app/src/test/`
- 当前状态: 仅包含示例测试，需要扩展

### 仪器测试

- 框架: AndroidJUnit4 + Espresso
- 位置: `app/src/androidTest/`
- 运行要求: 需要连接 Android 设备或模拟器

### 测试建议

1. 为每个检测器添加单元测试，模拟系统属性返回值
2. 使用 Mockito 模拟 Android 系统服务
3. 对 JNI 层进行集成测试

## Security Considerations

### 应用安全特性

1. **开发者模式检测** - 检测 USB 调试、WiFi ADB 等开发者功能是否开启
2. **网络环境检测** - 检测 VPN、代理、透明代理、出口 IP 一致性
3. **证书检测** - 枚举系统证书库，检测抓包工具植入的根证书
4. **网关安全检测** - 检测 OpenWrt 网关是否可未授权访问
5. **Root 框架检测** - KernelSU、APatch、ZygiskNext、SUSFS 等
6. **WXShadow 关联检测** - 通过 Shadow Page 自读 page fault、BRK 时延指纹、prctl 探测检测 WXShadow；通过 syscall 不一致性和 kallsyms 扫描检测 Anti-Detect；通过 dl_iterate_phdr vs /proc/self/maps 对比检测 Hide-Maps

### 代码安全实践

- 使用 `usesCleartextTraffic="true"` 允许明文 HTTP（用于网关检测）
- 敏感操作（如执行 shell 命令）需要处理异常
- 网络操作必须在后台线程执行（使用 Coroutines）

## Common Tasks

### 修改检测逻辑

编辑对应检测器的 `runCheck()` 或 `runCheckWithProgress()` 方法，返回包含适当 `CheckStatus` 的检测项列表。

### 修改 UI

- 主界面布局: `res/layout/activity_main.xml`
- 分类项布局: `res/layout/item_category.xml`
- 检测项布局: `res/layout/item_check.xml`
- 详情对话框布局: `res/layout/dialog_check_detail.xml`
- 适配器: `adapter/CategoryAdapter.kt`

### 更新依赖版本

编辑 `gradle/libs.versions.toml` 文件中的版本号。

## Troubleshooting

### 构建问题

1. **CMake 版本不匹配** - 确保本地安装 CMake 3.22.1
2. **NDK 未配置** - 确保 Android SDK 包含 NDK
3. **权限拒绝** - 某些检测需要 root 权限才能获取完整信息

### 运行时问题

1. **NetworkOnMainThreadException** - 确保网络操作在协程中执行
2. **权限被拒绝** - 检查是否已动态申请运行时权限
3. **JNI 加载失败** - 确保原生库已正确编译并打包

## References

- [Android Developer Documentation](https://developer.android.com/)
- [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
