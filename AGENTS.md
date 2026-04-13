# EnvCheck - AI Coding Agent Guide

## Project Overview

**EnvCheck** 是一款 Android 环境安全检测应用，包名为 `qpdb.env.check`。该应用用于检测 Android 设备的安全状态和环境配置，包括开发者模式、ADB 状态、网络环境、SIM 卡信息等。

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

原生库名称为 "check"，通过 `System.loadLibrary("check")` 加载。

## Project Structure

```
app/src/main/
├── AndroidManifest.xml          # 应用清单（包含权限声明）
├── cpp/                         # C++ 原生代码
│   ├── CMakeLists.txt
│   ├── native-lib.cpp
│   └── properties/
├── java/qpdb/env/check/
│   ├── EnvCheckApp.kt           # Application 类，提供全局 Context
│   ├── MainActivity.kt          # 主界面，使用 RecyclerView 显示可展开的分类
│   ├── adapter/                 # UI 适配器
│   │   └── CategoryAdapter.kt
│   ├── checkers/                # 检测器实现
│   │   ├── BatteryChecker.kt    # 电池信息检测
│   │   ├── BootloaderLockChecker.kt  # Bootloader 锁定状态检测
│   │   ├── DeveloperChecker.kt  # 开发者模式/ADB 检测
│   │   ├── InputDeviceChecker.kt  # 输入设备检测
│   │   ├── NetworkChecker.kt    # 网络环境检测
│   │   ├── SimCardChecker.kt    # SIM 卡信息
│   │   └── WebViewFingerPrintChecker.kt  # WebView 指纹检测
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
│       ├── FileUtil.kt          # JNI 文件检查
│       ├── HttpUtil.kt          # HTTP 请求
│       ├── KeyStoreUtil.kt      # 证书枚举
│       ├── NetworkUtil.kt       # 网络工具
│       ├── OpenWrtUtil.kt       # OpenWrt 网关检测
│       ├── PermissionUtil.kt    # 运行时权限处理
│       └── PropertyUtil.kt      # JNI 属性访问
├── res/                         # Android 资源文件
│   ├── layout/
│   │   ├── activity_main.xml    # 主界面布局
│   │   ├── item_category.xml    # 分类项布局
│   │   └── item_check.xml       # 检测项布局
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
    val categoryName: String           // 分类名称
    fun checkList(): List<CheckItem>   // 获取检测项列表
    fun runCheck(): List<CheckItem>    // 执行检测（默认调用 checkList()）
}
```

### 检测状态定义

- `PASS` - 检测通过（安全状态）
- `FAIL` - 检测失败（发现问题）
- `INFO` - 信息状态（等待检测或中性信息）

**重要**: `isPassed = true` 表示"安全/预期状态"，`false` 表示"检测到问题"。例如开发者模式已开启会返回 `FAIL`。

### 检测器注册

检测器在 `CheckerManager.registerDefaultCheckers()` 中注册：

```kotlin
CheckerRegistry.registerAll(
    BatteryChecker(),      // 电池信息检测
    DeveloperChecker(),    // 开发者模式和 ADB 检测
    SimCardChecker(),      // SIM 卡信息检测
    InputDeviceChecker(),  // 输入设备检测
    NetworkChecker(),      // 网络环境检测
)
```

当前已注释掉的检测器：`BootloaderLockChecker`、`WebViewFingerPrintChecker`。

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
5. 在 `CheckerManager.registerDefaultCheckers()` 中注册检测器

### 代码风格

- 使用 **官方 Kotlin 代码风格**（在 `gradle.properties` 中配置 `kotlin.code.style=official`）
- 使用 **ViewBinding** 访问视图（已在 `build.gradle.kts` 中启用）
- 异步操作使用 **Kotlin Coroutines** 和 `lifecycleScope`
- 日志使用 Android `Log` 类，TAG 格式为类名

### 权限管理

应用需要以下权限（在 `AndroidManifest.xml` 中声明）：

```xml
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

### 代码安全实践

- 使用 `usesCleartextTraffic="true"` 允许明文 HTTP（用于网关检测）
- 敏感操作（如执行 shell 命令）需要处理异常
- 网络操作必须在后台线程执行（使用 Coroutines）

## Common Tasks

### 修改检测逻辑

编辑对应检测器的 `runCheck()` 方法，返回包含适当 `CheckStatus` 的检测项列表。

### 修改 UI

- 主界面布局: `res/layout/activity_main.xml`
- 分类项布局: `res/layout/item_category.xml`
- 检测项布局: `res/layout/item_check.xml`
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
