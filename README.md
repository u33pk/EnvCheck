# EnvCheck

Android 设备环境安全检测应用，用于识别设备上的 Root 框架、内核模块及环境风险。

## 功能

- **Root 框架检测** — KernelSU、APatch、ZygiskNext、XPLike、SUSFS
- **WXShadow 关联检测** — Shadow Page、Anti-Detect、Hide-Maps 侧信道检测
- **系统环境检测** — 开发者模式、ADB、网络代理、Bootloader 状态
- **硬件信息检测** — SoC、GPU、摄像头、传感器
- **OEM / 包名扫描** — 自定义 OEM 服务探测与包名列表检查

## 技术栈

- Kotlin + Android Gradle Plugin
- C++ JNI（原生层高精度侧信道检测）
- 基于管理器的插件式架构

## 构建

```bash
./gradlew assembleDebug
```

Min SDK: 29 (Android 10)  
Target SDK: 36

## 架构

检测器实现 `Checkable` 接口，通过 `CheckerManager` 注册并执行。支持逐条实时进度回调，每个检测项完成后立即刷新 UI。

## 权限

- `INTERNET` / `ACCESS_NETWORK_STATE`
- `READ_PHONE_STATE`

## License

MIT
