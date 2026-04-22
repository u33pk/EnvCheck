package qpdb.env.check.checkers

import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import android.os.Process
import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.PropertyUtil
import qpdb.env.check.utils.XPLikeUtil

/**
 * XPLike (Vector / LSPosed) 检测器
 *
 * 基于 doc/xplike-detection.md 实现的多维度联合检测方案。
 * Vector 框架依赖 Zygisk 注入，在 Java 层留下大量可被观测的痕迹。
 *
 * 检测策略（按可靠性排序）：
 * 1. Binder 服务检测 — system_server 始终被注入，不受单个 package 排除影响
 * 2. 系统属性检测 — 全局修改，所有 App 可见
 * 3. ClassLoader 链检测 — 当前进程是否被注入的直接证据
 * 4. 堆栈指纹检测 — 运行时活跃证据
 * 5. /proc/self/maps 特征检测 — 内存中的代码痕迹
 * 6. Manager 包名检测 — 管理器应用存在性
 *
 * 注意：不直接检测 /data/adb 目录（无权限），优先使用运行时痕迹。
 */
class XPLikeChecker : Checkable {

    companion object {
        private const val TAG = "XPLikeChecker"

        // XPLike 特征类名前缀（堆栈检测用）
        private val STACK_TRACE_KEYWORDS = listOf(
            "org.matrix.vector",
            "de.robv.android.xposed",
            "org.lsposed"
        )

        // XPLike 特征 ClassLoader 名称
        private val CLASSLOADER_KEYWORDS = listOf(
            "InMemoryDexClassLoader",
            "ByteBufferDexClassLoader",
            "VectorModuleClassLoader",
            "xposed.dummy"
        )

        // Manager 包名
        private val MANAGER_PACKAGES = listOf(
            "org.lsposed.manager",
            "com.android.shell" // 寄生管理器宿主
        )
    }

    override val categoryName: String = "XPLike 检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(name = "Binder 服务检测", checkPoint = "xp_binder_service", description = "等待检测..."),
        CheckItem(name = "系统属性检测", checkPoint = "xp_system_prop", description = "等待检测..."),
        CheckItem(name = "ClassLoader 链检测", checkPoint = "xp_classloader", description = "等待检测..."),
        CheckItem(name = "堆栈指纹检测", checkPoint = "xp_stacktrace", description = "等待检测..."),
        CheckItem(name = "内存映射特征检测", checkPoint = "xp_maps", description = "等待检测..."),
        CheckItem(name = "Manager 包名检测", checkPoint = "xp_manager_pkg", description = "等待检测..."),
        CheckItem(name = "综合评估", checkPoint = "xp_summary", description = "等待检测...")
    )

    override fun runCheck(): List<CheckItem> {
        Log.i(TAG, "runCheck() 开始执行 XPLike 检测")
        val items = checkList().toMutableList()

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
            Log.i(TAG, "[$checkPoint] ${result.status}: ${result.description}")
        }

        try {
            applyResult("xp_binder_service", checkBinderService())
            applyResult("xp_system_prop", checkSystemProp())
            applyResult("xp_classloader", checkClassLoader())
            applyResult("xp_stacktrace", checkStackTrace())
            applyResult("xp_maps", checkMaps())
            applyResult("xp_manager_pkg", checkManagerPackage())
            applyResult("xp_summary", checkSummary(items))
        } catch (e: Exception) {
            Log.e(TAG, "检测过程异常", e)
        }

        return items
    }

    // ==================== Binder 服务检测 ====================

    /**
     * 检测 system_server 中是否注册了 Vector 的代理 Binder 服务 "serial_vector"。
     *
     * 文档指出：system_server 始终被注入，不受单个 package 排除影响。
     * 正常 Android 系统只有 "serial" 服务，不存在 "serial_vector"。
     */
    private fun checkBinderService(): CheckResult {
        return try {
            // 反射调用 ServiceManager.getService("serial_vector")
            val serviceManagerClass = Class.forName("android.os.ServiceManager")
            val getServiceMethod = serviceManagerClass.getDeclaredMethod("getService", String::class.java)
            val binder = getServiceMethod.invoke(null, "serial_vector") as? IBinder

            if (binder != null && binder.isBinderAlive) {
                CheckResult(CheckStatus.FAIL, "发现异常 Binder 服务 'serial_vector'，Vector 框架已注入 system_server")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到 'serial_vector' Binder 服务")
            }
        } catch (e: Exception) {
            Log.d(TAG, "Binder 服务检测异常: ${e.message}")
            CheckResult(CheckStatus.INFO, "Binder 服务检测失败: ${e.message}")
        }
    }

    // ==================== 系统属性检测 ====================

    /**
     * 检测 dalvik.vm.dex2oat-flags 是否被修改为包含 --inline-max-code-units=0。
     * Vector 通过修改此属性来禁用 dex2oat 的内联优化，确保 hook 生效。
     */
    private fun checkSystemProp(): CheckResult {
        return try {
            val dex2oatFlags = PropertyUtil.getProp("dalvik.vm.dex2oat-flags") ?: ""
            Log.d(TAG, "dex2oat-flags=$dex2oatFlags")

            if (dex2oatFlags.contains("--inline-max-code-units=0")) {
                CheckResult(CheckStatus.FAIL, "dalvik.vm.dex2oat-flags 被修改（包含 --inline-max-code-units=0），Vector dex2oat hook 迹象")
            } else if (dex2oatFlags.isNotEmpty()) {
                CheckResult(CheckStatus.INFO, "dalvik.vm.dex2oat-flags=$dex2oatFlags（未被 Vector 修改）")
            } else {
                CheckResult(CheckStatus.PASS, "dalvik.vm.dex2oat-flags 为空或未被修改")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "系统属性检测异常: ${e.message}")
        }
    }

    // ==================== ClassLoader 链检测 ====================

    /**
     * 遍历当前进程的 ClassLoader 链，检查是否存在 Vector 注入的异常 ClassLoader。
     *
     * 文档指出：被注入的进程中会出现 InMemoryDexClassLoader、VectorModuleClassLoader 等。
     */
    private fun checkClassLoader(): CheckResult {
        return try {
            val findings = mutableListOf<String>()
            var cl: ClassLoader? = this.javaClass.classLoader

            while (cl != null) {
                val className = cl.javaClass.name
                for (keyword in CLASSLOADER_KEYWORDS) {
                    if (className.contains(keyword)) {
                        findings.add(className)
                        break
                    }
                }
                cl = cl.parent
            }

            if (findings.isNotEmpty()) {
                CheckResult(CheckStatus.FAIL, "发现异常 ClassLoader: ${findings.distinct().joinToString(", ")}")
            } else {
                CheckResult(CheckStatus.PASS, "ClassLoader 链正常")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "ClassLoader 检测异常: ${e.message}")
        }
    }

    // ==================== 堆栈指纹检测 ====================

    /**
     * 检查所有线程的堆栈中是否出现 Vector / Xposed 特征类名。
     *
     * 文档列出了大量特征类名，如 org.matrix.vector.impl.hooks.VectorChain、
     * de.robv.android.xposed.XposedBridge 等。
     */
    private fun checkStackTrace(): CheckResult {
        return try {
            val findings = mutableListOf<String>()
            val stackTraces = Thread.getAllStackTraces()

            for ((thread, stackTrace) in stackTraces) {
                for (element in stackTrace) {
                    val className = element.className
                    for (keyword in STACK_TRACE_KEYWORDS) {
                        if (className.contains(keyword)) {
                            findings.add("[${thread.name}] $className.${element.methodName}")
                            break
                        }
                    }
                }
            }

            // 额外检查：主动触发异常并检查当前线程堆栈
            try {
                throw Exception("xplike_stack_probe")
            } catch (e: Exception) {
                for (element in e.stackTrace) {
                    for (keyword in STACK_TRACE_KEYWORDS) {
                        if (element.className.contains(keyword)) {
                            findings.add("[probe] ${element.className}.${element.methodName}")
                            break
                        }
                    }
                }
            }

            val distinctFindings = findings.distinct()
            if (distinctFindings.isNotEmpty()) {
                val summary = distinctFindings.take(3).joinToString("; ") +
                        if (distinctFindings.size > 3) " 等共 ${distinctFindings.size} 处" else ""
                CheckResult(CheckStatus.FAIL, "堆栈中发现 Vector/Xposed 特征类: $summary")
            } else {
                CheckResult(CheckStatus.PASS, "未在堆栈中发现 Vector/Xposed 特征类")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "堆栈检测异常: ${e.message}")
        }
    }

    // ==================== 内存映射特征检测 ====================

    /**
     * 读取 /proc/self/maps，查找 Vector 相关的内存映射特征字符串。
     *
     * 文档列出的特征：liboat_hook.so、Vector_、Dobby、InMemoryDexClassLoader、
     * org.matrix.vector、de.robv.android.xposed 等。
     */
    private fun checkMaps(): CheckResult {
        return try {
            val result = XPLikeUtil.nativeCheckMaps()
            if (result.isNotEmpty()) {
                CheckResult(CheckStatus.FAIL, "发现可疑内存映射特征: $result")
            } else {
                CheckResult(CheckStatus.PASS, "未在 /proc/self/maps 中发现 Vector 特征")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "maps 检测异常: ${e.message}")
        }
    }

    // ==================== Manager 包名检测 ====================

    /**
     * 检测设备上是否安装了 Vector/LSPosed 管理器应用。
     */
    private fun checkManagerPackage(): CheckResult {
        return try {
            val context = qpdb.env.check.EnvCheckApp.getContext()
            val pm = context.packageManager
            val findings = mutableListOf<String>()

            for (pkg in MANAGER_PACKAGES) {
                try {
                    pm.getPackageInfo(pkg, 0)
                    findings.add(pkg)
                } catch (_: PackageManager.NameNotFoundException) {
                    // 未安装
                }
            }

            if (findings.isNotEmpty()) {
                CheckResult(CheckStatus.FAIL, "发现 Manager 应用: ${findings.joinToString(", ")}")
            } else {
                CheckResult(CheckStatus.PASS, "未检测到 Vector/LSPosed Manager 应用")
            }
        } catch (e: Exception) {
            CheckResult(CheckStatus.INFO, "Manager 包名检测异常: ${e.message}")
        }
    }

    // ==================== 综合评估 ====================

    /**
     * 根据所有检测项的结果进行综合评估。
     *
     * 核心可靠判据：
     * - Binder 服务检测（system_server 始终注入，最可靠）
     * - 系统属性检测（全局修改）
     * - ClassLoader 链检测 / 堆栈指纹（当前进程被注入的直接证据）
     *
     * 辅助判据：
     * - 内存映射特征
     * - Manager 包名
     */
    private fun checkSummary(items: List<CheckItem>): CheckResult {
        val failPoints = items.filter {
            it.checkPoint != "xp_summary" && it.status == CheckStatus.FAIL
        }.map { it.name }

        return when {
            failPoints.size >= 2 -> CheckResult(
                CheckStatus.FAIL,
                "高度疑似 XPLike/Vector：${failPoints.joinToString(", ")}"
            )
            failPoints.isNotEmpty() -> CheckResult(
                CheckStatus.FAIL,
                "发现 XPLike/Vector 可疑特征：${failPoints.first()}"
            )
            else -> CheckResult(CheckStatus.PASS, "未检测到 XPLike/Vector 特征")
        }
    }
}
