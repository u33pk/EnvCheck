package qpdb.env.check.utils

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.util.Log
import qpdb.env.check.EnvCheckApp
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * 包名列表获取工具类
 *
 * 通过多个独立 API 途径交叉验证获取已安装包名列表，
 * 提供交集（多源一致）和并集（全量覆盖）两种视图。
 *
 * 检测思路：若不同 API 返回的包名集合不一致，说明可能存在包名隐藏/过滤行为。
 */
object PackageUtil {

    private const val TAG = "PackageUtil"
    private const val CACHE_TTL_MS = 5000L

    private var cachedSources: List<Set<String>>? = null
    private var cacheTimestamp: Long = 0L

    // ==================== 风险包名定义 ====================

    /**
     * 已知的风险/Root 工具包名列表
     */
    val RISK_PACKAGES = setOf(
        // Magisk
        "com.topjohnwu.magisk",
        "io.github.vvb2060.magisk",
        // KernelSU
        "me.weishu.kernelsu",
        // APatch
        "me.bmax.apatch",
        "me.bmax.apatch.next",
        // Superuser
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        // Xposed / LSPosed / EdXposed
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "com.solohsu.android.edxp.manager",
        "com.android.lsposed",
        "org.lsposed.manager",
        "com.reveny.nativecheck",
        // 其他常见 Root / 越狱工具
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",
        "com.saurik.substrate",
        "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree",
        "com.kstub",
    )

    // ==================== 公开接口 ====================

    /**
     * 获取多源包名交集
     * 仅保留所有途径都能成功获取到的包名（高可信度）
     */
    fun getIntersectionPackages(): Set<String> {
        val sources = collectPackageSources()
        if (sources.isEmpty()) return emptySet()

        var intersection = sources.first().toMutableSet()
        for (i in 1 until sources.size) {
            intersection.retainAll(sources[i])
        }
        return intersection
    }

    /**
     * 获取多源包名并集
     * 汇总所有途径获取到的包名（最大覆盖）
     */
    fun getUnionPackages(): Set<String> {
        val union = mutableSetOf<String>()
        collectPackageSources().forEach { union.addAll(it) }
        return union
    }

    /**
     * 获取给定包名集合中命中的风险包名
     */
    fun getMatchedRiskPackages(packages: Set<String>): Set<String> {
        return packages.intersect(RISK_PACKAGES)
    }

    // ==================== 多源采集 ====================

    /**
     * 通过多种独立途径采集包名列表
     * 带有 5 秒短期缓存，避免同一检测周期内重复采集
     */
    private fun collectPackageSources(): List<Set<String>> {
        val now = System.currentTimeMillis()
        val cached = cachedSources
        if (cached != null && (now - cacheTimestamp) < CACHE_TTL_MS) {
            Log.d(TAG, "使用缓存（${cached.size} 个来源，距今 ${now - cacheTimestamp}ms）")
            return cached
        }

        val sources = mutableListOf<Set<String>>()

        try {
            getPackagesViaApplications()?.let { sources.add(it) }
        } catch (e: Exception) {
            Log.e(TAG, "getInstalledApplications 失败", e)
        }

        try {
            getPackagesViaPackages()?.let { sources.add(it) }
        } catch (e: Exception) {
            Log.e(TAG, "getInstalledPackages 失败", e)
        }

        try {
            getPackagesViaPmList()?.let { sources.add(it) }
        } catch (e: Exception) {
            Log.e(TAG, "pm list packages 失败", e)
        }

        try {
            getPackagesViaDataApp()?.let { sources.add(it) }
        } catch (e: Exception) {
            Log.e(TAG, "/data/app 读取失败", e)
        }

        try {
            getPackagesViaPackagesForUid()?.let { sources.add(it) }
        } catch (e: Exception) {
            Log.e(TAG, "getPackagesForUid 失败", e)
        }

        try {
            getPackagesViaPackageInfo()?.let { sources.add(it) }
        } catch (e: Exception) {
            Log.e(TAG, "getPackageInfo 验证失败", e)
        }

        cachedSources = sources
        cacheTimestamp = now
        Log.d(TAG, "成功采集 ${sources.size} 个来源")
        return sources
    }

    // ==================== 途径 1：PackageManager.getInstalledApplications ====================

    /**
     * 通过 getInstalledApplications 获取包名（仅非系统应用）
     */
    private fun getPackagesViaApplications(): Set<String>? {
        return try {
            val pm = EnvCheckApp.getContext().packageManager
            val apps = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }
            apps.mapNotNull { it.packageName }.toSet().also {
                Log.d(TAG, "getInstalledApplications 获取 ${it.size} 个包")
            }
        } catch (e: Exception) {
            Log.e(TAG, "getInstalledApplications 异常", e)
            null
        }
    }

    // ==================== 途径 2：PackageManager.getInstalledPackages ====================

    /**
     * 通过 getInstalledPackages 获取包名
     */
    private fun getPackagesViaPackages(): Set<String>? {
        return try {
            val pm = EnvCheckApp.getContext().packageManager
            val pkgs = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
            pkgs.mapNotNull { it.packageName }.toSet().also {
                Log.d(TAG, "getInstalledPackages 获取 ${it.size} 个包")
            }
        } catch (e: Exception) {
            Log.e(TAG, "getInstalledPackages 异常", e)
            null
        }
    }

    // ==================== 途径 3：pm list packages Shell 命令 ====================

    /**
     * 通过 `pm list packages` 获取包名
     */
    private fun getPackagesViaPmList(): Set<String>? {
        return try {
            val result = execShell("pm list packages")
            if (result.isNullOrEmpty()) return null

            val packages = result.lines().mapNotNull { line ->
                line.trim().takeIf { it.startsWith("package:") }?.removePrefix("package:")?.trim()
            }.toSet()

            Log.d(TAG, "pm list packages 获取 ${packages.size} 个包")
            packages
        } catch (e: Exception) {
            Log.e(TAG, "pm list packages 异常", e)
            null
        }
    }

    // ==================== 途径 4：/data/app 目录读取 ====================

    /**
     * 通过读取 /data/app/ 下的目录名推断包名
     * 格式通常为：包名-xxx 或 包名==xxx
     */
    private fun getPackagesViaDataApp(): Set<String>? {
        return try {
            val dir = File("/data/app")
            if (!dir.exists() || !dir.canRead()) return null

            val packages = dir.listFiles()?.mapNotNull { file ->
                if (file.isDirectory) {
                    val name = file.name
                    // 常见格式: com.example-1, com.example==base.apk, com.example-abcdef==
                    name.substringBefore("-").substringBefore("==").takeIf { it.contains(".") }
                } else null
            }?.toSet() ?: emptySet()

            Log.d(TAG, "/data/app 读取 ${packages.size} 个包")
            packages
        } catch (e: Exception) {
            Log.e(TAG, "/data/app 读取异常", e)
            null
        }
    }

    // ==================== 途径 5：PackageManager.getPackagesForUid ====================

    /**
     * 通过 getPackagesForUid 遍历常见 uid 范围获取包名
     */
    private fun getPackagesViaPackagesForUid(): Set<String>? {
        return try {
            val pm = EnvCheckApp.getContext().packageManager
            val packages = mutableSetOf<String>()
            // 普通应用 uid 通常从 10000 开始，遍历前 300 个 uid 覆盖大部分应用
            for (uid in 0..10300) {
                val pkgs = pm.getPackagesForUid(uid)
                if (pkgs != null) {
                    packages.addAll(pkgs)
                }
            }
            Log.d(TAG, "getPackagesForUid 获取 ${packages.size} 个包")
            packages.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            Log.e(TAG, "getPackagesForUid 异常", e)
            null
        }
    }

    // ==================== 途径 6：PackageManager.getPackageInfo 验证 ====================

    /**
     * 通过 shell pm list 获取候选包名，再用 getPackageInfo 逐个验证
     * 如果 getPackageInfo 不抛 NameNotFoundException，则该包真实存在
     */
    private fun getPackagesViaPackageInfo(): Set<String>? {
        return try {
            val pm = EnvCheckApp.getContext().packageManager
            val candidates = execShell("pm list packages")?.lines()?.mapNotNull { line ->
                line.trim().takeIf { it.startsWith("package:") }?.removePrefix("package:")?.trim()
            } ?: return null

            val packages = mutableSetOf<String>()
            for (pkg in candidates) {
                try {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(pkg, 0)
                    packages.add(pkg)
                } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                    // 包不存在，跳过
                } catch (e: Exception) {
                    Log.w(TAG, "getPackageInfo($pkg) 异常: ${e.message}")
                }
            }

            Log.d(TAG, "getPackageInfo 验证通过 ${packages.size}/${candidates.size} 个包")
            packages.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            Log.e(TAG, "getPackageInfo 验证异常", e)
            null
        }
    }

    // ==================== 工具方法 ====================

    private fun execShell(command: String): String? {
        return try {
            val process = Runtime.getRuntime().exec(command)
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val error = process.errorStream.bufferedReader().use { it.readText() }
            process.waitFor()
            if (error.isNotBlank()) {
                Log.w(TAG, "Shell 命令 '$command' 错误输出: $error")
            }
            output.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            Log.e(TAG, "Shell 命令 '$command' 执行失败", e)
            null
        }
    }
}
