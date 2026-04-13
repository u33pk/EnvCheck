package qpdb.env.check

import android.app.Application
import android.content.Context
import android.os.Build
import android.os.SystemClock

/**
 * 应用类
 * 提供全局 Context 访问
 */
class EnvCheckApp : Application() {

    companion object {
        private lateinit var instance: EnvCheckApp

        /**
         * 获取全局 Context
         */
        fun getContext(): Context {
            return instance.applicationContext
        }

        /**
         * 获取应用实例
         */
        fun getInstance(): EnvCheckApp {
            return instance
        }
    }

    /**
     * 从进程创建到 Application.onCreate 的耗时（毫秒）。
     * 用于检测 KernelSU kernel_umount 导致的启动延迟侧信道。
     */
    var processStartupAgeMs: Long = -1
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        processStartupAgeMs = measureProcessStartupAgeMs()
    }

    /**
     * 计算进程启动到当前时刻的耗时。
     * 优先使用 Android 11+ 官方 API Process.getStartUptimeMillis()，
     * 避免解析 /proc/self/stat 在不同内核上的兼容性问题。
     */
    private fun measureProcessStartupAgeMs(): Long {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val startUptime = android.os.Process.getStartUptimeMillis()
                SystemClock.uptimeMillis() - startUptime
            } else {
                //  fallback：Android 10 及以下使用 elapsedRealtime 估算（精度较低）
                val now = SystemClock.elapsedRealtime()
                val startTimeAttr = java.io.File("/proc/self/stat")
                    .readText()
                    .substringAfter(")")
                    .trim()
                    .split(Regex("\\s+"))
                    .getOrNull(19)
                    ?.toLongOrNull() ?: return -1
                val clockTicks = android.system.Os.sysconf(android.system.OsConstants._SC_CLK_TCK)
                val sinceBootMs = startTimeAttr * 1000L / clockTicks
                now - sinceBootMs
            }
        } catch (e: Exception) {
            -1L
        }
    }
}
