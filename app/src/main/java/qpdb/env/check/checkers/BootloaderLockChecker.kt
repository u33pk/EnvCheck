package qpdb.env.check.checkers

import android.util.Log
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.model.Checkable
import qpdb.env.check.utils.PropertyUtil.getProp
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Bootloader 锁状态检测
 * 检测设备的 Bootloader 是否已解锁
 */
class BootloaderLockChecker : Checkable {

    companion object {
        private const val TAG = "BootloaderChecker"
    }

    override val categoryName: String = "Bootloader 状态"

    override fun checkList(): List<CheckItem> {
        Log.d(TAG, "checkList() 被调用")
        return listOf(
            CheckItem(
                name = "BL 锁状态",
                checkPoint = "bl_lock_status",
                description = "检查 Bootloader 是否已解锁"
            ),
            CheckItem(
                name = "系统完整性",
                checkPoint = "system_integrity",
                description = "检查系统完整性验证状态"
            ),
            CheckItem(
                name = "Verity 状态",
                checkPoint = "verity_status",
                description = "检查 Android Verified Boot 状态"
            ),
            CheckItem(
                name = "SELinux 状态",
                checkPoint = "selinux_status",
                description = "检查 SELinux 运行模式"
            )
        )
    }

    /**
     * 执行实际检测
     * 通过读取系统属性来判断 BL 状态
     */
    override fun runCheck(): List<CheckItem> {
        Log.d(TAG, "runCheck() 被调用")

        val items = checkList().toMutableList()

        try {
            // 检测 BL 锁状态
            val blLocked = isBootloaderLocked()
            Log.d(TAG, "BL 锁状态：$blLocked")
            items.find { it.checkPoint == "bl_lock_status" }?.let {
                it.status = if (blLocked) CheckStatus.PASS else CheckStatus.FAIL
            }

            // 检测系统完整性
            val systemIntact = isSystemIntact()
            Log.d(TAG, "系统完整性：$systemIntact")
            items.find { it.checkPoint == "system_integrity" }?.let {
                it.status = if (systemIntact) CheckStatus.PASS else CheckStatus.FAIL
            }

            // 检测 Verity 状态
            val verityEnabled = isVerityEnabled()
            Log.d(TAG, "Verity 状态：$verityEnabled")
            items.find { it.checkPoint == "verity_status" }?.let {
                it.status = if (verityEnabled) CheckStatus.PASS else CheckStatus.FAIL
            }

            // 检测 SELinux 状态
            val selinuxEnforcing = isSelinuxEnforcing()
            Log.d(TAG, "SELinux 状态：$selinuxEnforcing")
            items.find { it.checkPoint == "selinux_status" }?.let {
                it.status = if (selinuxEnforcing) CheckStatus.PASS else CheckStatus.FAIL
            }
        } catch (e: Exception) {
            Log.e(TAG, "检测过程出错：${e.message}", e)
        }

        return items
    }

    /**
     * 检查 Bootloader 是否已锁定
     * @return true 表示已锁定（安全），false 表示已解锁
     */
    private fun isBootloaderLocked(): Boolean {
        return try {
            // 方法 1: 通过系统属性检查
            val flashLocked = getSystemProperty("ro.boot.flash.locked")
            Log.d(TAG, "ro.boot.flash.locked = $flashLocked")
            val flashLockedBool = flashLocked == "1"

            // 方法 2: 通过 vendor 属性检查（某些设备）
            if (!flashLockedBool) {
                val vendorLocked = getSystemProperty("ro.boot.vbmeta.device_state")
                Log.d(TAG, "ro.boot.vbmeta.device_state = $vendorLocked")
                return vendorLocked == "locked"
            }

            flashLockedBool
        } catch (e: Exception) {
            Log.e(TAG, "isBootloaderLocked 出错：${e.message}")
            // 如果无法检测，默认认为已锁定（保守策略）
            true
        }
    }

    /**
     * 检查系统是否完整（未被修改）
     */
    private fun isSystemIntact(): Boolean {
        return try {
            val state = getSystemProperty("ro.boot.verifiedbootstate")
            Log.d(TAG, "ro.boot.verifiedbootstate = $state")
            // verifiedbootstate 可能的值：green, orange, yellow, red
            state == "green"
        } catch (e: Exception) {
            Log.e(TAG, "isSystemIntact 出错：${e.message}")
            true
        }
    }

    /**
     * 检查 Verity 是否启用
     */
    private fun isVerityEnabled(): Boolean {
        return try {
            val verity = getSystemProperty("partition.system.verified")
            Log.d(TAG, "partition.system.verified = $verity")
            verity.isNotEmpty() && verity != "false"
        } catch (e: Exception) {
            Log.e(TAG, "isVerityEnabled 出错：${e.message}")
            true
        }
    }

    /**
     * 检查 SELinux 是否为 Enforcing 模式
     */
    private fun isSelinuxEnforcing(): Boolean {
        return try {
            // 方法 1: 通过系统属性
            val propState = getSystemProperty("ro.boot.selinux")
            Log.d(TAG, "ro.boot.selinux = $propState")
            if (propState.isNotEmpty()) {
                return propState.equals("enforcing", ignoreCase = true)
            }

            // 方法 2: 通过 getenforce 命令
            val process = Runtime.getRuntime().exec("getenforce")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val state = reader.readLine()?.trim()
            reader.close()
            Log.d(TAG, "getenforce = $state")

            state.equals("Enforcing", ignoreCase = true)
        } catch (e: Exception) {
            Log.e(TAG, "isSelinuxEnforcing 出错：${e.message}")
            true
        }
    }

    /**
     * 获取系统属性值
     * 优先使用 native 方法，失败时使用 shell 命令
     * @param property 属性名称
     * @return 属性值，如果获取失败返回空字符串
     */
    private fun getSystemProperty(property: String): String {
        // 优先使用 native 方法
        val nativeResult = getProp(property)
        if (nativeResult != null) {
            return nativeResult
        }
        
        // native 方法失败时使用 shell 命令
        return try {
            val process = Runtime.getRuntime().exec("getprop $property")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()?.trim() ?: ""
            reader.close()
            value
        } catch (e: Exception) {
            Log.e(TAG, "getSystemProperty($property) 出错：${e.message}")
            ""
        }
    }
}
