package qpdb.env.check.checkers

import qpdb.env.check.model.Checkable
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus
import qpdb.env.check.utils.SoCDetectionUtil
import java.util.UUID

class SoCChecker : Checkable {
    override val categoryName: String = "SoC 信息检测"

    override fun checkList(): List<CheckItem> = listOf(
        CheckItem(
            name = "MIDR_EL1 (汇编读取)",
            checkPoint = "midr_asm",
            description = "等待检测..."
        ),
        CheckItem(
            name = "MIDR_EL1 (Sysfs 读取)",
            checkPoint = "midr_sysfs",
            description = "等待检测..."
        ),
        CheckItem(
            name = "MIDR_EL1 一致性校验",
            checkPoint = "midr_consistency",
            description = "等待检测..."
        )
    )

    override fun runCheck(): List<CheckItem> {
        val items = checkList().toMutableList()

        fun applyResult(checkPoint: String, result: CheckResult) {
            items.find { it.checkPoint == checkPoint }?.let {
                it.status = result.status
                it.description = result.description
            }
        }

        applyResult("midr_asm", checkMidrByAsm())
        applyResult("midr_sysfs", checkMidrBySysfs())
        applyResult("midr_consistency", checkMidrConsistency())

        return items
    }

    /**
     * 通过汇编读取所有核心的 MIDR_EL1
     */
    private fun checkMidrByAsm(): CheckResult {
        val coreCount = SoCDetectionUtil.nativeGetCpuCoreCount()
        if (coreCount <= 0) {
            return CheckResult(
                status = CheckStatus.INFO,
                description = "无法获取 CPU 核心数量"
            )
        }

        val sb = StringBuilder("共 ${coreCount} 个核心\n")

        for (i in 0 until coreCount) {
            val value = SoCDetectionUtil.nativeReadMidrByAsm(i)

            if (value == -1L) {
                sb.append("CPU$i: 读取失败\n")
            } else {
                val hex = String.format("0x%016X", value)
                val (implementer, _, _, partNum) = decodeMidr(value)
                sb.append("CPU$i: $hex ($implementer $partNum)\n")
            }
        }

        return CheckResult(
            status = CheckStatus.INFO,
            description = sb.toString().trim()
        )
    }

    /**
     * 通过 sysfs 读取所有核心的 MIDR_EL1
     */
    private fun checkMidrBySysfs(): CheckResult {
        val coreCount = SoCDetectionUtil.nativeGetCpuCoreCount()
        if (coreCount <= 0) {
            return CheckResult(
                status = CheckStatus.INFO,
                description = "无法获取 CPU 核心数量"
            )
        }

        val midrValues = mutableListOf<Long>()
        val sb = StringBuilder()

        for (i in 0 until coreCount) {
            val value = SoCDetectionUtil.nativeReadMidrBySysfs(i)
            midrValues.add(value)

            if (value == -1L) {
                sb.append("CPU$i: 读取失败\n")
            } else {
                val hex = String.format("0x%016X", value)
                sb.append("CPU$i: $hex\n")
            }
        }

        return CheckResult(
            status = CheckStatus.INFO,
            description = "共 ${coreCount} 个核心\n${sb.toString().trim()}"
        )
    }

    /**
     * 校验每个核心的汇编读取值与 sysfs 读取值的一致性
     */
    private fun checkMidrConsistency(): CheckResult {
        val coreCount = SoCDetectionUtil.nativeGetCpuCoreCount()
        if (coreCount <= 0) {
            return CheckResult(
                status = CheckStatus.INFO,
                description = "无法获取 CPU 核心数量"
            )
        }

        val sb = StringBuilder()
        var hasMismatch = false

        for (i in 0 until coreCount) {
            val asmValue = SoCDetectionUtil.nativeReadMidrByAsm(i)
            val sysfsValue = SoCDetectionUtil.nativeReadMidrBySysfs(i)

            if (asmValue == -1L || sysfsValue == -1L) {
                sb.append("CPU$i: 读取失败\n")
                continue
            }

            if (asmValue == sysfsValue) {
                sb.append("CPU$i: 一致\n")
            } else {
                hasMismatch = true
                sb.append("CPU$i: 不一致!\n")
                sb.append("  汇编: ${String.format("0x%016X", asmValue)}\n")
                sb.append("  Sysfs: ${String.format("0x%016X", sysfsValue)}\n")
            }
        }

        return CheckResult(
            status = if (hasMismatch) CheckStatus.FAIL else CheckStatus.PASS,
            description = if (hasMismatch) {
                "检测到不一致，可能存在 Hook 干扰\n${sb.toString().trim()}"
            } else {
                "所有核心汇编与 Sysfs 读取一致\n${sb.toString().trim()}"
            }
        )
    }

    /**
     * 解码 MIDR_EL1 各字段
     * MIDR_EL1 格式:
     * [31:24] Implementer (实现者)
     * [23:20] Variant (变体)
     * [19:16] Architecture (架构)
     * [15:4]  Primary Part Number (部件号)
     * [3:0]   Revision (修订版本)
     */
    private fun decodeMidr(midr: Long): MidrFields {
        val implementer = ((midr shr 24) and 0xFF).toInt()
        val variant = ((midr shr 20) and 0xF).toInt()
        val arch = ((midr shr 16) and 0xF).toInt()
        val partNum = ((midr shr 4) and 0xFFF).toInt()

        val implementerName = when (implementer.toChar()) {
            'A' -> "ARM"
            'Q' -> "Qualcomm"
            'S' -> "Samsung"
            'M' -> "MediaTek"
            'H' -> "HiSilicon"
            'N' -> "NVIDIA"
            'I' -> "Intel"
            'a' -> "Apple"
            else -> "Unknown(0x${implementer.toString(16)})"
        }

        val partName = getPartName(implementer, partNum)

        return MidrFields(
            implementer = "$implementerName",
            variant = "0x${variant.toString(16)}",
            arch = "0x${arch.toString(16)}",
            partNum = "$partName (0x${partNum.toString(16)})"
        )
    }

    private fun getPartName(implementer: Int, partNum: Int): String {
        return when (implementer.toChar()) {
            'A' -> when (partNum) {
                0xD05 -> "Cortex-A55"
                0xD07 -> "Cortex-A57"
                0xD08 -> "Cortex-A72"
                0xD09 -> "Cortex-A73"
                0xD0A -> "Cortex-A75"
                0xD0B -> "Cortex-A76"
                0xD0D -> "Cortex-A77"
                0xD41 -> "Cortex-A78"
                0xD44 -> "Cortex-X1"
                0xD46 -> "Cortex-A510"
                0xD47 -> "Cortex-A710"
                0xD48 -> "Cortex-X2"
                0xD4D -> "Cortex-A715"
                0xD4E -> "Cortex-X3"
                0xD80 -> "Cortex-A520"
                0xD81 -> "Cortex-A720"
                0xD82 -> "Cortex-X4"
                0xD87 -> "Cortex-X925"
                0xD88 -> "Cortex-A725"
                else -> "Unknown(0x${partNum.toString(16)})"
            }
            'a' -> when (partNum) {
                0x022 -> "M1 Icestorm"
                0x023 -> "M1 Firestorm"
                0x024 -> "M1 Blizzard"
                0x025 -> "M1 Avalanche"
                0x028 -> "M2 Blizzard"
                0x029 -> "M2 Avalanche"
                0x032 -> "M3"
                0x033 -> "M3 Pro"
                0x034 -> "M3 Max"
                0x035 -> "M4"
                0x036 -> "M4 Pro"
                0x037 -> "M4 Max"
                else -> "Apple(0x${partNum.toString(16)})"
            }
            'Q' -> when (partNum) {
                0x001 -> "Scorpion"
                0x02D -> "Krait"
                0x200 -> "Kryo"
                0x201 -> "Kryo 280"
                0x205 -> "Kryo 385"
                0x211 -> "Kryo 485"
                0x800 -> "Cortex-A76 (Qualcomm)"
                0x801 -> "Cortex-A55 (Qualcomm)"
                0x802 -> "Cortex-A77 (Qualcomm)"
                0x803 -> "Cortex-A78 (Qualcomm)"
                0x804 -> "Cortex-X1 (Qualcomm)"
                0x805 -> "Cortex-A510 (Qualcomm)"
                else -> "Qualcomm(0x${partNum.toString(16)})"
            }
            'S' -> when (partNum) {
                0x001 -> "Exynos M1"
                0x002 -> "Exynos M2"
                0x003 -> "Exynos M3"
                0x004 -> "Exynos M4"
                0x005 -> "Exynos M5"
                else -> "Samsung(0x${partNum.toString(16)})"
            }
            else -> "Unknown(0x${partNum.toString(16)})"
        }
    }

    private data class MidrFields(
        val implementer: String,
        val variant: String,
        val arch: String,
        val partNum: String
    )
}
