package qpdb.env.check.model

/**
 * 检测结果数据类
 * 用于同时返回检测状态和描述信息
 * @param status 检测状态
 * @param description 检测描述信息
 */
data class CheckResult(
    val status: CheckStatus,
    val description: String
) {
    /**
     * 便捷构造函数，兼容旧的布尔值调用
     */
    constructor(isPassed: Boolean, description: String) : this(
        status = if (isPassed) CheckStatus.PASS else CheckStatus.FAIL,
        description = description
    )

    /**
     * 向后兼容的属性，用于判断检测是否通过
     */
    val isPassed: Boolean
        get() = status == CheckStatus.PASS
}
