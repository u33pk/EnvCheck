package qpdb.env.check.model

/**
 * 检测状态枚举
 */
enum class CheckStatus {
    PASS,   // 通过 - 绿色
    FAIL,   // 不通过 - 红色
    INFO    // 信息 - 黄色（仅显示，不参与通过/失败判断）
}
