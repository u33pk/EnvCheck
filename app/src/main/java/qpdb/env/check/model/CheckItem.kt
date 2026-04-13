package qpdb.env.check.model

/**
 * 检测项数据类
 * @param name 检测项名称
 * @param checkPoint 检测点
 * @param description 描述信息
 * @param status 检测状态（通过/不通过/信息）
 * @param isChecked 是否已勾选
 */
data class CheckItem(
    val id: String = java.util.UUID.randomUUID().toString(),
    val name: String,           // 检测项名称
    val checkPoint: String,     // 检测点
    var description: String,    // 描述信息
    var status: CheckStatus = CheckStatus.INFO,  // 检测状态
    var isChecked: Boolean = false
)
