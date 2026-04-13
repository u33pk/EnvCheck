package qpdb.env.check.data

/**
 * 注册数据单例类
 * 存储用户注册过程中填写的信息
 */
object RegistrationData {
    var nickname: String = ""
    var birthday: String = ""
    var contactType: String = ""
    var contactValue: String = ""
    var password: String = ""
    var verificationCode: String = ""
    var agreementWaitTimeMs: Long = 0

    /**
     * 清空所有数据
     */
    fun clear() {
        nickname = ""
        birthday = ""
        contactType = ""
        contactValue = ""
        password = ""
        verificationCode = ""
        agreementWaitTimeMs = 0
    }

    /**
     * 获取联系方式显示文本
     */
    fun getContactDisplayText(): String {
        return when (contactType) {
            "EMAIL" -> "邮箱: $contactValue"
            "PHONE" -> "手机: $contactValue"
            else -> "联系方式: $contactValue"
        }
    }
}
