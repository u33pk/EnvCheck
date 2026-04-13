package qpdb.env.check.ui.behaviora.datepicker

/**
 * 日期选择器样式枚举
 */
enum class DatePickerStyle {
    SYSTEM_DEFAULT,      // 系统默认样式
    MATERIAL_CALENDAR,   // Material Calendar 样式
    MATERIAL_INPUT,      // Material Input 样式
    BOTTOM_SHEET;        // 底部弹出样式

    companion object {
        /**
         * 获取随机样式
         */
        fun random(): DatePickerStyle {
            return entries.random()
        }
    }
}
