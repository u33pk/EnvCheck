package qpdb.env.check.ui.behaviora.datepicker

import android.app.DatePickerDialog
import android.content.Context
import android.widget.DatePicker
import com.google.android.material.datepicker.MaterialDatePicker
import java.util.Calendar

/**
 * 日期选择器管理器
 * 支持多种日期选择样式
 */
class DatePickerManager(private val context: Context) {

    interface OnDateSelectedListener {
        fun onDateSelected(year: Int, month: Int, dayOfMonth: Int)
    }

    private var currentYear: Int = Calendar.getInstance().get(Calendar.YEAR)
    private var currentMonth: Int = Calendar.getInstance().get(Calendar.MONTH)
    private var currentDay: Int = Calendar.getInstance().get(Calendar.DAY_OF_MONTH)

    /**
     * 设置默认日期
     */
    fun setDate(calendar: Calendar) {
        currentYear = calendar.get(Calendar.YEAR)
        currentMonth = calendar.get(Calendar.MONTH)
        currentDay = calendar.get(Calendar.DAY_OF_MONTH)
    }

    /**
     * 显示随机样式的日期选择器
     */
    fun showRandomDatePicker(listener: OnDateSelectedListener) {
        when (DatePickerStyle.random()) {
            DatePickerStyle.SYSTEM_DEFAULT -> showSystemDatePicker(listener)
            DatePickerStyle.MATERIAL_CALENDAR -> showMaterialCalendarPicker(listener)
            DatePickerStyle.MATERIAL_INPUT -> showMaterialInputPicker(listener)
            DatePickerStyle.BOTTOM_SHEET -> showBottomSheetDatePicker(listener)
        }
    }

    /**
     * 显示系统默认样式日期选择器
     */
    private fun showSystemDatePicker(listener: OnDateSelectedListener) {
        DatePickerDialog(
            context,
            { _: DatePicker, year: Int, month: Int, day: Int ->
                listener.onDateSelected(year, month, day)
            },
            currentYear,
            currentMonth,
            currentDay
        ).show()
    }

    /**
     * 显示 Material Calendar 样式日期选择器
     */
    private fun showMaterialCalendarPicker(listener: OnDateSelectedListener) {
        val calendar = Calendar.getInstance().apply {
            set(currentYear, currentMonth, currentDay)
        }

        MaterialDatePicker.Builder.datePicker()
            .setTitleText("选择日期")
            .setSelection(calendar.timeInMillis)
            .build()
            .apply {
                addOnPositiveButtonClickListener { selection ->
                    val selectedCalendar = Calendar.getInstance().apply {
                        timeInMillis = selection
                    }
                    listener.onDateSelected(
                        selectedCalendar.get(Calendar.YEAR),
                        selectedCalendar.get(Calendar.MONTH),
                        selectedCalendar.get(Calendar.DAY_OF_MONTH)
                    )
                }
            }
            .show((context as androidx.fragment.app.FragmentActivity).supportFragmentManager, "MATERIAL_CALENDAR")
    }

    /**
     * 显示 Material Input 样式日期选择器（文本输入方式）
     */
    private fun showMaterialInputPicker(listener: OnDateSelectedListener) {
        val calendar = Calendar.getInstance().apply {
            set(currentYear, currentMonth, currentDay)
        }

        MaterialDatePicker.Builder.datePicker()
            .setTitleText("选择日期")
            .setSelection(calendar.timeInMillis)
            .setInputMode(MaterialDatePicker.INPUT_MODE_TEXT)
            .build()
            .apply {
                addOnPositiveButtonClickListener { selection ->
                    val selectedCalendar = Calendar.getInstance().apply {
                        timeInMillis = selection
                    }
                    listener.onDateSelected(
                        selectedCalendar.get(Calendar.YEAR),
                        selectedCalendar.get(Calendar.MONTH),
                        selectedCalendar.get(Calendar.DAY_OF_MONTH)
                    )
                }
            }
            .show((context as androidx.fragment.app.FragmentActivity).supportFragmentManager, "MATERIAL_INPUT")
    }

    /**
     * 显示底部弹出样式日期选择器（使用系统样式但显示在底部）
     */
    private fun showBottomSheetDatePicker(listener: OnDateSelectedListener) {
        // 使用系统样式但改变显示方式，创建一个自定义的 DialogFragment
        val bottomSheet = BottomSheetDatePicker.newInstance(currentYear, currentMonth, currentDay)
        bottomSheet.onDateSelectedListener = listener
        bottomSheet.show((context as androidx.fragment.app.FragmentActivity).supportFragmentManager, "BOTTOM_SHEET")
    }
}
