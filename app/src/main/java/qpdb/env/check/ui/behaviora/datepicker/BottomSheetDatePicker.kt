package qpdb.env.check.ui.behaviora.datepicker

import android.app.Dialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.DatePicker
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import qpdb.env.check.databinding.BottomSheetDatePickerBinding

/**
 * 底部弹出的日期选择器
 */
class BottomSheetDatePicker : BottomSheetDialogFragment() {

    companion object {
        private const val ARG_YEAR = "year"
        private const val ARG_MONTH = "month"
        private const val ARG_DAY = "day"

        fun newInstance(year: Int, month: Int, day: Int): BottomSheetDatePicker {
            return BottomSheetDatePicker().apply {
                arguments = Bundle().apply {
                    putInt(ARG_YEAR, year)
                    putInt(ARG_MONTH, month)
                    putInt(ARG_DAY, day)
                }
            }
        }
    }

    private var _binding: BottomSheetDatePickerBinding? = null
    private val binding get() = _binding!!

    var onDateSelectedListener: DatePickerManager.OnDateSelectedListener? = null

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        return BottomSheetDialog(requireContext(), theme)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = BottomSheetDatePickerBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val year = arguments?.getInt(ARG_YEAR) ?: 2000
        val month = arguments?.getInt(ARG_MONTH) ?: 0
        val day = arguments?.getInt(ARG_DAY) ?: 1

        // 设置 DatePicker 为 spinner 模式
        binding.datePicker.init(year, month, day, null)

        // 确认按钮
        binding.btnConfirm.setOnClickListener {
            onDateSelectedListener?.onDateSelected(
                binding.datePicker.year,
                binding.datePicker.month,
                binding.datePicker.dayOfMonth
            )
            dismiss()
        }

        // 取消按钮
        binding.btnCancel.setOnClickListener {
            dismiss()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
