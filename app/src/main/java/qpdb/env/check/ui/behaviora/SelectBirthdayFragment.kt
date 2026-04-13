package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.FragmentSelectBirthdayBinding
import qpdb.env.check.ui.behaviora.datepicker.DatePickerManager
import java.util.Calendar

/**
 * 选择生日 Fragment
 * 用户可以选择生日日期，每次点击会随机弹出不同样式的日期选择器
 */
class SelectBirthdayFragment : Fragment() {

    companion object {
        private const val TAG = "SelectBirthdayFragment"
        fun newInstance() = SelectBirthdayFragment()
    }

    private var _binding: FragmentSelectBirthdayBinding? = null
    private val binding get() = _binding!!

    private var selectedBirthday: Calendar? = null
    private lateinit var datePickerManager: DatePickerManager

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSelectBirthdayBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "选择生日界面已创建")

        // 初始化日期选择器管理器
        datePickerManager = DatePickerManager(requireContext())

        initViews()
    }

    private fun initViews() {
        // 点击日期标签显示日期选择器（随机样式）
        binding.tvBirthdayLabel.setOnClickListener {
            showRandomDatePicker()
        }

        // 设置下一步按钮点击事件
        binding.btnNext.setOnClickListener {
            val birthday = binding.tvBirthdayLabel.text.toString()
            Log.d(TAG, "用户点击下一步，选择的生日: $birthday")
            // 保存生日
            RegistrationData.birthday = birthday
            // 随机跳转到邮箱或手机号输入页面
            (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                ContactInputFragment.newInstanceRandom()
            )
        }
    }

    /**
     * 显示随机样式的日期选择器
     */
    private fun showRandomDatePicker() {
        // 如果已选择过日期，设置当前日期
        selectedBirthday?.let {
            datePickerManager.setDate(it)
        }

        datePickerManager.showRandomDatePicker(object : DatePickerManager.OnDateSelectedListener {
            override fun onDateSelected(year: Int, month: Int, dayOfMonth: Int) {
                selectedBirthday = Calendar.getInstance().apply {
                    set(year, month, dayOfMonth)
                }
                // 格式化显示日期：yyyy-MM-dd
                val formattedDate = String.format(
                    "%04d-%02d-%02d",
                    year,
                    month + 1,
                    dayOfMonth
                )
                binding.tvBirthdayLabel.text = formattedDate
                Log.d(TAG, "用户选择了生日: $formattedDate")
            }
        })
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
