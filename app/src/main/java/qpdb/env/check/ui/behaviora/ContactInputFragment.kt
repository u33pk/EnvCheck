package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.FragmentContactInputBinding

/**
 * 联系方式输入 Fragment
 * 支持输入邮箱或手机号，可随机进入并相互切换
 */
class ContactInputFragment : Fragment() {

    companion object {
        private const val TAG = "ContactInputFragment"
        private const val ARG_INPUT_TYPE = "input_type"

        enum class InputType {
            EMAIL, PHONE
        }

        /**
         * 随机创建 Fragment（邮箱或手机号）
         */
        fun newInstanceRandom(): ContactInputFragment {
            val randomType = if (kotlin.random.Random.nextBoolean()) {
                InputType.EMAIL
            } else {
                InputType.PHONE
            }
            return newInstance(randomType)
        }

        /**
         * 指定类型创建 Fragment
         */
        fun newInstance(inputType: InputType): ContactInputFragment {
            return ContactInputFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_INPUT_TYPE, inputType.name)
                }
            }
        }
    }

    private var _binding: FragmentContactInputBinding? = null
    private val binding get() = _binding!!

    private lateinit var currentInputType: InputType

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 从参数获取输入类型，默认为邮箱
        val typeName = arguments?.getString(ARG_INPUT_TYPE) ?: InputType.EMAIL.name
        currentInputType = InputType.valueOf(typeName)
        Log.d(TAG, "当前输入类型: $currentInputType")
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentContactInputBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "联系方式输入界面已创建，类型: $currentInputType")

        initViews()
        updateUI()
    }

    /**
     * 初始化视图
     */
    private fun initViews() {
        // 切换按钮点击事件
        binding.btnSwitchType.setOnClickListener {
            switchInputType()
        }

        // 接受验证码按钮点击事件
        binding.btnNext.setOnClickListener {
            val input = binding.etContactInput.text.toString().trim()
            Log.d(TAG, "用户点击接受验证码，$currentInputType: $input")
            
            // 保存联系方式
            RegistrationData.contactType = currentInputType.name
            RegistrationData.contactValue = input
            
            // 先显示滑动验证码
            val slideVerifyDialog = SlideVerifyDialog.newInstance {
                // 滑动验证成功后跳转到验证码输入页面
                Log.d(TAG, "滑动验证成功，跳转到验证码输入页面")
                (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                    VerifyCodeFragment.newInstance(currentInputType.name, input)
                )
            }
            slideVerifyDialog.show(parentFragmentManager, "SLIDE_VERIFY")
        }

        // 实时验证输入
        binding.etContactInput.doAfterTextChanged { text ->
            validateInput(text?.toString() ?: "")
        }
    }

    /**
     * 切换输入类型（邮箱 <-> 手机号）
     */
    private fun switchInputType() {
        currentInputType = when (currentInputType) {
            InputType.EMAIL -> InputType.PHONE
            InputType.PHONE -> InputType.EMAIL
        }
        Log.d(TAG, "切换到: $currentInputType")
        updateUI()
    }

    /**
     * 根据当前类型更新 UI
     */
    private fun updateUI() {
        when (currentInputType) {
            InputType.EMAIL -> {
                binding.tvTitle.text = "输入邮箱"
                binding.etContactInput.hint = "请输入邮箱地址"
                binding.etContactInput.inputType = android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
                binding.btnSwitchType.text = "更改为使用手机号"
            }
            InputType.PHONE -> {
                binding.tvTitle.text = "输入手机号"
                binding.etContactInput.hint = "请输入手机号"
                binding.etContactInput.inputType = android.text.InputType.TYPE_CLASS_PHONE
                binding.btnSwitchType.text = "更改为使用邮箱"
            }
        }
        // 清空输入框
        binding.etContactInput.text?.clear()
        binding.tvError.visibility = View.GONE
    }

    /**
     * 验证输入
     */
    private fun validateInput(input: String) {
        if (input.isEmpty()) {
            binding.tvError.visibility = View.GONE
            return
        }

        val isValid = when (currentInputType) {
            InputType.EMAIL -> isValidEmail(input)
            InputType.PHONE -> isValidPhone(input)
        }

        if (isValid) {
            binding.tvError.visibility = View.GONE
        } else {
            binding.tvError.visibility = View.VISIBLE
            binding.tvError.text = when (currentInputType) {
                InputType.EMAIL -> "请输入有效的邮箱地址"
                InputType.PHONE -> "请输入有效的手机号"
            }
        }
    }

    /**
     * 验证邮箱格式
     */
    private fun isValidEmail(email: String): Boolean {
        return android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()
    }

    /**
     * 验证手机号格式（简单验证：11位数字）
     */
    private fun isValidPhone(phone: String): Boolean {
        return phone.matches(Regex("^1[3-9]\\d{9}$"))
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
