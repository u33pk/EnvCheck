package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.os.CountDownTimer
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.FragmentVerifyCodeBinding

/**
 * 验证码输入 Fragment
 * 输入收到的验证码
 */
class VerifyCodeFragment : Fragment() {

    companion object {
        private const val TAG = "VerifyCodeFragment"
        private const val ARG_CONTACT_TYPE = "contact_type"
        private const val ARG_CONTACT_VALUE = "contact_value"
        
        // 倒计时总时长（60秒）
        private const val COUNTDOWN_MILLIS = 60000L
        // 倒计时间隔（1秒）
        private const val COUNTDOWN_INTERVAL = 1000L

        fun newInstance(contactType: String, contactValue: String): VerifyCodeFragment {
            return VerifyCodeFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_CONTACT_TYPE, contactType)
                    putString(ARG_CONTACT_VALUE, contactValue)
                }
            }
        }
    }

    private var _binding: FragmentVerifyCodeBinding? = null
    private val binding get() = _binding!!

    private lateinit var contactType: String
    private lateinit var contactValue: String
    private var countdownTimer: CountDownTimer? = null
    private var isFirstSend = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        contactType = arguments?.getString(ARG_CONTACT_TYPE) ?: "EMAIL"
        contactValue = arguments?.getString(ARG_CONTACT_VALUE) ?: ""
        Log.d(TAG, "验证码页面，类型: $contactType, 联系方式: $contactValue")
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentVerifyCodeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "验证码输入界面已创建")

        initViews()
        // 自动发送验证码
        sendVerificationCode()
    }

    private fun initViews() {
        // 设置子标题显示联系方式
        binding.tvSubtitle.text = when (contactType) {
            "EMAIL" -> "验证码已发送至邮箱: $contactValue"
            "PHONE" -> "验证码已发送至手机: $contactValue"
            else -> "验证码已发送"
        }

        // 发送验证码按钮点击事件
        binding.btnSendCode.setOnClickListener {
            sendVerificationCode()
        }

        // 下一步按钮点击事件
        binding.btnNext.setOnClickListener {
            val code = binding.etVerifyCode.text.toString().trim()
            Log.d(TAG, "用户点击下一步，验证码: $code")
            // 保存验证码
            RegistrationData.verificationCode = code
            // 跳转到输入密码页面
            (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                InputPasswordFragment.newInstance()
            )
        }

        // 实时监听输入
        binding.etVerifyCode.doAfterTextChanged { text ->
            val code = text?.toString()?.trim() ?: ""
            binding.btnNext.isEnabled = code.length >= 4
        }

        // 初始禁用下一步按钮
        binding.btnNext.isEnabled = false
    }

    /**
     * 发送验证码
     */
    private fun sendVerificationCode() {
        Log.d(TAG, "发送验证码到 $contactValue")
        
        // 如果是第一次发送，修改按钮文字
        if (isFirstSend) {
            binding.btnSendCode.text = "重新发送"
            isFirstSend = false
        }

        // 禁用按钮并开始倒计时
        binding.btnSendCode.isEnabled = false
        startCountdown()

        // TODO: 调用实际的验证码发送 API
    }

    /**
     * 开始倒计时
     */
    private fun startCountdown() {
        countdownTimer?.cancel()
        countdownTimer = object : CountDownTimer(COUNTDOWN_MILLIS, COUNTDOWN_INTERVAL) {
            override fun onTick(millisUntilFinished: Long) {
                val seconds = millisUntilFinished / 1000
                binding.btnSendCode.text = "${seconds}秒后重新发送"
            }

            override fun onFinish() {
                binding.btnSendCode.text = "重新发送"
                binding.btnSendCode.isEnabled = true
            }
        }.start()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        countdownTimer?.cancel()
        countdownTimer = null
        _binding = null
    }
}
