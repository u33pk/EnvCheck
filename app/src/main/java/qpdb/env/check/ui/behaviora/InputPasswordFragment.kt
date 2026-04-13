package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import com.google.android.material.snackbar.Snackbar
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.FragmentInputPasswordBinding

/**
 * 输入密码 Fragment
 * 用户输入密码并确认
 */
class InputPasswordFragment : Fragment() {

    companion object {
        private const val TAG = "InputPasswordFragment"
        fun newInstance() = InputPasswordFragment()
    }

    private var _binding: FragmentInputPasswordBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentInputPasswordBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "输入密码界面已创建")

        initViews()
    }

    private fun initViews() {
        // 监听密码输入变化，实时检查
        binding.etPassword.doAfterTextChanged {
            checkPasswordsMatch()
        }
        binding.etConfirmPassword.doAfterTextChanged {
            checkPasswordsMatch()
        }

        // 下一步按钮点击事件
        binding.btnNext.setOnClickListener {
            val password = binding.etPassword.text.toString()
            val confirmPassword = binding.etConfirmPassword.text.toString()

            Log.d(TAG, "用户点击下一步")

            // 检查密码是否为空
            if (password.isEmpty()) {
                showError("请输入密码")
                return@setOnClickListener
            }

            // 检查两次输入是否一致
            if (password != confirmPassword) {
                showError("密码不一致")
                return@setOnClickListener
            }

            // 密码验证通过
            Log.d(TAG, "密码验证通过")
            // 保存密码
            RegistrationData.password = password
            // 跳转到用户协议页面
            (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                UserAgreementFragment.newInstance()
            )
        }
    }

    /**
     * 检查两次输入的密码是否一致
     */
    private fun checkPasswordsMatch() {
        val password = binding.etPassword.text.toString()
        val confirmPassword = binding.etConfirmPassword.text.toString()

        // 只有在两个输入框都有内容时才更新UI
        if (password.isNotEmpty() && confirmPassword.isNotEmpty()) {
            if (password == confirmPassword) {
                binding.tvMatchStatus.text = "密码一致"
                binding.tvMatchStatus.setTextColor(requireContext().getColor(android.R.color.holo_green_dark))
                binding.tvMatchStatus.visibility = View.VISIBLE
            } else {
                binding.tvMatchStatus.text = "密码不一致"
                binding.tvMatchStatus.setTextColor(requireContext().getColor(android.R.color.holo_red_dark))
                binding.tvMatchStatus.visibility = View.VISIBLE
            }
        } else {
            binding.tvMatchStatus.visibility = View.GONE
        }
    }

    /**
     * 显示错误提示
     */
    private fun showError(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_SHORT).show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
