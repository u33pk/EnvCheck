package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.FragmentRegistrationSuccessBinding

/**
 * 注册成功 Fragment
 * 显示注册成功的信息和用户填写的注册内容
 */
class RegistrationSuccessFragment : Fragment() {

    companion object {
        private const val TAG = "RegistrationSuccessFragment"
        fun newInstance() = RegistrationSuccessFragment()
    }

    private var _binding: FragmentRegistrationSuccessBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentRegistrationSuccessBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "注册成功界面已创建")

        initViews()
        displayRegistrationInfo()
    }

    private fun initViews() {
        // 完成按钮
        binding.btnComplete.setOnClickListener {
            Log.d(TAG, "用户点击完成")
            // 跳转到行为展示页面
            (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                BehaviorDisplayFragment.newInstance(),
                addToBackStack = false // 不添加到返回栈，按返回直接结束 Activity
            )
        }
    }

    /**
     * 显示注册信息
     */
    private fun displayRegistrationInfo() {
        val infoBuilder = StringBuilder()

        infoBuilder.appendLine("昵称: ${RegistrationData.nickname}")
        infoBuilder.appendLine()
        infoBuilder.appendLine("生日: ${RegistrationData.birthday}")
        infoBuilder.appendLine()
        infoBuilder.appendLine(RegistrationData.getContactDisplayText())
        infoBuilder.appendLine()
        infoBuilder.appendLine("验证码: ${RegistrationData.verificationCode}")
        infoBuilder.appendLine()
        infoBuilder.appendLine("密码: ${RegistrationData.password}")
        infoBuilder.appendLine()
        infoBuilder.appendLine("协议等待时间: ${RegistrationData.agreementWaitTimeMs} ms")

        binding.tvRegistrationInfo.text = infoBuilder.toString()
        Log.d(TAG, "显示注册信息: $infoBuilder")
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
