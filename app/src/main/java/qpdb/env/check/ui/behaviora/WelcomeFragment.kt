package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import qpdb.env.check.databinding.FragmentWelcomeBinding

/**
 * 欢迎界面 Fragment
 * 显示欢迎信息和创建账户按钮
 */
class WelcomeFragment : Fragment() {

    companion object {
        private const val TAG = "WelcomeFragment"
        fun newInstance() = WelcomeFragment()
    }

    private var _binding: FragmentWelcomeBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentWelcomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "欢迎界面已创建")

        initViews()
    }

    private fun initViews() {
        // 设置创建账户按钮点击事件
        binding.btnCreateAccount.setOnClickListener {
            Log.d(TAG, "用户点击创建账户按钮")
            // 跳转到输入昵称页面
            (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                InputNicknameFragment.newInstance()
            )
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
