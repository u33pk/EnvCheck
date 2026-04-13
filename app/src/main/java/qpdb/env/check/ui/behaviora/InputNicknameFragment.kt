package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import qpdb.env.check.BehavioraActivity
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.FragmentInputNicknameBinding

/**
 * 输入昵称 Fragment
 * 用户可以输入昵称
 */
class InputNicknameFragment : Fragment() {

    companion object {
        private const val TAG = "InputNicknameFragment"
        fun newInstance() = InputNicknameFragment()
    }

    private var _binding: FragmentInputNicknameBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentInputNicknameBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "输入昵称界面已创建")

        initViews()
    }

    private fun initViews() {
        // 设置下一步按钮点击事件
        binding.btnNext.setOnClickListener {
            val nickname = binding.etNickname.text.toString().trim()
            Log.d(TAG, "用户点击下一步，昵称: $nickname")
            // 保存昵称
            RegistrationData.nickname = nickname
            // 跳转到选择生日页面
            (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                SelectBirthdayFragment.newInstance()
            )
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
