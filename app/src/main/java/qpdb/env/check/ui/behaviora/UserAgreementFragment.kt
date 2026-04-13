package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import androidx.fragment.app.Fragment
import qpdb.env.check.data.RegistrationData
import qpdb.env.check.databinding.FragmentUserAgreementBinding

/**
 * 用户协议 Fragment
 * 用户需要滑动到底部并阅读超过5秒才能接受
 */
class UserAgreementFragment : Fragment() {

    companion object {
        private const val TAG = "UserAgreementFragment"
        private const val MIN_READ_TIME_MS = 5000L // 最少阅读时间5秒
        private const val AGREEMENT_TEXT = "请输入文本。"
        private const val AGREEMENT_REPEAT_COUNT = 200 // 重复次数，确保内容足够长

        fun newInstance() = UserAgreementFragment()
    }

    private var _binding: FragmentUserAgreementBinding? = null
    private val binding get() = _binding!!

    private var startTime: Long = 0
    private var hasScrolledToBottom = false
    private var hasReadEnoughTime = false
    private val handler = Handler(Looper.getMainLooper())

    // 检查阅读时间的 Runnable
    private val checkReadTimeRunnable = Runnable {
        hasReadEnoughTime = true
        Log.d(TAG, "阅读时间已达到 $MIN_READ_TIME_MS ms")
        updateAcceptButtonState()
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentUserAgreementBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "用户协议界面已创建")

        initViews()
        startReadingTimer()
    }

    private fun initViews() {
        // 生成用户协议文本
        val agreementContent = AGREEMENT_TEXT.repeat(AGREEMENT_REPEAT_COUNT)
        binding.tvAgreementContent.text = agreementContent

        // 初始禁用接受按钮
        binding.btnAccept.isEnabled = false
        binding.btnAccept.alpha = 0.5f

        // 监听滚动到底部
        binding.scrollView.setOnScrollChangeListener { _: View, _: Int, scrollY: Int, _: Int, _: Int ->
            checkScrollPosition(scrollY)
        }

        // 接受按钮
        binding.btnAccept.setOnClickListener {
            Log.d(TAG, "用户接受用户协议")
            // 保存实际等待时间
            RegistrationData.agreementWaitTimeMs = getElapsedTime()
            // 跳转到注册成功页面
            (activity as? qpdb.env.check.BehavioraActivity)?.navigateToFragment(
                RegistrationSuccessFragment.newInstance()
            )
        }

        // 不接受按钮
        binding.btnDecline.setOnClickListener {
            Log.d(TAG, "用户不接受用户协议")
            // 返回上一页或退出
            activity?.onBackPressed()
        }
    }

    /**
     * 检查滚动位置
     */
    private fun checkScrollPosition(scrollY: Int) {
        val scrollView = binding.scrollView
        val childHeight = scrollView.getChildAt(0).height
        val scrollViewHeight = scrollView.height
        val maxScroll = childHeight - scrollViewHeight

        // 判断是否滚动到底部（允许10像素的误差）
        val isAtBottom = scrollY >= maxScroll - 10

        if (isAtBottom && !hasScrolledToBottom) {
            hasScrolledToBottom = true
            Log.d(TAG, "用户已滚动到底部")
            updateAcceptButtonState()
        }
    }

    /**
     * 开始阅读计时
     */
    private fun startReadingTimer() {
        startTime = SystemClock.elapsedRealtime()
        handler.postDelayed(checkReadTimeRunnable, MIN_READ_TIME_MS)
        Log.d(TAG, "开始阅读计时")
    }

    /**
     * 更新接受按钮状态
     */
    private fun updateAcceptButtonState() {
        if (hasScrolledToBottom && hasReadEnoughTime) {
            binding.btnAccept.isEnabled = true
            binding.btnAccept.alpha = 1.0f
            Log.d(TAG, "接受按钮已启用")
        }
    }

    /**
     * 获取已阅读时间（毫秒）
     */
    private fun getElapsedTime(): Long {
        return SystemClock.elapsedRealtime() - startTime
    }

    override fun onDestroyView() {
        super.onDestroyView()
        handler.removeCallbacks(checkReadTimeRunnable)
        _binding = null
    }
}
