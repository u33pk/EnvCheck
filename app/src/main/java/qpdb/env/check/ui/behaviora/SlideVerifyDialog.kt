package qpdb.env.check.ui.behaviora

import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.app.Dialog
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import androidx.core.animation.doOnEnd
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import qpdb.env.check.databinding.DialogSlideVerifyBinding
import kotlin.math.max
import kotlin.math.min

/**
 * 滑动验证码弹窗
 * 用户需要拖动滑块到最右侧完成验证
 */
class SlideVerifyDialog : BottomSheetDialogFragment() {

    companion object {
        private const val TAG = "SlideVerifyDialog"

        fun newInstance(onVerifySuccess: () -> Unit): SlideVerifyDialog {
            return SlideVerifyDialog().apply {
                this.onVerifySuccess = onVerifySuccess
            }
        }
    }

    private var _binding: DialogSlideVerifyBinding? = null
    private val binding get() = _binding!!

    private var onVerifySuccess: (() -> Unit)? = null

    // 滑块相关
    private var slideStartX = 0f
    private var slideViewWidth = 0
    private var trackWidth = 0
    private var maxSlideDistance = 0
    private var isVerified = false

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        return BottomSheetDialog(requireContext(), theme).apply {
            // 禁止拖动关闭
            behavior.isDraggable = false
            behavior.state = BottomSheetBehavior.STATE_EXPANDED
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = DialogSlideVerifyBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "滑动验证弹窗已创建")

        initViews()
    }

    private fun initViews() {
        // 取消按钮
        binding.btnCancel.setOnClickListener {
            dismiss()
        }

        initSlideView()
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun initSlideView() {
        // 等待布局完成后获取尺寸
        binding.slideTrack.post {
            trackWidth = binding.slideTrack.width
            slideViewWidth = binding.slideView.width
            maxSlideDistance = trackWidth - slideViewWidth
            Log.d(TAG, "轨道宽度: $trackWidth, 滑块宽度: $slideViewWidth, 最大滑动距离: $maxSlideDistance")
        }

        // 设置滑块触摸事件
        binding.slideView.setOnTouchListener { view, event ->
            if (isVerified) return@setOnTouchListener true

            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    slideStartX = event.rawX - view.x
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val newX = event.rawX - slideStartX
                    val clampedX = max(0f, min(newX, maxSlideDistance.toFloat()))
                    view.x = clampedX

                    // 更新提示文字透明度
                    val progress = clampedX / maxSlideDistance
                    binding.tvHint.alpha = 1 - progress
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    val currentX = view.x
                    if (currentX >= maxSlideDistance * 0.85f) {
                        // 滑动到足够位置，验证成功
                        snapToEndAndVerify()
                    } else {
                        // 未滑到位，回弹
                        snapToStart()
                    }
                    true
                }
                else -> false
            }
        }
    }

    /**
     * 滑块回弹到起始位置
     */
    private fun snapToStart() {
        ValueAnimator.ofFloat(binding.slideView.x, 0f).apply {
            duration = 200
            interpolator = DecelerateInterpolator()
            addUpdateListener {
                binding.slideView.x = it.animatedValue as Float
            }
            start()
        }
    }

    /**
     * 滑块吸附到末尾并验证成功
     */
    private fun snapToEndAndVerify() {
        isVerified = true
        ValueAnimator.ofFloat(binding.slideView.x, maxSlideDistance.toFloat()).apply {
            duration = 100
            interpolator = DecelerateInterpolator()
            addUpdateListener {
                binding.slideView.x = it.animatedValue as Float
            }
            doOnEnd {
                // 验证成功，更新UI
                binding.tvHint.text = "验证成功"
                binding.tvHint.alpha = 1f
                binding.slideView.isEnabled = false
                
                // 延迟后关闭弹窗并回调
                binding.root.postDelayed({
                    dismiss()
                    onVerifySuccess?.invoke()
                }, 500)
            }
            start()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
