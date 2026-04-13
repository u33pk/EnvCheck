package qpdb.env.check.ui.behaviora

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.fragment.app.Fragment
import qpdb.env.check.databinding.FragmentBehaviorDisplayBinding
import qpdb.env.check.ui.behaviora.gl.TrajectoryGLView

/**
 * 行为展示 Fragment
 * 使用3D OpenGL可视化展示所有触摸轨迹
 */
class BehaviorDisplayFragment : Fragment() {

    companion object {
        private const val TAG = "BehaviorDisplayFragment"
        fun newInstance() = BehaviorDisplayFragment()
    }

    private var _binding: FragmentBehaviorDisplayBinding? = null
    private val binding get() = _binding!!

    private var glView: TrajectoryGLView? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentBehaviorDisplayBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        Log.d(TAG, "行为展示界面已创建")

        initViews()
        setupGLView()
    }

    private fun initViews() {
        // 返回按钮
        binding.btnBack.setOnClickListener {
            Log.d(TAG, "用户点击返回")
            activity?.finish()
        }
    }

    /**
     * 设置OpenGL视图
     */
    private fun setupGLView() {
        try {
            // 创建GLSurfaceView
            glView = TrajectoryGLView(requireContext()).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.MATCH_PARENT
                )
            }

            // 替换文本视图为GL视图
            val parent = binding.scrollView.parent as ViewGroup
            val index = parent.indexOfChild(binding.scrollView)
            parent.removeView(binding.scrollView)
            parent.addView(glView, index)

            // 延迟刷新数据（等待GL上下文初始化完成）
            glView?.postDelayed({
                glView?.refreshData()
            }, 100)

            Log.d(TAG, "OpenGL视图已设置")

        } catch (e: Exception) {
            Log.e(TAG, "设置OpenGL视图失败", e)
            // 显示错误信息到文本视图
            binding.tvBehaviorContent.text = "3D可视化加载失败: ${e.message}"
            binding.tvBehaviorContent.visibility = View.VISIBLE
        }
    }

    override fun onResume() {
        super.onResume()
        glView?.onResume()
    }

    override fun onPause() {
        super.onPause()
        glView?.onPause()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        glView = null
        _binding = null
    }
}
