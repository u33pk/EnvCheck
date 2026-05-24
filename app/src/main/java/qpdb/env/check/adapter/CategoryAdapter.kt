package qpdb.env.check.adapter

import android.app.Dialog
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.RecyclerView
import qpdb.env.check.R
import qpdb.env.check.manager.CheckerManager
import qpdb.env.check.model.Category
import qpdb.env.check.model.CheckItem
import qpdb.env.check.model.DisplayMode
import qpdb.env.check.model.CheckStatus

class CategoryAdapter(
    categories: MutableList<Category> = mutableListOf(),
    private val onCategoryExpanded: (Category, Boolean) -> Unit = { _, _ -> }
) : RecyclerView.Adapter<CategoryAdapter.CategoryViewHolder>() {

    // 创建列表的副本，避免与外部引用共享
    private val categories: MutableList<Category> = categories.toMutableList()


    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): CategoryViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_category, parent, false)
        return CategoryViewHolder(view)
    }

    override fun onBindViewHolder(holder: CategoryViewHolder, position: Int) {
        holder.bind(categories[position])
    }

    override fun getItemCount(): Int = categories.size

    inner class CategoryViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val tvCategoryName: TextView = itemView.findViewById(R.id.tvCategoryName)
        private val tvStatus: TextView = itemView.findViewById(R.id.tvStatus)
        private val ivExpand: ImageView = itemView.findViewById(R.id.ivExpand)
        private val categoryHeader: View = itemView.findViewById(R.id.categoryHeader)
        private val expandableContent: View = itemView.findViewById(R.id.expandableContent)
        private val rvItems: RecyclerView = itemView.findViewById(R.id.rvItems)
        private val flCanvasContainer: FrameLayout = itemView.findViewById(R.id.flCanvasContainer)

        private lateinit var currentCategory: Category
        private lateinit var itemAdapter: ItemAdapter

        fun bind(category: Category) {
            currentCategory = category

            tvCategoryName.text = category.name

            if (category.displayMode == DisplayMode.CANVAS) {
                tvStatus.visibility = View.GONE
            } else {
                tvStatus.visibility = View.VISIBLE
                updateStatusDisplay(category)
            }

            ivExpand.rotation = if (category.isExpanded) 180f else 0f
            expandableContent.visibility = if (category.isExpanded) View.VISIBLE else View.GONE

            if (category.displayMode == DisplayMode.CANVAS) {
                rvItems.visibility = View.GONE
                flCanvasContainer.visibility = View.VISIBLE
                setupCanvasView(category)
            } else {
                rvItems.visibility = View.VISIBLE
                flCanvasContainer.visibility = View.GONE
                itemAdapter = ItemAdapter(category.items)
                rvItems.layoutManager = GridLayoutManager(itemView.context, 2)
                rvItems.adapter = itemAdapter
            }

            categoryHeader.setOnClickListener {
                category.isExpanded = !category.isExpanded
                ivExpand.rotation = if (category.isExpanded) 180f else 0f
                expandableContent.visibility = if (category.isExpanded) View.VISIBLE else View.GONE
                notifyItemChanged(bindingAdapterPosition)
                onCategoryExpanded(category, category.isExpanded)
            }
        }

        private fun setupCanvasView(category: Category) {
            flCanvasContainer.removeAllViews()
            val canvasView = CheckerManager.getCheckerByCategoryName(category.name)
                ?.createCanvasView(itemView.context)
                ?: TextView(itemView.context).apply {
                    text = "Canvas"
                    setTextColor(Color.WHITE)
                    gravity = android.view.Gravity.CENTER
                }
            flCanvasContainer.addView(canvasView)
        }

        private fun updateStatusDisplay(category: Category) {
            val passedCount = category.getPassedCount()
            val failedCount = category.getFailedCount()
            val infoCount = category.getInfoCount()
            val totalCount = category.getTotalCount()

            // 显示状态统计
            tvStatus.text = when {
                failedCount > 0 -> "$passedCount 通过 / $failedCount 不通过"
                infoCount > 0 && passedCount > 0 -> "$passedCount 通过 / $infoCount 信息"
                infoCount > 0 -> "$infoCount 信息"
                else -> "$passedCount/$totalCount 通过"
            }

            // 根据通过情况更新状态背景色
            when {
                failedCount > 0 -> {
                    // 有不通过项，显示红色
                    tvStatus.setBackgroundResource(R.drawable.status_failed)
                }
                passedCount == totalCount && totalCount > 0 -> {
                    // 全部通过，显示绿色
                    tvStatus.setBackgroundResource(R.drawable.status_passed)
                }
                infoCount > 0 -> {
                    // 只有信息项，显示黄色
                    tvStatus.setBackgroundResource(R.drawable.status_info)
                }
                else -> {
                    tvStatus.setBackgroundResource(R.drawable.status_failed)
                }
            }
        }
    }

    fun setCategories(newCategories: List<Category>) {
        categories.clear()
        categories.addAll(newCategories)
        notifyDataSetChanged()
    }

    fun updateCategory(category: Category) {
        val position = categories.indexOfFirst { it.id == category.id }
        if (position != -1) {
            notifyItemChanged(position)
        }
    }

    fun getCategories(): List<Category> = categories.toList()
}

class ItemAdapter(
    private val items: List<CheckItem>
) : RecyclerView.Adapter<ItemAdapter.ItemViewHolder>() {

    inner class ItemViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val tvItemName: TextView = itemView.findViewById(R.id.tvItemName)
        private val tvStatus: TextView = itemView.findViewById(R.id.tvStatus)
        private val itemContainer: View = itemView.findViewById(R.id.itemContainer)

        fun bind(item: CheckItem) {
            tvItemName.text = item.name
            updateStatusDisplay(item)

            itemView.setOnClickListener {
                showDetailDialog(item)
            }
        }

        private fun updateStatusDisplay(item: CheckItem) {
            when (item.status) {
                CheckStatus.PASS -> {
                    tvStatus.text = "通过"
                    itemContainer.setBackgroundResource(R.drawable.status_passed)
                }
                CheckStatus.FAIL -> {
                    tvStatus.text = "不通过"
                    itemContainer.setBackgroundResource(R.drawable.status_failed)
                }
                CheckStatus.INFO -> {
                    tvStatus.text = "信息"
                    itemContainer.setBackgroundResource(R.drawable.status_info)
                }
            }
        }

        private fun showDetailDialog(item: CheckItem) {
            val context = itemView.context
            val dialog = Dialog(context)
            dialog.setContentView(R.layout.dialog_check_detail)

            dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

            val headerContainer = dialog.findViewById<LinearLayout>(R.id.headerContainer)
            val tvTitle = dialog.findViewById<TextView>(R.id.tvDialogTitle)
            val tvStatus = dialog.findViewById<TextView>(R.id.tvDialogStatus)
            val tvDesc = dialog.findViewById<TextView>(R.id.tvDialogDescription)
            val btnConfirm = dialog.findViewById<TextView>(R.id.btnConfirm)

            val (statusText, accentColorRes) = when (item.status) {
                CheckStatus.PASS -> "通过" to R.drawable.status_passed
                CheckStatus.FAIL -> "不通过" to R.drawable.status_failed
                CheckStatus.INFO -> "信息" to R.drawable.status_info
            }

            headerContainer.setBackgroundResource(accentColorRes)
            tvTitle.text = item.name
            tvStatus.text = statusText
            tvDesc.text = item.description

            btnConfirm.setOnClickListener { dialog.dismiss() }

            dialog.show()
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ItemViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_check, parent, false)
        return ItemViewHolder(view)
    }

    override fun onBindViewHolder(holder: ItemViewHolder, position: Int) {
        holder.bind(items[position])
    }

    override fun getItemCount(): Int = items.size
}
