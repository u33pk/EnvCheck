package qpdb.env.check.adapter

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import qpdb.env.check.R
import qpdb.env.check.model.Category
import qpdb.env.check.model.CheckItem
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
        private val progressBar: ProgressBar = itemView.findViewById(R.id.progressBar)
        private val ivExpand: ImageView = itemView.findViewById(R.id.ivExpand)
        private val categoryHeader: View = itemView.findViewById(R.id.categoryHeader)
        private val expandableContent: View = itemView.findViewById(R.id.expandableContent)
        private val rvItems: RecyclerView = itemView.findViewById(R.id.rvItems)

        private lateinit var currentCategory: Category
        private lateinit var itemAdapter: ItemAdapter

        fun bind(category: Category) {
            currentCategory = category

            tvCategoryName.text = category.name
            updateStatusDisplay(category)
            progressBar.progress = category.getProgress()

            ivExpand.rotation = if (category.isExpanded) 180f else 0f
            expandableContent.visibility = if (category.isExpanded) View.VISIBLE else View.GONE

            itemAdapter = ItemAdapter(category.items)
            rvItems.layoutManager = LinearLayoutManager(itemView.context)
            rvItems.adapter = itemAdapter

            categoryHeader.setOnClickListener {
                category.isExpanded = !category.isExpanded
                ivExpand.rotation = if (category.isExpanded) 180f else 0f
                expandableContent.visibility = if (category.isExpanded) View.VISIBLE else View.GONE
                notifyItemChanged(adapterPosition)
                onCategoryExpanded(category, category.isExpanded)
            }
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
        private val tvCheckPoint: TextView = itemView.findViewById(R.id.tvCheckPoint)
        private val tvItemDescription: TextView = itemView.findViewById(R.id.tvItemDescription)
        private val tvStatus: TextView = itemView.findViewById(R.id.tvStatus)
        private val ivItemExpand: ImageView = itemView.findViewById(R.id.ivItemExpand)
        private val itemHeader: View = itemView.findViewById(R.id.itemHeader)
        private val itemDetailContent: View = itemView.findViewById(R.id.itemDetailContent)

        private lateinit var currentItem: CheckItem

        fun bind(item: CheckItem) {
            currentItem = item

            tvItemName.text = item.name
            tvCheckPoint.text = item.checkPoint
            tvItemDescription.text = item.description
            tvCheckPoint.visibility = if (item.checkPoint.isNotEmpty()) View.VISIBLE else View.GONE
            tvItemDescription.visibility = if (item.description.isNotEmpty()) View.VISIBLE else View.GONE

            // 更新状态显示
            updateStatusDisplay(item)

            // 点击展开/收起详情
            itemHeader.setOnClickListener {
                itemDetailContent.visibility = if (itemDetailContent.visibility == View.GONE) {
                    ivItemExpand.rotation = 180f
                    View.VISIBLE
                } else {
                    ivItemExpand.rotation = 0f
                    View.GONE
                }
            }
        }

        private fun updateStatusDisplay(item: CheckItem) {
            tvStatus.visibility = View.VISIBLE
            when (item.status) {
                CheckStatus.PASS -> {
                    tvStatus.text = "通过"
                    tvStatus.setBackgroundResource(R.drawable.status_passed)
                }
                CheckStatus.FAIL -> {
                    tvStatus.text = "不通过"
                    tvStatus.setBackgroundResource(R.drawable.status_failed)
                }
                CheckStatus.INFO -> {
                    tvStatus.text = "信息"
                    tvStatus.setBackgroundResource(R.drawable.status_info)
                }
            }
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
