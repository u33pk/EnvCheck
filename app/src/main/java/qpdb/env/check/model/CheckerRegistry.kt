package qpdb.env.check.model

/**
 * 检测器注册器
 * 用于注册和管理所有检测类
 */
object CheckerRegistry {
    
    private val checkers = mutableListOf<Checkable>()
    
    /**
     * 注册检测器
     */
    fun register(checker: Checkable) {
        // 避免重复注册
        if (!checkers.any { it::class.java == checker::class.java }) {
            checkers.add(checker)
        }
    }
    
    /**
     * 注册多个检测器
     */
    fun registerAll(vararg checkers: Checkable) {
        checkers.forEach { register(it) }
    }
    
    /**
     * 获取所有已注册的检测器
     */
    fun getAllCheckers(): List<Checkable> = checkers.toList()
    
    /**
     * 清除所有检测器
     */
    fun clear() {
        checkers.clear()
    }
    
    /**
     * 获取检测器数量
     */
    fun size(): Int = checkers.size
}
