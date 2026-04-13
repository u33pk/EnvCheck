package qpdb.env.check.tracker

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * JSON Lines 文件写入器
 * 将触摸事件以 JSON Lines 格式写入文件
 */
class JsonLineWriter(context: Context) {

    companion object {
        private const val TAG = "JsonLineWriter"
        private const val DATA_DIR = "data"
        private const val DATA_FILE = "data.jsonl"
    }

    private val dataDir = File(context.filesDir, DATA_DIR)
    private val dataFile = File(dataDir, DATA_FILE)
    private val writeQueue = ConcurrentLinkedQueue<String>()
    private val scope = CoroutineScope(Dispatchers.IO)

    init {
        // 确保目录存在
        if (!dataDir.exists()) {
            dataDir.mkdirs()
            Log.d(TAG, "创建数据目录: ${dataDir.absolutePath}")
        }
        Log.d(TAG, "数据文件路径: ${dataFile.absolutePath}")
    }

    /**
     * 写入单条 JSON 数据
     */
    fun writeJsonLine(json: String) {
        writeQueue.offer(json)
        flushQueue()
    }

    /**
     * 写入触摸事件（单条）
     * @deprecated 使用 writeJsonLine 配合 TouchTrajectory.toJson() 替代
     */
    fun writeTouchEvent(touchData: qpdb.env.check.tracker.TouchData) {
        writeJsonLine(touchData.toJson())
    }

    /**
     * 刷新队列到文件
     */
    private fun flushQueue() {
        scope.launch {
            withContext(Dispatchers.IO) {
                try {
                    FileWriter(dataFile, true).use { writer ->
                        var line = writeQueue.poll()
                        while (line != null) {
                            writer.write(line)
                            writer.write("\n")
                            line = writeQueue.poll()
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "写入文件失败", e)
                }
            }
        }
    }

    /**
     * 读取所有记录
     */
    fun readAllRecords(): List<String> {
        return if (dataFile.exists()) {
            dataFile.readLines()
        } else {
            emptyList()
        }
    }

    /**
     * 清空数据文件
     */
    fun clearData() {
        scope.launch {
            withContext(Dispatchers.IO) {
                try {
                    if (dataFile.exists()) {
                        dataFile.delete()
                        Log.d(TAG, "数据文件已清空")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "清空文件失败", e)
                }
            }
        }
    }

    /**
     * 获取文件路径
     */
    fun getDataFilePath(): String {
        return dataFile.absolutePath
    }
}
