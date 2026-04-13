package qpdb.env.check.utils

import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.GLES20
import android.util.Log
import qpdb.env.check.model.CheckResult
import qpdb.env.check.model.CheckStatus

/**
 * GPU 信息获取工具类
 * 负责 EGL 上下文创建、OpenGL 信息读取、GPU 计算性能测试
 */
object GpuInfoUtil {
    private const val TAG = "GpuInfoUtil"

    data class OpenGlInfo(
        val renderer: String,
        val version: String,
        val vendor: String,
        val extensions: String
    )

    /**
     * 使用 EGL14 创建 Pbuffer 上下文，安全获取 OpenGL 信息
     * 不需要 GLSurfaceView，可在后台线程直接调用
     */
    fun getOpenGlInfoWithEGL(): OpenGlInfo {
        val display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
        if (display == EGL14.EGL_NO_DISPLAY) {
            throw RuntimeException("eglGetDisplay failed")
        }

        val version = IntArray(2)
        if (!EGL14.eglInitialize(display, version, 0, version, 1)) {
            throw RuntimeException("eglInitialize failed, error=0x${Integer.toHexString(EGL14.eglGetError())}")
        }

        val attribList = intArrayOf(
            EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
            EGL14.EGL_RED_SIZE, 8,
            EGL14.EGL_GREEN_SIZE, 8,
            EGL14.EGL_BLUE_SIZE, 8,
            EGL14.EGL_ALPHA_SIZE, 8,
            EGL14.EGL_NONE
        )

        val configs = arrayOfNulls<EGLConfig>(1)
        val numConfigs = IntArray(1)
        if (!EGL14.eglChooseConfig(display, attribList, 0, configs, 0, configs.size, numConfigs, 0)) {
            EGL14.eglTerminate(display)
            throw RuntimeException("eglChooseConfig failed, error=0x${Integer.toHexString(EGL14.eglGetError())}")
        }

        val contextAttribs = intArrayOf(
            EGL14.EGL_CONTEXT_CLIENT_VERSION, 2,
            EGL14.EGL_NONE
        )

        val context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT, contextAttribs, 0)
        if (context == EGL14.EGL_NO_CONTEXT) {
            EGL14.eglTerminate(display)
            throw RuntimeException("eglCreateContext failed, error=0x${Integer.toHexString(EGL14.eglGetError())}")
        }

        val surfaceAttribs = intArrayOf(
            EGL14.EGL_WIDTH, 1,
            EGL14.EGL_HEIGHT, 1,
            EGL14.EGL_NONE
        )

        val surface = EGL14.eglCreatePbufferSurface(display, configs[0], surfaceAttribs, 0)
        if (surface == EGL14.EGL_NO_SURFACE) {
            EGL14.eglDestroyContext(display, context)
            EGL14.eglTerminate(display)
            throw RuntimeException("eglCreatePbufferSurface failed, error=0x${Integer.toHexString(EGL14.eglGetError())}")
        }

        if (!EGL14.eglMakeCurrent(display, surface, surface, context)) {
            EGL14.eglDestroySurface(display, surface)
            EGL14.eglDestroyContext(display, context)
            EGL14.eglTerminate(display)
            throw RuntimeException("eglMakeCurrent failed, error=0x${Integer.toHexString(EGL14.eglGetError())}")
        }

        val renderer = GLES20.glGetString(GLES20.GL_RENDERER) ?: "未知"
        val versionStr = GLES20.glGetString(GLES20.GL_VERSION) ?: "未知"
        val vendor = GLES20.glGetString(GLES20.GL_VENDOR) ?: "未知"
        val extensions = GLES20.glGetString(GLES20.GL_EXTENSIONS) ?: ""

        // Cleanup
        EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT)
        EGL14.eglDestroySurface(display, surface)
        EGL14.eglDestroyContext(display, context)
        EGL14.eglTerminate(display)

        Log.i(TAG, "EGL OpenGL: renderer=$renderer, version=$versionStr, vendor=$vendor, exts=${extensions.split(" ").size}")
        return OpenGlInfo(renderer, versionStr, vendor, extensions)
    }

    /**
     * GPU 运算性能测试
     * 在 EGL Pbuffer 上下文中运行 heavy shader，测量 GPU 计算耗时
     * 结果仅作为 INFO 显示，不参与通过/失败判定
     */
    fun measureGpuCompute(): CheckResult {
        val display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
        if (display == EGL14.EGL_NO_DISPLAY) {
            return CheckResult(CheckStatus.INFO, "EGL 显示获取失败")
        }

        val version = IntArray(2)
        if (!EGL14.eglInitialize(display, version, 0, version, 1)) {
            return CheckResult(CheckStatus.INFO, "EGL 初始化失败")
        }

        val attribList = intArrayOf(
            EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
            EGL14.EGL_RED_SIZE, 8,
            EGL14.EGL_GREEN_SIZE, 8,
            EGL14.EGL_BLUE_SIZE, 8,
            EGL14.EGL_ALPHA_SIZE, 8,
            EGL14.EGL_NONE
        )

        val configs = arrayOfNulls<EGLConfig>(1)
        val numConfigs = IntArray(1)
        if (!EGL14.eglChooseConfig(display, attribList, 0, configs, 0, configs.size, numConfigs, 0)) {
            EGL14.eglTerminate(display)
            return CheckResult(CheckStatus.INFO, "EGL 配置选择失败")
        }

        val contextAttribs = intArrayOf(EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE)
        val context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT, contextAttribs, 0)
        if (context == EGL14.EGL_NO_CONTEXT) {
            EGL14.eglTerminate(display)
            return CheckResult(CheckStatus.INFO, "EGL 上下文创建失败")
        }

        // 使用 256x256 Pbuffer，让更多 fragment 并行执行
        val surfaceAttribs = intArrayOf(EGL14.EGL_WIDTH, 256, EGL14.EGL_HEIGHT, 256, EGL14.EGL_NONE)
        val surface = EGL14.eglCreatePbufferSurface(display, configs[0], surfaceAttribs, 0)
        if (surface == EGL14.EGL_NO_SURFACE) {
            EGL14.eglDestroyContext(display, context)
            EGL14.eglTerminate(display)
            return CheckResult(CheckStatus.INFO, "EGL Surface 创建失败")
        }

        if (!EGL14.eglMakeCurrent(display, surface, surface, context)) {
            EGL14.eglDestroySurface(display, surface)
            EGL14.eglDestroyContext(display, context)
            EGL14.eglTerminate(display)
            return CheckResult(CheckStatus.INFO, "EGL MakeCurrent 失败")
        }

        return try {
            val vertexShaderCode = """
                attribute vec4 aPosition;
                void main() {
                    gl_Position = aPosition;
                }
            """.trimIndent()

            val fragmentShaderCode = """
                precision highp float;
                void main() {
                    mat4 m1 = mat4(1.1, 0.2, 0.3, 0.4,
                                   0.5, 1.2, 0.7, 0.8,
                                   0.9, 0.1, 1.3, 0.2,
                                   0.3, 0.4, 0.5, 1.4);
                    mat4 m2 = mat4(0.9, 0.1, 0.2, 0.3,
                                   0.4, 0.8, 0.1, 0.2,
                                   0.3, 0.4, 0.7, 0.1,
                                   0.2, 0.3, 0.4, 0.6);
                    mat4 result = m1;
                    int i;
                    for (i = 0; i < 1000; i++) {
                        result = result * m2;
                        result = result * m2;
                        result = result * m2;
                        result = result * m2;
                        result = result * m2;
                    }
                    gl_FragColor = vec4(result[0][0], result[1][1], result[2][2], 1.0);
                }
            """.trimIndent()

            val vs = loadShader(GLES20.GL_VERTEX_SHADER, vertexShaderCode)
            val fs = loadShader(GLES20.GL_FRAGMENT_SHADER, fragmentShaderCode)

            val program = GLES20.glCreateProgram()
            GLES20.glAttachShader(program, vs)
            GLES20.glAttachShader(program, fs)
            GLES20.glLinkProgram(program)

            val linkStatus = IntArray(1)
            GLES20.glGetProgramiv(program, GLES20.GL_LINK_STATUS, linkStatus, 0)
            if (linkStatus[0] == 0) {
                val error = GLES20.glGetProgramInfoLog(program)
                throw RuntimeException("Program link failed: $error")
            }

            val vertices = floatArrayOf(
                -1f, -1f, 0f,
                 1f, -1f, 0f,
                -1f,  1f, 0f,
                 1f,  1f, 0f
            )

            val bb = java.nio.ByteBuffer.allocateDirect(vertices.size * 4)
            bb.order(java.nio.ByteOrder.nativeOrder())
            val vertexBuffer = bb.asFloatBuffer()
            vertexBuffer.put(vertices)
            vertexBuffer.position(0)

            GLES20.glUseProgram(program)
            val positionHandle = GLES20.glGetAttribLocation(program, "aPosition")
            GLES20.glEnableVertexAttribArray(positionHandle)
            GLES20.glVertexAttribPointer(positionHandle, 3, GLES20.GL_FLOAT, false, 0, vertexBuffer)

            // Warm-up
            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
            GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)
            GLES20.glFinish()

            // Benchmark: 30 draws
            val drawCount = 30
            val start = System.nanoTime()
            repeat(drawCount) {
                GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)
                GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)
            }
            GLES20.glFinish()
            val end = System.nanoTime()

            val totalMs = (end - start) / 1_000_000.0
            val avgMs = totalMs / drawCount

            // Cleanup
            GLES20.glDisableVertexAttribArray(positionHandle)
            GLES20.glDeleteProgram(program)
            GLES20.glDeleteShader(vs)
            GLES20.glDeleteShader(fs)

            CheckResult(CheckStatus.INFO, "平均单次耗时 ${String.format("%.2f", avgMs)} ms (共 ${drawCount} 次, 总计 ${String.format("%.2f", totalMs)} ms)")
        } catch (e: Exception) {
            Log.e(TAG, "GPU 运算性能测试失败: ${e.message}")
            CheckResult(CheckStatus.INFO, "测试失败: ${e.message}")
        } finally {
            EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT)
            EGL14.eglDestroySurface(display, surface)
            EGL14.eglDestroyContext(display, context)
            EGL14.eglTerminate(display)
        }
    }

    /**
     * 编译 GLES Shader
     */
    private fun loadShader(type: Int, shaderCode: String): Int {
        val shader = GLES20.glCreateShader(type)
        GLES20.glShaderSource(shader, shaderCode)
        GLES20.glCompileShader(shader)
        val compiled = IntArray(1)
        GLES20.glGetShaderiv(shader, GLES20.GL_COMPILE_STATUS, compiled, 0)
        if (compiled[0] == 0) {
            val error = GLES20.glGetShaderInfoLog(shader)
            GLES20.glDeleteShader(shader)
            throw RuntimeException("Shader compile failed: $error")
        }
        return shader
    }
}
