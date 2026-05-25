package qpdb.env.check

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import qpdb.env.check.checkers.KeyAttestationChecker

@RunWith(AndroidJUnit4::class)
class KeyAttestationInstrumentedTest {

    @Test
    fun runKeyAttestationCheck() {
        val checker = KeyAttestationChecker()
        val items = checker.runCheck()
        items.forEach {
            Log.i("KeyAttestationTest", "[RESULT] ${it.checkPoint}: status=${it.status}")
            Log.i("KeyAttestationTest", "[DESC] ${it.description.replace("\n", " | ")}")
        }
    }
}
