import com.klaxit.hiddensecrets.Utils
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.shouldBe
import java.io.File

/**
 * Test Utils methods.
 */
class UtilsTest : WordSpec({

    val keyHash = "5ptCUaVG+0JGgprlT1yKuyJrUI4="
    val packageName = "com.klaxit.test"

    "Using getCppName()" should {
        "transform package separator" {
            Utils.getCppName(packageName) shouldBe "com_klaxit_test"
        }
        "transform package with underscore" {
            Utils.getCppName("com.klaxit.test_with_underscore") shouldBe "com_klaxit_test_1with_1underscore"
        }
        "transform package with escaping characters" {
            Utils.getCppName("com[test.klaxit;test.test_with_underscore") shouldBe "com_3test_klaxit_2test_test_1with_1underscore"
        }
    }

    "Using sha256()" should {
        "encode String in sha256" {
            val key = "youCanNotFindMySecret!"
            Utils.sha256(key) shouldBe "7bdc2b5992ef7b4cce0e06295f564f4fad0c96e5f82a0bcf9cd8323d3a3bcfbd"
        }
    }

    "Using encodeSecret()" should {
        "encode String with a seed" {
            val key = "keyToEncode"
            Utils.encodeSecret(
                key,
                keyHash,
                packageName
            ) shouldBe "{ 0x52, 0x1, 0x18, 0x6d, 0x5f, 0x21, 0xb, 0x55, 0x59, 0x57, 0x5d }"
        }
        "encode String with special characters" {
            val key = "@&é(§èçà)-ù,;:=#°_*%£?./+"
            Utils.encodeSecret(
                key,
                keyHash,
                packageName
            ) shouldBe "{ 0x79, 0x42, 0xa2, 0x90, 0x18, 0xa6, 0xc2, 0xf5, 0x9e, 0xf0, 0x9f, 0xa0, 0x90, 0x1f, 0x1d, 0xa6, 0x80, 0x1e, 0x58, 0x58, 0xe, 0x15, 0xa1, 0x88, 0x6a, 0x13, 0x14, 0xf3, 0xc5, 0x9, 0x4b, 0x1f, 0x4f }"
        }
    }

    "Using getKotlinFilePackage()" should {
        "find package name" {
            val kotlinFile = File("filename.kt")
            kotlinFile.writeText(
                "package com.test.activity\n" +
                    "\n" +
                    "import android.test.Intent\n" +
                    "import android.test.Bundle"
            )
            val kotlinPackage = Utils.getKotlinFilePackage(kotlinFile)
            kotlinFile.delete()
            kotlinPackage shouldBe "com.test.activity"
        }
        "find package name with escaping characters" {
            val kotlinFile = File("filename.kt")
            kotlinFile.writeText("package com.test.`object`\n" +
                "\n" +
                "import com.test.Hidden\n" +
                "import com.test.constant.NetworkConstants")
            val kotlinPackage = Utils.getKotlinFilePackage(kotlinFile)
            kotlinFile.delete()
            kotlinPackage shouldBe "com.test.object"
        }
    }
})
