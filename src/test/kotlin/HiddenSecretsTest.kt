import com.klaxit.hiddensecrets.HiddenSecretsPlugin
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.string.shouldContain
import org.gradle.testkit.runner.GradleRunner
import org.junit.rules.TemporaryFolder

/**
 * Test that HiddenSecrets commands are working.
 */
class HiddenSecretsTest : WordSpec({

    "Apply the plugin" should {
        val testProjectDir = TemporaryFolder()
        testProjectDir.create()
        val buildFile = testProjectDir.newFile("build.gradle")
        buildFile.appendText("""
        plugins {
            id 'com.klaxit.hiddensecrets'
            id 'com.android.application'
        }
        android {
            compileSdkVersion 29
        }
        """.trimIndent())
        val gradleRunner = GradleRunner.create()
            .withPluginClasspath()
            .withProjectDir(testProjectDir.root)
            .withTestKitDir(testProjectDir.newFolder())

        // Properties
        val key = "thisIsATestKey"
        val packageName = "com.package.test"
        val keyHash = "5ptCUaVG+0JGgprlT1yKuyJrUI4="

        "Make command ${HiddenSecretsPlugin.TASK_COPY_CPP} succeed" {
            val result = gradleRunner.withArguments(HiddenSecretsPlugin.TASK_COPY_CPP).build()
            println(result.output)
        }

        "Make command ${HiddenSecretsPlugin.TASK_COPY_KOTLIN} succeed" {
            val result = gradleRunner.withArguments(HiddenSecretsPlugin.TASK_COPY_KOTLIN, "-Ppackage=$packageName").build()
            println(result.output)
        }

        "Make command ${HiddenSecretsPlugin.TASK_OBFUSCATE} succeed" {
            val result = gradleRunner.withArguments(HiddenSecretsPlugin.TASK_OBFUSCATE, "-Pkey=$key", "-Ppackage=$packageName", "-PkeyHash=$keyHash").build()
            println(result.output)
            // Should contain obfuscated key
            result.output shouldContain "{ 0x45, 0xd, 0x5e, 0x42, 0x7d, 0x10, 0x76, 0x36, 0x6, 0x15, 0x16, 0x73, 0x51, 0x18 }"
        }

        "Make command ${HiddenSecretsPlugin.TASK_PACKAGE_NAME} succeed" {
            val result = gradleRunner.withArguments(HiddenSecretsPlugin.TASK_PACKAGE_NAME, "-Ppackage=$packageName").build()
            println(result.output)
            result.output shouldContain packageName
        }

        "Make command ${HiddenSecretsPlugin.TASK_FIND_KOTLIN_FILE} succeed" {
            val result = gradleRunner.withArguments(HiddenSecretsPlugin.TASK_FIND_KOTLIN_FILE).build()
            println(result.output)
        }
    }
})
