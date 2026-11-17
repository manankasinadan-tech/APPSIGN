package com.hephaistos.appsign.android.system

import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class RootProbeResult(
  val available: Boolean,
  val identity: String = "",
  val error: String? = null,
)

data class RootApkCandidate(
  val packageFolder: String,
  val apkPath: String,
  val displayLabel: String,
)

object RootBridge {

  suspend fun probeRootAccess(): RootProbeResult =
    withContext(Dispatchers.IO) {
      runCatching {
        val process = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
        val finished = process.waitFor(4, TimeUnit.SECONDS)
        if (!finished) {
          process.destroyForcibly()
          return@runCatching RootProbeResult(available = false, error = "su timed out")
        }
        val output = process.inputStream.bufferedReader().readText().trim()
        val ok = process.exitValue() == 0 && output.contains("uid=0")
        RootProbeResult(
          available = ok,
          identity = output,
          error = if (ok) null else output.ifBlank { "Exit code ${process.exitValue()}" },
        )
      }.getOrElse { err ->
        RootProbeResult(available = false, error = err.message ?: "su binary not found")
      }
    }

  suspend fun listInstalledApksViaRoot(): Result<List<RootApkCandidate>> =
    withContext(Dispatchers.IO) {
      runCatching {
        val process =
          ProcessBuilder(
              "su",
              "-c",
              "find /data/app -maxdepth 4 -type f -name 'base.apk' 2>/dev/null | head -n 120",
            )
            .redirectErrorStream(false)
            .start()
        val finished = process.waitFor(8, TimeUnit.SECONDS)
        if (!finished) {
          process.destroyForcibly()
          throw IllegalStateException("Root scan timed out.")
        }
        val lines = process.inputStream.bufferedReader().readLines().filter { it.isNotBlank() }
        if (process.exitValue() != 0 && lines.isEmpty()) {
          throw IllegalStateException("Root access denied or no APKs accessible.")
        }
        lines.map { path ->
          val parent = File(path).parentFile?.name ?: path
          val cleanPkg = parent.removePrefix("~~").substringBefore("-")
          RootApkCandidate(
            packageFolder = parent,
            apkPath = path,
            displayLabel = if (cleanPkg.isNotBlank()) "$cleanPkg (base.apk)" else path,
          )
        }.sortedBy { it.displayLabel.lowercase() }
      }
    }

  suspend fun copyProtectedApkToStaging(remotePath: String, stagingDir: File): File =
    withContext(Dispatchers.IO) {
      stagingDir.mkdirs()
      val parentName = File(remotePath).parentFile?.name?.replace(Regex("[^a-zA-Z0-9._-]"), "_") ?: "app"
      val destFile = File(stagingDir, "${parentName}_base.apk")
      val cmd = "cp \"$remotePath\" \"${destFile.absolutePath}\" && chmod 644 \"${destFile.absolutePath}\""
      val process = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
      val finished = process.waitFor(15, TimeUnit.SECONDS)
      if (!finished) {
        process.destroyForcibly()
        throw IllegalStateException("Root copy timed out for $remotePath")
      }
      if (process.exitValue() != 0 || !destFile.exists()) {
        val err = process.inputStream.bufferedReader().readText().trim()
        throw IllegalStateException("Root copy failed: $err")
      }
      destFile
    }
}
