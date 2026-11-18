package com.hephaistos.appsign.android.system

import com.hephaistos.appsign.core.crypto.CryptoSupport
import com.hephaistos.appsign.core.model.OsBackupEntry
import com.hephaistos.appsign.core.model.OsBackupManifest
import com.hephaistos.appsign.core.ossign.OsSignResignEngine
import java.io.File
import java.util.UUID
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

  suspend fun listDirectoryViaRoot(
    dirPath: String,
    directoriesOnly: Boolean = false,
  ): Result<List<FileBrowserEntry>> =
    withContext(Dispatchers.IO) {
      runCatching {
        val normalized = dirPath.trim().ifBlank { "/" }
        val qDir = shellQuote(normalized)
        // Strict symlink-aware listing without dereferencing symlinks
        val script =
          """
          DIR=$qDir
          [ -d "${'$'}DIR" ] && [ ! -L "${'$'}DIR" ] || { echo "__ERR__:Not a real directory"; exit 1; }
          for item in "${'$'}DIR"/* "${'$'}DIR"/.[!.]*; do
            [ -e "${'$'}item" ] || [ -L "${'$'}item" ] || continue
            name=${'$'}{item##*/}
            if [ -L "${'$'}item" ]; then
              echo "L|0|${'$'}name"
            elif [ -d "${'$'}item" ]; then
              echo "D|0|${'$'}name"
            else
              sz=${'$'}(wc -c < "${'$'}item" 2>/dev/null || echo 0)
              echo "F|${'$'}sz|${'$'}name"
            fi
          done
          """.trimIndent()

        val process = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
        val finished = process.waitFor(10, TimeUnit.SECONDS)
        if (!finished) {
          process.destroyForcibly()
          throw IllegalStateException("Root directory listing timed out for $normalized")
        }
        val lines = process.inputStream.bufferedReader().readLines().filter { it.isNotBlank() }
        val errLine = lines.firstOrNull { it.startsWith("__ERR__:") }
        if (errLine != null) {
          throw IllegalStateException(errLine.removePrefix("__ERR__:"))
        }
        if (process.exitValue() != 0 && lines.isEmpty()) {
          throw IllegalStateException("Root access denied reading $normalized")
        }

        val entries =
          lines.mapNotNull { line ->
            val parts = line.split("|", limit = 3)
            if (parts.size < 3) return@mapNotNull null
            val kind = parts[0]
            val size = parts[1].trim().toLongOrNull() ?: 0L
            val name = parts[2]
            if (name == "." || name == "..") return@mapNotNull null
            val isSym = kind == "L"
            val isDir = kind == "D"
            if (directoriesOnly && !isDir && !isSym) return@mapNotNull null
            val fullPath = if (normalized == "/") "/$name" else "${normalized.trimEnd('/')}/$name"
            FileBrowserEntry(
              name = name,
              path = fullPath,
              isDirectory = isDir,
              sizeBytes = size,
              lastModifiedMs = 0L,
              isSymlink = isSym,
            )
          }
        entries.sortedWith(compareBy<FileBrowserEntry> { !it.isDirectory }.thenBy { it.name.lowercase() })
      }
    }

  suspend fun copyProtectedApkToStaging(remotePath: String, stagingDir: File): File =
    withContext(Dispatchers.IO) {
      stagingDir.mkdirs()
      val parentName = File(remotePath).parentFile?.name?.replace(Regex("[^a-zA-Z0-9._-]"), "_") ?: "app"
      val destFile = File(stagingDir, "${parentName}_base.apk")
      val cmd = "cp ${shellQuote(remotePath)} ${shellQuote(destFile.absolutePath)} && chmod 644 ${shellQuote(destFile.absolutePath)}"
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

  suspend fun stageDirectoryTreeViaRoot(remoteDir: String, stagingRoot: File): Int =
    withContext(Dispatchers.IO) {
      if (stagingRoot.exists()) stagingRoot.deleteRecursively()
      stagingRoot.mkdirs()
      val qSrc = shellQuote(remoteDir.trimEnd('/').ifBlank { "/" })
      val qDst = shellQuote(stagingRoot.absolutePath)
      // Strictly never follow symlinks (-P, ! -type l); copy regular files of interest + preserve relative layout
      val script =
        """
        SRC=$qSrc
        DST=$qDst
        [ -d "${'$'}SRC" ] && [ ! -L "${'$'}SRC" ] || exit 1
        cd "${'$'}SRC" || exit 1
        COUNT=0
        for f in ${'$'}(find . -mindepth 1 ! -type l \( -name '*.apk' -o -name '*.apex' -o -name '*.jar' -o -name '*.capex' -o -name '*.xml' -o -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.der' -o -name '*.conf' -o -name '*.json' -o -name '*.txt' \)); do
          rel="${'$'}{f#./}"
          mkdir -p "${'$'}DST/${'$'}(dirname "${'$'}rel")"
          cp -f "${'$'}f" "${'$'}DST/${'$'}rel" && chmod 644 "${'$'}DST/${'$'}rel"
          COUNT=${'$'}((COUNT+1))
        done
        echo "STAGED=${'$'}COUNT"
        """.trimIndent()
      val process = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
      val finished = process.waitFor(120, TimeUnit.SECONDS)
      if (!finished) {
        process.destroyForcibly()
        throw IllegalStateException("Root staging timed out for $remoteDir")
      }
      val output = process.inputStream.bufferedReader().readText()
      if (process.exitValue() != 0) {
        throw IllegalStateException("Root staging failed: $output")
      }
      Regex("""STAGED=(\d+)""").find(output)?.groupValues?.get(1)?.toIntOrNull() ?: 0
    }

  suspend fun applyStagedFilesInPlaceViaRoot(
    stagedRoot: File,
    remoteRootDir: File,
    relativePaths: List<String>,
    createBackups: Boolean,
  ): OsBackupManifest? =
    withContext(Dispatchers.IO) {
      if (relativePaths.isEmpty()) return@withContext null
      val backupEntries = mutableListOf<OsBackupEntry>()
      val commands = StringBuilder()
      commands.appendLine("set -e")

      for (rel in relativePaths.distinct()) {
        val stagedFile = File(stagedRoot, rel)
        if (!stagedFile.exists() || !stagedFile.isFile) continue
        val remoteOrig = File(remoteRootDir, rel).absolutePath
        val remoteBak = "${remoteOrig}${OsSignResignEngine.BACKUP_SUFFIX}"
        val qStaged = shellQuote(stagedFile.absolutePath)
        val qOrig = shellQuote(remoteOrig)
        val qBak = shellQuote(remoteBak)
        val qTmp = shellQuote("${remoteOrig}.appsign.tmp")

        // Skip symlinks strictly; preserve mode/owner
        commands.appendLine("if [ ! -L $qOrig ] && [ -f $qOrig ]; then")
        if (createBackups) {
          commands.appendLine("  if [ ! -e $qBak ] && [ ! -L $qBak ]; then cp -p $qOrig $qBak; fi")
          backupEntries += OsBackupEntry(originalPath = remoteOrig, backupPath = remoteBak, kind = "ROOT_FILE")
        }
        commands.appendLine("  cp $qStaged $qTmp")
        commands.appendLine("  chmod --reference=$qOrig $qTmp 2>/dev/null || chmod 644 $qTmp")
        commands.appendLine("  chown --reference=$qOrig $qTmp 2>/dev/null || true")
        commands.appendLine("  mv -f $qTmp $qOrig")
        commands.appendLine("fi")
      }

      val process = ProcessBuilder("su", "-c", commands.toString()).redirectErrorStream(true).start()
      val finished = process.waitFor(120, TimeUnit.SECONDS)
      if (!finished) {
        process.destroyForcibly()
        throw IllegalStateException("Root write-back timed out.")
      }
      if (process.exitValue() != 0) {
        val err = process.inputStream.bufferedReader().readText()
        throw IllegalStateException("Root write-back failed: $err")
      }
      if (createBackups && backupEntries.isNotEmpty()) {
        OsBackupManifest(
          sessionId = UUID.randomUUID().toString(),
          rootDirectory = remoteRootDir.absolutePath,
          createdAtIso = CryptoSupport.nowIso(),
          entries = backupEntries,
        )
      } else {
        null
      }
    }

  suspend fun restoreRootBackups(manifest: OsBackupManifest): Pair<Int, List<String>> =
    withContext(Dispatchers.IO) {
      val errors = mutableListOf<String>()
      var restored = 0
      val script = buildString {
        for (entry in manifest.entries) {
          val qOrig = shellQuote(entry.originalPath)
          val qBak = shellQuote(entry.backupPath)
          appendLine("if [ ! -L $qOrig ] && [ ! -L $qBak ] && [ -f $qBak ]; then")
          appendLine("  if mv -f $qBak $qOrig; then echo \"RESTORED:${entry.originalPath}\"; else echo \"ERR:Failed ${entry.originalPath}\"; fi")
          appendLine("fi")
        }
      }
      val process = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
      process.waitFor(60, TimeUnit.SECONDS)
      for (line in process.inputStream.bufferedReader().readLines()) {
        if (line.startsWith("RESTORED:")) restored++
        if (line.startsWith("ERR:")) errors += line.removePrefix("ERR:")
      }
      restored to errors
    }

  suspend fun deleteRootBackups(manifest: OsBackupManifest): Pair<Int, List<String>> =
    withContext(Dispatchers.IO) {
      val errors = mutableListOf<String>()
      var deleted = 0
      val script = buildString {
        for (entry in manifest.entries) {
          val qBak = shellQuote(entry.backupPath)
          appendLine("if [ ! -L $qBak ] && [ -f $qBak ]; then")
          appendLine("  if rm -f $qBak; then echo \"DEL:${entry.backupPath}\"; else echo \"ERR:Failed ${entry.backupPath}\"; fi")
          appendLine("fi")
        }
      }
      val process = ProcessBuilder("su", "-c", script).redirectErrorStream(true).start()
      process.waitFor(60, TimeUnit.SECONDS)
      for (line in process.inputStream.bufferedReader().readLines()) {
        if (line.startsWith("DEL:")) deleted++
        if (line.startsWith("ERR:")) errors += line.removePrefix("ERR:")
      }
      deleted to errors
    }

  private fun shellQuote(arg: String): String = "'" + arg.replace("'", "'\\''") + "'"
}
