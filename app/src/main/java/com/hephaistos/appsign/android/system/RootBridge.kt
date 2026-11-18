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

private enum class RootNamespaceMode {
  MOUNT_MASTER_LONG,
  MOUNT_MASTER_SHORT,
  NSENTER_PID1,
  PLAIN,
}

object RootBridge {

  @Volatile
  private var resolvedMode: RootNamespaceMode? = null

  private fun buildSuProcessBuilder(mode: RootNamespaceMode, script: String): ProcessBuilder {
    return when (mode) {
      RootNamespaceMode.MOUNT_MASTER_LONG -> ProcessBuilder("su", "--mount-master", "-c", script)
      RootNamespaceMode.MOUNT_MASTER_SHORT -> ProcessBuilder("su", "-mm", "-c", script)
      RootNamespaceMode.NSENTER_PID1 ->
        ProcessBuilder("su", "-c", "nsenter -t 1 -m -- sh -c ${shellQuote(script)}")
      RootNamespaceMode.PLAIN -> ProcessBuilder("su", "-c", script)
    }
  }

  private fun ensureRootNamespaceMode(): RootNamespaceMode {
    resolvedMode?.let { return it }
    val testScript = "id; echo __CNT__=$(ls -1A /data/data 2>/dev/null | wc -l)"
    var bestMode: RootNamespaceMode = RootNamespaceMode.PLAIN
    var bestCount = -1

    for (candidate in listOf(
      RootNamespaceMode.MOUNT_MASTER_LONG,
      RootNamespaceMode.MOUNT_MASTER_SHORT,
      RootNamespaceMode.NSENTER_PID1,
      RootNamespaceMode.PLAIN,
    )) {
      val run =
        runCatching {
          val p = buildSuProcessBuilder(candidate, testScript).redirectErrorStream(true).start()
          if (!p.waitFor(4, TimeUnit.SECONDS)) {
            p.destroyForcibly()
            return@runCatching null
          }
          val out = p.inputStream.bufferedReader().readText()
          if (p.exitValue() == 0 && out.contains("uid=0")) {
            val cnt = Regex("""__CNT__=(\d+)""").find(out)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            cnt
          } else {
            null
          }
        }.getOrNull()
      if (run != null && run > bestCount) {
        bestCount = run
        bestMode = candidate
      }
    }

    resolvedMode = bestMode
    return bestMode
  }

  private fun startRootScript(script: String): Process {
    val mode = ensureRootNamespaceMode()
    return buildSuProcessBuilder(mode, script).redirectErrorStream(true).start()
  }

  suspend fun probeRootAccess(): RootProbeResult =
    withContext(Dispatchers.IO) {
      resolvedMode = null
      runCatching {
        val process = startRootScript("id")
        val finished = process.waitFor(5, TimeUnit.SECONDS)
        if (!finished) {
          process.destroyForcibly()
          return@runCatching RootProbeResult(available = false, error = "su timed out")
        }
        val output = process.inputStream.bufferedReader().readText().trim()
        val ok = process.exitValue() == 0 && output.contains("uid=0")
        RootProbeResult(
          available = ok,
          identity = if (ok) "$output (${resolvedMode?.name})" else output,
          error = if (ok) null else output.ifBlank { "Exit code ${process.exitValue()}" },
        )
      }.getOrElse { err ->
        RootProbeResult(available = false, error = err.message ?: "su binary not found")
      }
    }

  suspend fun listInstalledApksViaRoot(): Result<List<RootApkCandidate>> =
    withContext(Dispatchers.IO) {
      runCatching {
        val process = startRootScript("find /data/app -maxdepth 4 -type f -name 'base.apk' 2>/dev/null | head -n 120")
        val finished = process.waitFor(10, TimeUnit.SECONDS)
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
        // Strict symlink-aware child listing: never dereference child symlinks
        val script =
          """
          DIR=$qDir
          [ -d "${'$'}DIR" ] || { echo "__ERR__:Directory not found: ${'$'}DIR"; exit 1; }
          for item in "${'$'}DIR"/* "${'$'}DIR"/.[!.]*; do
            name=${'$'}{item##*/}
            [ "${'$'}name" = "*" ] || [ "${'$'}name" = ".[!.]*" ] && [ ! -e "${'$'}item" ] && [ ! -L "${'$'}item" ] && continue
            if [ -L "${'$'}item" ]; then
              echo "L|0|${'$'}name"
            elif [ -d "${'$'}item" ]; then
              echo "D|0|${'$'}name"
            elif [ -e "${'$'}item" ]; then
              sz=${'$'}(stat -c %s "${'$'}item" 2>/dev/null || wc -c < "${'$'}item" 2>/dev/null || echo 0)
              echo "F|${'$'}sz|${'$'}name"
            fi
          done
          """.trimIndent()

        val process = startRootScript(script)
        val finished = process.waitFor(20, TimeUnit.SECONDS)
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
      val process = startRootScript(cmd)
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
      val cleanRemote = remoteDir.trim().trimEnd('/').ifBlank { "/" }
      val qSrc = shellQuote(cleanRemote)
      val qDst = shellQuote(stagingRoot.absolutePath)
      // Strictly never follow symlinks inside traversal (-type l -prune); handle spaces safely via read -r
      val script =
        """
        SRC=$qSrc
        DST=$qDst
        [ -d "${'$'}SRC" ] || { echo "__ERR__:Directory not found under root: ${'$'}SRC"; exit 1; }
        cd "${'$'}SRC" || { echo "__ERR__:Cannot enter directory: ${'$'}SRC"; exit 1; }
        COUNT=0
        find . -mindepth 1 -type l -prune -o -type f ! -name '*.appsign.bak' ! -name '*.bak' \( -name '*.apk' -o -name '*.apex' -o -name '*.capex' -o -name '*.jar' -o -name '*.idsig' -o -name '*.xml' -o -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.der' -o -name '*.avbpubkey' -o -name '*.pubkey' -o -name '*.conf' -o -name '*.cfg' -o -name '*.json' -o -name '*.txt' -o -name '*.prop' -o -name '*.rc' -o -name '*.policy' -o -name '*.info' \) -print | while IFS= read -r f; do
          rel="${'$'}{f#./}"
          dir_rel="${'$'}(dirname "${'$'}rel")"
          mkdir -p "${'$'}DST/${'$'}dir_rel"
          if cp -f "${'$'}f" "${'$'}DST/${'$'}rel"; then
            chmod 644 "${'$'}DST/${'$'}rel" 2>/dev/null || true
            COUNT=${'$'}((COUNT+1))
          fi
        done
        echo "STAGED=1"
        """.trimIndent()
      val process = startRootScript(script)
      val finished = process.waitFor(180, TimeUnit.SECONDS)
      if (!finished) {
        process.destroyForcibly()
        throw IllegalStateException("Root staging timed out for $cleanRemote")
      }
      val output = process.inputStream.bufferedReader().readText()
      val errLine = output.lineSequence().firstOrNull { it.startsWith("__ERR__:") }
      if (errLine != null) {
        throw IllegalStateException(errLine.removePrefix("__ERR__:"))
      }
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

        // Skip symlinks strictly; preserve mode, owner, and SELinux context cleanly on toybox/Android
        commands.appendLine("if [ ! -L $qOrig ] && [ -f $qOrig ]; then")
        if (createBackups) {
          commands.appendLine("  if [ ! -e $qBak ] && [ ! -L $qBak ]; then cp -p $qOrig $qBak; fi")
          backupEntries += OsBackupEntry(originalPath = remoteOrig, backupPath = remoteBak, kind = "ROOT_FILE")
        }
        commands.appendLine("  MODE=$(stat -c %a $qOrig 2>/dev/null || echo 644)")
        commands.appendLine("  OWNER=$(stat -c %u:%g $qOrig 2>/dev/null || echo '')")
        commands.appendLine("  cp $qStaged $qTmp")
        commands.appendLine("  chmod \"\$MODE\" $qTmp 2>/dev/null || chmod 644 $qTmp")
        commands.appendLine("  [ -n \"\$OWNER\" ] && chown \"\$OWNER\" $qTmp 2>/dev/null || true")
        commands.appendLine("  chcon --reference=$qOrig $qTmp 2>/dev/null || true")
        commands.appendLine("  mv -f $qTmp $qOrig")
        commands.appendLine("fi")
      }

      val process = startRootScript(commands.toString())
      val finished = process.waitFor(180, TimeUnit.SECONDS)
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
      val process = startRootScript(script)
      process.waitFor(90, TimeUnit.SECONDS)
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
      val process = startRootScript(script)
      process.waitFor(90, TimeUnit.SECONDS)
      for (line in process.inputStream.bufferedReader().readLines()) {
        if (line.startsWith("DEL:")) deleted++
        if (line.startsWith("ERR:")) errors += line.removePrefix("ERR:")
      }
      deleted to errors
    }

  private fun shellQuote(arg: String): String = "'" + arg.replace("'", "'\\''") + "'"
}
