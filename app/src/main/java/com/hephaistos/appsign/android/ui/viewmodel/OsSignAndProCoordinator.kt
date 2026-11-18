package com.hephaistos.appsign.android.ui.viewmodel

import android.content.Context
import android.net.Uri
import com.hephaistos.appsign.android.data.local.ManagedKeyEntity
import com.hephaistos.appsign.android.data.repository.HistoryRepository
import com.hephaistos.appsign.android.data.repository.KeyRegistryRepository
import com.hephaistos.appsign.android.system.DeviceStorageHelper
import com.hephaistos.appsign.android.system.RootBridge
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.model.AskContainer
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.OsBackupManifest
import com.hephaistos.appsign.core.model.OsResignKeyStrategy
import com.hephaistos.appsign.core.model.OsSignInspectionReport
import com.hephaistos.appsign.core.model.OsSignResignReport
import com.hephaistos.appsign.core.model.ResignProResult
import com.hephaistos.appsign.core.model.TargetSignatureProfile
import com.hephaistos.appsign.core.ossign.OsResignPlan
import com.hephaistos.appsign.core.ossign.OsSignAnalyzerEngine
import com.hephaistos.appsign.core.ossign.OsSignResignEngine
import com.hephaistos.appsign.core.pro.ResignProEngine
import com.hephaistos.appsign.core.report.ReportFormatters
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable

data class OsSignUiState(
  val targetDirPath: String = "",
  val viaRoot: Boolean = false,
  val isRunning: Boolean = false,
  val progressLabel: String = "",
  val progressCurrent: Int = 0,
  val progressTotal: Int = 0,
  val inspectionReport: OsSignInspectionReport? = null,
  val resignReport: OsSignResignReport? = null,
  val activeBackupManifest: OsBackupManifest? = null,
  val activeBackupViaRoot: Boolean = false,
  val showStrategyDialog: Boolean = false,
  val createBackups: Boolean = true,
  val statusMessage: String? = null,
  val errorMessage: String? = null,
)

@Serializable
data class PersistedOsBackupState(
  val viaRoot: Boolean,
  val manifest: OsBackupManifest,
)

class OsSignAndProCoordinator(
  private val appContext: Context,
  private val keyRepo: KeyRegistryRepository,
  private val historyRepo: HistoryRepository,
) {
  private val askKeysDir: File
    get() = File(appContext.filesDir, "appsign_keys").apply { mkdirs() }

  private val osStagingDir: File
    get() = File(appContext.cacheDir, "appsign_os_staging")

  private val persistedManifestFile: File
    get() = File(appContext.filesDir, "appsign_os_backups.json")

  fun loadPersistedBackupState(): PersistedOsBackupState? =
    runCatching {
      if (!persistedManifestFile.exists()) return null
      ReportFormatters.json.decodeFromString(
        PersistedOsBackupState.serializer(),
        persistedManifestFile.readText(Charsets.UTF_8),
      )
    }.getOrNull()

  fun savePersistedBackupState(viaRoot: Boolean, manifest: OsBackupManifest?) {
    if (manifest == null || manifest.entries.isEmpty()) {
      persistedManifestFile.delete()
      return
    }
    val payload = PersistedOsBackupState(viaRoot = viaRoot, manifest = manifest)
    persistedManifestFile.writeText(
      ReportFormatters.json.encodeToString(PersistedOsBackupState.serializer(), payload),
      Charsets.UTF_8,
    )
  }

  suspend fun analyzeResignProTarget(apkFile: File): TargetSignatureProfile =
    withContext(Dispatchers.IO) { ResignProEngine.analyzeTarget(apkFile) }

  suspend fun executeResignPro(
    targets: List<SelectedApkTarget>,
    analyzedProfile: TargetSignatureProfile?,
    identities: List<IdentityInput>,
    workDir: File,
    safTreeUri: Uri?,
  ): ResignProResult {
    val createdContainers = mutableListOf<AskContainer>()
    var primaryProResult: ResignProResult? = null

    for ((idx, target) in targets.withIndex()) {
      val outFile = File(workDir, "${target.localFile.nameWithoutExtension}-resignpro.apk")
      val result =
        withContext(Dispatchers.IO) {
          ResignProEngine.resignPro(
            inputApk = target.localFile,
            outputApk = outFile,
            identities = identities,
            askOutputDir = askKeysDir,
            targetProfileOverride = if (idx == 0) analyzedProfile else null,
            onAskCreated = { container, _ -> createdContainers += container },
          )
        }
      if (result.resignResult.success && safTreeUri != null) {
        withContext(Dispatchers.IO) {
          runCatching {
            DeviceStorageHelper.copyFileToSafTree(
              appContext,
              outFile,
              safTreeUri,
              "application/vnd.android.package-archive",
            )
            result.resignResult.v4IdsigOutputPath?.let { idsig ->
              DeviceStorageHelper.copyFileToSafTree(appContext, File(idsig), safTreeUri)
            }
          }
        }
      }
      if (primaryProResult == null) primaryProResult = result
      historyRepo.logOperation(
        operationType = "RESIGNPRO",
        fileNames = target.displayName,
        keyAlias = result.generatedAskContainers.firstOrNull()?.metadata?.alias,
        status = if (result.resignResult.success) "SUCCESS" else "FAILED",
        detailsSummary =
          if (result.resignResult.success) {
            val spec = result.targetProfile.signerProfiles.firstOrNull()?.keySpec
            "Cloned ${spec?.keyAlgorithm} ${spec?.keySizeBits}-bit -> ${outFile.name}"
          } else {
            result.resignResult.errorMessage ?: "RESIGNPRO failed"
          },
        reportJson = ReportFormatters.resignProToJson(result),
      )
    }

    createdContainers.distinctBy { it.keyId }.forEach { container ->
      keyRepo.registerContainer(container)
    }
    return primaryProResult ?: throw IllegalStateException("No target APK processed.")
  }

  suspend fun runOsVerify(
    targetDirPath: String,
    viaRoot: Boolean,
    onProgress: (Int, String) -> Unit,
  ): OsSignInspectionReport {
    val scanRoot =
      if (viaRoot) {
        onProgress(0, "Root staging...")
        RootBridge.stageDirectoryTreeViaRoot(targetDirPath, osStagingDir)
        osStagingDir
      } else {
        File(targetDirPath)
      }

    val rawReport = withContext(Dispatchers.IO) { OsSignAnalyzerEngine.analyzeDirectory(scanRoot, onProgress) }
    val normalizedReport =
      if (viaRoot) {
        rawReport.copy(rootDirectory = targetDirPath)
      } else {
        rawReport
      }
    historyRepo.logOperation(
      operationType = "OS_VERIFY",
      fileNames = File(targetDirPath).name.ifBlank { targetDirPath },
      keyAlias = "${normalizedReport.groups.size} groups",
      status = "SUCCESS",
      detailsSummary =
        "Signed=${normalizedReport.signedArtifactsCount}, Preserved=${normalizedReport.preservedUnsignedCount}, SymlinksIgnored=${normalizedReport.symlinksIgnoredCount}",
      reportJson = ReportFormatters.osSignInspectionToJson(normalizedReport),
    )
    return normalizedReport
  }

  suspend fun runOsResign(
    targetDirPath: String,
    viaRoot: Boolean,
    existingInspection: OsSignInspectionReport?,
    strategy: OsResignKeyStrategy,
    identitiesPerGroup: Map<String, IdentityInput>,
    selectedKeysPerGroup: Map<String, ManagedKeyEntity>,
    passphrasesPerGroup: Map<String, CharArray>,
    clonePassphrase: CharArray?,
    createBackups: Boolean,
    onProgress: (Int, Int, String) -> Unit,
  ): OsSignResignReport {
    val inspection =
      existingInspection
        ?: runOsVerify(targetDirPath, viaRoot) { count, label -> onProgress(count, 0, label) }

    val unlockedMap =
      if (strategy == OsResignKeyStrategy.USE_EXISTING_KEYS) {
        withContext(Dispatchers.IO) {
          inspection.groups.associate { grp ->
            val entity =
              selectedKeysPerGroup[grp.groupId]
                ?: throw IllegalArgumentException("Missing key for group ${grp.label}")
            grp.groupId to keyRepo.unlockKey(entity, passphrasesPerGroup[grp.groupId])
          }
        }
      } else {
        emptyMap()
      }

    val createdContainers = mutableListOf<AskContainer>()
    val plan =
      OsResignPlan(
        strategy = strategy,
        identityPerGroup = identitiesPerGroup,
        existingKeyPerGroup = unlockedMap,
        clonePassphrase = clonePassphrase,
        createBackups = if (viaRoot) false else createBackups,
      )

    val rawReport =
      withContext(Dispatchers.IO) {
        OsSignResignEngine.executeResign(
          inspection = inspection,
          plan = plan,
          askOutputDir = askKeysDir,
          onAskCreated = { container, _ -> createdContainers += container },
          onProgress = onProgress,
        )
      }

    createdContainers.distinctBy { it.keyId }.forEach { container ->
      keyRepo.registerContainer(container)
    }

    val finalManifest =
      if (viaRoot) {
        val changedRelPaths =
          (rawReport.outcomes.filter { it.success }.map { it.relativePath } +
            inspection.allPermissionReferences.map { it.relativePath }).distinct()
        RootBridge.applyStagedFilesInPlaceViaRoot(
          stagedRoot = osStagingDir,
          remoteRootDir = File(targetDirPath),
          relativePaths = changedRelPaths,
          createBackups = createBackups,
        )
      } else {
        rawReport.backupManifest
      }

    val finalReport =
      rawReport.copy(
        rootDirectory = targetDirPath,
        backupManifest = finalManifest,
      )

    if (finalManifest != null) {
      savePersistedBackupState(viaRoot = viaRoot, manifest = finalManifest)
    }

    historyRepo.logOperation(
      operationType = "OS_RESIGN",
      fileNames = File(targetDirPath).name.ifBlank { targetDirPath },
      keyAlias = strategy.name,
      status = if (finalReport.totalFailed == 0) "SUCCESS" else "WARNING",
      detailsSummary =
        "Succeeded=${finalReport.totalSucceeded}/${finalReport.totalResigned}, Refs=${finalReport.totalReferencesUpdated}, SymlinksIgnored=${finalReport.symlinksIgnoredCount}",
      reportJson = ReportFormatters.osSignResignToJson(finalReport),
    )
    return finalReport
  }

  suspend fun restoreBackups(manifest: OsBackupManifest, viaRoot: Boolean): Pair<Int, List<String>> {
    val result =
      withContext(Dispatchers.IO) {
        if (viaRoot) RootBridge.restoreRootBackups(manifest)
        else OsSignResignEngine.restoreFromBackups(manifest)
      }
    if (result.second.isEmpty()) {
      persistedManifestFile.delete()
    }
    return result
  }

  suspend fun deleteBackups(manifest: OsBackupManifest, viaRoot: Boolean): Pair<Int, List<String>> {
    val result =
      withContext(Dispatchers.IO) {
        if (viaRoot) RootBridge.deleteRootBackups(manifest)
        else OsSignResignEngine.deleteBackups(manifest)
      }
    if (result.second.isEmpty()) {
      persistedManifestFile.delete()
    }
    return result
  }
}
