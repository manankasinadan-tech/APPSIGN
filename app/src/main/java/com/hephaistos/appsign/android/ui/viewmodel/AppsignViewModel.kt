package com.hephaistos.appsign.android.ui.viewmodel

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.ui.theme.ThemePreference
import com.hephaistos.appsign.android.data.local.AppsignDatabase
import com.hephaistos.appsign.android.data.local.ManagedKeyEntity
import com.hephaistos.appsign.android.data.local.OperationHistoryEntity
import com.hephaistos.appsign.android.data.repository.AppLanguage
import com.hephaistos.appsign.android.data.repository.AppSettings
import com.hephaistos.appsign.android.data.repository.HistoryRepository
import com.hephaistos.appsign.android.data.repository.KeyRegistryRepository
import com.hephaistos.appsign.android.data.repository.SettingsRepository
import com.hephaistos.appsign.android.system.DeviceStorageHelper
import com.hephaistos.appsign.android.system.RootBridge
import com.hephaistos.appsign.android.system.RootProbeResult
import com.hephaistos.appsign.core.apk.ApkSignerEngine
import com.hephaistos.appsign.core.apk.ApkVerifierEngine
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.ask.AskPasswordRequiredException
import com.hephaistos.appsign.core.model.ApkResignResult
import com.hephaistos.appsign.core.model.ApkVerificationReport
import com.hephaistos.appsign.core.model.AskInspectResult
import com.hephaistos.appsign.core.model.AskMode
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.IdentityInput
import com.hephaistos.appsign.core.model.OsResignKeyStrategy
import com.hephaistos.appsign.core.model.ResignProResult
import com.hephaistos.appsign.core.model.SigningOptions
import com.hephaistos.appsign.core.model.TargetSignatureProfile
import com.hephaistos.appsign.core.model.VerificationStatus
import com.hephaistos.appsign.core.report.ReportFormatters
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class SelectedApkTarget(
  val displayName: String,
  val localFile: File,
  val sourceLabel: String,
)

data class VerifyUiState(
  val targets: List<SelectedApkTarget> = emptyList(),
  val isRunning: Boolean = false,
  val currentIndex: Int = 0,
  val currentFileName: String = "",
  val reports: List<ApkVerificationReport> = emptyList(),
  val errorMessage: String? = null,
)

sealed interface SigningKeySource {
  data class ManagedAsk(val entity: ManagedKeyEntity) : SigningKeySource
  data class ExternalKeyFile(val file: File, val formatHint: String) : SigningKeySource
}

data class ResignUiState(
  val targets: List<SelectedApkTarget> = emptyList(),
  val selectedKeySource: SigningKeySource? = null,
  val enableV1: Boolean = true,
  val enableV2: Boolean = true,
  val enableV3: Boolean = true,
  val enableV31: Boolean = false,
  val enableV4: Boolean = false,
  val alignBeforeSign: Boolean = true,
  val outputDirectoryPath: String = "/sdcard/APPSIGN/signed",
  val outputTreeUri: Uri? = null,
  val outputTreeLabel: String? = null,
  val isRunning: Boolean = false,
  val currentIndex: Int = 0,
  val currentFileName: String = "",
  val results: List<ApkResignResult> = emptyList(),
  val needsKeyPasswordFor: SigningKeySource? = null,
  val errorMessage: String? = null,
  // RESIGNPRO additions
  val isProMode: Boolean = false,
  val isAnalyzingPro: Boolean = false,
  val analyzedProProfile: TargetSignatureProfile? = null,
  val proResult: ResignProResult? = null,
)

data class KeyManagerUiState(
  val inspectingResult: AskInspectResult? = null,
  val passwordPromptEntity: ManagedKeyEntity? = null,
  val exportTargetEntity: ManagedKeyEntity? = null,
  val lastSecurityWarning: String? = null,
  val statusMessage: String? = null,
  val errorMessage: String? = null,
)

class AppsignViewModel(
  private val appContext: Context,
  private val settingsRepo: SettingsRepository,
  private val historyRepo: HistoryRepository,
  private val keyRepo: KeyRegistryRepository,
) : ViewModel() {

  val settings: StateFlow<AppSettings> =
    settingsRepo.settingsFlow.stateIn(viewModelScope, SharingStarted.Eagerly, AppSettings())

  val history: StateFlow<List<OperationHistoryEntity>> =
    historyRepo.historyFlow.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  val managedKeys: StateFlow<List<ManagedKeyEntity>> =
    keyRepo.keysFlow.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

  private val _verifyState = MutableStateFlow(VerifyUiState())
  val verifyState: StateFlow<VerifyUiState> = _verifyState.asStateFlow()

  private val _resignState = MutableStateFlow(ResignUiState())
  val resignState: StateFlow<ResignUiState> = _resignState.asStateFlow()

  private val _keyUiState = MutableStateFlow(KeyManagerUiState())
  val keyUiState: StateFlow<KeyManagerUiState> = _keyUiState.asStateFlow()

  private val _osSignState = MutableStateFlow(OsSignUiState())
  val osSignState: StateFlow<OsSignUiState> = _osSignState.asStateFlow()

  private val coordinator = OsSignAndProCoordinator(appContext, keyRepo, historyRepo)

  private val _hasStoragePermission = MutableStateFlow(DeviceStorageHelper.hasFullStorageAccess(appContext))
  val hasStoragePermission: StateFlow<Boolean> = _hasStoragePermission.asStateFlow()

  private val _rootProbe = MutableStateFlow<RootProbeResult?>(null)
  val rootProbe: StateFlow<RootProbeResult?> = _rootProbe.asStateFlow()

  private val stagingDir: File
    get() = File(appContext.cacheDir, "appsign_staging").apply { mkdirs() }

  init {
    viewModelScope.launch {
      keyRepo.syncDiskKeys()
      coordinator.loadPersistedBackupState()?.let { persisted ->
        _osSignState.value =
          _osSignState.value.copy(
            targetDirPath = persisted.manifest.rootDirectory,
            viaRoot = persisted.viaRoot,
            activeBackupManifest = persisted.manifest,
            activeBackupViaRoot = persisted.viaRoot,
          )
      }
      settings.collect { s ->
        val current = _resignState.value
        if (!current.isRunning && current.results.isEmpty() && current.targets.isEmpty()) {
          _resignState.value =
            current.copy(
              enableV1 = s.defaultV1,
              enableV2 = s.defaultV2,
              enableV3 = s.defaultV3,
              enableV31 = s.defaultV31,
              enableV4 = s.defaultV4,
              alignBeforeSign = s.alignBeforeSign,
              outputDirectoryPath = s.defaultOutputDir,
            )
        }
      }
    }
  }

  fun refreshStoragePermission() {
    _hasStoragePermission.value = DeviceStorageHelper.hasFullStorageAccess(appContext)
  }

  fun probeRootAccess() {
    viewModelScope.launch {
      val result = RootBridge.probeRootAccess()
      _rootProbe.value = result
      if (!result.available && settings.value.rootAccessEnabled) {
        settingsRepo.setRootAccessEnabled(false)
      }
    }
  }

  fun setRootAccessEnabled(enabled: Boolean) {
    viewModelScope.launch {
      if (enabled) {
        val probe = RootBridge.probeRootAccess()
        _rootProbe.value = probe
        settingsRepo.setRootAccessEnabled(probe.available)
      } else {
        settingsRepo.setRootAccessEnabled(false)
      }
    }
  }

  fun updateTheme(theme: ThemePreference) = viewModelScope.launch { settingsRepo.updateTheme(theme) }

  fun updateLanguage(language: AppLanguage) = viewModelScope.launch { settingsRepo.updateLanguage(language) }

  fun updateDefaultDirs(browseDir: String, outputDir: String) =
    viewModelScope.launch {
      settingsRepo.updateDefaultDirs(browseDir, outputDir)
      _resignState.value = _resignState.value.copy(outputDirectoryPath = outputDir.trim())
    }

  fun updateSigningDefaults(v1: Boolean, v2: Boolean, v3: Boolean, v31: Boolean, v4: Boolean, align: Boolean) =
    viewModelScope.launch {
      settingsRepo.updateSigningDefaults(v1, v2, v3, v31, v4, align)
      _resignState.value =
        _resignState.value.copy(
          enableV1 = v1,
          enableV2 = v2,
          enableV3 = v3,
          enableV31 = v31,
          enableV4 = v4,
          alignBeforeSign = align,
        )
    }

  // --- VERIFY FLOW ---

  fun addVerifyUris(uris: List<Uri>) {
    if (uris.isEmpty()) return
    viewModelScope.launch {
      val added =
        uris.mapNotNull { uri ->
          runCatching {
            val file = DeviceStorageHelper.stageUriToFile(appContext, uri, File(stagingDir, "verify"))
            SelectedApkTarget(file.name, file, "SAF")
          }.getOrNull()
        }
      _verifyState.value =
        _verifyState.value.copy(
          targets = (_verifyState.value.targets + added).distinctBy { it.localFile.absolutePath },
          errorMessage = null,
        )
    }
  }

  fun addVerifyPaths(paths: List<String>) {
    val added = paths.map { path -> File(path) }.filter { it.exists() }.map { SelectedApkTarget(it.name, it, it.absolutePath) }
    _verifyState.value =
      _verifyState.value.copy(
        targets = (_verifyState.value.targets + added).distinctBy { it.localFile.absolutePath },
        errorMessage = null,
      )
  }

  fun addVerifyRootApk(remotePath: String) {
    viewModelScope.launch {
      runCatching {
        val staged = RootBridge.copyProtectedApkToStaging(remotePath, File(stagingDir, "root_verify"))
        SelectedApkTarget(File(remotePath).parentFile?.name?.plus("/base.apk") ?: staged.name, staged, "ROOT:$remotePath")
      }.onSuccess { target ->
        _verifyState.value =
          _verifyState.value.copy(
            targets = (_verifyState.value.targets + target).distinctBy { it.localFile.absolutePath },
            errorMessage = null,
          )
      }.onFailure { err ->
        _verifyState.value = _verifyState.value.copy(errorMessage = err.message)
      }
    }
  }

  fun clearVerifySelection() {
    _verifyState.value = VerifyUiState()
  }

  fun runVerification() {
    val targets = _verifyState.value.targets
    if (targets.isEmpty() || _verifyState.value.isRunning) return
    viewModelScope.launch {
      _verifyState.value = _verifyState.value.copy(isRunning = true, reports = emptyList(), errorMessage = null)
      val reports = mutableListOf<ApkVerificationReport>()
      for ((idx, target) in targets.withIndex()) {
        _verifyState.value =
          _verifyState.value.copy(currentIndex = idx + 1, currentFileName = target.displayName)
        val reportResult = withContext(Dispatchers.IO) { runCatching { ApkVerifierEngine.verify(target.localFile) } }
        reportResult.onSuccess { report ->
          reports += report
          val statusStr =
            when (report.overallStatus) {
              VerificationStatus.VALID -> "SUCCESS"
              VerificationStatus.VALID_WITH_WARNINGS -> "WARNING"
              VerificationStatus.INVALID,
              VerificationStatus.UNSIGNED -> "FAILED"
            }
          historyRepo.logOperation(
            operationType = "VERIFY",
            fileNames = target.displayName,
            keyAlias = report.allUniqueSigners.firstOrNull()?.subjectDn,
            status = statusStr,
            detailsSummary =
              "${report.overallStatus} • schemes=${report.schemeResults.filter { it.verified }.joinToString(",") { it.scheme.name }}",
            reportJson = ReportFormatters.verificationToJson(listOf(report)),
          )
        }.onFailure { err ->
          _verifyState.value = _verifyState.value.copy(errorMessage = err.message)
        }
      }
      _verifyState.value = _verifyState.value.copy(isRunning = false, reports = reports)
    }
  }

  // --- RESIGN FLOW ---

  fun addResignUris(uris: List<Uri>) {
    if (uris.isEmpty()) return
    viewModelScope.launch {
      val added =
        uris.mapNotNull { uri ->
          runCatching {
            val file = DeviceStorageHelper.stageUriToFile(appContext, uri, File(stagingDir, "resign_in"))
            SelectedApkTarget(file.name, file, "SAF")
          }.getOrNull()
        }
      _resignState.value =
        _resignState.value.copy(
          targets = (_resignState.value.targets + added).distinctBy { it.localFile.absolutePath },
          analyzedProProfile = null,
          proResult = null,
          errorMessage = null,
        )
      if (_resignState.value.isProMode) {
        analyzeTargetForPro()
      }
    }
  }

  fun addResignPaths(paths: List<String>) {
    val added = paths.map { File(it) }.filter { it.exists() }.map { SelectedApkTarget(it.name, it, it.absolutePath) }
    _resignState.value =
      _resignState.value.copy(
        targets = (_resignState.value.targets + added).distinctBy { it.localFile.absolutePath },
        analyzedProProfile = null,
        proResult = null,
        errorMessage = null,
      )
    if (_resignState.value.isProMode) {
      analyzeTargetForPro()
    }
  }

  fun selectManagedKeyForResign(entity: ManagedKeyEntity) {
    _resignState.value = _resignState.value.copy(selectedKeySource = SigningKeySource.ManagedAsk(entity), errorMessage = null)
  }

  fun selectExternalKeyUriForResign(uri: Uri) {
    viewModelScope.launch {
      runCatching {
        val staged = DeviceStorageHelper.stageUriToFile(appContext, uri, File(stagingDir, "ext_keys"))
        val hint = staged.extension.lowercase()
        _resignState.value =
          _resignState.value.copy(
            selectedKeySource = SigningKeySource.ExternalKeyFile(staged, hint),
            errorMessage = null,
          )
      }.onFailure { err ->
        _resignState.value = _resignState.value.copy(errorMessage = err.message)
      }
    }
  }

  fun updateResignSchemes(
    v1: Boolean = _resignState.value.enableV1,
    v2: Boolean = _resignState.value.enableV2,
    v3: Boolean = _resignState.value.enableV3,
    v31: Boolean = _resignState.value.enableV31,
    v4: Boolean = _resignState.value.enableV4,
    align: Boolean = _resignState.value.alignBeforeSign,
  ) {
    _resignState.value =
      _resignState.value.copy(
        enableV1 = v1,
        enableV2 = v2,
        enableV3 = v3,
        enableV31 = v31,
        enableV4 = v4,
        alignBeforeSign = align,
      )
  }

  fun setResignOutputFolderPath(path: String) {
    _resignState.value = _resignState.value.copy(outputDirectoryPath = path, outputTreeUri = null, outputTreeLabel = null)
  }

  fun setResignOutputSafTree(uri: Uri) {
    _resignState.value =
      _resignState.value.copy(
        outputTreeUri = uri,
        outputTreeLabel = uri.lastPathSegment ?: uri.toString(),
      )
  }

  fun clearResignSelection() {
    _resignState.value =
      _resignState.value.copy(
        targets = emptyList(),
        results = emptyList(),
        analyzedProProfile = null,
        proResult = null,
        errorMessage = null,
      )
  }

  fun setResignProMode(enabled: Boolean) {
    _resignState.value = _resignState.value.copy(isProMode = enabled, errorMessage = null)
    if (enabled && _resignState.value.targets.isNotEmpty() && _resignState.value.analyzedProProfile == null) {
      analyzeTargetForPro()
    }
  }

  fun analyzeTargetForPro() {
    val firstTarget = _resignState.value.targets.firstOrNull() ?: return
    if (_resignState.value.isAnalyzingPro) return
    viewModelScope.launch {
      _resignState.value = _resignState.value.copy(isAnalyzingPro = true, errorMessage = null)
      runCatching { coordinator.analyzeResignProTarget(firstTarget.localFile) }
        .onSuccess { profile ->
          _resignState.value =
            _resignState.value.copy(
              isAnalyzingPro = false,
              analyzedProProfile = profile,
              enableV1 = profile.enableV1,
              enableV2 = profile.enableV2,
              enableV3 = profile.enableV3,
              enableV31 = profile.enableV31,
              enableV4 = profile.enableV4,
              alignBeforeSign = profile.wasZipAligned || true,
            )
        }
        .onFailure { err ->
          _resignState.value = _resignState.value.copy(isAnalyzingPro = false, errorMessage = err.message)
        }
    }
  }

  fun startResignPro(identities: List<IdentityInput>) {
    val state = _resignState.value
    if (state.targets.isEmpty() || state.isRunning) return
    viewModelScope.launch {
      _resignState.value = state.copy(isRunning = true, results = emptyList(), proResult = null, errorMessage = null)
      val workDir =
        if (state.outputTreeUri != null) {
          File(appContext.cacheDir, "appsign_saf_out").apply { mkdirs() }
        } else {
          val chosen = File(state.outputDirectoryPath)
          if (DeviceStorageHelper.hasFullStorageAccess(appContext)) {
            chosen.apply { mkdirs() }
          } else {
            File(appContext.getExternalFilesDir(null) ?: appContext.filesDir, "signed").apply { mkdirs() }
          }
        }
      runCatching {
        coordinator.executeResignPro(
          targets = state.targets,
          analyzedProfile = state.analyzedProProfile,
          identities = identities,
          workDir = workDir,
          safTreeUri = state.outputTreeUri,
        )
      }.onSuccess { proRes ->
        _resignState.value =
          _resignState.value.copy(
            isRunning = false,
            analyzedProProfile = proRes.targetProfile,
            proResult = proRes,
            results = listOf(proRes.resignResult),
          )
      }.onFailure { err ->
        _resignState.value = _resignState.value.copy(isRunning = false, errorMessage = err.message)
      }
    }
  }

  fun startResign(passphrase: CharArray? = null, aliasOverride: String? = null) {
    val state = _resignState.value
    val keySource = state.selectedKeySource
    if (state.targets.isEmpty() || keySource == null || state.isRunning) return

    viewModelScope.launch {
      _resignState.value = state.copy(isRunning = true, results = emptyList(), needsKeyPasswordFor = null, errorMessage = null)
      val unlockedResult =
        withContext(Dispatchers.IO) {
          runCatching {
            when (keySource) {
              is SigningKeySource.ManagedAsk -> keyRepo.unlockKey(keySource.entity, passphrase)
              is SigningKeySource.ExternalKeyFile -> {
                val ext = keySource.formatHint
                val container =
                  when (ext) {
                    "ask" -> AskKeyManager.readAsk(keySource.file)
                    "p12", "pfx" -> AskKeyManager.importFromPkcs12(keySource.file, passphrase ?: CharArray(0), aliasOverride)
                    "jks" -> AskKeyManager.importFromJks(keySource.file, passphrase ?: CharArray(0), aliasOverride)
                    else -> AskKeyManager.readAsk(keySource.file)
                  }
                AskKeyManager.unlockAsk(container, if (container.mode == AskMode.ASK_LOCKED) passphrase else null)
              }
            }
          }
        }

      unlockedResult.onFailure { err ->
        if (err is AskPasswordRequiredException || (passphrase == null && keySource is SigningKeySource.ExternalKeyFile)) {
          _resignState.value = _resignState.value.copy(isRunning = false, needsKeyPasswordFor = keySource)
        } else {
          _resignState.value = _resignState.value.copy(isRunning = false, errorMessage = err.message)
        }
        return@launch
      }

      val material = unlockedResult.getOrThrow()
      val signingOpts =
        SigningOptions(
          enableV1 = state.enableV1,
          enableV2 = state.enableV2,
          enableV3 = state.enableV3,
          enableV31 = state.enableV31,
          enableV4 = state.enableV4,
          alignBeforeSign = state.alignBeforeSign,
        )

      val workDir =
        if (state.outputTreeUri != null) {
          File(appContext.cacheDir, "appsign_saf_out").apply { mkdirs() }
        } else {
          val chosen = File(state.outputDirectoryPath)
          if (DeviceStorageHelper.hasFullStorageAccess(appContext)) {
            chosen.apply { mkdirs() }
          } else {
            File(appContext.getExternalFilesDir(null) ?: appContext.filesDir, "signed").apply { mkdirs() }
          }
        }

      val results = mutableListOf<ApkResignResult>()
      for ((idx, target) in state.targets.withIndex()) {
        _resignState.value = _resignState.value.copy(currentIndex = idx + 1, currentFileName = target.displayName)
        val outFile = File(workDir, "${target.localFile.nameWithoutExtension}-signed.apk")
        val res = withContext(Dispatchers.IO) { ApkSignerEngine.resign(target.localFile, outFile, material, signingOpts) }
        if (res.success && state.outputTreeUri != null) {
          runCatching {
            DeviceStorageHelper.copyFileToSafTree(appContext, outFile, state.outputTreeUri, "application/vnd.android.package-archive")
            res.v4IdsigOutputPath?.let { idsig ->
              DeviceStorageHelper.copyFileToSafTree(appContext, File(idsig), state.outputTreeUri)
            }
          }
        }
        results += res
        historyRepo.logOperation(
          operationType = "RESIGN",
          fileNames = target.displayName,
          keyAlias = material.alias,
          status = if (res.success) "SUCCESS" else "FAILED",
          detailsSummary =
            if (res.success) {
              "Signed & Verified (${res.appliedSchemes.joinToString(",") { it.name }}) -> ${outFile.name}"
            } else {
              res.errorMessage ?: "Sign error"
            },
          reportJson = ReportFormatters.resignToJson(listOf(res)),
        )
      }
      _resignState.value = _resignState.value.copy(isRunning = false, results = results)
    }
  }

  fun dismissResignPasswordPrompt() {
    _resignState.value = _resignState.value.copy(needsKeyPasswordFor = null)
  }

  // --- KEY MANAGER FLOW ---

  fun createAskKey(options: CreateAskOptions, selectForResign: Boolean = false) {
    viewModelScope.launch {
      runCatching { keyRepo.createKey(options) }
        .onSuccess { entity ->
          val warning = if (entity.mode == AskMode.ASK_OPEN.name) AskKeyManager.UNENCRYPTED_WARNING_EN else null
          _keyUiState.value = _keyUiState.value.copy(lastSecurityWarning = warning, statusMessage = "Created ${entity.alias}", errorMessage = null)
          if (selectForResign) {
            selectManagedKeyForResign(entity)
          }
          historyRepo.logOperation(
            operationType = "KEY",
            fileNames = "${entity.alias}.ask",
            keyAlias = entity.alias,
            status = "SUCCESS",
            detailsSummary = "Created ${entity.mode} (${entity.algorithm} ${entity.keySizeBits}-bit)",
          )
        }
        .onFailure { err -> _keyUiState.value = _keyUiState.value.copy(errorMessage = err.message) }
    }
  }

  fun importAskUri(uri: Uri) {
    viewModelScope.launch {
      runCatching {
        val staged = DeviceStorageHelper.stageUriToFile(appContext, uri, File(stagingDir, "ask_import"))
        keyRepo.importAskFile(staged)
      }.onSuccess { entity ->
        _keyUiState.value = _keyUiState.value.copy(statusMessage = "Imported ${entity.alias}", errorMessage = null)
        historyRepo.logOperation("KEY", "${entity.alias}.ask", entity.alias, "SUCCESS", "Imported ASK (${entity.mode})")
      }.onFailure { err ->
        _keyUiState.value = _keyUiState.value.copy(errorMessage = err.message)
      }
    }
  }

  fun importExternalKeystore(
    uri: Uri,
    format: String,
    storePass: CharArray?,
    alias: String?,
    certUri: Uri?,
    askPass: CharArray?,
  ) {
    viewModelScope.launch {
      runCatching {
        val mainFile = DeviceStorageHelper.stageUriToFile(appContext, uri, File(stagingDir, "ks_import"))
        val container =
          withContext(Dispatchers.IO) {
            when (format.lowercase()) {
              "ask" -> AskKeyManager.readAsk(mainFile)
              "p12" -> AskKeyManager.importFromPkcs12(mainFile, storePass ?: CharArray(0), alias, storePass ?: CharArray(0), askPass)
              "jks" -> AskKeyManager.importFromJks(mainFile, storePass ?: CharArray(0), alias, storePass ?: CharArray(0), askPass)
              "pkcs8" -> {
                val cUri = certUri ?: throw IllegalArgumentException("X.509 certificate file is required.")
                val certFile = DeviceStorageHelper.stageUriToFile(appContext, cUri, File(stagingDir, "ks_import"))
                AskKeyManager.importFromPkcs8AndCert(mainFile, certFile, alias ?: mainFile.nameWithoutExtension, askPass)
              }
              else -> throw IllegalArgumentException("Unsupported format: $format")
            }
          }
        keyRepo.registerContainer(container)
      }.onSuccess { entity ->
        _keyUiState.value = _keyUiState.value.copy(statusMessage = "Imported ${entity.alias}", errorMessage = null)
        historyRepo.logOperation("KEY", "${entity.alias}.ask", entity.alias, "SUCCESS", "Imported from $format")
      }.onFailure { err ->
        _keyUiState.value = _keyUiState.value.copy(errorMessage = err.message)
      }
    }
  }

  fun inspectKey(entity: ManagedKeyEntity) {
    viewModelScope.launch {
      runCatching { keyRepo.inspectKey(entity) }
        .onSuccess { res -> _keyUiState.value = _keyUiState.value.copy(inspectingResult = res, errorMessage = null) }
        .onFailure { err -> _keyUiState.value = _keyUiState.value.copy(errorMessage = err.message) }
    }
  }

  fun closeInspect() {
    _keyUiState.value = _keyUiState.value.copy(inspectingResult = null)
  }

  fun requestExportKey(entity: ManagedKeyEntity) {
    _keyUiState.value = _keyUiState.value.copy(exportTargetEntity = entity, errorMessage = null)
  }

  fun closeExportKey() {
    _keyUiState.value = _keyUiState.value.copy(exportTargetEntity = null)
  }

  fun performExportKey(
    entity: ManagedKeyEntity,
    format: String,
    unlockPass: CharArray?,
    exportPass: CharArray?,
    safTreeUri: Uri?,
    directDirPath: String,
  ) {
    viewModelScope.launch {
      runCatching {
        withContext(Dispatchers.IO) {
          val container = keyRepo.readContainer(entity)
          val unlocked = AskKeyManager.unlockAsk(container, unlockPass)
          val outDir =
            if (safTreeUri != null) {
              File(appContext.cacheDir, "appsign_export").apply { mkdirs() }
            } else if (DeviceStorageHelper.hasFullStorageAccess(appContext)) {
              File(directDirPath).apply { mkdirs() }
            } else {
              File(appContext.getExternalFilesDir(null) ?: appContext.filesDir, "keys").apply { mkdirs() }
            }
          val base = entity.alias.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "key" }
          val producedFiles = mutableListOf<File>()
          var warning: String? = null

          when (format) {
            "ask-open" -> {
              val f = File(outDir, "$base.open.ask")
              val c = AskKeyManager.changeProtection(container, unlockPass, null)
              AskKeyManager.writeAsk(c, f)
              producedFiles += f
              warning = AskKeyManager.UNENCRYPTED_WARNING_EN
            }
            "ask-locked" -> {
              val f = File(outDir, "$base.locked.ask")
              val c = AskKeyManager.changeProtection(container, unlockPass, exportPass ?: throw IllegalArgumentException("Password required"))
              AskKeyManager.writeAsk(c, f)
              producedFiles += f
            }
            "p12" -> {
              val f = File(outDir, "$base.p12")
              AskKeyManager.exportToPkcs12(unlocked, f, exportPass ?: throw IllegalArgumentException("Password required"))
              producedFiles += f
            }
            "jks" -> {
              val f = File(outDir, "$base.jks")
              AskKeyManager.exportToJks(unlocked, f, exportPass ?: throw IllegalArgumentException("Password required"))
              producedFiles += f
            }
            "pkcs8" -> {
              val kf = File(outDir, "$base.pk8.pem")
              val cf = File(outDir, "$base.cert.pem")
              warning = AskKeyManager.exportToPkcs8AndCert(unlocked, kf, cf, pemEncoded = true)
              producedFiles += kf
              producedFiles += cf
            }
          }

          if (safTreeUri != null) {
            producedFiles.forEach { file -> DeviceStorageHelper.copyFileToSafTree(appContext, file, safTreeUri) }
          }
          producedFiles.joinToString(", ") { it.name } to warning
        }
      }.onSuccess { (names, warning) ->
        _keyUiState.value =
          _keyUiState.value.copy(
            exportTargetEntity = null,
            lastSecurityWarning = warning,
            statusMessage = "Exported: $names",
            errorMessage = null,
          )
        historyRepo.logOperation("KEY", names, entity.alias, "SUCCESS", "Exported $format")
      }.onFailure { err ->
        _keyUiState.value = _keyUiState.value.copy(errorMessage = err.message)
      }
    }
  }

  fun deleteKey(entity: ManagedKeyEntity) {
    viewModelScope.launch {
      keyRepo.deleteKey(entity)
      historyRepo.logOperation("KEY", "${entity.alias}.ask", entity.alias, "SUCCESS", "Deleted from registry")
    }
  }

  fun clearKeyNotices() {
    _keyUiState.value = _keyUiState.value.copy(statusMessage = null, errorMessage = null, lastSecurityWarning = null)
  }

  // --- OS SIGN FLOW ---

  fun setOsTargetDirectory(path: String, viaRoot: Boolean) {
    _osSignState.value =
      _osSignState.value.copy(
        targetDirPath = path.trim(),
        viaRoot = viaRoot,
        inspectionReport = null,
        resignReport = null,
        errorMessage = null,
        statusMessage = null,
      )
  }

  fun setOsCreateBackups(enabled: Boolean) {
    _osSignState.value = _osSignState.value.copy(createBackups = enabled)
  }

  fun openOsStrategyDialog() {
    _osSignState.value = _osSignState.value.copy(showStrategyDialog = true, errorMessage = null)
  }

  fun dismissOsStrategyDialog() {
    _osSignState.value = _osSignState.value.copy(showStrategyDialog = false)
  }

  fun runOsVerify() {
    val cur = _osSignState.value
    if (cur.targetDirPath.isBlank() || cur.isRunning) return
    viewModelScope.launch {
      _osSignState.value = cur.copy(isRunning = true, errorMessage = null, statusMessage = null)
      var resolvedViaRoot = cur.viaRoot
      runCatching {
        coordinator.runOsVerify(
          targetDirPath = cur.targetDirPath,
          viaRoot = cur.viaRoot,
          onResolvedRootMode = { usedRoot ->
            resolvedViaRoot = usedRoot
            _osSignState.value = _osSignState.value.copy(viaRoot = usedRoot)
          },
        ) { count, label ->
          _osSignState.value =
            _osSignState.value.copy(progressCurrent = count, progressLabel = label)
        }
      }.onSuccess { report ->
        _osSignState.value =
          _osSignState.value.copy(
            isRunning = false,
            viaRoot = resolvedViaRoot,
            inspectionReport = report,
            progressLabel = "",
          )
      }.onFailure { err ->
        _osSignState.value =
          _osSignState.value.copy(
            isRunning = false,
            errorMessage = err.message ?: "OS Sign verify failed",
            progressLabel = "",
          )
      }
    }
  }

  fun runOsResign(
    strategy: OsResignKeyStrategy,
    identitiesPerGroup: Map<String, IdentityInput>,
    selectedKeysPerGroup: Map<String, ManagedKeyEntity>,
    passphrasesPerGroup: Map<String, CharArray>,
    clonePassphrase: CharArray?,
    createBackups: Boolean,
  ) {
    val cur = _osSignState.value
    if (cur.targetDirPath.isBlank() || cur.isRunning) return
    viewModelScope.launch {
      _osSignState.value =
        cur.copy(
          showStrategyDialog = false,
          isRunning = true,
          createBackups = createBackups,
          errorMessage = null,
          statusMessage = null,
        )
      var resolvedViaRoot = cur.viaRoot
      runCatching {
        coordinator.runOsResign(
          targetDirPath = cur.targetDirPath,
          viaRoot = cur.viaRoot,
          existingInspection = cur.inspectionReport,
          strategy = strategy,
          identitiesPerGroup = identitiesPerGroup,
          selectedKeysPerGroup = selectedKeysPerGroup,
          passphrasesPerGroup = passphrasesPerGroup,
          clonePassphrase = clonePassphrase,
          createBackups = createBackups,
          onResolvedRootMode = { usedRoot ->
            resolvedViaRoot = usedRoot
            _osSignState.value = _osSignState.value.copy(viaRoot = usedRoot)
          },
        ) { idx, total, label ->
          _osSignState.value =
            _osSignState.value.copy(progressCurrent = idx, progressTotal = total, progressLabel = label)
        }
      }.onSuccess { report ->
        val updatedManifest = report.backupManifest ?: _osSignState.value.activeBackupManifest
        _osSignState.value =
          _osSignState.value.copy(
            isRunning = false,
            viaRoot = resolvedViaRoot,
            resignReport = report,
            activeBackupManifest = updatedManifest,
            activeBackupViaRoot = if (report.backupManifest != null) resolvedViaRoot else _osSignState.value.activeBackupViaRoot,
            progressLabel = "",
            statusMessage = "Resigned ${report.totalSucceeded}/${report.totalResigned} artifacts",
          )
      }.onFailure { err ->
        _osSignState.value =
          _osSignState.value.copy(
            isRunning = false,
            errorMessage = err.message ?: "OS Sign resign failed",
            progressLabel = "",
          )
      }
    }
  }

  fun restoreOsBackups() {
    val cur = _osSignState.value
    val manifest = cur.activeBackupManifest ?: return
    if (cur.isRunning) return
    viewModelScope.launch {
      _osSignState.value = cur.copy(isRunning = true, errorMessage = null, statusMessage = null)
      runCatching { coordinator.restoreBackups(manifest, cur.activeBackupViaRoot) }
        .onSuccess { (count, errors) ->
          _osSignState.value =
            _osSignState.value.copy(
              isRunning = false,
              activeBackupManifest = if (errors.isEmpty()) null else manifest,
              resignReport = null,
              statusMessage = "Restored $count file(s) to original state.",
              errorMessage = errors.takeIf { it.isNotEmpty() }?.joinToString("\n"),
            )
        }
        .onFailure { err ->
          _osSignState.value = _osSignState.value.copy(isRunning = false, errorMessage = err.message)
        }
    }
  }

  fun deleteOsBackups() {
    val cur = _osSignState.value
    val manifest = cur.activeBackupManifest ?: return
    if (cur.isRunning) return
    viewModelScope.launch {
      _osSignState.value = cur.copy(isRunning = true, errorMessage = null, statusMessage = null)
      runCatching { coordinator.deleteBackups(manifest, cur.activeBackupViaRoot) }
        .onSuccess { (count, errors) ->
          _osSignState.value =
            _osSignState.value.copy(
              isRunning = false,
              activeBackupManifest = if (errors.isEmpty()) null else manifest,
              statusMessage = "Deleted $count .appsign.bak backup file(s).",
              errorMessage = errors.takeIf { it.isNotEmpty() }?.joinToString("\n"),
            )
        }
        .onFailure { err ->
          _osSignState.value = _osSignState.value.copy(isRunning = false, errorMessage = err.message)
        }
    }
  }

  // --- HISTORY ---
  fun deleteHistoryEntry(id: Long) = viewModelScope.launch { historyRepo.delete(id) }
  fun clearHistory() = viewModelScope.launch { historyRepo.clearAll() }

  class Factory(private val context: Context) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
      val appCtx = context.applicationContext
      val db = AppsignDatabase.getInstance(appCtx)
      return AppsignViewModel(
        appContext = appCtx,
        settingsRepo = SettingsRepository(appCtx),
        historyRepo = HistoryRepository(db.historyDao()),
        keyRepo = KeyRegistryRepository(appCtx, db.keyDao()),
      ) as T
    }
  }
}
