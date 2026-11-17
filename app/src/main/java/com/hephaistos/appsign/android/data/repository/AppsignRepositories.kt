package com.hephaistos.appsign.android.data.repository

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.ui.theme.ThemePreference
import com.hephaistos.appsign.android.data.local.ManagedKeyDao
import com.hephaistos.appsign.android.data.local.ManagedKeyEntity
import com.hephaistos.appsign.android.data.local.OperationHistoryDao
import com.hephaistos.appsign.android.data.local.OperationHistoryEntity
import com.hephaistos.appsign.core.ask.AskKeyManager
import com.hephaistos.appsign.core.model.AskContainer
import com.hephaistos.appsign.core.model.AskInspectResult
import com.hephaistos.appsign.core.model.CreateAskOptions
import com.hephaistos.appsign.core.model.UnlockedKeyMaterial
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext

enum class AppLanguage(val code: String, val label: String) {
  FR("fr", "Français"),
  EN("en", "English"),
}

data class AppSettings(
  val themePreference: ThemePreference = ThemePreference.SYSTEM,
  val language: AppLanguage = AppLanguage.FR,
  val defaultBrowseDir: String = "/sdcard",
  val defaultOutputDir: String = "/sdcard/APPSIGN/signed",
  val defaultV1: Boolean = true,
  val defaultV2: Boolean = true,
  val defaultV3: Boolean = true,
  val defaultV31: Boolean = false,
  val defaultV4: Boolean = false,
  val alignBeforeSign: Boolean = true,
  val rootAccessEnabled: Boolean = false,
)

private val Context.appsignDataStore by preferencesDataStore(name = "appsign_settings")

class SettingsRepository(private val context: Context) {
  private object Keys {
    val THEME = stringPreferencesKey("theme_preference")
    val LANGUAGE = stringPreferencesKey("language")
    val BROWSE_DIR = stringPreferencesKey("default_browse_dir")
    val OUTPUT_DIR = stringPreferencesKey("default_output_dir")
    val V1 = booleanPreferencesKey("default_v1")
    val V2 = booleanPreferencesKey("default_v2")
    val V3 = booleanPreferencesKey("default_v3")
    val V31 = booleanPreferencesKey("default_v31")
    val V4 = booleanPreferencesKey("default_v4")
    val ALIGN = booleanPreferencesKey("align_before_sign")
    val ROOT_ENABLED = booleanPreferencesKey("root_access_enabled")
  }

  val settingsFlow: Flow<AppSettings> =
    context.appsignDataStore.data.map { prefs ->
      AppSettings(
        themePreference =
          prefs[Keys.THEME]?.let { runCatching { ThemePreference.valueOf(it) }.getOrNull() }
            ?: ThemePreference.SYSTEM,
        language =
          prefs[Keys.LANGUAGE]?.let { runCatching { AppLanguage.valueOf(it) }.getOrNull() }
            ?: AppLanguage.FR,
        defaultBrowseDir = prefs[Keys.BROWSE_DIR] ?: "/sdcard",
        defaultOutputDir = prefs[Keys.OUTPUT_DIR] ?: "/sdcard/APPSIGN/signed",
        defaultV1 = prefs[Keys.V1] ?: true,
        defaultV2 = prefs[Keys.V2] ?: true,
        defaultV3 = prefs[Keys.V3] ?: true,
        defaultV31 = prefs[Keys.V31] ?: false,
        defaultV4 = prefs[Keys.V4] ?: false,
        alignBeforeSign = prefs[Keys.ALIGN] ?: true,
        rootAccessEnabled = prefs[Keys.ROOT_ENABLED] ?: false,
      )
    }

  suspend fun updateTheme(theme: ThemePreference) {
    context.appsignDataStore.edit { it[Keys.THEME] = theme.name }
  }

  suspend fun updateLanguage(language: AppLanguage) {
    context.appsignDataStore.edit { it[Keys.LANGUAGE] = language.name }
  }

  suspend fun updateDefaultDirs(browseDir: String, outputDir: String) {
    context.appsignDataStore.edit {
      if (browseDir.isNotBlank()) it[Keys.BROWSE_DIR] = browseDir.trim()
      if (outputDir.isNotBlank()) it[Keys.OUTPUT_DIR] = outputDir.trim()
    }
  }

  suspend fun updateSigningDefaults(
    v1: Boolean,
    v2: Boolean,
    v3: Boolean,
    v31: Boolean,
    v4: Boolean,
    align: Boolean,
  ) {
    context.appsignDataStore.edit {
      it[Keys.V1] = v1
      it[Keys.V2] = v2
      it[Keys.V3] = v3
      it[Keys.V31] = v31
      it[Keys.V4] = v4
      it[Keys.ALIGN] = align
    }
  }

  suspend fun setRootAccessEnabled(enabled: Boolean) {
    context.appsignDataStore.edit { it[Keys.ROOT_ENABLED] = enabled }
  }
}

class HistoryRepository(private val dao: OperationHistoryDao) {
  val historyFlow: Flow<List<OperationHistoryEntity>> = dao.observeAll()

  suspend fun logOperation(
    operationType: String,
    fileNames: String,
    keyAlias: String? = null,
    status: String,
    detailsSummary: String,
    reportJson: String = "",
  ) {
    dao.insert(
      OperationHistoryEntity(
        operationType = operationType,
        fileNames = fileNames,
        keyAlias = keyAlias,
        status = status,
        detailsSummary = detailsSummary,
        reportJson = reportJson,
      )
    )
  }

  suspend fun delete(id: Long) = dao.deleteById(id)

  suspend fun clearAll() = dao.clearAll()
}

class KeyRegistryRepository(private val context: Context, private val dao: ManagedKeyDao) {
  val keysFlow: Flow<List<ManagedKeyEntity>> = dao.observeAll()

  private val keystoreDir: File
    get() = File(context.filesDir, "appsign_keys").apply { mkdirs() }

  suspend fun syncDiskKeys() =
    withContext(Dispatchers.IO) {
      val files = keystoreDir.listFiles { f -> f.isFile && f.extension.equals("ask", true) } ?: return@withContext
      for (file in files) {
        runCatching {
          val container = AskKeyManager.readAsk(file)
          dao.upsert(container.toEntity(file.absolutePath))
        }
      }
    }

  suspend fun createKey(options: CreateAskOptions): ManagedKeyEntity =
    withContext(Dispatchers.IO) {
      val container = AskKeyManager.createAsk(options)
      val safeAlias = options.alias.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "key" }
      val target = File(keystoreDir, "${safeAlias}_${container.keyId.take(8)}.ask")
      AskKeyManager.writeAsk(container, target)
      val entity = container.toEntity(target.absolutePath)
      dao.upsert(entity)
      entity
    }

  suspend fun importAskFile(sourceFile: File): ManagedKeyEntity =
    withContext(Dispatchers.IO) {
      val container = AskKeyManager.readAsk(sourceFile)
      val safeAlias = container.metadata.alias.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "key" }
      val target = File(keystoreDir, "${safeAlias}_${container.keyId.take(8)}.ask")
      AskKeyManager.writeAsk(container, target)
      val entity = container.toEntity(target.absolutePath)
      dao.upsert(entity)
      entity
    }

  suspend fun registerContainer(container: AskContainer): ManagedKeyEntity =
    withContext(Dispatchers.IO) {
      val safeAlias = container.metadata.alias.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "key" }
      val target = File(keystoreDir, "${safeAlias}_${container.keyId.take(8)}.ask")
      AskKeyManager.writeAsk(container, target)
      val entity = container.toEntity(target.absolutePath)
      dao.upsert(entity)
      entity
    }

  suspend fun inspectKey(entity: ManagedKeyEntity): AskInspectResult =
    withContext(Dispatchers.IO) { AskKeyManager.inspectAsk(File(entity.filePath)) }

  suspend fun readContainer(entity: ManagedKeyEntity): AskContainer =
    withContext(Dispatchers.IO) { AskKeyManager.readAsk(File(entity.filePath)) }

  suspend fun unlockKey(entity: ManagedKeyEntity, passphrase: CharArray?): UnlockedKeyMaterial =
    withContext(Dispatchers.IO) {
      val container = AskKeyManager.readAsk(File(entity.filePath))
      AskKeyManager.unlockAsk(container, passphrase)
    }

  suspend fun deleteKey(entity: ManagedKeyEntity) =
    withContext(Dispatchers.IO) {
      File(entity.filePath).delete()
      dao.deleteById(entity.keyId)
    }

  private fun AskContainer.toEntity(path: String): ManagedKeyEntity =
    ManagedKeyEntity(
      keyId = keyId,
      alias = metadata.alias,
      filePath = path,
      mode = mode.name,
      algorithm = metadata.algorithm,
      keySizeBits = metadata.keySizeBits,
      sha256Fingerprint = metadata.fingerprints.sha256,
      subjectDn = metadata.subjectDn,
      createdAtIso = metadata.createdAtIso,
    )
}
