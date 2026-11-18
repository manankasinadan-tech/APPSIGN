package com.hephaistos.appsign.android.system

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.core.content.ContextCompat
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class FileBrowserEntry(
  val name: String,
  val path: String,
  val isDirectory: Boolean,
  val sizeBytes: Long,
  val lastModifiedMs: Long,
  val isSymlink: Boolean = false,
)

object DeviceStorageHelper {

  fun defaultSdcardPath(): String {
    val ext = Environment.getExternalStorageDirectory()
    val sdcard = File("/sdcard")
    return when {
      sdcard.exists() && sdcard.isDirectory -> "/sdcard"
      ext.exists() -> ext.absolutePath
      else -> "/sdcard"
    }
  }

  fun hasFullStorageAccess(context: Context): Boolean {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      runCatching { Environment.isExternalStorageManager() }.getOrDefault(false)
    } else {
      val read =
        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) ==
          PackageManager.PERMISSION_GRANTED
      val write =
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
          ContextCompat.checkSelfPermission(context, Manifest.permission.WRITE_EXTERNAL_STORAGE) ==
            PackageManager.PERMISSION_GRANTED
        } else {
          true
        }
      read && write
    }
  }

  fun createAllFilesAccessIntent(context: Context): Intent {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
        data = Uri.parse("package:${context.packageName}")
      }
    } else {
      Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.parse("package:${context.packageName}")
      }
    }
  }

  fun createFallbackAllFilesIntent(): Intent {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
    } else {
      Intent(Settings.ACTION_SETTINGS)
    }
  }

  suspend fun listDirectory(
    dirPath: String,
    allowedExtensions: Set<String>? = null,
    directoriesOnly: Boolean = false,
  ): Result<List<FileBrowserEntry>> =
    withContext(Dispatchers.IO) {
      runCatching {
        val dir = File(dirPath)
        if (!dir.exists() || !dir.isDirectory) {
          throw IllegalStateException("Directory unavailable: $dirPath")
        }
        val children = dir.listFiles() ?: throw IllegalStateException("Permission denied reading $dirPath")
        children
          .map { file ->
            val isSym = runCatching { Files.isSymbolicLink(file.toPath()) }.getOrDefault(false)
            val isRealDir = !isSym && file.isDirectory
            Triple(file, isSym, isRealDir)
          }
          .filter { (file, isSym, isRealDir) ->
            if (isSym) {
              true // show symlinks flagged as SYMLINK (non-navigable/ignored)
            } else if (directoriesOnly) {
              isRealDir
            } else if (isRealDir) {
              true
            } else {
              allowedExtensions == null ||
                allowedExtensions.any { ext -> file.extension.equals(ext, ignoreCase = true) }
            }
          }
          .sortedWith(compareBy<Triple<File, Boolean, Boolean>> { !it.third }.thenBy { it.first.name.lowercase() })
          .map { (file, isSym, isRealDir) ->
            FileBrowserEntry(
              name = file.name,
              path = file.absolutePath,
              isDirectory = isRealDir,
              sizeBytes = if (!isSym && file.isFile) file.length() else 0L,
              lastModifiedMs = if (!isSym) file.lastModified() else 0L,
              isSymlink = isSym,
            )
          }
      }
    }

  suspend fun stageUriToFile(context: Context, uri: Uri, stagingDir: File): File =
    withContext(Dispatchers.IO) {
      stagingDir.mkdirs()
      val displayName = resolveDisplayName(context, uri) ?: "imported_${System.currentTimeMillis()}"
      val safeName = displayName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
      val dest = File(stagingDir, safeName)
      context.contentResolver.openInputStream(uri)?.use { input ->
        dest.outputStream().use { output -> input.copyTo(output) }
      } ?: throw IllegalStateException("Cannot open URI stream: $uri")
      dest
    }

  suspend fun copyFileToSafTree(
    context: Context,
    sourceFile: File,
    treeUri: Uri,
    mimeType: String = "application/octet-stream",
  ): Uri =
    withContext(Dispatchers.IO) {
      val docId = DocumentsContract.getTreeDocumentId(treeUri)
      val parentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
      val createdUri =
        DocumentsContract.createDocument(context.contentResolver, parentUri, mimeType, sourceFile.name)
          ?: throw IllegalStateException("Unable to create document ${sourceFile.name} in SAF folder.")
      context.contentResolver.openOutputStream(createdUri)?.use { out ->
        sourceFile.inputStream().use { input -> input.copyTo(out) }
      } ?: throw IllegalStateException("Unable to write to SAF document: $createdUri")
      createdUri
    }

  fun resolveDisplayName(context: Context, uri: Uri): String? {
    if (uri.scheme == "file") {
      return uri.path?.let { File(it).name }
    }
    return runCatching {
      context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { cursor ->
          if (cursor.moveToFirst()) {
            val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0) cursor.getString(idx) else null
          } else {
            null
          }
        }
    }.getOrNull()
  }
}
