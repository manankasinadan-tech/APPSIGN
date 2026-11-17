package com.hephaistos.appsign.android.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.InsertDriveFile
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.system.DeviceStorageHelper
import com.hephaistos.appsign.android.system.FileBrowserEntry
import com.hephaistos.appsign.android.system.RootApkCandidate
import com.hephaistos.appsign.android.system.RootBridge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import java.io.File

@Composable
fun AppsignEmblem(size: Dp = 40.dp, modifier: Modifier = Modifier) {
  val primary = MaterialTheme.colorScheme.primary
  val onSurface = MaterialTheme.colorScheme.onSurface
  Canvas(modifier = modifier.size(size)) {
    val w = this.size.width
    val h = this.size.height
    val cx = w / 2f
    val cy = h / 2f
    val hex =
      Path().apply {
        moveTo(cx, h * 0.06f)
        lineTo(w * 0.90f, h * 0.28f)
        lineTo(w * 0.90f, h * 0.72f)
        lineTo(cx, h * 0.94f)
        lineTo(w * 0.10f, h * 0.72f)
        lineTo(w * 0.10f, h * 0.28f)
        close()
      }
    drawPath(hex, color = primary.copy(alpha = 0.14f))
    drawPath(hex, color = primary, style = Stroke(width = w * 0.065f, join = StrokeJoin.Round))
    drawCircle(
      color = onSurface,
      radius = w * 0.13f,
      center = Offset(cx, cy - h * 0.06f),
      style = Stroke(width = w * 0.055f),
    )
    drawLine(
      color = primary,
      start = Offset(cx, cy + h * 0.07f),
      end = Offset(cx, h * 0.72f),
      strokeWidth = w * 0.07f,
      cap = StrokeCap.Round,
    )
  }
}

@Composable
fun StatusPillBadge(
  text: String,
  containerColor: Color,
  contentColor: Color,
  modifier: Modifier = Modifier,
) {
  Surface(
    color = containerColor,
    contentColor = contentColor,
    shape = RoundedCornerShape(50),
    modifier = modifier,
  ) {
    Text(
      text = text,
      style = MaterialTheme.typography.labelSmall,
      fontWeight = FontWeight.SemiBold,
      maxLines = 1,
      overflow = TextOverflow.Ellipsis,
      modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
    )
  }
}

@Composable
fun SectionCard(
  modifier: Modifier = Modifier,
  content: @Composable ColumnScope.() -> Unit,
) {
  Surface(
    modifier = modifier.fillMaxWidth(),
    shape = MaterialTheme.shapes.large,
    color = MaterialTheme.colorScheme.surface,
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    tonalElevation = 1.dp,
  ) {
    Column(modifier = Modifier.padding(16.dp), content = content)
  }
}

@Composable
fun ExpandableAuditCard(
  title: String,
  subtitle: String? = null,
  initiallyExpanded: Boolean = false,
  trailingBadge: (@Composable () -> Unit)? = null,
  modifier: Modifier = Modifier,
  content: @Composable ColumnScope.() -> Unit,
) {
  var expanded by remember { mutableStateOf(initiallyExpanded) }
  Surface(
    modifier = modifier.fillMaxWidth(),
    shape = MaterialTheme.shapes.medium,
    color = MaterialTheme.colorScheme.surface,
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
  ) {
    Column {
      Row(
        modifier =
          Modifier.fillMaxWidth()
            .minimumInteractiveComponentSize()
            .clickable { expanded = !expanded }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
          )
          if (!subtitle.isNullOrBlank()) {
            Text(
              text = subtitle,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
        }
        if (trailingBadge != null) {
          Spacer(Modifier.width(8.dp))
          trailingBadge()
        }
        Spacer(Modifier.width(4.dp))
        Icon(
          imageVector = if (expanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
          contentDescription = if (expanded) "Collapse" else "Expand",
          tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
      }
      AnimatedVisibility(visible = expanded) {
        Column(modifier = Modifier.padding(start = 14.dp, end = 14.dp, bottom = 14.dp)) {
          HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
          Spacer(Modifier.height(10.dp))
          content()
        }
      }
    }
  }
}

@Composable
fun FingerprintRow(
  label: String,
  value: String,
  onCopied: (String) -> Unit,
) {
  val clipboard = LocalClipboardManager.current
  Row(
    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
    verticalAlignment = Alignment.CenterVertically,
  ) {
    Column(modifier = Modifier.weight(1f)) {
      Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
      Text(
        text = value,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurface,
      )
    }
    IconButton(
      onClick = {
        clipboard.setText(AnnotatedString(value))
        onCopied(label)
      },
      modifier = Modifier.minimumInteractiveComponentSize(),
    ) {
      Icon(
        imageVector = Icons.Rounded.ContentCopy,
        contentDescription = "Copy $label",
        tint = MaterialTheme.colorScheme.primary,
        modifier = Modifier.size(18.dp),
      )
    }
  }
}

@Composable
fun PasswordPromptDialog(
  title: String,
  label: String,
  onConfirm: (CharArray) -> Unit,
  onDismiss: () -> Unit,
) {
  var pw by remember { mutableStateOf("") }
  AlertDialog(
    onDismissRequest = onDismiss,
    icon = { Icon(Icons.Rounded.Lock, contentDescription = null) },
    title = { Text(title) },
    text = {
      OutlinedTextField(
        value = pw,
        onValueChange = { pw = it },
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth().testTag("password_prompt_input"),
      )
    },
    confirmButton = {
      Button(
        onClick = { onConfirm(pw.toCharArray()) },
        enabled = pw.isNotEmpty(),
        modifier = Modifier.testTag("password_prompt_confirm"),
      ) {
        Text(LocalAppsignStrings.current.unlockButton)
      }
    },
    dismissButton = {
      TextButton(onClick = onDismiss) { Text(LocalAppsignStrings.current.cancel) }
    },
  )
}

@Composable
fun SdcardExplorerDialog(
  initialDir: String,
  hasStorageAccess: Boolean,
  pickFolderMode: Boolean = false,
  allowedExtensions: Set<String> = setOf("apk"),
  onOpenSettings: () -> Unit,
  onSelectFiles: (List<String>) -> Unit = {},
  onSelectFolder: (String) -> Unit = {},
  onDismiss: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var currentDir by remember { mutableStateOf(initialDir.ifBlank { "/sdcard" }) }
  var entries by remember { mutableStateOf<List<FileBrowserEntry>>(emptyList()) }
  var loadError by remember { mutableStateOf<String?>(null) }
  var isLoading by remember { mutableStateOf(true) }
  val selectedPaths = remember { mutableStateListOf<String>() }

  LaunchedEffect(currentDir, hasStorageAccess) {
    isLoading = true
    loadError = null
    val res =
      DeviceStorageHelper.listDirectory(
        dirPath = currentDir,
        allowedExtensions = if (pickFolderMode) null else allowedExtensions,
        directoriesOnly = pickFolderMode,
      )
    res
      .onSuccess { entries = it }
      .onFailure {
        entries = emptyList()
        loadError = it.message
      }
    isLoading = false
  }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = {
      Column {
        Text(strings.explorerTitle, style = MaterialTheme.typography.titleLarge)
        Text(
          text = currentDir,
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.primary,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
    },
    text = {
      Column(modifier = Modifier.fillMaxWidth()) {
        if (!hasStorageAccess) {
          Surface(
            color = MaterialTheme.colorScheme.tertiaryContainer,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
          ) {
            Column(modifier = Modifier.padding(10.dp)) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                  Icons.Rounded.Warning,
                  contentDescription = null,
                  tint = MaterialTheme.colorScheme.onTertiaryContainer,
                  modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text(
                  text = strings.storageRequiredHint,
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onTertiaryContainer,
                )
              }
              Spacer(Modifier.height(6.dp))
              OutlinedButton(
                onClick = {
                  onDismiss()
                  onOpenSettings()
                }
              ) {
                Icon(Icons.Rounded.Settings, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text(strings.openSettings)
              }
            }
          }
        }

        val parent = File(currentDir).parentFile
        if (parent != null) {
          Row(
            modifier =
              Modifier.fillMaxWidth()
                .minimumInteractiveComponentSize()
                .clickable { currentDir = parent.absolutePath }
                .padding(vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
          ) {
            Icon(Icons.Rounded.ArrowUpward, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(8.dp))
            Text(strings.parentDir, style = MaterialTheme.typography.bodyMedium)
          }
          HorizontalDivider()
        }

        Box(modifier = Modifier.fillMaxWidth().heightIn(min = 180.dp, max = 300.dp)) {
          when {
            isLoading -> CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
            loadError != null ->
              Text(
                text = loadError ?: "",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.align(Alignment.Center).padding(12.dp),
              )
            entries.isEmpty() ->
              Text(
                text = strings.emptyFolder,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.align(Alignment.Center).padding(12.dp),
              )
            else ->
              LazyColumn {
                items(entries, key = { it.path }) { item ->
                  val checked = selectedPaths.contains(item.path)
                  Row(
                    modifier =
                      Modifier.fillMaxWidth()
                        .minimumInteractiveComponentSize()
                        .clickable {
                          if (item.isDirectory) {
                            currentDir = item.path
                          } else if (!pickFolderMode) {
                            if (checked) selectedPaths.remove(item.path) else selectedPaths.add(item.path)
                          }
                        }
                        .padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                  ) {
                    Icon(
                      imageVector = if (item.isDirectory) Icons.Rounded.Folder else Icons.AutoMirrored.Rounded.InsertDriveFile,
                      contentDescription = null,
                      tint =
                        if (item.isDirectory) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                      Text(item.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                      if (!item.isDirectory) {
                        Text(
                          text = "${item.sizeBytes / 1024} KB",
                          style = MaterialTheme.typography.labelSmall,
                          color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                      }
                    }
                    if (!item.isDirectory && !pickFolderMode) {
                      Checkbox(
                        checked = checked,
                        onCheckedChange = {
                          if (checked) selectedPaths.remove(item.path) else selectedPaths.add(item.path)
                        },
                      )
                    }
                  }
                }
              }
          }
        }
      }
    },
    confirmButton = {
      if (pickFolderMode) {
        Button(onClick = { onSelectFolder(currentDir) }) { Text(strings.selectCurrentFolder) }
      } else {
        Button(
          onClick = { onSelectFiles(selectedPaths.toList()) },
          enabled = selectedPaths.isNotEmpty(),
        ) {
          Text("${strings.confirmSelection} (${selectedPaths.size})")
        }
      }
    },
    dismissButton = { TextButton(onClick = onDismiss) { Text(strings.cancel) } },
  )
}

@Composable
fun RootApkPickerDialog(
  onSelectPath: (String) -> Unit,
  onDismiss: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var candidates by remember { mutableStateOf<List<RootApkCandidate>>(emptyList()) }
  var isLoading by remember { mutableStateOf(true) }
  var error by remember { mutableStateOf<String?>(null) }

  LaunchedEffect(Unit) {
    isLoading = true
    RootBridge.listInstalledApksViaRoot()
      .onSuccess { candidates = it }
      .onFailure { error = it.message }
    isLoading = false
  }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(strings.rootExplorerTitle) },
    text = {
      Box(modifier = Modifier.fillMaxWidth().heightIn(min = 180.dp, max = 320.dp)) {
        when {
          isLoading -> CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
          error != null ->
            Text(
              text = error ?: "",
              color = MaterialTheme.colorScheme.error,
              style = MaterialTheme.typography.bodySmall,
              modifier = Modifier.align(Alignment.Center),
            )
          candidates.isEmpty() ->
            Text(
              text = strings.emptyFolder,
              style = MaterialTheme.typography.bodySmall,
              modifier = Modifier.align(Alignment.Center),
            )
          else ->
            LazyColumn {
              items(candidates, key = { it.apkPath }) { item ->
                Row(
                  modifier =
                    Modifier.fillMaxWidth()
                      .minimumInteractiveComponentSize()
                      .clickable {
                        onSelectPath(item.apkPath)
                        onDismiss()
                      }
                      .padding(vertical = 8.dp),
                  verticalAlignment = Alignment.CenterVertically,
                ) {
                  Icon(Icons.Rounded.Description, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                  Spacer(Modifier.width(10.dp))
                  Column {
                    Text(item.displayLabel, style = MaterialTheme.typography.bodyMedium)
                    Text(
                      item.apkPath,
                      style = MaterialTheme.typography.labelSmall,
                      color = MaterialTheme.colorScheme.onSurfaceVariant,
                      maxLines = 1,
                      overflow = TextOverflow.Ellipsis,
                    )
                  }
                }
              }
            }
        }
      }
    },
    confirmButton = { TextButton(onClick = onDismiss) { Text(strings.close) } },
  )
}
