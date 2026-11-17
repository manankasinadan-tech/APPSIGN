package com.hephaistos.appsign.android.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowForward
import androidx.compose.material.icons.automirrored.rounded.MenuBook
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.EditNote
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.data.local.OperationHistoryEntity
import com.hephaistos.appsign.android.ui.components.AppsignEmblem
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun HomeScreen(
  hasStorageAccess: Boolean,
  rootActive: Boolean,
  recentHistory: List<OperationHistoryEntity>,
  onOpenVerify: () -> Unit,
  onOpenResign: () -> Unit,
  onOpenKeys: () -> Unit,
  onOpenHistory: () -> Unit,
  onOpenDocs: () -> Unit,
  onOpenSettings: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  val scrollState = rememberScrollState()

  Column(
    modifier = Modifier.fillMaxSize().verticalScroll(scrollState).padding(horizontal = 20.dp, vertical = 16.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Column(modifier = Modifier.fillMaxWidth().widthIn(max = 760.dp)) {
      // Brand Header
      Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
      ) {
        AppsignEmblem(size = 46.dp)
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
          Text(
            text = strings.appName,
            style = MaterialTheme.typography.displaySmall,
            color = MaterialTheme.colorScheme.onBackground,
          )
          Text(
            text = strings.appSubtitle,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }

      Spacer(Modifier.height(14.dp))

      // Capability Status Pills
      FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
      ) {
        StatusPillBadge(
          text = strings.offlineBadge,
          containerColor = MaterialTheme.colorScheme.secondaryContainer,
          contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        )
        StatusPillBadge(
          text = if (hasStorageAccess) strings.storageReady else strings.storageSafOnly,
          containerColor = MaterialTheme.colorScheme.primaryContainer,
          contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        )
        if (rootActive) {
          StatusPillBadge(
            text = strings.rootActive,
            containerColor = MaterialTheme.colorScheme.tertiaryContainer,
            contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
          )
        }
      }

      Spacer(Modifier.height(20.dp))

      // Two Large Primary Action Cards
      HeroOperationCard(
        title = strings.verifyHeroTitle,
        description = strings.verifyHeroDesc,
        icon = Icons.Rounded.VerifiedUser,
        accentColor = MaterialTheme.colorScheme.primary,
        testTag = "home_verify_card",
        onClick = onOpenVerify,
      )

      Spacer(Modifier.height(14.dp))

      HeroOperationCard(
        title = strings.resignHeroTitle,
        description = strings.resignHeroDesc,
        icon = Icons.Rounded.EditNote,
        accentColor = MaterialTheme.colorScheme.secondary,
        testTag = "home_resign_card",
        onClick = onOpenResign,
      )

      Spacer(Modifier.height(24.dp))

      // Secondary Tools Grid
      Text(
        text = strings.quickToolsTitle,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onBackground,
      )
      Spacer(Modifier.height(10.dp))

      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        QuickToolTile(
          title = strings.navKeys,
          icon = Icons.Rounded.Key,
          testTag = "home_keys_tile",
          onClick = onOpenKeys,
          modifier = Modifier.weight(1f),
        )
        QuickToolTile(
          title = strings.navHistory,
          icon = Icons.Rounded.History,
          testTag = "home_history_tile",
          onClick = onOpenHistory,
          modifier = Modifier.weight(1f),
        )
      }
      Spacer(Modifier.height(12.dp))
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        QuickToolTile(
          title = strings.navDocs,
          icon = Icons.AutoMirrored.Rounded.MenuBook,
          testTag = "home_docs_tile",
          onClick = onOpenDocs,
          modifier = Modifier.weight(1f),
        )
        QuickToolTile(
          title = strings.navSettings,
          icon = Icons.Rounded.Settings,
          testTag = "home_settings_tile",
          onClick = onOpenSettings,
          modifier = Modifier.weight(1f),
        )
      }

      Spacer(Modifier.height(24.dp))

      // Recent Activity Preview
      Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
      ) {
        Text(
          text = strings.recentActivityTitle,
          style = MaterialTheme.typography.titleMedium,
          modifier = Modifier.weight(1f),
        )
        if (recentHistory.isNotEmpty()) {
          TextButton(onClick = onOpenHistory) { Text(strings.viewAll) }
        }
      }

      Spacer(Modifier.height(8.dp))

      if (recentHistory.isEmpty()) {
        SectionCard {
          Text(
            text = strings.noRecentActivity,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      } else {
        SectionCard {
          recentHistory.take(3).forEachIndexed { idx, entry ->
            if (idx > 0) Spacer(Modifier.height(10.dp))
            val timeStr =
              SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(entry.timestampMs))
            Row(verticalAlignment = Alignment.CenterVertically) {
              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = "${entry.operationType} • ${entry.fileNames}",
                  style = MaterialTheme.typography.titleSmall,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                )
                Text(
                  text = "$timeStr • ${entry.detailsSummary}",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                )
              }
              Spacer(Modifier.width(8.dp))
              StatusPillBadge(
                text = entry.status,
                containerColor =
                  when (entry.status) {
                    "SUCCESS" -> MaterialTheme.colorScheme.secondaryContainer
                    "WARNING" -> MaterialTheme.colorScheme.tertiaryContainer
                    else -> MaterialTheme.colorScheme.errorContainer
                  },
                contentColor =
                  when (entry.status) {
                    "SUCCESS" -> MaterialTheme.colorScheme.onSecondaryContainer
                    "WARNING" -> MaterialTheme.colorScheme.onTertiaryContainer
                    else -> MaterialTheme.colorScheme.onErrorContainer
                  },
              )
            }
          }
        }
      }
      Spacer(Modifier.height(24.dp))
    }
  }
}

@Composable
private fun HeroOperationCard(
  title: String,
  description: String,
  icon: ImageVector,
  accentColor: Color,
  testTag: String,
  onClick: () -> Unit,
) {
  Surface(
    modifier =
      Modifier.fillMaxWidth()
        .minimumInteractiveComponentSize()
        .testTag(testTag)
        .clickable(onClick = onClick),
    shape = MaterialTheme.shapes.large,
    color = MaterialTheme.colorScheme.surface,
    border = BorderStroke(1.dp, accentColor.copy(alpha = 0.45f)),
    tonalElevation = 2.dp,
  ) {
    Row(
      modifier = Modifier.padding(20.dp),
      verticalAlignment = Alignment.CenterVertically,
    ) {
      Surface(
        shape = MaterialTheme.shapes.medium,
        color = accentColor.copy(alpha = 0.14f),
        modifier = Modifier.size(52.dp),
      ) {
        Icon(
          imageVector = icon,
          contentDescription = title,
          tint = accentColor,
          modifier = Modifier.padding(12.dp),
        )
      }
      Spacer(Modifier.width(16.dp))
      Column(modifier = Modifier.weight(1f)) {
        Text(
          text = title,
          style = MaterialTheme.typography.headlineSmall,
          fontWeight = FontWeight.Bold,
          color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.height(4.dp))
        Text(
          text = description,
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
      }
      Spacer(Modifier.width(8.dp))
      Icon(
        imageVector = Icons.AutoMirrored.Rounded.ArrowForward,
        contentDescription = null,
        tint = accentColor,
      )
    }
  }
}

@Composable
private fun QuickToolTile(
  title: String,
  icon: ImageVector,
  testTag: String,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Surface(
    modifier =
      modifier
        .minimumInteractiveComponentSize()
        .testTag(testTag)
        .clickable(onClick = onClick),
    shape = MaterialTheme.shapes.medium,
    color = MaterialTheme.colorScheme.surface,
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
  ) {
    Row(
      modifier = Modifier.padding(horizontal = 14.dp, vertical = 16.dp),
      verticalAlignment = Alignment.CenterVertically,
    ) {
      Icon(
        imageVector = icon,
        contentDescription = title,
        tint = MaterialTheme.colorScheme.primary,
        modifier = Modifier.size(22.dp),
      )
      Spacer(Modifier.width(10.dp))
      Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}
