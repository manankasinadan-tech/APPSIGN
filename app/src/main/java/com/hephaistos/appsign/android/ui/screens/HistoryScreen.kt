package com.hephaistos.appsign.android.ui.screens

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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.hephaistos.appsign.android.data.local.OperationHistoryEntity
import com.hephaistos.appsign.android.ui.components.SectionCard
import com.hephaistos.appsign.android.ui.components.StatusPillBadge
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun HistoryScreen(
  history: List<OperationHistoryEntity>,
  onDeleteEntry: (Long) -> Unit,
  onClearAll: () -> Unit,
) {
  val strings = LocalAppsignStrings.current
  var filter by remember { mutableStateOf("ALL") }
  val filtered =
    remember(history, filter) {
      if (filter == "ALL") history else history.filter { it.operationType == filter }
    }

  Column(
    modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 16.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Column(modifier = Modifier.fillMaxWidth().widthIn(max = 760.dp)) {
      Row(verticalAlignment = Alignment.CenterVertically) {
        Text(strings.historyTitle, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
        if (history.isNotEmpty()) {
          TextButton(onClick = onClearAll, modifier = Modifier.testTag("history_clear_button")) {
            Icon(Icons.Rounded.DeleteSweep, contentDescription = null)
            Spacer(Modifier.width(4.dp))
            Text(strings.clearHistory)
          }
        }
      }

      Spacer(Modifier.height(10.dp))

      FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        listOf(
          "ALL" to strings.filterAll,
          "VERIFY" to strings.filterVerify,
          "RESIGN" to strings.filterResign,
          "KEY" to strings.filterKeys,
        ).forEach { (key, label) ->
          FilterChip(selected = filter == key, onClick = { filter = key }, label = { Text(label) })
        }
      }

      Spacer(Modifier.height(12.dp))

      if (filtered.isEmpty()) {
        SectionCard {
          Text(strings.noHistoryItems, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
      } else {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
          items(filtered, key = { it.id }) { item ->
            val dateStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(item.timestampMs))
            SectionCard {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                  Text("${item.operationType} • ${item.fileNames}", style = MaterialTheme.typography.titleSmall)
                  Text(dateStr, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                StatusPillBadge(
                  text = item.status,
                  containerColor =
                    when (item.status) {
                      "SUCCESS" -> MaterialTheme.colorScheme.secondaryContainer
                      "WARNING" -> MaterialTheme.colorScheme.tertiaryContainer
                      else -> MaterialTheme.colorScheme.errorContainer
                    },
                  contentColor =
                    when (item.status) {
                      "SUCCESS" -> MaterialTheme.colorScheme.onSecondaryContainer
                      "WARNING" -> MaterialTheme.colorScheme.onTertiaryContainer
                      else -> MaterialTheme.colorScheme.onErrorContainer
                    },
                )
                IconButton(onClick = { onDeleteEntry(item.id) }) {
                  Icon(Icons.Rounded.Delete, contentDescription = strings.deleteButton, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
              }
              Spacer(Modifier.height(6.dp))
              Text(item.detailsSummary, style = MaterialTheme.typography.bodySmall)
              if (!item.keyAlias.isNullOrBlank()) {
                Text("Key: ${item.keyAlias}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
              }
            }
          }
        }
      }
    }
  }
}
