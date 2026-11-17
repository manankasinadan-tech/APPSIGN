package com.hephaistos.appsign.android.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.MenuBook
import androidx.compose.material.icons.automirrored.rounded.MenuBook
import androidx.compose.material.icons.outlined.EditNote
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material.icons.rounded.EditNote
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavDestination.Companion.hasRoute
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.hephaistos.appsign.android.ui.i18n.LocalAppsignStrings
import com.hephaistos.appsign.android.ui.screens.DocumentationScreen
import com.hephaistos.appsign.android.ui.screens.HistoryScreen
import com.hephaistos.appsign.android.ui.screens.HomeScreen
import com.hephaistos.appsign.android.ui.screens.KeyManagerScreen
import com.hephaistos.appsign.android.ui.screens.ResignScreen
import com.hephaistos.appsign.android.ui.screens.SettingsScreen
import com.hephaistos.appsign.android.ui.screens.VerifyScreen
import com.hephaistos.appsign.android.ui.viewmodel.AppsignViewModel
import kotlinx.serialization.Serializable

@Serializable data object HomeRoute
@Serializable data object VerifyRoute
@Serializable data object ResignRoute
@Serializable data object KeyManagerRoute
@Serializable data object HistoryRoute
@Serializable data object DocumentationRoute
@Serializable data object SettingsRoute

private data class NavItem(
  val route: Any,
  val label: String,
  val selectedIcon: ImageVector,
  val unselectedIcon: ImageVector,
  val testTag: String,
)

@Composable
fun AppsignApp(viewModel: AppsignViewModel) {
  val strings = LocalAppsignStrings.current
  val navController = rememberNavController()
  val backStackEntry by navController.currentBackStackEntryAsState()
  val currentDestination = backStackEntry?.destination

  val settings by viewModel.settings.collectAsStateWithLifecycle()
  val history by viewModel.history.collectAsStateWithLifecycle()
  val managedKeys by viewModel.managedKeys.collectAsStateWithLifecycle()
  val verifyState by viewModel.verifyState.collectAsStateWithLifecycle()
  val resignState by viewModel.resignState.collectAsStateWithLifecycle()
  val keyUiState by viewModel.keyUiState.collectAsStateWithLifecycle()
  val hasStorage by viewModel.hasStoragePermission.collectAsStateWithLifecycle()
  val rootProbe by viewModel.rootProbe.collectAsStateWithLifecycle()

  val primaryNavItems =
    listOf(
      NavItem(HomeRoute, strings.navHome, Icons.Rounded.Home, Icons.Outlined.Home, "nav_home"),
      NavItem(VerifyRoute, strings.navVerify, Icons.Rounded.VerifiedUser, Icons.Outlined.VerifiedUser, "nav_verify"),
      NavItem(ResignRoute, strings.navResign, Icons.Rounded.EditNote, Icons.Outlined.EditNote, "nav_resign"),
      NavItem(KeyManagerRoute, strings.navKeys, Icons.Rounded.Key, Icons.Outlined.Key, "nav_keys"),
      NavItem(SettingsRoute, strings.navSettings, Icons.Rounded.Settings, Icons.Outlined.Settings, "nav_settings"),
    )

  val railNavItems =
    primaryNavItems +
      listOf(
        NavItem(HistoryRoute, strings.navHistory, Icons.Rounded.History, Icons.Outlined.History, "nav_history"),
        NavItem(DocumentationRoute, strings.navDocs, Icons.AutoMirrored.Rounded.MenuBook, Icons.AutoMirrored.Outlined.MenuBook, "nav_docs"),
      )

  fun navigateSingleTop(route: Any) {
    navController.navigate(route) {
      popUpTo(navController.graph.findStartDestination().id) { saveState = true }
      launchSingleTop = true
      restoreState = true
    }
  }

  BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
    val useRail = maxWidth >= 680.dp

    Scaffold(
      contentWindowInsets = WindowInsets.safeDrawing,
      bottomBar = {
        if (!useRail) {
          NavigationBar {
            primaryNavItems.forEach { item ->
              val selected = currentDestination?.hasRoute(item.route::class) == true
              NavigationBarItem(
                selected = selected,
                onClick = { navigateSingleTop(item.route) },
                icon = {
                  Icon(
                    imageVector = if (selected) item.selectedIcon else item.unselectedIcon,
                    contentDescription = item.label,
                  )
                },
                label = { Text(item.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                modifier = Modifier.testTag(item.testTag),
              )
            }
          }
        }
      },
    ) { innerPadding ->
      Row(modifier = Modifier.fillMaxSize().padding(innerPadding)) {
        if (useRail) {
          NavigationRail {
            railNavItems.forEach { item ->
              val selected = currentDestination?.hasRoute(item.route::class) == true
              NavigationRailItem(
                selected = selected,
                onClick = { navigateSingleTop(item.route) },
                icon = {
                  Icon(
                    imageVector = if (selected) item.selectedIcon else item.unselectedIcon,
                    contentDescription = item.label,
                  )
                },
                label = { Text(item.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                modifier = Modifier.testTag(item.testTag),
              )
            }
          }
        }

        Box(modifier = Modifier.weight(1f).fillMaxSize()) {
          NavHost(navController = navController, startDestination = HomeRoute) {
            composable<HomeRoute> {
              HomeScreen(
                hasStorageAccess = hasStorage,
                rootActive = settings.rootAccessEnabled,
                recentHistory = history,
                onOpenVerify = { navigateSingleTop(VerifyRoute) },
                onOpenResign = { navigateSingleTop(ResignRoute) },
                onOpenKeys = { navigateSingleTop(KeyManagerRoute) },
                onOpenHistory = { navigateSingleTop(HistoryRoute) },
                onOpenDocs = { navigateSingleTop(DocumentationRoute) },
                onOpenSettings = { navigateSingleTop(SettingsRoute) },
              )
            }
            composable<VerifyRoute> {
              VerifyScreen(
                state = verifyState,
                defaultBrowseDir = settings.defaultBrowseDir,
                hasStorageAccess = hasStorage,
                rootEnabled = settings.rootAccessEnabled,
                onAddUris = viewModel::addVerifyUris,
                onAddPaths = viewModel::addVerifyPaths,
                onAddRootApk = viewModel::addVerifyRootApk,
                onRunVerification = viewModel::runVerification,
                onClear = viewModel::clearVerifySelection,
                onOpenSettings = { navigateSingleTop(SettingsRoute) },
              )
            }
            composable<ResignRoute> {
              ResignScreen(
                state = resignState,
                managedKeys = managedKeys,
                defaultBrowseDir = settings.defaultBrowseDir,
                hasStorageAccess = hasStorage,
                onAddUris = viewModel::addResignUris,
                onAddPaths = viewModel::addResignPaths,
                onSelectManagedKey = viewModel::selectManagedKeyForResign,
                onSelectExternalKeyUri = viewModel::selectExternalKeyUriForResign,
                onCreateInlineKey = { opts -> viewModel.createAskKey(opts, selectForResign = true) },
                onUpdateSchemes = viewModel::updateResignSchemes,
                onSetOutputPath = viewModel::setResignOutputFolderPath,
                onSetOutputSafTree = viewModel::setResignOutputSafTree,
                onStartResign = { pw -> viewModel.startResign(pw) },
                onDismissPassword = viewModel::dismissResignPasswordPrompt,
                onClearSelection = viewModel::clearResignSelection,
                onOpenSettings = { navigateSingleTop(SettingsRoute) },
              )
            }
            composable<KeyManagerRoute> {
              KeyManagerScreen(
                keys = managedKeys,
                uiState = keyUiState,
                defaultOutputDir = settings.defaultOutputDir,
                onCreateKey = { opts -> viewModel.createAskKey(opts, selectForResign = false) },
                onImportKeystore = viewModel::importExternalKeystore,
                onInspectKey = viewModel::inspectKey,
                onCloseInspect = viewModel::closeInspect,
                onRequestExport = viewModel::requestExportKey,
                onCloseExport = viewModel::closeExportKey,
                onPerformExport = viewModel::performExportKey,
                onDeleteKey = viewModel::deleteKey,
                onClearNotices = viewModel::clearKeyNotices,
              )
            }
            composable<HistoryRoute> {
              HistoryScreen(
                history = history,
                onDeleteEntry = viewModel::deleteHistoryEntry,
                onClearAll = viewModel::clearHistory,
              )
            }
            composable<DocumentationRoute> {
              DocumentationScreen()
            }
            composable<SettingsRoute> {
              SettingsScreen(
                settings = settings,
                hasStoragePermission = hasStorage,
                rootProbe = rootProbe,
                onUpdateTheme = viewModel::updateTheme,
                onUpdateLanguage = viewModel::updateLanguage,
                onUpdateDefaultDirs = viewModel::updateDefaultDirs,
                onUpdateSigningDefaults = viewModel::updateSigningDefaults,
                onRefreshStoragePermission = viewModel::refreshStoragePermission,
                onProbeRoot = viewModel::probeRootAccess,
                onToggleRoot = viewModel::setRootAccessEnabled,
              )
            }
          }
        }
      }
    }
  }
}
