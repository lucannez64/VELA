package com.vela.android.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.vela.android.core.VaultItem
import com.vela.android.sync.SyncSettings
import com.vela.android.sync.SyncState
import com.vela.android.ui.screens.AddItemScreen
import com.vela.android.ui.screens.AuditLogScreen
import com.vela.android.ui.screens.BreachMonitorScreen
import com.vela.android.ui.screens.DevicesScreen
import com.vela.android.ui.screens.EnrollDeviceScreen
import com.vela.android.ui.screens.ItemDetailScreen
import com.vela.android.ui.screens.SettingsScreen
import com.vela.android.ui.screens.SharingScreen
import com.vela.android.ui.screens.UnlockScreen
import com.vela.android.ui.screens.VaultBrowserScreen
import com.vela.android.ui.screens.WelcomeScreen
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

object VelaRoutes {
    const val WELCOME = "welcome"
    const val UNLOCK = "unlock"
    const val VAULT = "vault"
    const val ITEM_DETAIL = "item/{itemId}"
    const val ADD_ITEM = "add_item"
    const val EDIT_ITEM = "edit_item/{itemId}"
    const val SETTINGS = "settings"
    const val ENROLL = "enroll"
    const val DEVICES = "devices"
    const val SHARING = "sharing"
    const val AUDIT_LOG = "audit_log"
    const val BREACH_MONITOR = "breach_monitor"

    fun itemDetail(id: String) = "item/$id"
    fun editItem(id: String) = "edit_item/$id"
}

data class BottomNavItem(
    val route: String,
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

val bottomNavItems = listOf(
    BottomNavItem(VelaRoutes.VAULT, "Vault", Icons.Filled.Shield, Icons.Outlined.Shield),
    BottomNavItem(VelaRoutes.SHARING, "Sharing", Icons.Filled.Share, Icons.Outlined.Share),
    BottomNavItem(VelaRoutes.SETTINGS, "Settings", Icons.Filled.Settings, Icons.Outlined.Settings)
)

@Composable
fun VelaNavHost(
    isUnlocked: Boolean,
    hasBiometricVault: Boolean,
    hasPasswordVault: Boolean,
    itemCount: Int,
    items: List<com.vela.android.core.VaultItem>,
    onAddItem: (com.vela.android.core.VaultItem) -> Unit,
    onUpdateItem: (com.vela.android.core.VaultItem) -> Unit,
    onDeleteItem: (String) -> Unit,
    onLock: () -> Unit,
    onReset: () -> Unit,
    onCreateBiometricVault: () -> Unit,
    onUnlockBiometric: () -> Unit,
    onCreatePasswordVault: (String) -> Unit,
    onUnlockPassword: (String) -> Unit,
    onOpenAutofillSettings: () -> Unit,
    onSyncNow: () -> Unit,
    onResolveConflictUseLocal: () -> Unit,
    onResolveConflictUseRemote: () -> Unit,
    onUpdateSyncServer: (String, String) -> Unit,
    onUpdateSyncPreferences: (Boolean, Int) -> Unit,
    onNavigateToEnroll: () -> Unit,
    onEnrollDevice: (String, String) -> Unit,
    onProtectEnrolledBiometric: () -> Unit,
    onProtectEnrolledPassword: (String) -> Unit,
    serverUrl: String,
    syncSettings: SyncSettings,
    syncState: com.vela.android.sync.SyncState,
    userId: String?
) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    val hasVault = hasBiometricVault || hasPasswordVault
    var preselectedShareItemId by remember { mutableStateOf<String?>(null) }

    val authRoute = when {
        !hasVault -> VelaRoutes.WELCOME
        !isUnlocked -> VelaRoutes.UNLOCK
        else -> VelaRoutes.VAULT
    }

    LaunchedEffect(authRoute, currentRoute) {
        val routeRequiresUnlockedVault = currentRoute in listOf(
            VelaRoutes.VAULT,
            VelaRoutes.SHARING,
            VelaRoutes.SETTINGS,
            VelaRoutes.ADD_ITEM,
            VelaRoutes.ITEM_DETAIL,
            VelaRoutes.EDIT_ITEM,
            VelaRoutes.DEVICES,
            VelaRoutes.AUDIT_LOG,
            VelaRoutes.BREACH_MONITOR
        )
        val isEnrollRoute = currentRoute == VelaRoutes.ENROLL

        val shouldRedirect = when (authRoute) {
            VelaRoutes.WELCOME -> currentRoute != VelaRoutes.WELCOME && !isEnrollRoute
            VelaRoutes.UNLOCK -> currentRoute != VelaRoutes.UNLOCK && routeRequiresUnlockedVault
            VelaRoutes.VAULT -> currentRoute == null || currentRoute == VelaRoutes.WELCOME || currentRoute == VelaRoutes.UNLOCK || isEnrollRoute
            else -> false
        }

        if (shouldRedirect) {
            navController.navigate(authRoute) {
                popUpTo(navController.graph.findStartDestination().id) { inclusive = true }
                launchSingleTop = true
            }
        }
    }

    val showBottomBar = isUnlocked && currentRoute in listOf(VelaRoutes.VAULT, VelaRoutes.SHARING, VelaRoutes.SETTINGS)

    Scaffold(
        bottomBar = {
            if (showBottomBar) {
                NavigationBar(
                    containerColor = VelaColors.SurfaceLow,
                    contentColor = VelaColors.TextPrimary,
                    tonalElevation = 0.dp
                ) {
                    bottomNavItems.forEach { item ->
                        val selected = navBackStackEntry?.destination?.hierarchy?.any {
                            it.route == item.route
                        } == true

                        NavigationBarItem(
                            icon = {
                                Icon(
                                    if (selected) item.selectedIcon else item.unselectedIcon,
                                    item.label
                                )
                            },
                            label = {
                                Text(
                                    item.label,
                                    fontSize = 12.sp,
                                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
                                )
                            },
                            selected = selected,
                            onClick = {
                                navController.navigate(item.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = VelaColors.Green,
                                selectedTextColor = VelaColors.Green,
                                unselectedIconColor = VelaColors.TextMuted,
                                unselectedTextColor = VelaColors.TextMuted,
                                indicatorColor = VelaColors.Green.copy(alpha = 0.12f)
                            )
                        )
                    }
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = authRoute,
            modifier = Modifier.padding(padding)
        ) {
            composable(VelaRoutes.WELCOME) {
                WelcomeScreen(
                    onCreateBiometricVault = {
                        onCreateBiometricVault()
                    },
                    onCreatePasswordVault = { password ->
                        onCreatePasswordVault(password)
                    },
                    onNavigateToEnroll = {
                        onNavigateToEnroll()
                        navController.navigate(VelaRoutes.ENROLL)
                    }
                )
            }

            composable(VelaRoutes.ENROLL) {
                val scope = rememberCoroutineScope()
                var enrolling by remember { mutableStateOf(false) }
                var enrolled by remember { mutableStateOf(false) }
                var error by remember { mutableStateOf<String?>(null) }

                EnrollDeviceScreen(
                    errorMessage = error,
                    isEnrolling = enrolling,
                    isEnrolled = enrolled,
                    onEnroll = { url, code ->
                        enrolling = true
                        error = null
                        scope.launch(Dispatchers.IO) {
                            try {
                                onEnrollDevice(url, code)
                                withContext(Dispatchers.Main) {
                                    enrolled = true
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    error = e.message ?: "Enrollment failed"
                                }
                            } finally {
                                withContext(Dispatchers.Main) {
                                    enrolling = false
                                }
                            }
                        }
                    },
                    onProtectBiometric = {
                        onProtectEnrolledBiometric()
                    },
                    onProtectPassword = { password ->
                        onProtectEnrolledPassword(password)
                    },
                    onBack = { navController.popBackStack() }
                )
            }

            composable(VelaRoutes.UNLOCK) {
                UnlockScreen(
                    hasBiometricVault = hasBiometricVault,
                    hasPasswordVault = hasPasswordVault,
                    onUnlockBiometric = onUnlockBiometric,
                    onUnlockPassword = onUnlockPassword
                )
            }

            composable(VelaRoutes.VAULT) {
                VaultBrowserScreen(
                    items = items,
                    itemCount = itemCount,
                    onItemClick = { item ->
                        navController.navigate(VelaRoutes.itemDetail(item.id))
                    },
                    onAddItem = {
                        navController.navigate(VelaRoutes.ADD_ITEM)
                    },
                    onLock = onLock
                )
            }

            composable(VelaRoutes.ADD_ITEM) {
                AddItemScreen(
                    editItem = null,
                    onSave = { item ->
                        onAddItem(item)
                        navController.popBackStack()
                    },
                    onBack = { navController.popBackStack() }
                )
            }

            composable(VelaRoutes.ITEM_DETAIL) { backStackEntry ->
                val itemId = backStackEntry.arguments?.getString("itemId") ?: return@composable
                val item = items.find { it.id == itemId }
                ItemDetailScreen(
                    item = item,
                    onBack = { navController.popBackStack() },
                    onEdit = { navController.navigate(VelaRoutes.editItem(itemId)) },
                    onDelete = {
                        onDeleteItem(itemId)
                        navController.popBackStack()
                    },
                    onShare = {
                        preselectedShareItemId = itemId
                        navController.navigate(VelaRoutes.SHARING) {
                            popUpTo(navController.graph.findStartDestination().id) {
                                saveState = true
                            }
                            launchSingleTop = true
                            restoreState = true
                        }
                    }
                )
            }

            composable(VelaRoutes.EDIT_ITEM) { backStackEntry ->
                val itemId = backStackEntry.arguments?.getString("itemId") ?: return@composable
                val item = items.find { it.id == itemId } ?: return@composable
                AddItemScreen(
                    editItem = item,
                    onSave = { updated ->
                        onUpdateItem(updated)
                        navController.popBackStack()
                    },
                    onBack = { navController.popBackStack() }
                )
            }

            composable(VelaRoutes.SETTINGS) {
                SettingsScreen(
                    serverUrl = serverUrl,
                    syncSettings = syncSettings,
                    syncState = syncState,
                    userId = userId,
                    onOpenDevices = { navController.navigate(VelaRoutes.DEVICES) },
                    onOpenAuditLog = { navController.navigate(VelaRoutes.AUDIT_LOG) },
                    onOpenBreachMonitor = { navController.navigate(VelaRoutes.BREACH_MONITOR) },
                    onUpdateSyncServer = onUpdateSyncServer,
                    onUpdateSyncPreferences = onUpdateSyncPreferences,
                    onSyncNow = onSyncNow,
                    onResolveConflictUseLocal = onResolveConflictUseLocal,
                    onResolveConflictUseRemote = onResolveConflictUseRemote,
                    onOpenAutofillSettings = onOpenAutofillSettings,
                    onLock = onLock,
                    onReset = onReset
                )
            }

            composable(VelaRoutes.SHARING) {
                val preselected = preselectedShareItemId
                preselectedShareItemId = null
                SharingScreen(
                    items = items,
                    onBack = { navController.navigate(VelaRoutes.VAULT) },
                    preselectedItemId = preselected
                )
            }

            composable(VelaRoutes.DEVICES) {
                DevicesScreen(onBack = { navController.popBackStack() })
            }

            composable(VelaRoutes.AUDIT_LOG) {
                AuditLogScreen(onBack = { navController.popBackStack() })
            }

            composable(VelaRoutes.BREACH_MONITOR) {
                BreachMonitorScreen(items = items, onBack = { navController.popBackStack() })
            }
        }
    }
}
