package com.vela.android.ui.navigation

import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import com.vela.android.core.accountsNeedingAttention

import com.vela.android.core.withMeta

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.vela.android.core.VaultItem
import com.vela.android.core.VelaRepositories
import com.vela.android.sync.SyncSettings
import com.vela.android.sync.V3EnrollmentLocator
import com.vela.android.sync.SyncState
import com.vela.android.ui.screens.AddItemScreen
import com.vela.android.ui.screens.AuditLogScreen
import com.vela.android.ui.screens.BreachMonitorScreen
import com.vela.android.ui.screens.DevicesScreen
import com.vela.android.ui.screens.EnrollDeviceScreen
import com.vela.android.ui.screens.ItemDetailScreen
import com.vela.android.ui.screens.RecoverAccountScreen
import com.vela.android.ui.screens.RecoverySetupScreen
import com.vela.android.ui.screens.SettingsScreen
import com.vela.android.ui.screens.SharingScreen
import com.vela.android.ui.screens.UnlockScreen
import com.vela.android.ui.screens.VaultBrowserScreen
import com.vela.android.ui.screens.WebAccessScreen
import com.vela.android.ui.screens.WelcomeScreen
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.outlined.GridView
import androidx.compose.material.icons.outlined.Casino
import androidx.compose.material.icons.outlined.MoreHoriz
import com.vela.android.ui.components.InstrumentDock
import com.vela.android.ui.components.InstrumentDockItem
import com.vela.android.ui.screens.OverviewScreen
import com.vela.android.ui.screens.GeneratorScreen
import com.vela.android.ui.screens.MoreScreen

object VelaRoutes {
    const val OVERVIEW = "overview"
    const val GENERATOR = "generator"
    const val MORE = "more"
    const val WELCOME = "welcome"
    const val UNLOCK = "unlock"
    const val VAULT = "vault"
    const val ITEM_DETAIL = "item/{itemId}"
    const val ADD_ITEM = "add_item"
    const val EDIT_ITEM = "edit_item/{itemId}"
    const val SETTINGS = "settings"
    const val ENROLL = "enroll"
    const val RECOVER = "recover"
    const val RECOVERY_SETUP = "recovery_setup"
    const val DEVICES = "devices"
    const val WEB_ACCESS = "web_access"
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
    BottomNavItem(VelaRoutes.OVERVIEW, "Overview", com.vela.android.ui.components.InstrumentIcons.Grid, com.vela.android.ui.components.InstrumentIcons.Grid),
    BottomNavItem(VelaRoutes.VAULT, "Vault", com.vela.android.ui.components.InstrumentIcons.Vault, com.vela.android.ui.components.InstrumentIcons.Vault),
    BottomNavItem(VelaRoutes.GENERATOR, "Generate", com.vela.android.ui.components.InstrumentIcons.Dice, com.vela.android.ui.components.InstrumentIcons.Dice),
    BottomNavItem(VelaRoutes.MORE, "More", com.vela.android.ui.components.InstrumentIcons.Dots, com.vela.android.ui.components.InstrumentIcons.Dots)
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
    onOpenPasskeyProviderSettings: () -> Unit,
    onSyncNow: () -> Unit,
    onResolveConflictUseLocal: () -> Unit,
    onResolveConflictUseRemote: () -> Unit,
    onUpdateSyncServer: (String, String) -> Unit,
    onUpdateSyncPreferences: (Boolean, Int) -> Unit,
    autoLockMinutes: Int,
    clipboardClearSeconds: Int,
    onUpdateAutoLockMinutes: (Int) -> Unit,
    onUpdateClipboardClearSeconds: (Int) -> Unit,
    onNavigateToEnroll: () -> Unit,
    onEnrollDevice: (String, String) -> Unit,
    /// Enrollment v3 (audit P-1). Multi-step because a person stands in the
    /// middle: it reports this device's own fingerprint through `onFingerprint`
    /// and only returns once the other device's user has confirmed it.
    onJoinDeviceV3: suspend (String, String, (String) -> Unit) -> Unit,
    onNavigateToRecover: () -> Unit,
    onRecoverAccount: (String, String, String, Long, String?, String, String) -> Unit,
    onProtectEnrolledBiometric: () -> Unit,
    onProtectEnrolledPassword: (String) -> Unit,
    serverUrl: String,
    syncSettings: SyncSettings,
    syncState: com.vela.android.sync.SyncState,
    userId: String?,
    themeSetting: String,
    onThemeChange: (String) -> Unit
) {
    val organization by VelaRepositories.vault.organization.collectAsState()
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    val hasVault = hasBiometricVault || hasPasswordVault
    var generatedPassword by remember { mutableStateOf("") }
    var favoritesOnly by remember { mutableStateOf(false) }
    var attentionOnly by remember { mutableStateOf(false) }
    var recentVersion by remember { mutableStateOf(0) }
    var preselectedShareItemId by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(isUnlocked) { if (!isUnlocked) { generatedPassword = ""; favoritesOnly = false; attentionOnly = false } }

    val authRoute = when {
        !hasVault -> VelaRoutes.WELCOME
        !isUnlocked -> VelaRoutes.UNLOCK
        else -> VelaRoutes.OVERVIEW
    }

    LaunchedEffect(authRoute, currentRoute) {
        val routeRequiresUnlockedVault = currentRoute in listOf(
            VelaRoutes.OVERVIEW, VelaRoutes.GENERATOR, VelaRoutes.MORE,
            VelaRoutes.VAULT,
            VelaRoutes.SHARING,
            VelaRoutes.SETTINGS,
            VelaRoutes.ADD_ITEM,
            VelaRoutes.ITEM_DETAIL,
            VelaRoutes.EDIT_ITEM,
            VelaRoutes.DEVICES,
            VelaRoutes.AUDIT_LOG,
            VelaRoutes.BREACH_MONITOR, VelaRoutes.RECOVERY_SETUP, VelaRoutes.WEB_ACCESS
        )
        val isEnrollRoute = currentRoute == VelaRoutes.ENROLL || currentRoute == VelaRoutes.RECOVER

        val shouldRedirect = when (authRoute) {
            VelaRoutes.WELCOME -> currentRoute != VelaRoutes.WELCOME && !isEnrollRoute
            VelaRoutes.UNLOCK -> currentRoute != VelaRoutes.UNLOCK && routeRequiresUnlockedVault
            VelaRoutes.OVERVIEW -> currentRoute == null || currentRoute == VelaRoutes.WELCOME || currentRoute == VelaRoutes.UNLOCK || isEnrollRoute
            else -> false
        }

        if (shouldRedirect) {
            navController.navigate(authRoute) {
                popUpTo(navController.graph.findStartDestination().id) { inclusive = true }
                launchSingleTop = true
            }
        }
    }

    val showBottomBar = isUnlocked && currentRoute in listOf(VelaRoutes.OVERVIEW, VelaRoutes.VAULT, VelaRoutes.GENERATOR, VelaRoutes.MORE)

    Scaffold(
        bottomBar = {
            if (showBottomBar) {
                val selectedRoute = bottomNavItems.firstOrNull { item ->
                    navBackStackEntry?.destination?.hierarchy?.any { it.route == item.route } == true
                }?.route ?: VelaRoutes.OVERVIEW
                InstrumentDock(
                    items = bottomNavItems.map { InstrumentDockItem(it.route, it.label, it.selectedIcon) },
                    selectedRoute = selectedRoute,
                    onSelect = { route ->
                        navController.navigate(route) {
                            popUpTo(navController.graph.findStartDestination().id) {
                                saveState = true
                            }
                            launchSingleTop = true
                            restoreState = true
                        }
                    },
                    modifier = Modifier.navigationBarsPadding()
                )
            }
        }
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = authRoute,
            enterTransition = { fadeIn(tween(250)) + slideInVertically(tween(250, easing = com.vela.android.ui.components.InstrumentEase), initialOffsetY = { it / 60 }) },
            exitTransition = { fadeOut(tween(150)) },
            popEnterTransition = { fadeIn(tween(250)) },
            popExitTransition = { fadeOut(tween(150)) + slideOutVertically(tween(200), targetOffsetY = { it / 80 }) },
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
                    },
                    onNavigateToRecover = {
                        onNavigateToRecover()
                        navController.navigate(VelaRoutes.RECOVER)
                    }
                )
            }

            composable(VelaRoutes.ENROLL) {
                val scope = rememberCoroutineScope()
                var enrolling by remember { mutableStateOf(false) }
                var enrolled by remember { mutableStateOf(false) }
                var error by remember { mutableStateOf<String?>(null) }

                var joinFingerprint by remember { mutableStateOf<String?>(null) }
                var joinJob by remember { mutableStateOf<Job?>(null) }

                EnrollDeviceScreen(
                    errorMessage = error,
                    isEnrolling = enrolling,
                    isEnrolled = enrolled,
                    joinFingerprint = joinFingerprint,
                    onCancelJoin = {
                        joinJob?.cancel()
                        joinJob = null
                        joinFingerprint = null
                        enrolling = false
                    },
                    onEnroll = { url, code ->
                        enrolling = true
                        error = null
                        val job = scope.launch(Dispatchers.IO) {
                            try {
                                // Which flow runs is decided by the code's own
                                // prefix, never guessed: a v2 and a v3 install
                                // have to keep enrolling each other until old
                                // builds age out.
                                if (V3EnrollmentLocator.looksLikeV3(code)) {
                                    onJoinDeviceV3(url, code) { fingerprint ->
                                        joinFingerprint = fingerprint
                                    }
                                } else {
                                    onEnrollDevice(url, code)
                                }
                                withContext(Dispatchers.Main) {
                                    joinFingerprint = null
                                    enrolled = true
                                }
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    joinFingerprint = null
                                    error = e.message ?: "Enrollment failed"
                                }
                            } finally {
                                withContext(NonCancellable + Dispatchers.Main) {
                                    enrolling = false
                                }
                            }
                        }
                        joinJob = job
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

            composable(VelaRoutes.RECOVER) {
                val scope = rememberCoroutineScope()
                var recovering by remember { mutableStateOf(false) }
                var recovered by remember { mutableStateOf(false) }
                var error by remember { mutableStateOf<String?>(null) }

                RecoverAccountScreen(
                    errorMessage = error,
                    isRecovering = recovering,
                    isRecovered = recovered,
                    onRecover = { url, userIdInput, cloudUserId, share1Epoch, cloudSplitId, share1B64, deviceName ->
                        recovering = true
                        error = null
                        scope.launch(Dispatchers.IO) {
                            try {
                                onRecoverAccount(
                                    url,
                                    userIdInput,
                                    cloudUserId,
                                    share1Epoch,
                                    cloudSplitId,
                                    share1B64,
                                    deviceName,
                                )
                                withContext(Dispatchers.Main) {
                                    recovered = true
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    error = e.message ?: "Account recovery failed"
                                }
                            } finally {
                                withContext(Dispatchers.Main) {
                                    recovering = false
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

            composable(VelaRoutes.OVERVIEW) {
                OverviewScreen(items, syncState,
                    onItem = {
                        VelaRepositories.recent.touch(it.id)
                        recentVersion++
                        navController.navigate(VelaRoutes.itemDetail(it.id))
                    },
                    onVault = { favoritesOnly = false; attentionOnly = false; navController.navigate(VelaRoutes.VAULT) },
                    onFavorites = { favoritesOnly = true; attentionOnly = false; navController.navigate(VelaRoutes.VAULT) },
                    onAttention = { favoritesOnly = false; attentionOnly = true; navController.navigate(VelaRoutes.VAULT) },
                    onGenerate = { navController.navigate(VelaRoutes.GENERATOR) }, onLock = onLock,
                    recentIds = remember(recentVersion) { VelaRepositories.recent.orderedIds() })
            }
            composable(VelaRoutes.GENERATOR) {
                GeneratorScreen({ password -> generatedPassword = password; navController.navigate(VelaRoutes.ADD_ITEM) }, syncState)
            }
            composable(VelaRoutes.MORE) {
                MoreScreen(userId, onNavigate = { route ->
                    when (route) {
                        "favorites" -> { favoritesOnly = true; attentionOnly = false; navController.navigate(VelaRoutes.VAULT) }
                        "attention" -> { favoritesOnly = false; attentionOnly = true; navController.navigate(VelaRoutes.VAULT) }
                        else -> navController.navigate(route)
                    }
                }, onLock = onLock, syncState = syncState,
                    favorites = items.count { it.favorite },
                    attention = remember(items) { items.accountsNeedingAttention().size })
            }

            composable(VelaRoutes.VAULT) {
                VaultBrowserScreen(
                    items = items,
                    itemCount = itemCount,
                    onItemClick = { item ->
                        navController.navigate(VelaRoutes.itemDetail(item.id))
                    },
                    onAddItem = {
                        generatedPassword = ""
                        navController.navigate(VelaRoutes.ADD_ITEM)
                    },
                    onLock = onLock,
                    initialFavoritesOnly = favoritesOnly,
                    initialAttentionOnly = attentionOnly,
                    syncState = syncState,
                    organization = organization,
                    onEnableCollections = { VelaRepositories.vault.enableRichItems() },
                    onMutateOrganization = { VelaRepositories.vault.mutateOrganization(it) }
                )
            }

            dialog(VelaRoutes.ADD_ITEM, dialogProperties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false, securePolicy = SecureFlagPolicy.Inherit)) {
                AddItemScreen(
                    editItem = null,
                    initialPassword = generatedPassword,
                    organization = organization,
                    onSave = { item ->
                        onAddItem(item)
                        generatedPassword = ""
                        navController.popBackStack()
                    },
                    onBack = { generatedPassword = ""; navController.popBackStack() }
                )
            }

            composable(VelaRoutes.ITEM_DETAIL) { backStackEntry ->
                val itemId = backStackEntry.arguments?.getString("itemId") ?: return@composable
                val item = items.find { it.id == itemId }
                LaunchedEffect(itemId) { VelaRepositories.recent.touch(itemId); recentVersion++ }
                ItemDetailScreen(
                    item = item,
                    organization = organization,
                    onBack = { navController.popBackStack() },
                    onEdit = { navController.navigate(VelaRoutes.editItem(itemId)) },
                    onDelete = {
                        onDeleteItem(itemId)
                        navController.popBackStack()
                    },
                    onToggleFavorite = { current ->
                        onUpdateItem(current.withMeta { it.copy(favorite = !it.favorite) })
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

            dialog(VelaRoutes.EDIT_ITEM, dialogProperties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false, securePolicy = SecureFlagPolicy.Inherit)) { backStackEntry ->
                val itemId = backStackEntry.arguments?.getString("itemId") ?: return@dialog
                val item = items.find { it.id == itemId } ?: return@dialog
                AddItemScreen(
                    editItem = item,
                    organization = organization,
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
                    onOpenRecoverySetup = { navController.navigate(VelaRoutes.RECOVERY_SETUP) },
                    onUpdateSyncServer = onUpdateSyncServer,
                    onUpdateSyncPreferences = onUpdateSyncPreferences,
                    onSyncNow = onSyncNow,
                    onResolveConflictUseLocal = onResolveConflictUseLocal,
                    onResolveConflictUseRemote = onResolveConflictUseRemote,
                    onOpenAutofillSettings = onOpenAutofillSettings,
                    onOpenPasskeyProviderSettings = onOpenPasskeyProviderSettings,
                    onLock = onLock,
                    onReset = onReset,
                    autoLockMinutes = autoLockMinutes,
                    clipboardClearSeconds = clipboardClearSeconds,
                    onUpdateAutoLockMinutes = onUpdateAutoLockMinutes,
                    onUpdateClipboardClearSeconds = onUpdateClipboardClearSeconds,
                    themeSetting = themeSetting,
                    onThemeChange = onThemeChange,
                    onBack = { navController.popBackStack() },
                    biometricUnlockEnabled = hasBiometricVault
                )
            }

            composable(VelaRoutes.RECOVERY_SETUP) {
                RecoverySetupScreen(onBack = { navController.popBackStack() })
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
                DevicesScreen(
                    onBack = { navController.popBackStack() },
                    onWebAccess = { navController.navigate(VelaRoutes.WEB_ACCESS) },
                )
            }

            composable(VelaRoutes.WEB_ACCESS) {
                WebAccessScreen(onBack = { navController.popBackStack() })
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
