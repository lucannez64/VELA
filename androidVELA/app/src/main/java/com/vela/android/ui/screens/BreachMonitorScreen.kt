package com.vela.android.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vela.android.core.BreachCheckService
import com.vela.android.core.PasswordBreachResult
import com.vela.android.core.VaultItem
import com.vela.android.core.VaultMeta
import com.vela.android.core.VelaRepositories
import com.vela.android.ui.components.VelaButton
import com.vela.android.ui.components.VelaButtonStyle
import com.vela.android.ui.components.VelaCard
import com.vela.android.ui.components.VelaTextField
import com.vela.android.ui.theme.VelaColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant

@Composable
fun BreachMonitorScreen(items: List<VaultItem>, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var email by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var passwordResults by remember { mutableStateOf<List<PasswordBreachResult>>(emptyList()) }
    var passwordChecking by remember { mutableStateOf(false) }
    var passwordCheckedCount by remember { mutableStateOf(0) }
    var passwordTotalCount by remember { mutableStateOf(0) }
    val monitors = items.filterIsInstance<VaultItem.BreachMonitor>().sortedBy { it.email.lowercase() }

    Column(Modifier.fillMaxSize().background(VelaColors.SurfaceBase).padding(20.dp)) {
        ScreenHeader("Breach Monitor", onBack)
        Spacer(Modifier.height(16.dp))
        VelaCard {
            Text("Email monitoring", fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(10.dp))
            VelaTextField(email, { email = it }, label = "Email", placeholder = "email@example.com")
            Spacer(Modifier.height(10.dp))
            VelaButton(
                "Check & Add",
                onClick = {
                    scope.launch(Dispatchers.IO) {
                        runCatching { BreachCheckService.checkEmail(email.trim()) }
                            .onSuccess { breaches ->
                                val now = Instant.now()
                                VelaRepositories.vault.addItem(
                                    VaultItem.BreachMonitor(
                                        meta = VaultMeta(
                                            name = email.trim(),
                                            createdAt = now,
                                            updatedAt = now
                                        ),
                                        email = email.trim(),
                                        checkedAt = now,
                                        breachCount = breaches.size,
                                        breaches = breaches
                                    )
                                )
                                VelaRepositories.audit.record("breach_email_checked", "${email.trim()}: ${breaches.size} breach(es)")
                                withContext(Dispatchers.Main) { email = ""; error = null }
                            }
                            .onFailure { e -> withContext(Dispatchers.Main) { error = e.message ?: "Email check failed" } }
                    }
                },
                enabled = email.contains("@")
            )
        }

        Spacer(Modifier.height(12.dp))
        VelaCard {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f)) {
                    Text("Password breach check", fontWeight = FontWeight.SemiBold)
                    Text("Uses Pwned Passwords k-anonymity like desktop.", color = VelaColors.TextMuted, fontSize = 12.sp)
                }
                VelaButton(if (passwordChecking) "Checking..." else "Check", {
                    scope.launch(Dispatchers.IO) {
                        val passwords = items.filterIsInstance<VaultItem.Login>()
                            .filter { it.password.isNotBlank() }
                            .distinctBy { it.password }
                        withContext(Dispatchers.Main) {
                            error = null
                            passwordResults = emptyList()
                            passwordCheckedCount = 0
                            passwordTotalCount = passwords.size
                            passwordChecking = true
                        }
                        runCatching {
                            val results = mutableListOf<PasswordBreachResult>()
                            passwords.chunked(PASSWORD_CHECK_PARALLELISM).forEach { batch ->
                                val batchResults = batch.map { login ->
                                    async {
                                        val result = BreachCheckService.checkPassword(login.password)
                                        if (result.breached) {
                                            result.copy(description = "Password for '${login.name}' found ${result.count} times in breaches")
                                        } else {
                                            result.copy(description = "Password for '${login.name}' is safe")
                                        }
                                    }
                                }.awaitAll()
                                results += batchResults
                                withContext(Dispatchers.Main) {
                                    passwordCheckedCount = results.size
                                    passwordResults = results.toList()
                                }
                            }
                            results.toList()
                        }.onSuccess { results ->
                            VelaRepositories.audit.record("breach_passwords_checked", "${results.count { it.breached }} exposed password(s)")
                        }.onFailure { e ->
                            withContext(Dispatchers.Main) { error = e.message ?: "Password breach check failed" }
                        }
                        withContext(Dispatchers.Main) { passwordChecking = false }
                    }
                }, style = VelaButtonStyle.Surface, fullWidth = false, enabled = !passwordChecking)
            }
            if (passwordChecking || passwordTotalCount > 0) {
                Spacer(Modifier.height(12.dp))
                LinearProgressIndicator(
                    progress = { if (passwordTotalCount == 0) 0f else passwordCheckedCount.toFloat() / passwordTotalCount.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                    color = VelaColors.Green,
                    trackColor = VelaColors.SurfaceHighest
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    if (passwordChecking) {
                        "Checked $passwordCheckedCount of $passwordTotalCount unique passwords"
                    } else {
                        "Last check: $passwordCheckedCount of $passwordTotalCount unique passwords"
                    },
                    color = VelaColors.TextMuted,
                    fontSize = 12.sp
                )
            }
        }

        error?.let {
            Spacer(Modifier.height(10.dp))
            Text(it, color = VelaColors.ErrorRed, fontSize = 13.sp)
        }
        Spacer(Modifier.height(16.dp))
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(monitors, key = { it.id }) { item ->
                VelaCard {
                    Text(item.email, fontWeight = FontWeight.SemiBold)
                    Text("Last checked: ${item.checkedAt ?: "Never"}", color = VelaColors.TextMuted, fontSize = 12.sp)
                    Text("${item.breachCount} breach${if (item.breachCount == 1) "" else "es"}", color = if (item.breachCount > 0) VelaColors.ErrorRed else VelaColors.Green)
                    item.breaches.take(4).forEach { breach ->
                        Spacer(Modifier.height(8.dp))
                        Text(breach.title.ifBlank { breach.name }, fontWeight = FontWeight.Medium, fontSize = 13.sp)
                        Text("${breach.domain} · ${breach.breachDate}", color = VelaColors.TextMuted, fontSize = 12.sp)
                    }
                }
            }
            if (passwordResults.isNotEmpty()) {
                val breachedResults = passwordResults.filter { it.breached }
                items(breachedResults) { result ->
                    VelaCard {
                        Text(
                            "Exposed ${result.count} times",
                            fontWeight = FontWeight.SemiBold,
                            color = VelaColors.ErrorRed
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(result.description, color = VelaColors.TextSecondary, fontSize = 13.sp)
                    }
                }
                if (passwordResults.all { !it.breached }) {
                    item {
                        VelaCard {
                            Text("All passwords are secure!", fontWeight = FontWeight.SemiBold, color = VelaColors.Green)
                            Spacer(Modifier.height(4.dp))
                            Text("None of your vault passwords have been found in known data breaches.", color = VelaColors.TextSecondary, fontSize = 13.sp)
                        }
                    }
                }
                if (breachedResults.isNotEmpty()) {
                    item {
                        VelaCard {
                            Text("Warning: Compromised passwords detected!", fontWeight = FontWeight.SemiBold, color = VelaColors.ErrorRed)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "${breachedResults.size} password(s) in your vault have been exposed in data breaches. Consider changing them immediately.",
                                color = VelaColors.TextSecondary,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
                item {
                    VelaCard {
                        Text("Password results", fontWeight = FontWeight.SemiBold)
                        Text("${passwordResults.count { it.breached }} exposed of ${passwordResults.size} checked", color = VelaColors.TextSecondary)
                    }
                }
            }
        }
    }
}

private const val PASSWORD_CHECK_PARALLELISM = 6
