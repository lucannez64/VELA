# Registers VELA's identity package on this machine for development.
#
# What it does:
#   1. copies the fusion manifest + logo assets next to the provider exe
#      (the external location must hold everything the package references),
#   2. builds the identity .msix with MakeAppx (Windows SDK),
#   3. creates/loads a self-signed code-signing certificate (CN=VELA) and
#      imports its public half into CurrentUser\TrustedPeople,
#   4. signs the package and registers it with Add-AppxPackage, pointing the
#      external location at the exe's directory.
#
# After this, `vela-passkey-provider.exe --register` runs with package
# identity and WebAuthNPluginAddAuthenticator accepts it.
#
# Usage:  .\register-dev.ps1 [-ProviderExe <path-to-vela-passkey-provider.exe>]
# Uninstall:
#   Get-AppxPackage VELA.PasskeyProvider | Remove-AppxPackage

param(
    [string]$ProviderExe = ""
)

$ErrorActionPreference = "Stop"

if (-not $ProviderExe) {
    $repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $ProviderExe = Join-Path $repoRoot "target\debug\vela-passkey-provider.exe"
}
if (-not (Test-Path $ProviderExe)) {
    throw "Provider exe not found at '$ProviderExe'. Build first: cargo build -p vela-win-passkey"
}
$externalLocation = Split-Path -Parent $ProviderExe
Write-Host "External location (exe dir): $externalLocation"

# 1. Stage package-referenced files next to the exe.
$assetsDir = Join-Path $externalLocation "Assets"
New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null
Copy-Item (Join-Path $PSScriptRoot "vela-passkey-provider.manifest") `
    (Join-Path $externalLocation "vela-passkey-provider.manifest") -Force
Copy-Item (Join-Path $PSScriptRoot "Assets\*") $assetsDir -Force

# 2. Find MakeAppx / Signtool in the newest Windows SDK.
$sdkRoots = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending
$makeappx = $null; $signtool = $null
foreach ($root in $sdkRoots) {
    foreach ($arch in @("x64", "x86")) {
        $candidate = if ($arch) { Join-Path $root.FullName $arch } else { $root.FullName }
        $p = Join-Path $candidate "MakeAppx.exe"
        if (Test-Path $p) { $makeappx = $p }
        $p = Join-Path $candidate "Signtool.exe"
        if (Test-Path $p) { $signtool = $p }
    }
    if ($makeappx -and $signtool) { break }
}
if (-not $makeappx) { throw "MakeAppx.exe not found - install the Windows SDK." }
Write-Host "MakeAppx: $makeappx"

# 3. Build the identity package.
$outDir = Join-Path $PSScriptRoot "build"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$packagePath = Join-Path $outDir "VELA.PasskeyProvider.msix"
& $makeappx pack /o /d $PSScriptRoot /nv /p $packagePath
if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed with exit code $LASTEXITCODE" }

# 4. Dev certificate: create once, reuse thereafter.
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq "CN=VELA" -and $_.HasPrivateKey -and $_.FriendlyName -eq "VELA dev signing" } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) {
    Write-Host "Creating self-signed code-signing certificate CN=VELA..."
    $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=VELA" `
        -KeyUsage DigitalSignature -FriendlyName "VELA dev signing" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
}
$pfxPath = Join-Path $outDir "vela-dev.pfx"
$pwdPlain = "vela-dev-only"
$null = $cert | Export-PfxCertificate -FilePath $pfxPath -Password (ConvertTo-SecureString $pwdPlain -Force -AsPlainText)

# Trust: the public half must be in TrustedPeople or Add-AppxPackage refuses
# with CERT_E_UNTRUSTEDROOT.
$cerPath = Join-Path $outDir "vela-dev.cer"
$null = $cert | Export-Certificate -FilePath $cerPath
$existing = Get-ChildItem Cert:\CurrentUser\TrustedPeople | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $existing) {
    Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null
    Write-Host "Imported CN=VELA into CurrentUser\TrustedPeople."
}

# 5. Sign + register.
& $signtool sign /fd SHA256 /f $pfxPath /p $pwdPlain $packagePath
if ($LASTEXITCODE -ne 0) { throw "Signtool failed with exit code $LASTEXITCODE" }

# Re-register cleanly when a previous version is present.
$existingPackage = Get-AppxPackage VELA.PasskeyProvider -ErrorAction SilentlyContinue
if ($existingPackage) {
    Write-Host "Removing previously registered identity package..."
    $existingPackage | Remove-AppxPackage
}

Write-Host "Registering identity package with external location..."
Add-AppxPackage -Path $packagePath -ExternalLocation $externalLocation

$pkg = Get-AppxPackage VELA.PasskeyProvider
if ($pkg) {
    Write-Host "Identity package registered: $($pkg.PackageFullName)"
    Write-Host "External location: $($pkg.InstallLocation)"
} else {
    throw "Package registration reported success but the package is not visible."
}

