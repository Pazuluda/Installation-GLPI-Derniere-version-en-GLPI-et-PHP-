# ===========================================
# Install GLPI internal CA certificate in Windows
# ===========================================

Write-Host "=== Installing GLPI internal CA certificate ===" -ForegroundColor Cyan

# FULL PATH to certificate, here change the direction file thank you
$CertFile = "C:\Users\client\Desktop\myCA.crt"

# Check if file exists
if (-Not (Test-Path $CertFile)) {
    Write-Host "ERROR: Certificate file not found:" -ForegroundColor Red
    Write-Host $CertFile -ForegroundColor Red
    Write-Host "Make sure the file exists and try again."
    exit 1
}

Write-Host "-> Loading CA certificate..." -ForegroundColor Cyan

try {
    $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertFile)
}
catch {
    Write-Host "ERROR: Unable to load certificate file." -ForegroundColor Red
    exit 1
}

# Open Windows Trusted Root Certification Authorities
try {
    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )

    $Store.Open("ReadWrite")
    $Store.Add($Cert)
    $Store.Close()

    Write-Host "SUCCESS: CA certificate installed." -ForegroundColor Green
    Write-Host "Your HTTPS GLPI instance should now appear SECURE with a lock icon." -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Certificate installation failed." -ForegroundColor Red
    Write-Host "Run PowerShell as Administrator and try again." -ForegroundColor Yellow
}