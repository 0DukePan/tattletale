# Install tattle on Windows.
#
#   irm https://raw.githubusercontent.com/OWNER/tattletale/main/install.ps1 | iex
#
# Downloads the latest release, verifies its SHA256 against the published
# checksum, and puts the binary somewhere on the user PATH. No admin rights and
# no machine-wide changes: everything lands under %LOCALAPPDATA%.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = if ($env:TATTLE_REPO) { $env:TATTLE_REPO } else { 'OWNER/tattletale' }
$dest = Join-Path $env:LOCALAPPDATA 'tattletale\bin'

Write-Host 'tattletale installer' -ForegroundColor Yellow
Write-Host "  repository: $repo"

# Resolve the newest release without the GitHub API (no rate limits, no token).
$latest = "https://github.com/$repo/releases/latest/download"
$asset = 'SHA256SUMS.txt'

try {
    $sums = (Invoke-WebRequest -Uri "$latest/$asset" -UseBasicParsing).Content
} catch {
    throw "Could not reach the release page for $repo. Check the repository name and your connection."
}

$zipLine = ($sums -split "`n" | Where-Object { $_ -match '\.zip$' } | Select-Object -First 1)
if (-not $zipLine) { throw 'No zip asset found in the latest release.' }

$parts = $zipLine.Trim() -split '\s+'
$expected = $parts[0]
$zipName = $parts[1]
Write-Host "  asset:      $zipName"

$tmp = Join-Path $env:TEMP ("tattle-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $zipPath = Join-Path $tmp $zipName
    Write-Host '  downloading...'
    Invoke-WebRequest -Uri "$latest/$zipName" -OutFile $zipPath -UseBasicParsing

    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        throw "Checksum mismatch: expected $expected, got $actual. Refusing to install."
    }
    Write-Host '  checksum:   ok' -ForegroundColor Green

    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    $exe = Get-ChildItem $tmp -Recurse -Filter 'tattle.exe' | Select-Object -First 1
    if (-not $exe) { throw 'tattle.exe was not found inside the archive.' }

    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item $exe.FullName (Join-Path $dest 'tattle.exe') -Force
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# Add to the user PATH if it is not already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$dest*") {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $dest } else { "$userPath;$dest" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-Host "  PATH:       added $dest (open a new terminal)"
} else {
    Write-Host "  PATH:       already contains $dest"
}

Write-Host ''
Write-Host 'Installed.' -ForegroundColor Green
Write-Host ''
Write-Host '  tattle doctor              check this machine'
Write-Host '  tattle                     live view'
Write-Host '  tattle report --open       write and open a receipt'
Write-Host '  tattle demo                see a labelled example first'
Write-Host ''
