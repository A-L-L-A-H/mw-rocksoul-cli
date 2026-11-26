param([Parameter(Mandatory = $true)][string]$Tag, [string]$Notes = "")
$ErrorActionPreference = 'Stop'
if (-not $Notes) { $Notes = "Rocksoul $Tag" }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$dist = Join-Path $root 'dist'
Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $dist | Out-Null
$targets = @(@('windows','amd64','.exe'), @('linux','amd64',''), @('linux','arm64',''), @('darwin','arm64',''))
$env:CGO_ENABLED = '0'
foreach ($t in $targets) {
  $env:GOOS = $t[0]; $env:GOARCH = $t[1]
  $out = Join-Path $dist "rocksoul-$($t[0])-$($t[1])$($t[2])"
  go build -trimpath -ldflags '-s -w' -o $out ./cmd/rocksoul
  if ($LASTEXITCODE -ne 0) { throw "build failed for $($t[0])/$($t[1])" }
}
Remove-Item Env:GOOS, Env:GOARCH
$lines = Get-ChildItem $dist -File | Where-Object Name -ne 'checksums.txt' | ForEach-Object {
  "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)"
}
[IO.File]::WriteAllText((Join-Path $dist 'checksums.txt'), (($lines -join "`n") + "`n"))
$assets = Get-ChildItem $dist -File | ForEach-Object FullName
gh release create $Tag @assets --title $Tag --notes $Notes
if ($LASTEXITCODE -ne 0) { throw 'gh release create failed' }
