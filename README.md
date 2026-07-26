# jnutil

### Build and Test Instructions (PowerShell)
```(powershell)
$root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$appName = "jnUtil"
$config = "Release"
$packagesDir = "$root\packages"

dotnet restore "$root\jnUtil.sln"
dotnet build "$root\jnUtil.sln" --no-restore --configuration $config
dotnet test "$root\jnUtilTests\jnUtilTests.csproj" --no-build --configuration $config --verbosity normal

# Simulate publish (dry run, no actual push)
$xml = [Xml] (Get-Content "$root\$appName\$appName.csproj")
$version = $xml.Project.PropertyGroup.Version
Write-Host "Version: $version"

New-Item -ItemType Directory -Force -Path $packagesDir | Out-Null
dotnet pack "$root\$appName\$appName.csproj" --configuration $config --output $packagesDir

dotnet pack "$root\$appName\$appName.csproj" --no-build --configuration $config --output $packagesDir
$pkg = Get-ChildItem -Recurse -Filter *.nupkg | Select-Object -First 1
Write-Host "Would publish: $($pkg.FullName)"
```