# jnutil

### Build and Test Instructions (PowerShell)
```(powershell)
dotnet restore 
dotnet build --no-restore --configuration Release
dotnet test --no-build --configuration Release --verbosity normal

# Simulate publish (dry run, no actual push)
$xml = [Xml] (Get-Content "$root\$appName\$appName.csproj")
$version = $xml.Project.PropertyGroup.Version
Write-Host "Version: $version"

dotnet pack --configuration Release -p:IncludeSymbols=false

$pkg = Get-ChildItem -Recurse -Filter *.nupkg | Select-Object -First 1
Write-Host "Would publish: $($pkg.FullName)"
```