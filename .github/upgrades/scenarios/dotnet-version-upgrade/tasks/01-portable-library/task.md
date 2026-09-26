# 01-portable-library: Retarget the helper library and tests

Update `jnUtil/jnUtil.csproj` and `jnUtilTests/jnUtilTests.csproj` together so the package builds for portable `net10.0` instead of `net10.0-windows`. Investigate platform-specific source and package dependencies exposed by the retargeting, and replace or guard them with portable alternatives while preserving the library's public behavior. Update tests alongside the library when they depend on Windows-only APIs or assumptions.

**Done when**: Both projects target portable `net10.0`, the NuGet package can be packed without Windows-only targeting, the solution builds with no warnings or errors, and all tests pass.

## Scope Inventory and Research

- **Projects**: `jnUtil/jnUtil.csproj` (NuGet class library) and `jnUtilTests/jnUtilTests.csproj` (MSTest project referencing the library).
- **Targeting**: Both SDK-style projects define `TargetFramework` in their respective project files; no local `.props` or `.targets` imports define the TFM.
- **Assessment**: Both projects have zero API and package incidents; all reported dependencies support the requested target. No package updates are required.
- **Platform-specific code**: `SecurityHelper` uses `ProtectedData` and file encryption only behind `RuntimeInformation.IsOSPlatform(OSPlatform.Windows)` checks. Existing tests skip the corresponding account-protection behavior outside Windows. `X509Helper` declares Windows CryptoAPI P/Invoke methods, which are valid in a portable assembly but must not force a Windows TFM.
- **Stubs**: No `// STUB:` markers were found in either project.
- **Build tooling**: Both projects are modern SDK-style projects without WPF, WinForms, or legacy TFMs; validate with `dotnet build` and `dotnet test`.
