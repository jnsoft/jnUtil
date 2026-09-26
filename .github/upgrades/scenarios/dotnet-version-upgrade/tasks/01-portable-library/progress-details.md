# 01-portable-library Progress

## Changes
- Retargeted `jnUtil/jnUtil.csproj` from `net10.0-windows` to `net10.0`.
- Retargeted `jnUtilTests/jnUtilTests.csproj` from `net10.0-windows` to `net10.0`.
- Kept existing runtime platform guards for Windows account-protection APIs and existing non-Windows test skips.
- Refactored CMS debug logging to retain debug exception details without release-build unused-variable warnings.

## Validation
- `dotnet build jnUtil.sln -c Release`: succeeded with zero warnings and zero errors.
- `dotnet test jnUtilTests/jnUtilTests.csproj -c Release --no-build`: 49 passed, 0 failed, 0 skipped.
- `dotnet pack jnUtil/jnUtil.csproj -c Release --no-build -o artifacts/packages`: succeeded; produced `jnUtil.2.0.2.nupkg` targeting `net10.0`.

## Notes
- An initial `dotnet pack --no-build` attempt failed because no Release assembly had yet been built. Building Release first resolved NU5026; no source or package incompatibility was involved.
