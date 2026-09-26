# .NET Version Upgrade Plan

## Overview

**Target**: Retarget the jnUtil helper-library NuGet package and its test project from Windows-only .NET 10 to portable `net10.0`.
**Scope**: Two SDK-style modern .NET projects with compatible dependencies and a direct test-to-library reference.

## Tasks

### 01-portable-library: Retarget the helper library and tests

Update `jnUtil/jnUtil.csproj` and `jnUtilTests/jnUtilTests.csproj` together so the package builds for portable `net10.0` instead of `net10.0-windows`. Investigate platform-specific source and package dependencies exposed by the retargeting, and replace or guard them with portable alternatives while preserving the library's public behavior. Update tests alongside the library when they depend on Windows-only APIs or assumptions.

**Done when**: Both projects target portable `net10.0`, the NuGet package can be packed without Windows-only targeting, the solution builds with no warnings or errors, and all tests pass.

---

### 02-validate-package: Validate portable package output

Build, test, and pack the completed solution to verify the released `jnUtil` artifact advertises portable `net10.0` compatibility. Confirm no residual project configuration, transitive dependency, or warning forces Windows targeting.

**Done when**: The solution build and test suite complete without warnings or errors, and a successfully produced NuGet package targets `net10.0` rather than `net10.0-windows`.
