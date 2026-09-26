# .NET Version Upgrade

## Preferences
- **Flow Mode**: Automatic
- **Target Framework**: net10.0
- **Goal**: Make the helper library NuGet package portable by removing Windows-only targeting.

## Upgrade Options
**Source**: .github/upgrades/scenarios/dotnet-version-upgrade/upgrade-options.md

### Strategy
- Upgrade Strategy: All-at-Once

## Strategy
**Selected**: All-at-Once
**Rationale**: Two SDK-style modern .NET projects have compatible packages, no assessed API incidents, and a direct test-to-library dependency.

### Execution Constraints
- Retarget the library and test project together in one atomic change.
- Remove or replace Windows-only dependencies discovered during the portable build.
- Restore and build the full solution after project-file and code changes.
- Run the complete test suite only after the solution builds without warnings.

## Source Control
- **Source Branch**: multi-platform
- **Working Branch**: upgrade-dotnet-10
- **Commit Strategy**: After Each Task
- **Branch Sync**: Auto (Merge)
