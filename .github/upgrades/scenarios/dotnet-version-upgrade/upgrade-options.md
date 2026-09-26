# Upgrade Options — jnUtil

Assessment: 2 SDK-style .NET 10 Windows-targeted projects, compatible packages, and no assessed API incidents.

## Strategy

### Upgrade Strategy
The solution has two modern .NET projects, a shallow dependency graph, and no identified package or API migration risks.

| Value | Description |
|-------|-------------|
| **All-at-Once** (selected) | Retarget the library and its test project together in one atomic pass. |
| Top-Down | Keep the solution incrementally buildable through temporary multi-targeting and later consolidation. |
