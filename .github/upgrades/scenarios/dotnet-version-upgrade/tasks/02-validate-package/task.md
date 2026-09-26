# 02-validate-package: Validate portable package output

Build, test, and pack the completed solution to verify the released `jnUtil` artifact advertises portable `net10.0` compatibility. Confirm no residual project configuration, transitive dependency, or warning forces Windows targeting.

**Done when**: The solution build and test suite complete without warnings or errors, and a successfully produced NuGet package targets `net10.0` rather than `net10.0-windows`.
