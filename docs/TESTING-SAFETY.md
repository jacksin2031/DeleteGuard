# Testing safety boundary

DeleteGuard's kernel/runtime validation is designed around a disposable VM boundary.

The repository intentionally does **not** provide a one-click command that disables Secure Boot, modifies firmware settings, enables test mode, installs a development minifilter, enables Driver Verifier, and starts destructive tests on an arbitrary Windows host.

Instead:

- VM preparation requires explicit acknowledgement.
- later scripts require a machine-bound marker under `%ProgramData%`;
- destructive tests are restricted to `C:\DeleteGuard-VMTest`;
- the cleanup path requires a sentinel before recursive deletion;
- Driver Verifier targets only `DeleteGuardFilter.sys`;
- Secure Boot must be changed manually by the tester if necessary;
- production data and the normal workstation are out of bounds.

This safety boundary is part of DeleteGuard's release process, not just documentation guidance.
