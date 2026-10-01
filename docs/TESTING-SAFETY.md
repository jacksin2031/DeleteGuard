# Testing safety boundary

DeleteGuard's kernel/runtime validation is designed around a disposable VM boundary.

The repository intentionally does **not** provide a one-click command that disables Secure Boot, modifies firmware settings, enables test mode, installs a development minifilter, enables Driver Verifier, and starts destructive tests on an arbitrary Windows host.

Instead:

- VM preparation requires explicit acknowledgement.
- later scripts require a machine-bound marker under `%ProgramData%`;
- destructive tests are restricted to `C:\DeleteGuard-VMTest`;
- existing test-root/path components are rejected if they are NTFS reparse points (for example junctions or symbolic links), preventing the fixed test path from being redirected into unrelated data;
- the cleanup path requires a sentinel before recursive deletion;
- Driver Verifier targets only `DeleteGuardFilter.sys`;
- Secure Boot must be changed manually by the tester if necessary;
- the local test-signing private key is not exported;
- production data and the normal workstation are out of bounds.

CI parses the test-VM scripts with Windows PowerShell 5.1 and smoke-tests the destructive-path allow/deny boundary. Those checks validate the harness itself; they do not replace an actual loaded-driver run in a disposable VM.

This safety boundary is part of DeleteGuard's release process, not just documentation guidance.
