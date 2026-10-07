# CHANGELOG

- **2.5.0** - 07.10.2026 - Checkmk 2.5 support: the special agent uses the new password store (`cmk.password_store.v1_unstable`) and crash reports (`cmk.server_side_programs.v1_unstable`) instead of the deprecated `cmk.special_agents.v0_unstable`/`cmk.utils.password_store`, with fallback for 2.3/2.4. Rules and command line unchanged (existing 2.4 rules are migrated by `omd update`)
- **2.4.9** - 07.10.2026 - Fix rate services staying PEND for several check intervals after discovery (only one counter was initialized per run); hosts use the shared rate helper
- **2.4.8** - 07.10.2026 - Migrate repo to checkmk-plugin-template (devcontainer, CI, releases via GitHub), format code with black/isort, fix flake8 findings, pool capacity default parameters in rule spec format (fixes cmk-validate-plugins)
- **2.4.7** - 12.12.2025 - raise rest api timeouts
- **2.4.6** - 12.12.2025 - catch api error 400
- **2.4.5** - 05.12.2025 - Change URL
- **2.4.4** - 05.12.2025 - Fix Pylance Errors
- **2.4.3** - 05.12.2025 - Refactor: Extract duplicated code to lib.py, standardize imports and param access
- **2.4.2** - 05.12.2025 - Add Manpages
- **2.4.1** - 05.12.2025 - Major Code Cleanup, minor Bugfixes, Typing
- **2.3.7** - 05.12.2025 - yield sansymphony host labels
- **2.3.6** - 25.11.2025 - Added new service for pool capacity monitoring with magic factor support, adds possibility to ignore pool oversubscription
- **2.3.5** - 07.08.2025 - Changed until version to 2.4 and code cleanup by Andreas Döhler
- **2.3.4** - 25.10.2024 - Fixed iscsi Port connection status
- **2.3.3** - 16.09.2024 - Fixed pool size calculation and perfdata unit
- **2.3.2** - 13.09.2024 - Fixed minor latency and alert bugs
- **2.3.1** - 20.06.2024 - First "official" release of the new DataCore SANsymphony plugin
