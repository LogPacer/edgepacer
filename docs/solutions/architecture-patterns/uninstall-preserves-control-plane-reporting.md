---
title: Preserve control-plane reporting while uninstalling installed artifacts
category: architecture-patterns
source_pr: https://github.com/LogPacer/edgepacer/pull/144
verified_against: 38901c875087922ad0da147a7fab5919e52ba5f3
verified_at: 2026-09-07
---

# Preserve control-plane reporting while uninstalling installed artifacts

## Problem

A supervisor-managed install keeps the control-plane URL and bootstrap credential in supervisor-owned configuration, not necessarily in the operator's interactive environment. If `uninstall` reports after deleting that configuration, or assumes `EDGEPACER_RAILS_URL` is exported, it can remove local state while silently failing to tell the control plane that the installation is gone.

Uninstall also has a wider artifact set than the supervisor unit and state directory. An interrupted or rolled-back update can leave agent `.new` or `.backup` files, and a manager self-update can leave a `.old` rename-aside. Leaving these behind makes an uninstall incomplete and may retain stale executables after credentials and configuration have been removed.

## Invariant

An uninstall must report first, remove only artifacts created by the install/update lifecycle, and remain locally successful when reporting is impossible or the network fails.

1. Resolve the control-plane URL before supervisor configuration is removed.
2. Let an explicit `--rails` or `EDGEPACER_RAILS_URL` value take precedence over persisted configuration.
3. Otherwise recover the URL from the platform-specific configuration written by install: the systemd/Windows env file or the launchd plist.
4. If no URL is available, log that reporting was skipped. If the POST fails, continue with local cleanup.
5. Remove the supervisor, its configuration, token state, the agent executable, and known update leftovers.
6. Apply platform semantics to the running manager executable: Unix may unlink it while it runs; Windows must leave it for manual deletion because a running `.exe` is locked.

The ordering is part of the contract. Reporting uses the persisted server bootstrap token, so deleting `token_store` before `report_uninstall` would make a correct URL insufficient.

## EdgePacer implementation

`src/manager/supervisor.rs` implements the lifecycle boundary:

- `uninstall` resolves `rails_url`, calls the best-effort `report_uninstall`, removes the platform supervisor, deletes the token store, then removes agent and manager artifacts.
- `stored_rails_url` reads `/etc/edgepacer/edgepacer.env` on Linux, the launchd plist on macOS, and the adjacent `edgepacer.env` on Windows.
- `rails_url_from_env_file` accepts CRLF or LF env files and rejects a missing or empty value. `rails_url_from_plist` reverses the escaping applied when install rendered the plist; `&amp;` is decoded last so no earlier substitution creates a new entity.
- `remove_agent_binaries` removes the configured agent path plus `.backup` and `.new`. `remove_manager_binary` always clears `.old`, unlinks the current executable only off Windows, and gives Windows operators an explicit cleanup message.

The control-plane request remains deliberately best-effort: an uninstall must not strand local credentials or a service just because the host is offline. The control plane, rather than the agent, decides what to do with the server-side installation record.

## Verification pattern

Test parsing and artifact cleanup without depending on a real supervisor or network:

1. Cover normal, CRLF, missing, and empty env-file URLs.
2. Cover plist extraction and XML entity restoration.
3. Create a temporary agent executable with `.backup` and `.new` neighbors and assert that all three are removed.
4. Assert the no-artifact case is quiet.
5. Compile platform-specific paths for Windows and validate Linux/macOS paths on their native CI hosts.

Source PR #144 added these focused tests and recorded a successful Windows cross-compile. The current default branch retains the parsing helpers, cleanup ordering, platform-specific removal behavior, and regression tests.
