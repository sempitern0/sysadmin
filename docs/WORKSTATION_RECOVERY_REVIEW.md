# Workstation recovery review

## Corrected in this revision

- Completed entries were replayed on a second Restore invocation. Recovery now skips them, preserving changes made after a completed rollback.
- Journal persistence errors were caught together with setting errors, allowing further changes without a reliable checkpoint. A failed save now aborts recovery immediately and restores the in-memory status for retry.
- Validation happened too late, potentially after earlier entries had changed. Schema, identity fields, timestamp, unique integer indices, known statuses/types, registry state shape and power GUIDs are now checked before any write.
- History order depended on folder names. It now uses the recorded timestamp, including when a run directory has been renamed.
- Removed the unused HasPoint field: a saved point descriptor does not prove that Windows still retains the restore point.

## Code boundaries

`Assert-RecoveryJournal` validates the whole journal. `Get-RecoveryHistory` discovers and summarizes it. `Select-RecoverySnapshot` handles selection. `Invoke-JournalRecovery` owns reverse ordering, ShouldProcess, status persistence and result counts. `Restore-RecordedEntry` retains the compare-before-write and verification logic for each setting. Presentation consumes the result object.

Keep the root script standalone. Use named functions with one responsibility, descriptive variables, four-space indentation and comments explaining invariants rather than restating assignments. Avoid unrelated formatting changes and new dependencies. New recovery entry types must add validation, execution and failure-case tests together. Keep Windows PowerShell 5.1 syntax compatibility.

## Validation

PowerShell 7.4.6 on Linux: parser and existing AD/migration suites pass, plus 189 workstation checks (63 planning, 52 console/process, 45 inventory/licensing, 29 recovery). Recovery tests cover empty/corrupt/foreign history, operator mismatch, ordering independent of directory names, cancellation, WhatIf, reverse entry order, repeated recovery, conflicts, setting failures, persistence failure, manual account handling and invalid journals rejected before writes.

Tests use isolated temporary journals and doubles for system mutations. They do not harden or restore the execution host. Windows inventory smoke test is explicitly skipped on Linux. The GitHub connector returned no workflow runs for the pre-review head; no Windows CI success is claimed.

## Remaining acceptance work

On a disposable Windows client, exercise Apply -> Restore -> Restore again, both from PowerShell 7 and Windows PowerShell 5.1. Verify a later administrator change remains intact, a partial run is recoverable, registry types and startup entries are preserved, and a restart leaves the intended state. Check System Restore separately: its UI and available points belong to Windows and may affect unrelated installations.

Journal validation detects malformed data; it is not a cryptographic authenticity guarantee. Keep journals in the protected local StateRoot and do not import untrusted snapshots. No transaction spans the setting write and journal save: retry logic checks current values against before/after states to handle interruption. Multiple runs must be recovered newest first. Without journals or retained Windows restore points, the original state cannot be inferred reliably.
