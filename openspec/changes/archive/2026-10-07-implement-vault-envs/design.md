## Context

Profile-per-file matches INIT separation model.

## Goals / Non-Goals

**Goals:** JSON v1 profile model, export formatter (`export KEY="value"`), unset/remove confirmations as message helpers.

**Non-Goals:** Shell wrapper, `env load` (CLI change).

## Decisions

- Creating a profile on first `set` is allowed (per spec scenario).
- Export escapes values for POSIX shells.

## Risks / Trade-offs

- Special characters in values need careful quoting in export.
