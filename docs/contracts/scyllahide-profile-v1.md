# ScyllaHide profile contract v1

`scyllahide.profile` is implemented by each x32dbg/x64dbg backend instance.
It edits only that debugger installation's `plugins/scylla_hide.ini`.

- `{"action":"get"}` returns the configured profile, bounded available profile
  names, a SHA-256 config generation, and the profile observed at plugin startup.
- `{"action":"set", ...}` additionally requires `profile`,
  `expected_config_generation`, `instance_id`, and `operation_id`.
- A set uses an atomic file replacement and verifies the resulting file. It is
  never retried blindly.
- `restart_required` compares the current file generation with the generation
  observed at plugin startup. It does not claim that ScyllaHide exposes its live
  internal state.
- When a restart is needed, `next_actions` directs the caller to
  `gateway.debugger_restart`. The backend cannot restart its own owning process.

The tool does not accept arbitrary paths, INI keys, or raw INI content. Input,
profile count, profile-name length, file size, runtime, and response size are
bounded.
