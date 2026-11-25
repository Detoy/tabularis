Refs #1328 (phase 5: Kubernetes and SSM tunnels). Stacked on #1655: this branch is #1655's head plus one commit, so please review it after #1655 lands. I will rebase it onto `main` then.

## Summary

The health check can only replace a half-open SSH tunnel. A `kubectl port-forward` or an AWS SSM session whose process is still running but no longer forwards (after sleep or a network change) passes `is_alive()`, so recovery reconnects to the same stuck local port and the connection ends up lost. This PR makes both health loops (desktop and the `tabularis web` loop from #1655) replace a half-open SSH, Kubernetes or SSM tunnel the same way.

## Root cause

1. `TunnelLease` could only name an SSH cache entry, and `discard_ssh_tunnel` could only stop an SSH tunnel.
2. On desktop the lease was read from params that `expand_k8s_connection_params` had already resolved. Resolving a Kubernetes connection points it at `127.0.0.1:<local port>` and sets `k8s_enabled = false`, so even a Kubernetes-aware lease lookup would find nothing there.

## Fix

- `TunnelLease` now holds a `TunnelRoute` (`Ssh`, `K8s` or `Ssm`) plus the generation. `tunnel_lease()` and `discard_tunnel()` replace the SSH-only pair. `discard_tunnel()` stops only the generation that was leased, so a tunnel that was already replaced is left alone.
- A discarded port-forward is stopped but stays cached, so its replacement binds the same local port. An SSM session is stopped and removed from the cache, like SSH.
- `K8sTunnel::stop` now waits for `kubectl` to exit. Without that wait the killed process still looked alive and was handed out again.
- New `saved_tunnel_lease(runtime, connection_id, params)`: it reads the lease from the saved params, expanded but not resolved. Both loops use it: desktop `resolve_params` and the web `resolve_saved`, which replaces the web loop's inline SSH-only lookup.

## Test plan

Run on Linux (cloud box) against this branch:

- `cargo test --lib tunnel`: 165 passed, 0 failed, 1 ignored.
- `cargo test --lib`: 3016 passed, 0 failed, 19 ignored.
- `cargo check --no-default-features`: builds (server-only).
- `cargo clippy --lib`: no warnings in the changed code (the 4 hits in `tunnels.rs` are `incompatible_msrv` notes on lines 372 to 399, which this PR does not touch).
- `rustfmt --check` on the changed files: clean.

New tests (6):
- `tunnel_lease_names_the_cached_k8s_port_forward`, `discard_stops_a_k8s_port_forward_and_keeps_its_port`, `discard_leaves_a_replaced_k8s_port_forward_running`, `ssm_lease_discard_stops_only_the_leased_session`, and `a_discarded_k8s_port_forward_is_rebuilt_on_the_same_port`, which uses a fake `kubectl` whose port-forward accepts TCP and never forwards a byte (the half-open case).
- `saved_tunnel_lease_names_the_k8s_port_forward_resolving_hides`: a saved Kubernetes profile with a cached port-forward. It asserts that the resolved params give no lease (the old desktop path) and that `saved_tunnel_lease` names the port-forward and its generation.

Mutation checks:
- Making `discard_tunnel` a no-op for Kubernetes and SSM (the behaviour on `main`) fails the Kubernetes and SSM discard tests, including the half-open fake `kubectl` test.
- Making `saved_tunnel_lease` read the lease from resolved params (what desktop did before) fails the new test at the lease assertion.

## Limits

- No run against a real cluster or a real SSM session. The half-open case is covered by the fake `kubectl` and by unit tests of the cache.
- The desktop `resolve_params` wiring itself has no test, because it needs a Tauri `AppHandle`. The logic it now calls is tested directly.
- GitNexus is not available in this environment, so impact was checked with grep: `tunnel_lease`, `discard_tunnel` and `saved_tunnel_lease` are called only from the two health loops and the tests. Risk LOW.
- The commits are not signed (cloud environment).

This PR was written with the help of an AI coding assistant (Claude Code). Every command and result above was run in this session.
