# Morpheus SessionRouter SR-1 — Foundry Fork PoC

Proof-of-concept for a responsible-disclosure report to the MorpheusAIs bug
bounty program (report SR-1, submitted by D4rm4 / DARMA150).

**Finding:** SessionRouter provider approvals are bearer instruments that
never expire.

1. `_extractProviderApproval` decodes the `user` field of a signed provider
   approval and discards it — any account can replay any other user's
   approval to open a session (the `SessionApprovedForAnotherUser` check was
   removed in commit `605cfcc5`, 2024-11-26; the error is still declared in
   `ISessionRouter` and never thrown).
2. Production approvals carry **millisecond** timestamps, while the
   `SIGNATURE_TTL` (600 s) check compares against `block.timestamp` in
   seconds — the expiry check can never fire, so unused approvals stay valid
   forever.

**Demonstrated impact (Base mainnet fork, block 58,597,769):** replaying a
real approval issued to another user opens a session and consumes the
approval (the victim's own later use reverts); `closeSession` then pays the
provider 1.7836 MOR from the protocol funding account while the attacker
recovers 100% of stake — net cost 0.

## Run

```bash
forge test
```

The test forks Base mainnet in `setUp()` via `createSelectFork` (public RPC
endpoint configured in the test; swap in your own Base RPC if rate-limited).
Expected: **7 passed, 0 failed**, including the control tests (named user
succeeds, second use reverts, seconds-domain expired approval reverts with
`SessionApproveExpired`, millisecond approval still accepted after warping
+2 days).

## Files

- `foundry.toml` — project config
- `test/SessionRouterApprovalPoC.t.sol` — the PoC (7 tests)
- `test/PocData.sol` — verbatim on-chain approval/receipt data used by the PoC
