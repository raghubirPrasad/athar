// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title GovernanceLedger — ATHAR scan and decision anchoring (SPEC §12.2)
/// @notice Stores only hashes, counts and timestamps. No IAM data is ever written on-chain.
/// @dev Roles: SCANNER_ROLE may commit scans, DECIDER_ROLE may record decisions. A decision can
///      only reference a finding whose leaf is provably part of a committed scan's Merkle root
///      (OpenZeppelin `MerkleProof`, sorted-pair nodes, double-hashed leaves — see SPEC §12.3).
contract GovernanceLedger is AccessControl {
    bytes32 public constant SCANNER_ROLE = keccak256("SCANNER_ROLE");
    bytes32 public constant DECIDER_ROLE = keccak256("DECIDER_ROLE");

    /// @dev Lowest and highest valid decision codes (SPEC §12.2):
    ///      1 approved · 2 rejected · 3 auto_remediated · 4 remediation_applied · 5 exception_granted.
    uint8 public constant MIN_DECISION = 1;
    uint8 public constant MAX_DECISION = 5;

    struct ScanCommit {
        bytes32 snapshotHash;
        bytes32 findingsRoot;
        bytes32 rulesetHash;
        uint32 findingCount;
        uint64 timestamp;
        address submitter;
    }

    ScanCommit[] private _commits;

    event ScanCommitted(
        uint256 indexed scanIndex,
        bytes32 snapshotHash,
        bytes32 findingsRoot,
        bytes32 rulesetHash,
        uint32 findingCount
    );

    event DecisionRecorded(
        uint256 indexed scanIndex,
        bytes32 indexed findingLeaf,
        uint8 decision,
        bytes32 actorHash,
        bytes32 evidenceHash,
        uint64 timestamp
    );

    /// @dev The supplied proof does not place `findingLeaf` under the scan's `findingsRoot`.
    error InvalidProof();
    /// @dev `scanIndex` is not a committed scan.
    error UnknownScan();
    /// @dev `decision` is outside [MIN_DECISION, MAX_DECISION].
    error InvalidDecision();

    /// @param admin Receives DEFAULT_ADMIN_ROLE, SCANNER_ROLE and DECIDER_ROLE. In ATHAR this is the
    ///        API's writer address (SPEC §12.5); production would split these across wallets.
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SCANNER_ROLE, admin);
        _grantRole(DECIDER_ROLE, admin);
    }

    /// @notice Anchor one scan: the snapshot's manifest hash, the findings Merkle root and the ruleset hash.
    /// @dev Idempotency is the caller's job (SPEC §12.4): the contract accepts duplicate commits.
    /// @param snapshotHash keccak256 over the sorted file hashes of the month's manifest.
    /// @param findingsRoot Merkle root of the double-hashed finding instance hashes (zero if no findings).
    /// @param rulesetHash keccak256 of canonical_json(rule ids + versions + thresholds).
    /// @param findingCount Number of leaves under `findingsRoot`.
    /// @return scanIndex Position of this commit; used by `recordDecision` and `verifyFinding`.
    function commitScan(bytes32 snapshotHash, bytes32 findingsRoot, bytes32 rulesetHash, uint32 findingCount)
        external
        onlyRole(SCANNER_ROLE)
        returns (uint256 scanIndex)
    {
        scanIndex = _commits.length;
        _commits.push(
            ScanCommit({
                snapshotHash: snapshotHash,
                findingsRoot: findingsRoot,
                rulesetHash: rulesetHash,
                findingCount: findingCount,
                timestamp: uint64(block.timestamp),
                submitter: msg.sender
            })
        );
        emit ScanCommitted(scanIndex, snapshotHash, findingsRoot, rulesetHash, findingCount);
    }

    /// @notice Record a human or policy decision about one committed finding.
    /// @dev Reverts with `UnknownScan` for an uncommitted `scanIndex`, `InvalidDecision` for a code outside
    ///      1..5 and `InvalidProof` unless `proof` places `findingLeaf` under that scan's `findingsRoot`.
    /// @param scanIndex Index returned by `commitScan`.
    /// @param findingLeaf keccak256(instanceHash) — the double-hashed leaf (SPEC §12.3).
    /// @param proof Sibling hashes from the leaf to the root (OpenZeppelin sorted-pair format).
    /// @param decision Decision code, 1..5 (SPEC §12.2).
    /// @param actorHash keccak256(user_id) of the approver; never the id itself.
    /// @param evidenceHash keccak256(canonical_json({plan_id, action, model_id, prompt_version, rationale_hash})).
    function recordDecision(
        uint256 scanIndex,
        bytes32 findingLeaf,
        bytes32[] calldata proof,
        uint8 decision,
        bytes32 actorHash,
        bytes32 evidenceHash
    ) external onlyRole(DECIDER_ROLE) {
        if (scanIndex >= _commits.length) revert UnknownScan();
        if (decision < MIN_DECISION || decision > MAX_DECISION) revert InvalidDecision();
        if (!MerkleProof.verify(proof, _commits[scanIndex].findingsRoot, findingLeaf)) revert InvalidProof();
        emit DecisionRecorded(
            scanIndex, findingLeaf, decision, actorHash, evidenceHash, uint64(block.timestamp)
        );
    }

    /// @notice Check whether `findingLeaf` is part of the scan at `scanIndex`.
    /// @dev Returns false (does not revert) for an unknown scan so verifiers can probe safely.
    /// @param scanIndex Index returned by `commitScan`.
    /// @param findingLeaf The double-hashed leaf.
    /// @param proof Sibling hashes from the leaf to the root.
    /// @return True iff the proof is valid against the committed root.
    function verifyFinding(uint256 scanIndex, bytes32 findingLeaf, bytes32[] calldata proof)
        external
        view
        returns (bool)
    {
        if (scanIndex >= _commits.length) return false;
        return MerkleProof.verify(proof, _commits[scanIndex].findingsRoot, findingLeaf);
    }

    /// @notice Read one commit.
    /// @dev Reverts with `UnknownScan` instead of an array-bounds panic so clients get a typed error.
    /// @param scanIndex Index returned by `commitScan`.
    /// @return The stored commit.
    function getCommit(uint256 scanIndex) external view returns (ScanCommit memory) {
        if (scanIndex >= _commits.length) revert UnknownScan();
        return _commits[scanIndex];
    }

    /// @notice Number of commits so far; the next `commitScan` returns this value.
    /// @return Count of stored commits.
    function commitCount() external view returns (uint256) {
        return _commits.length;
    }
}
