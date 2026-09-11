// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {Hashes} from "@openzeppelin/contracts/utils/cryptography/Hashes.sol";
import {GovernanceLedger} from "../src/GovernanceLedger.sol";

/// @dev Test-only Merkle builder mirroring `ledger/merkle.py` (SPEC §12.3): double-hashed leaves,
///      leaves sorted ascending, sorted-pair (commutative) nodes, odd node promoted unchanged.
library TestMerkle {
    function leaf(bytes memory preimage) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(preimage)));
    }

    function sort(bytes32[] memory xs) internal pure returns (bytes32[] memory) {
        for (uint256 i = 1; i < xs.length; i++) {
            bytes32 key = xs[i];
            uint256 j = i;
            while (j > 0 && xs[j - 1] > key) {
                xs[j] = xs[j - 1];
                j--;
            }
            xs[j] = key;
        }
        return xs;
    }

    function nextLevel(bytes32[] memory level) internal pure returns (bytes32[] memory) {
        uint256 n = (level.length + 1) / 2;
        bytes32[] memory up = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 a = 2 * i;
            up[i] = a + 1 < level.length ? Hashes.commutativeKeccak256(level[a], level[a + 1]) : level[a];
        }
        return up;
    }

    /// @dev `sortedLeaves` must already be sorted. Empty input yields bytes32(0) like the Python side.
    function root(bytes32[] memory sortedLeaves) internal pure returns (bytes32) {
        if (sortedLeaves.length == 0) return bytes32(0);
        bytes32[] memory level = sortedLeaves;
        while (level.length > 1) {
            level = nextLevel(level);
        }
        return level[0];
    }

    function proof(bytes32[] memory sortedLeaves, uint256 index) internal pure returns (bytes32[] memory) {
        bytes32[] memory buf = new bytes32[](64);
        uint256 k = 0;
        bytes32[] memory level = sortedLeaves;
        while (level.length > 1) {
            uint256 sib = index ^ 1;
            if (sib < level.length) buf[k++] = level[sib];
            level = nextLevel(level);
            index /= 2;
        }
        bytes32[] memory out = new bytes32[](k);
        for (uint256 i = 0; i < k; i++) {
            out[i] = buf[i];
        }
        return out;
    }
}

contract GovernanceLedgerTest is Test {
    GovernanceLedger internal ledger;

    address internal admin = makeAddr("admin");
    address internal stranger = makeAddr("stranger");

    bytes32 internal constant SNAPSHOT = keccak256("snapshot");
    bytes32 internal constant RULESET = keccak256("ruleset");

    bytes32[] internal leaves;
    bytes32 internal treeRoot;

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

    function setUp() public {
        ledger = new GovernanceLedger(admin);
        leaves = new bytes32[](5);
        for (uint256 i = 0; i < leaves.length; i++) {
            leaves[i] = TestMerkle.leaf(abi.encodePacked("finding-", i));
        }
        leaves = TestMerkle.sort(leaves);
        treeRoot = TestMerkle.root(leaves);
    }

    function _commit() internal returns (uint256) {
        vm.prank(admin);
        return ledger.commitScan(SNAPSHOT, treeRoot, RULESET, uint32(leaves.length));
    }

    // ---------------------------------------------------------------- roles

    function test_Constructor_GrantsAllRolesToAdmin() public view {
        assertTrue(ledger.hasRole(ledger.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(ledger.hasRole(ledger.SCANNER_ROLE(), admin));
        assertTrue(ledger.hasRole(ledger.DECIDER_ROLE(), admin));
        assertFalse(ledger.hasRole(ledger.SCANNER_ROLE(), stranger));
        assertFalse(ledger.hasRole(ledger.DECIDER_ROLE(), stranger));
    }

    // ---------------------------------------------------------------- commit

    function test_CommitScan_HappyPath_StoresAndEmits() public {
        assertEq(ledger.commitCount(), 0);

        vm.expectEmit(true, false, false, true, address(ledger));
        emit ScanCommitted(0, SNAPSHOT, treeRoot, RULESET, 5);
        uint256 idx = _commit();

        assertEq(idx, 0);
        assertEq(ledger.commitCount(), 1);
        GovernanceLedger.ScanCommit memory c = ledger.getCommit(0);
        assertEq(c.snapshotHash, SNAPSHOT);
        assertEq(c.findingsRoot, treeRoot);
        assertEq(c.rulesetHash, RULESET);
        assertEq(c.findingCount, 5);
        assertEq(c.timestamp, uint64(block.timestamp));
        assertEq(c.submitter, admin);
    }

    function test_CommitScan_IndexIncrements() public {
        assertEq(_commit(), 0);
        assertEq(_commit(), 1);
        assertEq(_commit(), 2);
        assertEq(ledger.commitCount(), 3);
    }

    function test_CommitScan_RevertsForUnauthorised() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, ledger.SCANNER_ROLE()
            )
        );
        vm.prank(stranger);
        ledger.commitScan(SNAPSHOT, treeRoot, RULESET, 5);
    }

    function test_GetCommit_RevertsForUnknownScan() public {
        vm.expectRevert(GovernanceLedger.UnknownScan.selector);
        ledger.getCommit(0);
        _commit();
        vm.expectRevert(GovernanceLedger.UnknownScan.selector);
        ledger.getCommit(1);
    }

    // ---------------------------------------------------------------- decision

    function test_RecordDecision_HappyPath_Emits() public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 2);
        bytes32 actor = keccak256("user-approver");
        bytes32 evidence = keccak256("evidence");

        vm.expectEmit(true, true, false, true, address(ledger));
        emit DecisionRecorded(idx, leaves[2], 1, actor, evidence, uint64(block.timestamp));
        vm.prank(admin);
        ledger.recordDecision(idx, leaves[2], proof, 1, actor, evidence);
    }

    function test_RecordDecision_AcceptsEveryValidCode() public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 0);
        for (uint8 code = 1; code <= 5; code++) {
            vm.prank(admin);
            ledger.recordDecision(idx, leaves[0], proof, code, bytes32(0), bytes32(0));
        }
    }

    function test_RecordDecision_RevertsForUnauthorised() public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, ledger.DECIDER_ROLE()
            )
        );
        vm.prank(stranger);
        ledger.recordDecision(idx, leaves[0], proof, 1, bytes32(0), bytes32(0));
    }

    function test_RecordDecision_RevertsOnInvalidProof() public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 1); // proof for a different leaf
        vm.expectRevert(GovernanceLedger.InvalidProof.selector);
        vm.prank(admin);
        ledger.recordDecision(idx, leaves[0], proof, 1, bytes32(0), bytes32(0));
    }

    function test_RecordDecision_RevertsOnForeignLeaf() public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 0);
        bytes32 foreign = TestMerkle.leaf("not-in-tree");
        vm.expectRevert(GovernanceLedger.InvalidProof.selector);
        vm.prank(admin);
        ledger.recordDecision(idx, foreign, proof, 1, bytes32(0), bytes32(0));
    }

    function test_RecordDecision_RevertsOnUnknownScan() public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 0);
        vm.expectRevert(GovernanceLedger.UnknownScan.selector);
        vm.prank(admin);
        ledger.recordDecision(idx + 1, leaves[0], proof, 1, bytes32(0), bytes32(0));
    }

    function test_RecordDecision_RevertsOnInvalidDecisionCode() public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 0);

        vm.expectRevert(GovernanceLedger.InvalidDecision.selector);
        vm.prank(admin);
        ledger.recordDecision(idx, leaves[0], proof, 0, bytes32(0), bytes32(0));

        vm.expectRevert(GovernanceLedger.InvalidDecision.selector);
        vm.prank(admin);
        ledger.recordDecision(idx, leaves[0], proof, 6, bytes32(0), bytes32(0));
    }

    function test_RecordDecision_ChecksScanBeforeDecisionBeforeProof() public {
        // Ordering matters for clients mapping errors: unknown scan wins over a bad code and a bad proof.
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(GovernanceLedger.UnknownScan.selector);
        vm.prank(admin);
        ledger.recordDecision(0, bytes32(0), empty, 9, bytes32(0), bytes32(0));

        uint256 idx = _commit();
        vm.expectRevert(GovernanceLedger.InvalidDecision.selector);
        vm.prank(admin);
        ledger.recordDecision(idx, bytes32(0), empty, 9, bytes32(0), bytes32(0));
    }

    // ---------------------------------------------------------------- verify

    function test_VerifyFinding_TrueForEveryLeaf() public {
        uint256 idx = _commit();
        for (uint256 i = 0; i < leaves.length; i++) {
            assertTrue(ledger.verifyFinding(idx, leaves[i], TestMerkle.proof(leaves, i)));
        }
    }

    function test_VerifyFinding_FalseForUnknownScan() public {
        bytes32[] memory proof = TestMerkle.proof(leaves, 0);
        assertFalse(ledger.verifyFinding(0, leaves[0], proof));
        _commit();
        assertFalse(ledger.verifyFinding(1, leaves[0], proof));
    }

    function test_VerifyFinding_FalseForWrongProof() public {
        uint256 idx = _commit();
        assertFalse(ledger.verifyFinding(idx, leaves[0], TestMerkle.proof(leaves, 1)));
    }

    function test_VerifyFinding_SingleLeafTree_EmptyProof() public {
        bytes32[] memory one = new bytes32[](1);
        one[0] = TestMerkle.leaf("only");
        vm.prank(admin);
        uint256 idx = ledger.commitScan(SNAPSHOT, TestMerkle.root(one), RULESET, 1);
        assertTrue(ledger.verifyFinding(idx, one[0], new bytes32[](0)));
        assertFalse(ledger.verifyFinding(idx, TestMerkle.leaf("other"), new bytes32[](0)));
    }

    // ---------------------------------------------------------------- fuzz

    /// @dev A random proof never verifies against a real root (except the degenerate leaf == root case
    ///      with an empty proof, which is by construction a valid one-leaf tree and is excluded).
    function testFuzz_RandomProofNeverVerifies(bytes32 leaf, bytes32[] calldata proof) public {
        vm.assume(!(proof.length == 0 && leaf == treeRoot));
        uint256 idx = _commit();
        assertFalse(ledger.verifyFinding(idx, leaf, proof));
        vm.expectRevert(GovernanceLedger.InvalidProof.selector);
        vm.prank(admin);
        ledger.recordDecision(idx, leaf, proof, 1, bytes32(0), bytes32(0));
    }

    /// @dev A correct proof always verifies, for any leaf set of size 1..8 (duplicates allowed).
    function testFuzz_CorrectProofAlwaysVerifies(bytes32[8] memory preimages, uint8 size, uint8 target)
        public
    {
        uint256 n = bound(size, 1, 8);
        uint256 t = bound(target, 0, n - 1);
        bytes32[] memory xs = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            xs[i] = TestMerkle.leaf(abi.encode(preimages[i]));
        }
        xs = TestMerkle.sort(xs);
        bytes32 r = TestMerkle.root(xs);
        vm.prank(admin);
        // casting to 'uint32' is safe because n is bounded to 1..8 above
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 idx = ledger.commitScan(SNAPSHOT, r, RULESET, uint32(n));

        bytes32[] memory proof = TestMerkle.proof(xs, t);
        assertTrue(ledger.verifyFinding(idx, xs[t], proof));
        vm.prank(admin);
        ledger.recordDecision(idx, xs[t], proof, 3, bytes32(0), bytes32(0));
    }

    function testFuzz_DecisionCodeBounds(uint8 code) public {
        uint256 idx = _commit();
        bytes32[] memory proof = TestMerkle.proof(leaves, 0);
        vm.prank(admin);
        if (code >= 1 && code <= 5) {
            ledger.recordDecision(idx, leaves[0], proof, code, bytes32(0), bytes32(0));
        } else {
            vm.expectRevert(GovernanceLedger.InvalidDecision.selector);
            ledger.recordDecision(idx, leaves[0], proof, code, bytes32(0), bytes32(0));
        }
    }

    function testFuzz_UnknownScanIndexAlwaysFalse(uint256 scanIndex) public {
        _commit();
        vm.assume(scanIndex >= ledger.commitCount());
        assertFalse(ledger.verifyFinding(scanIndex, leaves[0], TestMerkle.proof(leaves, 0)));
    }
}
