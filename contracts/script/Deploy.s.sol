// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {GovernanceLedger} from "../src/GovernanceLedger.sol";

/// @title Deploy GovernanceLedger (SPEC §12.5)
/// @notice Reads `PRIVATE_KEY` from the environment; the deployer becomes admin, scanner and decider.
/// @dev The API normally deploys from the committed artifact (`ledger/client.py`); this script is the
///      manual/CI path: `PRIVATE_KEY=0x... forge script script/Deploy.s.sol --rpc-url $LEDGER_RPC_URL --broadcast`.
///      Anvil's dev key #0 is a publicly known key — never use it with value.
contract Deploy is Script {
    function run() external returns (GovernanceLedger ledger) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(pk);
        vm.startBroadcast(pk);
        ledger = new GovernanceLedger(admin);
        vm.stopBroadcast();
        console.log("GovernanceLedger deployed at", address(ledger));
        console.log("admin / scanner / decider", admin);
    }
}
