// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
contract EvmCounter {
    uint256 public value;
    event Changed(address indexed sender, uint256 value);
    constructor() { value = 7; }
    function set(uint256 next) external { value = next; emit Changed(msg.sender, next); }
    function fail() external { value = 999; emit Changed(msg.sender,999); revert("rollback"); }
    function pay(address payable recipient, uint256 amount) external payable {
        (bool ok,) = recipient.call{value:amount}(""); require(ok,"payment");
    }
    function destroy(address payable recipient) external { selfdestruct(recipient); }
}
