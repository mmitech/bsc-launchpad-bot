// SPDX-License-Identifier: MIT
pragma solidity ^0.6.6;

contract Ownable {
    address public owner;
    mapping(address => bool) public approverCallers;

    constructor() public {
        owner = msg.sender;
        approverCallers[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    modifier onlyApproverCallers() {
        require(approverCallers[msg.sender] == true, "Caller is not approved");
        _;
    }

    function addApproverCallers(address[] memory _callers) public onlyOwner {
        for (uint i=0; i < _callers.length; i++) {
            if(!isApproverCaller(_callers[i]) &&  _callers[i] != address(0)){
                approverCallers[_callers[i]] = true;
            }
        }
    }
    
    function removeApproverCallers(address[] memory _callers) public onlyOwner {
        for (uint i=0; i < _callers.length; i++) {
            if(isApproverCaller(_callers[i])){
                approverCallers[_callers[i]] = false;
            }
        }
    }

    function isApproverCaller(address _caller) public view returns(bool) {
        return approverCallers[_caller];
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "new owner is the zero address");
        owner = newOwner;
    }
}