//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./RegistrationVerifier.sol";
pragma experimental ABIEncoderV2;

contract Registration{
    address public administrator;
    mapping (uint => string) private Commitment;
    RegistrationVerifier private verifier;

    function updateVerifier(address verifier_address) external {
        verifier=RegistrationVerifier(verifier_address);
    }

    function verification(uint256 accountNR, string memory dc, uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[26] calldata input) external {
        uint[26] memory new_input;
        for(uint256 i=0; i < 26; i++){
            new_input[i] = input[i];
        }

        require(this.checkZKP(a, b, c, new_input));
        this.setCommitment(accountNR, dc);
    }

    function checkZKP(uint[2] memory a,uint[2][2] memory b, uint[2] memory c, uint[26] memory input) public returns(bool) {
        RegistrationVerifier.Proof memory proof = RegistrationVerifier.Proof(Pairing.G1Point(a[0],a[1]),Pairing.G2Point(b[0],b[1]),Pairing.G1Point(c[0],c[1]));
        return verifier.verifyTx(proof,input);
    }

    function setCommitment(uint256 accountNR, string memory dc) external{
        Commitment[accountNR] = dc;
    }

    function getCommitment(uint256 accountNR)external view returns (string memory){
        return Commitment[accountNR];
    }

}
