// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract RegistrationVerifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2c4f1bcb874ad78d136268cca0f8a4313471686cef58f2639d62e05a9a923ebe), uint256(0x2d9f496be4757b41f129fc6e20e6795e5d7f44251cf7e74f39b56360f00c3e77));
        vk.beta = Pairing.G2Point([uint256(0x25f394880e894e75a3aee4bbc190d9f02ed6b9853cb0aa005b6a1f5cfaf1451c), uint256(0x089814beaba8fd630e46f7d951b5859d5391539bf4dc870e36df2d4e79d20cb0)], [uint256(0x0dad9de833603102a1fccf312046d9ecb76b17a50d1e363011febb22ebdeadce), uint256(0x1cf2ea0f2beb22a01dca999b09fab5461e483a4bcf3c3ad2ef9127e6623d3e7c)]);
        vk.gamma = Pairing.G2Point([uint256(0x182e776498a9473be060df127e55b6fc51a51f169e7804a1ade6092326fc9497), uint256(0x2a7a317e00cd33fa48ad33a3cbb32a4e22abcff02f428857fc10ef50fdd0d91e)], [uint256(0x24f9f54abef71a05ce157696c97c911034d9e3c28d4499df8305f424e8d4586b), uint256(0x0444eee81766d1641c173300809fc03f3d6712b39a48fda7e575d12167fbaf0d)]);
        vk.delta = Pairing.G2Point([uint256(0x0404f1880a57cb1afb9ead31da3d4a3424405ceddccc40e84256488775f9bc06), uint256(0x0338ad825db28a877ad6d81d3f833338dacbc50dcab3c91b671f4388cb0f3f05)], [uint256(0x02cf943168188222d9c468e79d1f1d02d712b7c2623ea321795916f7b5943afa), uint256(0x1947fb052fcbc3129a32361c3ebf8a394a9e4efa8b154f13e807ecb1a34dce9e)]);
        vk.gamma_abc = new Pairing.G1Point[](27);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x04a9daaeccec9fce19b2006d463e21d248aa54d0937353cd34f57d58d8673b8a), uint256(0x2f2a560204a7e0bd39aac2de8721035bcdcf5cb556096193e0115971de26c276));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x175509d5fdd61ae04cc2d36e1847df5e1a2bab27e710feff994fabe19ec023bb), uint256(0x24404cf222ec5ce07c197311442948b8a640fd70c1a41e3d5eb2f4df0aed3b47));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x00a978ae524f494677a793ca60091b618d853d513f068b797473248eec405854), uint256(0x017eea194e10b41ada97eaac60b54821719b0f9ee3e99195942d150514213641));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0b4ee7823ad20b6f67f61572912c31730e90e0a440ae0bb86a21d0923d0f9b51), uint256(0x303d2a5a3978945cf10dabefe18fcd473c0842220515edd327d52e43c68da6a8));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x14196c4e207ab3e150ab0d968aa7eff6ae2df7d41fe63652293bfa60d0ae0e7a), uint256(0x23d96d0d06de78d2c0787e99b9b5d6ef61de89aa6a6f9fca4b1a588c6cfe1144));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0a7298a284d5ef161703a7e6f12998c0568b9639999d92fdf12f26ca7096aaed), uint256(0x02c69e58bd3a981bcb9a8e6428bfe5791fdf3214178d3c6c88463651369c14f0));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1f948ff658c60ce45d75a29c285dcf04d324c0565e8685cb83e56650a089bc7c), uint256(0x09404a843f28211d4c9d46bb5961dd5c5acce54ae27be3a24c271bf365461305));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x009e1973d0491dafb5bd7a36212ffcc9cd208e06a47e4856dad746f197c874d0), uint256(0x0fac242f29c4cb7f033237f03f176c19652afe0cd546ea0981ee9e498df448c8));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x115d1667ff11731616eb9d846ab15f9ef5f359a178a7b5060686b1bcce44ba05), uint256(0x0c82667afb89a00f7bb24230c7e185ab31f194663216455a163f1eea92a0fd2f));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x07a0864e041ad92c7587857c37990c2f594dd78573a137433c1db7e4d3084479), uint256(0x0fed2130e8bbcc21bd8f34d2fc84f4485a2948fe915cbcc4f2067c116ac2a067));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x104362aa6c8f9a0808eeb74182aabb7d2f58518ba2644ff8e9e9bb739d18af57), uint256(0x2a27fc426560c6b3f30e7ced0201909e5c353aa113e372ce23e9a9455d813f43));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x22c6d23aa95138de0dce9432b9fa5940d17bcb6e2a1b089cd7b28dfa587c0298), uint256(0x2f92bd0dc5ccbaa8c1dcf63839379b0bd5497cd58b36a41f8367a896507b79c7));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1ee4e267af17f58cc96a3dce54a854303b36ee556ebfbddb40918739f95537b7), uint256(0x0e2e4ea933395c0857e8e7a26bbacf475b032ff4d34335f2f9c65ab5baeae5d9));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x260746b6444c81aa2a6b15b557e56e00a99bd790e941f79a6c14401caebc5e4a), uint256(0x0181751d202ec50e4553ccda91267bdf8f668acd7355a28c7e18b4ff4b463ccb));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1f6a27d0c98dd71410744949788046077c067b57c26c8947978fae69424ee5b9), uint256(0x023164301e7ef893b3880b1737a7e5ba241e2b27be26ed31c19911f9334a6660));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x14e067342a4c184e23f6d0afa4509b1e0f4060e029d9940d6ae9b27208b5eb8c), uint256(0x05504a64e26e347b005ba8563d53b940e6ef6192835e3b9e0335ca7b229a5b35));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x073eded757855b4ab0ba63fae04b2c8389f9f5218deda2bc2e32843fe51ba0e9), uint256(0x1d54d9966de6b946d2d8dc7e74b5e119c35e8ec4506ed52210e729c6dd2e2aec));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x24470adb015b9e99f352fac1e0d55c0c4f9a97a5f086d9c948a425822c201036), uint256(0x2bf96ccacd19ccd77dd605b82af7ded3b259da03557989c5cedcb39f0ed52c20));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x00969f6f0adb3d5d084711053a9459af72fad0c96cc2e91dc8fe1cff79d21e44), uint256(0x062d6234ea70f17e14731b35450ca6aef829439a98e21bab759747ae0b0a7773));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x02ce7c24bda80afeb5bfe86e16dd5f8a791ed468b4bbf7dc80985004a75d9cb7), uint256(0x0e0d2f37b056ec6f5f5c8cbb01ca26f4b06ee0f86a4d55134e33c9e192ca843a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x017cdc4650c9434ed4c196419c84b9f29e0dc07e8b1c9cea76883271a20c3fbe), uint256(0x01ae4d68e00ac697cdd9fa52a56bc986270298be65b7ceb34f14a9e4cbd22aa6));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0215cd7efad7b6b4fc6064ceebefe4913babf4de1c4ea9bfb2e25941a8842e75), uint256(0x19aa93d576224f6fc6da21776c613b21831b61ee61a7541634dede0fe8e24c35));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x108b4f2ef8aca5110b93e9794f4e246969cfce915ec6a79bdcbf446772f171dc), uint256(0x2539794d998dc4db30beaa55f0509396fae7e1be99f78588eac63bd8eb12c3a4));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0b2e4456bd1a19d958c74bdcdb30eadb9f6010bc653189b332caa76e91a68dc5), uint256(0x1d83f69ab21bc3d2d17f35aed1cd8dcbef45f43c79bf5bcc6087d8361edb10dd));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0972c27edc1579ffc41bc223657a833dc8710c7dc70ce66d099ce14d32e4aee4), uint256(0x278847254ee0d00ebfc392270a658f72b8b923b0b456124cdd60d031469b9a85));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2980d1f49b1da06ca7851d0636468291ecfebc1e90474aac73e7fb4274b24418), uint256(0x092a4b120ddd45ec870b451ceadd11c61bc362b76df556cac09a189d11f37d7f));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1b3f1d7d414ea46cd5a111ae88c9362a4c02c4d10473927da2622deec2d29661), uint256(0x13a77a0117aed51b9237409f0c0d0b866cf3bebfde6428ad456cd4a3829afdbf));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[26] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](26);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
