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
        vk.alpha = Pairing.G1Point(uint256(0x08a054f935f6dc6d8aab8d060ca63f5bac50c61aa18404b80a7d8be753e90dd9), uint256(0x19d1ae1d3a0acaf7133731381f650693fb8173638a437999d6ae8805b5e27f34));
        vk.beta = Pairing.G2Point([uint256(0x0965d03cf0fc78dfb72d8ef9208638e531fdd42b5f2be55d83d509ad971b8409), uint256(0x21fa236705ec2734d0a78f9023cd29c67119c46d367fbe45135224178eeef850)], [uint256(0x2aee69623e7468d7185c14990b0946f5f85075c6101bf378605f5daaf4c15860), uint256(0x2315aa572dd2bf807dc8ae18ad1e06a98b44cab862e23cf400e692417a3ef818)]);
        vk.gamma = Pairing.G2Point([uint256(0x266594fe8730571343d687976e24631aba8b7dcf6d5f1b3ad2ba0913d5bcff70), uint256(0x0d62d83069f6fc489b38db76981aba6b5b361902edfb7994284f7a7a72a040e4)], [uint256(0x1e949b02b539f58c560c52dc7c14ef63842764af20ec0c42c8e0206c9d222049), uint256(0x04f7f5bce44f7ab7058eaf83ab07292e73fe8602955f9f3109466aac6c0374e8)]);
        vk.delta = Pairing.G2Point([uint256(0x049d428010f0a70fefec9245632136d18acabd7eb4c47ee5fbd9b07178fcd1f7), uint256(0x2e100e6c3f141d945dbfc3d06f556cac4bfa4f2275602a0aeb579c42fd8e1b47)], [uint256(0x161d71462d1fdab49f149d0cf84521dcaae62ad22cbf1c3444cb8b26f7936604), uint256(0x11a098d4cbb78c05a098e69202173d32ab729e84743acc50b354ad515b2cd853)]);
        vk.gamma_abc = new Pairing.G1Point[](27);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2756e9a5fec63fc9a6138efedc8e1cb515c460b7f801b186285db823b49a1da4), uint256(0x1e1ef0379cd17dd0f9b83e7441b740138c6909aa414dbaa0c6abc62b4c25df04));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x24dfd4612f5340221f96fd7e5cbce84faba91aca011016cf3290b93bce616f3f), uint256(0x00a67edd39f941c1e9ea3f0f84ca71dc63f0e94b19b11c96be196f7c0ea263c4));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x05d05fbc285b9e5289ee9a7449f70b3b5ada825eada22c5b4ef7cea091e224e8), uint256(0x140a9f484e9f271b7cc281e5de1c3d8a2f2d7672e66f2726a9b9ff27e374dbf5));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1b0b4bd3e497875eb5141114f230bd50423acd63b862b67a2ed4e997c070aa3d), uint256(0x22353e69485b6e3a2270ffb82176f1033ab4b65039b65242d8de9471784dcc3c));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2ab8596133ab7e9376067fd3526470c2ea222be514172254635aede1fc91f64f), uint256(0x19ca79e2af85cefe20354f0786015f79adcf252bde5da8132520a50fc9840186));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x22ccbe8fa0a0d17da6e2ec0ff94c9118d5ab4db7c5dedd41bd44e7de74526fad), uint256(0x18d0b63d5e9eb0d88fddf8c66fb8be56cb0752009f0f34e8900af9551daf3480));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x25b86c24fb06139927aa189c9fa8f96342d93ce5c7e486cc79daa1dfc0bfd19c), uint256(0x213b98a485da31b7049f4c3497571071269ed8eee5c0d4a6959648bc7faf6702));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x13cedd68a97aaa2283822e8462d098c31e8dc67132420635edb9deb082b7b779), uint256(0x0b741a94b0ae1356359f00d2e259fc4d1a7e8d472b5c76e2d0578b662f60d9e8));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2cc1684b1469e5cf7c756d0415279a2a4fcb8cf657a2098fe22ae80cfd33b155), uint256(0x0cded0f439ca900e7ea0e9599301a9e3e9f1aa8d3ef3d9b2d7b9b24c3ea3b596));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0a259e98da89a2cadcd4f91369e30a26c13245285ea2c62eb112c9f95e80429d), uint256(0x04a7851c6e9f9a733f21fa5c3b5f2fce45569ae17590e39eb3ac192636207660));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x23b25405de9bdc4e4ce541c8ac7663f8c913958d9ee961a6e04f0e7944d9e4b5), uint256(0x05d894b9ab239f686331af0f4b5d0dbbd6692b5720e5ce847cf396ef1130406f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2fdb99d53d6a07ec0863741ea40b4db61712f71ed3244aed27d9ce35a65249c7), uint256(0x1f396327026e775824b761b69a11bb8922ac8b61511d44a33176d30fadb4baab));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1f5cb621a9311bde67452a3428917c912f2f955db2e6a1cc079fc203e14e0f2e), uint256(0x2ce51843e2a28392b62b08acb4eb231ed28255624363771bec8dbfb46a890182));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x06525327561a7f710a1fbc7230d7e243f3db09784b329fb42972d9dc1dc6f5f4), uint256(0x0541de32e4f1479f4189ec007258543a5c743bd9e7b64efc0688f9fb6882a8b4));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1f4fb6bc93b8fdb1c912d2955d8dd75006f78a6ea6357ca1f8fbf76b12eddca4), uint256(0x04f6d0c2fad81342852de0d5ed8e9ee857ff5d27844621e881d30c25d42d3834));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0d234c2ad4cb18cfbcf66d146baf212d0d1e7d847f29c6ae37c6c9f409afd2c4), uint256(0x155f2d4d82cd17855ef2a2cefbc2e6cf40d3d6aef72b24293e1151ac8cdbd97f));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x250f881545914a8c34ec277c963c1cc6f3d008cf641f9854ffd326495dee15f8), uint256(0x28dadc9dddf5ea1ce178537b04b9f63babe9887c02fda30b45bee4761eb68c49));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x18847d3fd0439483a053b39d202f866fefcdfe63723dd15510cd8a2a612fcc2b), uint256(0x114a2348e783a434e52ae903a45a2fd494ee26fa09c579e299c0dbc324ee9062));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x24b23569d632a4779cdf70bac099befe6c6aeeb155dd162dec88e7ca87533107), uint256(0x2283bba84508572df63479cf4c3ed7195a109c67e44362194d0009180911881a));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2d4183db5d1ee8fb0908d7c430ab921bc8a4609b272525ea8ff9e0f16afdc9a9), uint256(0x2a8338e7f457e3add3abe9ccdd6f777f23ed3caf34eba2e5223aa58be37366e1));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1027ff3e0810c68749d9986fe11d3d3700e0195fc24365fc438096719c8c1d8e), uint256(0x0a44eff7f193bb26651250619cafe7cc96d9774a65a8f2a2d63e90dc4c72603a));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1d4ea682f5a2d1e8eecebaa8c2e5775217e02664e5e86d4897f8dbb43e10fea2), uint256(0x1dd0db6a52b814234902954fa91ca2d2154b3ebdb6826111afe7c4435f251c58));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1d5def0f61710a3dff6680a5c30a04775124fe760d6bf1bfbeda2ccb125318c6), uint256(0x2dd10c22c2a03ee849fe96bb989872761f3905dcab8a84bcdbc793993b848c9c));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x199d828c5aaf2069e6c4df642b5ed823bf8418e7176831cb97b8a051aa7017e9), uint256(0x0c9b07a5bdf1515e972491885d80f9c2fce21126ccd1692750da650b00905d63));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x038b88ee52d5e4640fef831968b8419a238012956a27307ff7719375b614372c), uint256(0x1b3b111839588749f3fc74aceb09374961afa080d4547bd78f4399b08558a758));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1249204cac9eb90f2160e34c5244c5675cf670683b319577c02d18bcb9ab0242), uint256(0x251dd61c9276b88b9ab11ccc16383dac6d5432d5c8c8470801a1e3da5212836e));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x02b4736b675d895d81f60c901df3a5b724c272684c1ff43a6f2af16df909dcc2), uint256(0x232569c2093505d019e94ee4e51d80a80da4ce40b919bb3eda43d1a85af47692));
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
