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

contract Verifier {
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
        vk.alpha = Pairing.G1Point(uint256(0x16fb33aacea7ea239bd6ea5a617af6f75b160675d26c1a0abe03e2f600780caa), uint256(0x24011f21f6e7c8acda58250556f5a0b0a5f4e9a1724334c3144a0c06521a5c4d));
        vk.beta = Pairing.G2Point([uint256(0x22d9b2ed5a631fb3cf7b1e7fae8ce4f8b043a63c77a11616e4c0a3a9456a1bf5), uint256(0x22ecc17ebd5c5e5ec253ceb2d1c8f059af1b100d859c9063918734c4fedf2599)], [uint256(0x0dcc18f6fa09dd5559f552be622b2b74e666e279fe2a39707c23eeef2ebabdc9), uint256(0x2dd8a2243c209eefb8306466b84091f5f997045d37a6a01fcf0fdbc404c12f3f)]);
        vk.gamma = Pairing.G2Point([uint256(0x20b52bf248d0e92b7d5d04ee4fad3beea757f16dc9dab2925788c165529d716b), uint256(0x1be4f077c1fc18ff3d3bd52a11a4d8644e8d0edf0c105a6027c49a96b36c18e2)], [uint256(0x0a9c9a7ed6a7463587718b0290ba355c3fda4066e62d9787527c248b18303831), uint256(0x067c0b4ed0ce52b502c29c818eda97bff5c2bc826b890abc0048accc4d6c41b1)]);
        vk.delta = Pairing.G2Point([uint256(0x2e2d1e8a3a0a5009e162fc00d377f972d2d8c8d1d4a91574f7248e6c5cd1cf59), uint256(0x0d80ea23cd6a8513af3beb8fc4ede789410afb0a2d5051daf2f8e29816c24f3f)], [uint256(0x247c4629709480f64b97e3d89c7c76dc95317f32bd363ddb7d76962bca1c9086), uint256(0x1b55e1eacd46ab276f4c3109e9daa3ddef26dbdfe7647e1055623664b2a3b71c)]);
        vk.gamma_abc = new Pairing.G1Point[](210);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x031b5a74c425e276c409dab68db065826cd3840a8340bf78e3a3c1edf48af309), uint256(0x2775ed1db342c03dbc5b575671b6d38df723f247a5365c242488a76f69354dcc));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x14977d0a5fb3d81143434587c5ffcac75c5f0b9a9c93af82cbbd8cbe487552fb), uint256(0x1d72f3ce4bc2993a043007d8a51c852a80cb5622a94a0d1edd5f7a3a48c0e5d8));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x19aa0d4266b3c5f79b6b8b8f34101669874973a55ca3da6cd9d27cf296bfaa2d), uint256(0x252f4d924af536fab4ef84b1d208f8e17d29b42a9650cb68b9e3793483c197ca));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1716c7219fdeb542bb77c3a8a0c49e6a64fc0cdd5c2d8f3d971360ea86f545e5), uint256(0x0710806d7d66c5b1ce704ce77cd5cfd2a1c06e08b8278156a25ff8f6e3a42b90));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1d48ca4c419f63e8e3310ce732062ea9633fe223a089620eb78db4ad359f1f76), uint256(0x2ce18e04faebf45712f5d188787e7646993e22517c1e0dbe7b29b99936c77845));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x13c340ea9206e9a43a496f4c0db7eb230e2054ed095cf9d2e9e14a8f8b13f7ce), uint256(0x24fe848e8daffb32f801f682b2004974247aa27f7716845a2230f704e85da84f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x216885b204620f1f1cc0d218b35d1018a28d5e4d589572875f6415c19e134c4b), uint256(0x2b68689191be5f56b2a99b4374f0f13a30a67e445e118e4dbd35d3fd255d67a2));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0603e9987be1e5e2b313bf5dee9c2ea4296aeac19a8b58dc41707ac19061de09), uint256(0x2953c40cc2111c4fb424c5aac86a9ade1af93a577662893227a279cde953f57e));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x185585e06d2db4f52529d5065b4b44b9830abdf3e88595936a4767ebacdef3d2), uint256(0x0ef6d77c72cd8fbe2fe324d7e1558cf2078d61a6331a4230098862d6429ef98e));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0007c964eed953cb0da50ecb4d25589ebe470cca17043b735983dd12d618b705), uint256(0x23d6b846df4e7c20385a64b9f2c81c28672cfc8168662869c0c024feb70f7609));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x13cdd6c594c96e342e4e59661048af2ecf8dee53c621a7b88fd7dbedf85bd7d9), uint256(0x2a1df666ae36cc65f50b66cf3a2c0e451c29989743821ec27145661b9cbed2ae));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0329d44a6268dc409588df09bf996212165ec625017d69df076d39b93716a7d4), uint256(0x302ba0f8b5d95441b7d6d6778b38b71dfbcb1d20a5649648c546cd0140bc68ab));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1ac56ddae7d511443ca37180f7c77cdc9820d1db0e4c97d5097d3a83674edc4d), uint256(0x109e0adb2358a53486dc223a05ee8842e7f5f66fad5450fc6f162f5c618cd980));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x301309d13d2534ffb0be4b44a92936992dcc8b8d9d7054dfd86b13e2bf8645e0), uint256(0x222b592cd894c911aaab2a452e95165e064b7023bab2d43f7e9d3cfac10742ae));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x008ed95bf70e0d1bf0f7389ad0d1a0b52598c01683442107526045b90146f107), uint256(0x092e2d03f1b6e4b38670ce446c298f3f45cfb58ded0ce51d84d667bb004cc9b0));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x01abdbb6fca704400614289dd35d176b6babd0d92a0bda5c19a1128b933d02b3), uint256(0x2b78f2d35e394a811b6df15dfd40cfdfceb9e23263368fc2a3334c886190cb81));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1ad812a1a83371502fdd549388ff8c168f713b0870e398e31c7b033bb3e155dd), uint256(0x222c5d3274efe6fb4897e6bfba0ccbac09863a008751de89f0d48d09a68a2854));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2eb09f5c5873a4ec23464e2f3871cb13db77664dd954caef4096f72d86e7fbcb), uint256(0x1570f567c652543ede8f08c58b6670bb349c6dbf669ea45f3b5c98674954af4f));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0f0932a029502c08854c23d9896cbbe784f88ed44d2e4cf64779aa3437e10a60), uint256(0x04f6a25ace392a65ad50621f5d4ddb7bad594efc8fe81729a935853ac12d03cc));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x22ad1ef52bf7f753112fadd8d5c172525aa6053f04f7783dfcdf6a14b92c350d), uint256(0x155cc30860da50bda09569b0b14bb6ab23b119ab0c48a25e4a027d9c642ee353));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1efad5906cf8331e40cd9d274e99706554ac53159899eacdd2b031b7a3d1674c), uint256(0x0c79ab9ace28cb839eedd6842db7c4ff5be8d3d51b9a1b48e4948e257967a2dc));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x05fbc5bb0b1c072cfb0e0983a545cfdb4ed0dc01241646021c18a599830ef706), uint256(0x3032504071d0837c77fafd71059a6b11d2aee70d391531d55fee58a1b99c3ef5));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x021a45f2bf06c2b911407bc55d91394b0908b59b6cad4de7aba75740c0048a94), uint256(0x25ef6fccf61ddf138305f6889683d05c1c5971ba791c989b370374c9fd89f47d));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2b4e981d2e5a4431f369090e5b033db3a92fc689e7806af663ed1dc00d427a63), uint256(0x27c358d0f6bd0701c7002f89cc91646d391f05cad88903cf93992b99b5364c68));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2fd700df862833627d28e7492b335ae4205d6bc08ce620083e9826d1cd0757e1), uint256(0x150f4c571afb95f7acfe6377ccd2deb565d69e82152339aca1380fd270e22cab));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x293521abb4651ed656da1c9281e92c843ea58f026a2fcb13b175abf2727940f7), uint256(0x1748863bd0f59bbc496c732844b936bf77b318ef71e9ea98bd4a74fe31ba8e61));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x16665d0da39b724b65ea6176f750245a9130d1a288e6abfc053579304457b579), uint256(0x2ed7d567f85df0c3f14bbb2f0d63738bb52965a3bb9fb7007db8dab4d5cd033c));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x11a348fe02499b6a99d995181baafa7a9b7d1645d3c34afecc46540cec55e775), uint256(0x288e1795888e6cf4042b399bf387bb387399eece772300c26299479e8a62970e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x188ded0b6c23e4acf33d6fc6fa5e92a827c0fe2afcf9ebc5646271338a327b1b), uint256(0x00bcb3b1911edb74bffb862df293e3b73cb3975e851551760a79b2258b6b3071));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x00e17c79a3029b805555a56386f4b5311b7b43051b8683ff974633a0bf0af7a0), uint256(0x1eedb3e6def32011b4bea9d8e9b54813c5ca99b101840a23c71aed1f586ffdb7));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1031b0062c7a44cc72100476d3ab56f28f18739442f545a0526890cb62350ad2), uint256(0x171ec2f34835c16c22d53838761694aee982c1521fd2a601d03360bbc0f2d6b8));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2ec4079f3bdf7c9788b64e27db15bad2d4b4a5e893c9e92fdd4926195c65fc2c), uint256(0x126cb04dadc354abfcb1a5cc2771fdc7e54c205fbcee0d269f67cc47930978fb));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x01e42b96aa3106fbbd7e151d8cec6252e79f1288bdbce925029a26e964b80825), uint256(0x155d7d1779588dbbafabb32aff2150e332ab87b803371d106d6657720962c10d));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x06173dbd5c694a5e96e289ebb42fdf102d3df40ed723a4634c093e1020492de0), uint256(0x08cf4c14c12762d466a5708675c264067fd53c78bed7bac18bd161ab2901ce7c));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0fb12ea31ca8ae9503c937098ec782a84868dd0316e03d1755e1c11197628e01), uint256(0x0f379aec6dd4c48afb90da9c7598e81c8e556fecc050dac6aa5f0c240462ae1c));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x197611badf5195a403a37c10d808e57502ae6b18ecc436abb4f9a86328471d1b), uint256(0x0e1b46d260fb107a80bdf8cece93d966bcd89490d2513995282b81125338666a));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x24e2240313d29db0c3f06f09ec9d2cfb6f3165eecd518fc59aa9d13a1a93ddec), uint256(0x2098ccb98514173ee830d19924eb7a951175ad32b572a63b67231dd6b159be4e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x08c4b6e45d0469c11c0386b65c60830187a8ec9e4535a65ac86c6e6f07624b76), uint256(0x2cb07d7d3ba80bf8690a36ae19dc50493e5459fc657ac0729de2e6a41ecace26));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1bf223eec80c91fdb8dbdfe98bb7b30c321b509cc465bb5699d1b35a9c4d47c7), uint256(0x07923faee1c6815b6ebd58af0d7127143a4d71cff96f9ea6aaf317b80707e921));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0446f4d74d2fbe8ab63040b7007bc3d0d11b02d39042994611de4b7e0f3d39ff), uint256(0x2ef964a1146408475eebc9f8e3c985e218513925a1d19a7fc40b813b8ea96f18));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x0da523922c61738ec54a094ce6cacb68c00e6560ba7bcd1b1a0090cb2ce0f131), uint256(0x0faf35c997bd6d4a4eb046730d7664581f3b80644ce8b6869c1632f9b8907d88));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0924841c8695d02a847b246a6b0b178f2502d73682e7699bb323c1cd411715c7), uint256(0x02c2635b0a72eb7e86f9276742e4f52b4eb6ef4181703ce3b29ed6f376185e82));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x04eada49a54303110da1fdb55d9cb18c4450fab5f4712c659a4dcd78641fe8d7), uint256(0x0974c27084b0e22f5ee3f40832553d831df7a99377120709382aa0138d8a10d2));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0bcede68e43f87720ae0da3805724716286998e82845b9446fdb5b30d056fd86), uint256(0x151de9100a75ebdd30a8a24ec7b88eb3c7ac2bd6c958f2aab75ed8f6e11b4dbe));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x03679f66e4e6f6b3652a92e6d39bb8e078b95d2937c6b286492bfb0307d97c9e), uint256(0x25606b5bdfdfae98cd9fe637167e08c66d8f9345cf22a04d467ce5d607e3c02d));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x294132c3eb4fa32d42884d079bf7354b64f8f8af8b7407a736ab858ed5ff8fff), uint256(0x1555189160c934c3c6ceeec815c2dd941f4c5934463bf9bd00124327a337ac1c));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x18adccf992ad058b86ab5f0b6167cbbfec14e2b26378a51e8910a73044f302ec), uint256(0x1886d48ebc0256e5eaf39d8c0072661c540bfd1924db766bec4d82621af4855b));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x13a2b4203022a994b9490b6422435878980ac09075430b10ccbea974921dca5b), uint256(0x029e20972765f849104563c5af1b130628611ffaf6851d50dd3855b957e6e9e7));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x15095c47ef6ab9265677ea77c31d0dff5319e4a4329fac3a2e2c9de15a3ffb56), uint256(0x000f98eebf76e5ae626b88db82d1fabb9760498db69317d667ede0bf67dc3b4d));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1d9ab291aa5e2ac325f67fcd5557424e5a5dc64abc32d1fe087beadfd65f952a), uint256(0x15c5930de3dae934517c57593a5cf2eff40e6a97fece86de032c56fe407a318a));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1445cbc8ebb4430bf24d42c1579667f2332b75da99d8b24d2240aef3eca4bca1), uint256(0x26cf01168f148f5838eb0bb2130960502efe8cbe945324ffe9d740d138f7bfd7));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x25bb1d11b035eef417ed5208f852e4417a461113aa5b182c3331bcc671c13203), uint256(0x2ca8568c73e931c7fe27daf745dfeacff388695f7b754d4c0d2044f0ccc2e5a0));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1577e499d10041a663941b213a67425cd12ff3b7e22aa2f44ed2b7573959b9be), uint256(0x2bc2c5e47cc74a2e4750eca0a3d0adfe4796daf0cfa6eaaa09f504d02be4c2f1));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x12477249540a77d48ee7c05d866cf4edf9ee0f5aa32bfd8bd2aa4c1b61e937a2), uint256(0x22e09b60cd3226be0f467e10bb06150eeb9b2d9b81d9892641904055c648dd71));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x03663702aa29fa3deda616d497fb4f5a6f7c6ef153b9e249e06129a6319096b7), uint256(0x004ddde34ced2492ea481f3f6ce627b5dcdc785e237a9dfb7327ea19e6ea3740));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x050ef86965980d5ac290d61a8690e2aaa3224ff0e16e85f67ef29e3c87992f86), uint256(0x1e99479bf00642a69aa67fc516d1a02388aad3705edab981613313af7024d3d8));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x19f9228409484feb04ea4c6fc11708e44a08475c936856ffc927e91d5567cdd2), uint256(0x1bcb08c43de92b3a413f7d8ea49114c4c89e4b7c1edf446a8fda6432bb712bdc));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x23f2e8fcea1d21a01f6d9461fc56e7587fb5e367b29f302f9da5f009b5f73cd9), uint256(0x00e0b23791590007fd5e23f3008515d2a9a8dc16efb91b35560602e64ed7d4fa));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0e08a9688de22511c09c65926846b21e2c480a5cc2971e702d334d65b1681b1c), uint256(0x11a8f766b716a01d58c7367358e803a78731cd3f6aa424dd2396d82ad6f6e546));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x207e9bf8715dca0f1d809ae18783561ea79409daa05f5b7657b90491931026c0), uint256(0x2414247c78d4d7290cd2cace59965169a0c79eab69bc30ef1f358c9b798f2ffe));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1bcfa6849b01d8750a54dcb195e0439cc02740b466b972e117d5018f96ee690c), uint256(0x27664663bb08e7075aedaae7e61e598902473d2ffc4acaa269d394d60392b239));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0d8ca1c539d61455a5d7848f83b363558f506db26899064b77b2716e3c8d7f9d), uint256(0x1d6d2f17c1387fff56c242e89b5cb7a457640798c3fc1a22ef699302a82479ca));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x095413fe00b43a99ced9b84e4a9ad9f13849bd648258b1aa7d4b24681a4375bb), uint256(0x121f9586b7faf65ce5788b42fdd9c7edf02393b033de032a60274fc4f0b4c4b7));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x1c55a05acf950788028b0bccb96d780e0367f8340e40f1b061cd424551dd1188), uint256(0x01921e4418e7d61f4cf73f4f91a01af83f119779c6c7b3553be9507988b5a04d));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x280c125ad84bbaffaab6724cc7f6ac89a3b123f4d70dd79a5b6c187d4626ca78), uint256(0x07e99aff05d3b77fe964e683a496b90211d597049fef0917581e8a2124e31e8d));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x039cd892869655e0cd42803405fd8ec6981b633077321c0402f973c59cb81ac3), uint256(0x08c52430d27dee5ff14373901dd84038e4e6c915fec891e19cf05fc7d66b19ce));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x11ac69be6d808eee9be1450f048b237b8f08572a71affd7827f5327e1d975d1c), uint256(0x18427bf60475d9afce0f7e6d2a244389784bc2ac3c2d9f5c3bdf7d7e38a4e095));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x28bd5655aaea985d375c9d4980f136b2d1b493b8d1c75d3fc004de09e3fd7bd5), uint256(0x07f1e7b4b137eba6bc166880421c03354752540c2f0339bcda357a9e1347c955));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x201e299712bd9f10c68a18c61d7bc451e1847691190b12d2a03d2de5817df44b), uint256(0x0d85223439530b345f6e838883be29ce783bb42be172ab926f323859d6360783));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x08b276b52a2801f87b674df192709e6deb125eb2a236f62be3272e1e998aa528), uint256(0x278e0f767cdce417b9d547968b2949b62a50eb903601143cfcfc69df6728bab5));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x213bff7768767c661b5d9b2363d827aeda51184c22b77a209789ab9861a2d4bc), uint256(0x2da6f6085c5f2a03aa86adb829af50eaeef11ba916663bd1dae9a0ad35d7bb66));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0fad7836d86c8df23f6f21ce7bcbfee9ff4c85e4d68b535843bc37ff0730dfa4), uint256(0x252dd9f6d1b6c2646282772806d49366f7cea3f77141d72aa4373eb694dab3ad));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1fcddabae2fdd8cb7adf8050e8e7e3b4058aae4b45291f8618b7a1656f383b61), uint256(0x226bb95100906681740da95fa224b0653a7f4c7bd863643df2476b808ea1853a));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x08a642b5a85b1626bc88f3be4b9cade11e6da8069e354ef8d8b4befbb0c1d893), uint256(0x304201c8cdf6c9106c3af5194cb0b9fdcbc206330e55fb71a51d6c060dd6e0f4));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1ea631bb4702ae3ac829b82181e62f0c1dc90bf18080c650f2af7497e084428e), uint256(0x2601c55b3bcd4f46854180f0a53e8641f383adf28fb335e538bef0c88742a466));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0b3313e2b783e30c3da81fc385cab2b299e8bf2bf495dfc8678688b0c7922afb), uint256(0x2f39b8fbfd26024ac241000e49ba7634e0e4bb9afb1a1f8ddf582d3282423229));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x193bd800453b919dbc2f980686610a354ea35f8e83897a9f3fdf5b16426e1622), uint256(0x05c41dd78fe264ee916eba499daa129c621e39f005456fe8758ff3f28af82466));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x187f70d69a1ba9778d09e2f8ec861100255af3799719ddbea462b7475174a021), uint256(0x01f925dfba94ce2d56dd5f145f7c584b9d51c168016364007b29fbc17642c76f));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1726a266a1c7818aa108059f8be362b462f9f90039db949a1fb0b38292fed3a2), uint256(0x296f9dce1bffaaca2f5835ed3fc6003715248d2c7fb8f832e107495cfcfd7c9b));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1c4c78d80a1307e713a669c0af41d896255cf730b0dd54740c1245731090674d), uint256(0x1a93820342f15de1a889917d3a967a9e34d995270ce18fe570a14dfc90bd13af));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1a9be666db9545d73f509ef028a8575f0e071ca3c66ccaf5d852fe310db02288), uint256(0x15cd5dd3d2390cc1bce93a53319fd42ae37e304d82d186bc6db38a15754e3557));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x23fea1ca7b8873ac316ba3ab48f6eb41cea60ddfd753e7e90add307529b72491), uint256(0x195f3e62c7380bbe6f40cd208b7098a02ff06c07300d99b753ff02aff1bb11b7));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x1d5353753e8cb8b57e3bee71850aba15b2d034820d89c115b8c7ae2395fe9fa5), uint256(0x2e78f97f83721fbf22ce3c9f266867e633039ec5b01d52cf4ac1018511a9a9dd));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x101e4531d8d6fec4acd64a1e13902d78689bb0092eebedc0751d4a1dfe1d1dc5), uint256(0x273931a4a492cd456b7bc40363d5d87c45b0728e296f96d07dec4538c72d4a87));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x0a551470448dfa127d133b743bfd71523ab2f73a2bf3731491ee19801534636e), uint256(0x2311bccce23020447e6fac4d5058805fb3743bb9bbc7a667c5406eb6a073a75e));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x09126c09f0d5116e1ca966aaaffc5661ec62a7b98ac5abc7e4cbbf22b64e076a), uint256(0x1a99255c2cc9b75b0d9a1b0993d4d1371caeb626d6a8b35286ce5dffea9ba13e));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0a72f71c7b3f689d2255e8b09cd4a74d7674910781fa0f9c9414acb3b5e6df12), uint256(0x1203368614a6af757fe8d7fc3a65d06abfaac444bf2b34c1ec760dcce486663c));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x1196cbc9979b42548a3d17251c95030e01679be68d6505472eca8937e1129a1e), uint256(0x204cefcf58d80352204bf5ed8898f990578b5b30bc13e4a46280e5146f9e8a83));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x27db3fb4df101fd60aaca8b8d5a698a802ffd698fb2da2bde3a04bc642b6f99c), uint256(0x22f71b6d9e82e3537eba1927a95677440fafc7709505a28fda43db299ff0dbc2));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x0e4d8f540a096e3f62a37ba91f19831ff9221604f4ce5558864e55c2e16fd9cd), uint256(0x1c603e434bdd0c4a2bb5679c65cc53071bb32bf37720f547eab956185b46f918));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2454ce74b4a7057967f289230b13394499847ee85317ade03e928d0e6e0db831), uint256(0x11e45f001013241566f2140b4ae2e73f7c7c1127f6ccbce9108a2fd6bd922b40));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1a980b5fa294652ad2b2b6470e9f22d4bc54a308116bca6c36e0dc92a1af5763), uint256(0x1e787ce280440664359a1ce6c086ddd06d94b41ac349564aa38892ce69e1eb61));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x081acaf5e69b53706f09926ccb0738dac1ca026b70edabe8730cf7ab76483faa), uint256(0x23bb3f68550ceee4b4fbc9f9231e1afeb7d421b8c1d7ff0b984881b74b555cd3));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x013b9d4ece4a87fb79db9e03ff825856be2274e0d23e9597449858210874f756), uint256(0x1add556ec9c7c033182421245ab289e670eab76233b0b854a4c3cf865bc3e6a6));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x159e70224e9422b60a848ba0901c2bd8ecd168e0e40bdba808662889d15880db), uint256(0x238ca766ef03ead205374e823a9b733b7615f9a8867b6042fb2ecc9bd807bef1));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x1ec6e56f7dc706f0b9a1153f59b1737060c09be57757eb01193a7fb7365f0b51), uint256(0x2a504ece694cd775aec2cfc7f2973b6f849851cb43258b0e88fa953e1d5386b2));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x2e0c811e816978492b1c51103cc0430ddf8fcf9e83b6e09545dbec27b9aff2cf), uint256(0x0f9a5f7f1036c96457aa5c7adb390f20fac51a9b3bb5a5dc57e3fa9413a0f6cd));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x252c41b3d3aa58c2ccdb48f622f330ca647b4e40f5807d14cbcf5380de817fc0), uint256(0x19110ff92f0ef2135e083a93ec4a4d273733a7fd5bb5f8951a5fded278039d49));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x07a6ff8c602de6293a74836a17370d63bce9372336f9b592bf14ef8a87b0a254), uint256(0x304a950b6182f2e26282243a97412e15fdfee179f15c7ff6ed53a553dade7af6));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x209dd7ae7e955436b11ae0f41df6c1b344990b6c2f1d40e174a0eae037ce70c2), uint256(0x01ab3cfc37c83cb2a7d5100f7b964b5ea7ddcaf31a4cce91bc5968327116ec01));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x0bfef1e79c6e91a58d966e26d6413d7f3610dc5f3e88d34b30a5ed86269de60b), uint256(0x22b05a973105348c5b5737b0e4f789a4872cb361c623b480f7ad4d6504bdf371));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x143db3cc400e7bd8594a9fb4b7a0d89e9da1ff1f382808a16624ee72e9ee959c), uint256(0x220a49005b154f3ff30b4657f15c50a5a60e5a3b0878c7f8698fc112b3e86f5b));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x05742b4970906a2659c2e691d28663e604851b43f440e951fa60b76a96054b1b), uint256(0x2d0057a57585da0c19295b6890cabd3121750bc097ea2e274285107b47d1333f));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x028f80b3ff2d009b5dccdd70218a3c7c00fe6c2bba2543e61199903117cfefed), uint256(0x0f1c7424aee63674e060f0ddef5d92ad3ceee516272120b790be90a27d0d3017));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x2edfc1938841c091c280a6cb8355769586e2712c0a0637266a4ed679b4d6fc48), uint256(0x20b2854cd16aeef7005309fbc67d5aedcfecb55cfa632d324c7b6950f18186bc));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x09246e9b2d5e9ae6fb9bbf13f0293cf3d0ea5b2288c640e221343aa55683c39e), uint256(0x18fd31080b9ee921b262e86832f6a569d3aea7986890ea7b0a10c5f4dc30c6dd));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x2f3cac76476371245e61a47fe1e67f942bfbf54d4d95e442be6f1b59b3749011), uint256(0x0bbbb27d4da371967e3b616983370e7f6d16459de3fc9559a4e308b497c50851));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x23e66df1fed230c54375da133f2873fde9b6feff012724845dfcff6cf489e3f0), uint256(0x231d69873620145dac6bafd9b7fbbd219b09a8fc7253bf9a802d18071290303b));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2e083827adc165f0ac2ac9f2cdb4c96308781130c566aa52762511d65821f581), uint256(0x0360774c1b8335c373541993521c5d9fbe4c1bb7890dadd54f6807fa73391674));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x0c4dd943e675f0bd45b9b30845b9454f735c127832abae423a86f5c482e6be41), uint256(0x26546b9ab2b6b62f6832cbfc3efc8648757d461891baf5806cf48b15ef533db4));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x22db30705c506f502b60e028244b29307184067d155d51b0b35344b0a4ccbd88), uint256(0x0571d74715d52a9777529dd335732b3d336889f40702b8a4c55f156347d3d60f));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x02687cab8157d9ccb1cf824a1061acf61db2b0d99f3ef92ef361123c4d8c1175), uint256(0x280697fb0da267bc66c0f99b67a2ddf1c156570563cd944851581f659b5d72cf));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0037c0c9ffe76f9f284d4e558b56ebdc9ff81a8c0a10c52d28bb257b9a05ed37), uint256(0x2eb1e1c4c42ff45e29b7dfbc132400ac9ed699bf92c7e96ff145da39dbcfff5d));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x192e73704fb6a49cb1bd5e86a1fae51fecc6ef28570ecc558d15750b9f1b9ca9), uint256(0x0c0796e773911d95b02939bf013c26cea62f1c5e94cabac978175376a5e9c171));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x002372b1e8f959fc9ebf964b20147dd708e6362d000e4b8c4f56ce2d089afe84), uint256(0x0f02e6f5064ec7917323bbccb08bc88d0290f9df15137d8e82ca03f9661fbf81));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x00a2491403844b47b640ad2aebfe4a5975d3fdca85597593f0e086f41b4c6876), uint256(0x2896fee824e9e079f4ad817f73a443effa697d93b658611fe71788349baee5e2));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x25207adb2c5f9e107ebc64f9c332856b6e61b85666edfe6163f3169b1e5dbfe0), uint256(0x1ace569d831dbccf09124c574820930cce41d72f2ef59923e37c3f2967f10789));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x1dcebc6d2e8b061c104e7ea530ef0946cea63ee41adbdcbefc71932a9dcf4b76), uint256(0x1ad1e78a62493cee933e992e70e35aba4cd0c434095d22fe2c2a35f3282f0bd1));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x25b2811a1f0418c8c80de6747994b5ce40eece7109568779694c177e1183635d), uint256(0x103d93ab219e296fe8059f95534d41da4749b00cf97614e7897467af1deff4a2));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x229042aad3149abb79bf50b3ac8b7dc240798cd74aec2b350269cfa96ade1e89), uint256(0x201471cd1136ac04bc1d405628de2b3aea2eef658dccb993fec6baa572ab3fc1));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x12395865b9220298dde6d02806952f2f21f7addfb57d4bb66175609b6a73ce06), uint256(0x1267c1397d11ccdacf9792afeb0014c97f3ddc4d41602e8807520a95680f563a));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x2fde99d1edc30078e25ba56088a3e777e0f24de3a35b8150c8df2ac71c871118), uint256(0x2088eddee23d4c7104912ebe848d42b0e218dc881f2f4626e02f5860aa2c2ec1));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x2310d8f9a696a87547f8e5690ced729aae3a1a8e898b9e0c3022b34a1ba89dec), uint256(0x24e898dd29c6aa82771ef171707aef29c64f074e1e542165a266e40d943e3a4f));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x25cfd7e5b7dab507982aaf35e200ee1ef74c5455b5541883b3a8353ad8cb20bd), uint256(0x1bd3feabeb2b19ccadd1e1dd41504bc08bacbf5c9ea8612233ff61c969f4e6df));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x07d408610fc841f9d56aadbdc9ad0deac0c3a4c910922ecbe3bb469746a7fbfb), uint256(0x108b4ac024f5a57383a2d2c4ce7d76c83366ca144e786a7a3042ea404b0775cd));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x2a4d67179dfa882bf76780f2c00f20f94b40bb15950354fe8875fcc9a32f738e), uint256(0x0af28d8e3fc887a066aea302593f807659099b078ebeb0f5c74c9ffb6000bbec));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x0fba97baa4d4a2dbcff477492edfafaeee65b768e775275c6d27b89d3da656ca), uint256(0x0949490fb363d33940ff19f96f7c8dab2e50eee23fd115e5cc72b4577843fe57));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x038b2f47e4ed0fc1e124cb4d5fc602667caa37ca4b96bf6cde180ad000dcf9d9), uint256(0x0a21425348f6de6bb5a6c68c0eb251c3ab7f061436ec183f06c93b2fba020aa7));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x2cab8e54281d530944b9b450541cf2abb8dad663506b24b3b251a138a789a16c), uint256(0x26576d10daa47c64d94cdb9b67965cd3eea7d3704eff0d18c244aa03d707e3d4));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x08fb0a09c13483b10124f3fe94f99f540f1dfd7a96c73ec862e563a39d5604cb), uint256(0x13cc09cb2ddf9b299eadb38ec0ad4dc2da93a4ae0e41eadd16a5bca23755bc2b));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x03e8d5e2acc6e6dd17ba3b2dc535560e0bbd9ca7f83ded50757f6b88b30b3394), uint256(0x1d8029f0afbbca7e28152e0b6b1ae51cd6881006260dba5d06fbfad2d1876307));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x12aa6c675bb069c5aabc6a780d666f8d0469998514d9ca303199b3365cea2d4a), uint256(0x0e1eefd764fc472721f6295599ed652101400473148905353f4912d63009497c));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x115f784ea1e0c000a117cf80d50dbe9fbfb283cde5c8dfcbed1cce4102094c58), uint256(0x02ff4f71ad0c6c9b0b5f72c72281c9293bbadc7072df2531573a47dd1ace4a32));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x2d11e17b074b0e193641e7016e820618307ce6a661d43b4c44aa8dc7c59fd804), uint256(0x1b193a1d61b0ac18a4f0198e63e0dc2c4225eb2cffc512e8a52ff89689e10492));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x1af52308b47e56e8c9b81e9dd23336833731c604ae02ab5922a15cb6bfb6c56d), uint256(0x2770cc695475368cc5493db751a29ec3c8637319ceb03356e4e77635235bf797));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x1d559cfd46d809a9fd6d1e8390c482809e09056d9026fad347ba821f47a0a7dd), uint256(0x16a423e70ef1f32f5694b33ee633bd6432afdcf503b2d6000b738c1a48e25f7e));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x25738abfcb2bbac757aa533d84ee14e3855eac45cff706142be4413e065d2f0a), uint256(0x2f34426a78d8b1973c1ebf135f69ecafce1d19d2085bfffc2ebc3c6e868dff54));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x160b1f7a1b9db3f14126461177238762c3c60581d1f6ac975a308b6352381205), uint256(0x236c52b32d40dbc98fab5edcc98e0b84ce8719813b0828dcf989416eddaa88f4));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2559e014f55facfe86a7f0b41d08eac34a9fdbc08b032e5b595f191c4be00102), uint256(0x24e23f1ce5a83e5429232723102f8fdd76eb600567069db14f902b15d21ca4ef));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x1523dff385590bbef20c48294b4de25051e63538b145149334b665cf92aae6c7), uint256(0x1e39ba355f6843be458c1b5113c4049d0add2aec318a13e596734fe43bff7b34));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0d042f0227d611d626f970513a3738aa153184bda541c700440ab67c4e58a2e8), uint256(0x0359d76b122e897e9ad0a3814218384747db829162d21df80e313607d1a07d05));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2970b6670f584bb384816aaab072a3059c3a09ba8955ed56b942a07d008a3d93), uint256(0x13bca04f1f7e5222aee8d0629a33f00eacfd3f1e335b1ea6038f3dfbb44848e4));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x0e91945e64ff9a166d5a5558955177f70254cab7efb43d12a9f896af2b520d86), uint256(0x210947a809c8a3124cce042ab464aaf953a81ce9131fbf8cbf894c6ea8be9b89));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x17e48ca41a839727196c62c8faa2882f555320c9433abb3af698bb08128effa6), uint256(0x29487b4f299fc92e39b13d0c00395ad67aefaab61c63ada56a77289fa6733a40));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x2aa74784f5fb533e117785dc7faad1821e75d79d85563096dc1be7707b942fdc), uint256(0x02e451daf00f6e97e29693e96b0d8ff0a4242b16d706165fa64f327b641944cf));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x0ad9dfa00cca4fe96f6dfc0452aa239569fc01baea6635f1964d957b8dd83d45), uint256(0x16c1ac107410acdd54cceba9f9ee56b49fe21bd1a8b292e865002217bc341632));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x23a32c6fb9e6233211e540becc13d7f1bb4cd63002813169d7271f618c27bda0), uint256(0x2df07b919ddc3aafc53212efe0ed1a3eb91a87d2176cb4b07f4c0c248c65c418));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x0f3755ff88d2eaaebbdd022438a6df1872d953312a64c5ed5e49cd99262511f0), uint256(0x049a5fcd6d4bd1f1ac3e0ceaae49790b1a3a85ac8850b215f309064636ffa8f4));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x26024ad4318e6b7c89e5c6159b29ed6167aca1d24de33fa7db18902eccc89366), uint256(0x24e5a1e5e68acc21abc883a46d76c8705be6d1c725b4a6d9258183fb06654ade));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x1cae599e600580927c7a339d1b4a5f29dc2a81baa19d586bf86bb17a184a87b0), uint256(0x200b97e546d65d2be1813e8e20ffbedcca3905efdfbef9b189e8fe6d46393d1b));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x08bbf10d185a39e9c970797140386dfb72720f9c16efc00e327ab2e5214e8b54), uint256(0x090fb745c3dec9eafdc9c34bc5391a9fbd46daec75aa0675a2f183e62c20e859));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1a6a55bd44889c6c862911f2e4d9f40ed07898ec289affa669ad13554572fffe), uint256(0x1a5f5a958c644aee45c6c544d771bc4b6f363949db9642b1628637d7150c1640));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x01c05f42b048475aa17ebde5a959767ef9a5c7f2de4739f245d252cc36bc2241), uint256(0x290bf9cc8d2f5a8cf0572353ef0b6dcd5cbf2fd2ef55f8bb55594b0c382b5e3a));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x041d68080b2b8ad6f479bfbe304a0eee5f2c45f8e4f6a1209b4524685b652973), uint256(0x14cacaff2c01d7672a8c551c6ae9aba9ff96307a0a76b6b8222a5e1e590fe59c));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x14ba51369b1885d48a5faaf7a7025ce45129d4b22c663fc099b35959b1f94b1c), uint256(0x1575ee6da73d0d183ee4e26426f3231d89cde4ffe57413b040288bae8fe63f3c));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x2b5a9e410c478de0ff452296f6a432808ab426837e9e7c0099f18dc0445ed09d), uint256(0x2e823077c769ba097bddf6cb9b91e7ee06b605f7512ed1d6c6f0223ce71ea80c));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x2791d35b233eb40da83eb56e843eec2e3627b319817abf6b76004aa09e2857cd), uint256(0x0c514e1cf631ae459aaf7955fdf027e05aa41be9979cccdfd23d5663b07a3cef));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x04b8e5a278c1515ddabb4085fb7dd8e4c8d23d7cad097f8c85c1d98f8861e6bc), uint256(0x246e04bbe9046774aa4a45bd85212b4ed86a782afc04401f6fbd69464417323f));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x0b80b140a8586ae5ab23852890d96b0070c5536d2969e9694826110ea350affc), uint256(0x0ae0008becba024a85744f604f47efdc8553cb6b48211742959e30de6d7d60cd));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x031c51db60fafe2a6f152357b7def49967d2f5ce236d452bf77d27ea07173b3c), uint256(0x05bfd8d498eff80dc755a190db4d4079e6aa0814a622f10a474089419cabd55c));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0ea4d9eecbc78c18d7ef781e8b2054966f7c70c250cb8b154b2839fbb8c89cbd), uint256(0x238aa7db6a1d19fbcb8490cc41b23b750c65ba971bc0f8ab79c913b4b813c494));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x1a0e31fad46800bf36e16218b4ed0a57ad0786eb69966b31bf6824c4d080e10a), uint256(0x0494d2c16d7121da63a15de552901a4c8d4e818a7711f214d35a883a1ae0aaac));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x0a0230d1df574ea3b2348a4ca84325aa7a018ee84dfd265c8fd6fd603f1136c8), uint256(0x1c9842010d9dd98f512c295de11d6f6290c9b0505e6622aa44879e0fce980fea));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x2beda659712fa68be48f8d6b8c1fc3fb7701d6d0c4dbf45276247188d3e15966), uint256(0x04c4da9b2219e783a104a96898b6737929d89cf86b7f85429e823fa5e5fbcc0b));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x00c3a31cd590303ecf31542c9d2ee04df1079ec6972bc9c516141f58adaad183), uint256(0x146056723f90ce8b904a4adeac63fbe9447fe62dfcbb3741dbf0c6c8a527a47c));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x0af33b9f7117fed676ac796e6401e7e440f684eea085f5d0723974a865f2300f), uint256(0x1deb6d521b76d89577dc5d3d9e2810aeef20e9381635bfe6b50fee1ef80cdaec));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x2eb2c445bfeaf03129c6be6006e159bd2842a7ca1519f04021da9669348b4144), uint256(0x1667d2bbeb8c295aaaf6eebaea85ead7df85c15efd25844b23c6dc33f3348b21));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x1d96f0a9581267bca1e13b8144a17e908f02899a08a4b96a942af711f216def2), uint256(0x111bb78d68ea2366445be5ded0fcaa5993aa1acd58049cd5748c2c9498207464));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x04b2cc1035fb063c6928f3ca3c871602aeafc7a72fc15b6589098d2eff30db88), uint256(0x272af8be74abfb3b84b17f6bca58a2e95ae01930204fa10298b17d92e4ccd4ca));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x1fb62489077a4b372c037cfb810c10d64824b04ce8fbcaa5de2ae6638a9ac018), uint256(0x00f5dc0d7e6df97cbc515319bc2f97331cf57efb053614e7e3fd34390c9444b1));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x1abccb890e9a69c6f2905ef15ee71efc95ab130b23b35bc70219d1239a047713), uint256(0x08c9c35ce3dd97464db173f8423cd8a8794e5d29ca229f0f07af54e500ccd2af));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x02be6bad0bc8c08e30425a66c30c31ab1e8c2c6143b6394276000a5d23645da7), uint256(0x182a2b4c42871249ec88405a6e16dabfadb77ca011aeb95e68f4aef3c9768b04));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x02c9216022c10a14ed86011c72595a8609f486a6bc959ac596a48641dfa3224a), uint256(0x08b98944369341a7ac42a8c8a818e9610c4fec87d9bf80efb749f63d9c8dfa5b));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x2702d60a4a61046c59e464a0d4f7614bc6b04e3efa18f45aa6bc9f41184aaf4f), uint256(0x26d68ab07dc8252c86016cec2701d321222eac36b5751c95a0ca53b28030539a));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x11d7d73fb5747d154c9b4148574af0159152159988ecf7b515814250551f8472), uint256(0x13b8af96e14f20ff3174191db562c83cfa3d7b614f5b8cbabfbea79a71587e65));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x160ae7aa64fd2f0f45ab7daefb963af65ada59f6aee8fc1b2e87f70cc4732ba7), uint256(0x05de0a7834f3a8a5fad8b5d2a4dc947829c3e3077e16b57c9671d2dd36182358));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x174c09db4d39c404c84315fadf10cffdfcd78bee4a8f6ded2c4cc05012d0623e), uint256(0x1ae7855f0c5eb72f5bee9bdfb09a7930b4d3b3adb66391a3e0fc93568157851f));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x0393fea8fcb13f5336388472c06ff1ba742dd84d556ae5d79eb9b2f9c5d53d61), uint256(0x250cad6f98867fa054fbe811e30696271cd67716d84bb9cdc41896351c8d8639));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x2033698ef8502c46f9e0b228e9bec1a387162de762c51441adeb1587999a78bc), uint256(0x1b3f80a9fdd655aa004f78e64ea3588d2f38119e27733bd5e28e54b918e0f2b5));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x07d05a9cd6bec0dd5b84b93f6c86738ac1334739e1a2090e7b33c131187bc6bd), uint256(0x1c4883c2b368116d763300b09439264042d4b2def8748d602c6268958b74ce7c));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x2e11b3e185a2377d6309b4ffe668bf5696ee3828b85b243165355d089eb9bfdf), uint256(0x1419a8295464fdfc4626ee8c4f0736cc6a689a8d32fd471e9323dbab646abc52));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x086c6b20e3735e34d59331142c938e285a88df4d06cfa1d5478b37513c683a42), uint256(0x0adcf4ca86d0c3625b51fc990ee2f83977672669cb3d1bd543ffb0549a9bff16));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x1055bd97dc90d1602f448f4fe3e1de852e99afdc03d73218c243369db83b813b), uint256(0x1a5a9358ee6b76085a2e913d42394cdda369d6594f9b7f7caaf2fdc88e4cc55b));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x10922638722af0be2293f97b2f8631a3cc9ec168543c05a186bb3e6a647be34e), uint256(0x02877f1345700e967e5f72a0d1f60b8d91f889ad9f9e639e77408145a6ab7adf));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x2de2247b380e757a51dcd7f47721d4e25db527764d5313397aeaebfe1d184ce2), uint256(0x1d60bdec4dd9a7a910341702b1bdecacb79ddcfd8fc384af6cf62c81624c3de1));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x124fe88e4e6ee4cec9e102744ca138965dd30a527e701a0f9b6ca658c6924b0b), uint256(0x050d985eb07c2205d72109e9fc3a6cb2bf25a8168bf0ed26559b1fdbdbd44cf5));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x29913c98c2bc6b5d3d024961351a14e8931e1e9f292a7082b7b49746c17396cb), uint256(0x0aea80d51950653a92ae49f55582a07389c026da7f49a5121a7f3a90407d32c7));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x2481fd8bb9e8f04fb3805cbdcb9c471e41211510ddd303435d133f81bb534bcb), uint256(0x1cb57ba558dbb5719786059c8883920ad5ceb7366ae4772e1ced89b406117441));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x1c72b970a108e3d06346fe63694f4eab978776267ced7d3da47af516dc8d9d0a), uint256(0x0be56212761a6e0678cee92cf986216bf52d048a301c0f69eb206e9bebf9d785));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x03ac7d3829f1ad745a21955c9a02808433dfe783cf34af2276baf5d30a0e1d01), uint256(0x1566a8c54d92fb924cee9a9d6ed9e7bd4a18af7a6b689a75ba8c31641b105d9c));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x0adbb0a2cc6f5889ed3cfaaec4b96ef331840bae63f7cf9372dcf9a4ced14b83), uint256(0x24d3bfeb5a601fe841f559af2f0b2962bd302c8058a6cd17c1a90b40ff8481a8));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x2324457c0e68f820759ea0d4f161d495f39c62dd51d1c75c3e8560c56e9ecdc1), uint256(0x01f9886de1fb6470e509fa8f2090d41cfc3b94c94aa2eb2fe48d147774015fcc));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x1e59b9671bb09e63e4fd1f5cafa53e38ece63cdb978cd3e1d1d18b69403a1616), uint256(0x0fa4edca3d89e75ed5914bc4fbc404b62af88f2047ec5e82aa78c5123a7722f5));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x2aa10210f1967374cb5e9419c42bcd0d34e4f5cb57fb378cd8a8f1f874da19f3), uint256(0x0a81f7cb3af9847069d20b9fc2c23946cf45c6e6db263f59f901ed0455abfb68));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x0d6bd6ada25f3cf7d30976927fd1eafc5d1016a5eba568982eb76854ceab8723), uint256(0x0cd3dec917d48c6834312c3d3b09164c7b544e654e385296975b56d764d04047));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x081327838b9410094c41b971b1cca3e5d4581fbda95d98e42a7e0aea3e251b79), uint256(0x046a106c4fc7c9d7547d0ba79927859d971d809189c4b6e1f86da4d51e60b1a7));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x23d1e015cd556463b1802b2e37c6ad133e2868548aec470980698a0ff827f307), uint256(0x006c69c105db2f0ba9d238b131e975e94e25345e0fbccc79f565cd338b07248c));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x031dc3e173499d7342278a267b2bceeffc9519ff4183e4ac0da77eba511ec839), uint256(0x0368ecd6c974411483271dd5e768966061ddb45181d82df75c19438ae591a1d9));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x1e4e63bba7e228d264f55599824d3acfd812149cbec5040cf674b9f6fc356bac), uint256(0x1347544aee110a10bf5e6a1720add53c8c7e2065998da84dde29d1d85a44b3d6));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x23587e6235de9981dc09fa91e075d7a8fcd69a40c967b4ac17c9631bb019505e), uint256(0x2dba552c9ec8e47c0d09ac548c7473280a33af6adb97049d68486f5cdf467c0b));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x20e3c939087335b7f94a00470bc6cc89ac2d6036ab6c977cda550f5f00edc47e), uint256(0x0a0ca586d8efd1bec67260f8166f592483c05b0656f4d270624d6efd45409ec6));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0cecb02183e150b86f3e1b13be4bc7b51ddcc88f002f4b4fc35123dbaf81c1ea), uint256(0x16192e0f031440db8e53389f883c2923ff5fa0232a37e29b34c1bba8290b8af2));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x2b313667d21a5af3a5862861df25522e6dd3f9e861979f843d4e3f0cc6e08fd4), uint256(0x09c96c8fbee7226bbffd1e36c2917f9ac1172f7bd9777a3470ce1005ad35bb36));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x18685331386b75507c0119ae89d55972d8d17634b039445d19f492e486f9d6ba), uint256(0x0e110d291de45f042e3f1518acb69dbe53e3f8d581b799a9455bf89e87d9efdd));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x2cc8d1d454e489961e233b90223d6384a0bc96565052ae9cdbe7affd26f3b253), uint256(0x2522ac8b112d50bdbb045470edbbd4f53859fd61ad859f39f39f3ee8ff48545a));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x1dc057b388ce68b37c60e19991d5933cd84d60a1f29d75048c4dbd16b8db6643), uint256(0x1bd11c15174b10b89a0c2ce02a756c6481d5a0922139096c99b0ed1f8ed91884));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x0937577c9f36ff9d3c407f73bb17159c4b781e405f90e0e5ccf624cceee05351), uint256(0x163d6242316c4eb6794289f3a2be9dd5c56d4d223f97d5459d6938bb99ada114));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x01a06c020ff32c2e98559f8782338cc2069c04d301b580d6c57a5e24224a85c4), uint256(0x13ce6e170b742278326319a21fd7fa001d8ed9b90ac523a10255a5c5ffabdc3e));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x184db259db649ad9a3525b11da92d4592ec7ab6ec2df32e5b0ec9ea42b949199), uint256(0x2c41da1efd2d29bbcccbee41dda17bda03c1642b16eef7559665fa88cfc109c6));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x2a9ccbda9b4b01fce3d35ce5cd12a1e44e9033203c7a15640e465609c0dfcb51), uint256(0x23c4382314ef71da08128c5b5032e3544a887a9bcecffb9093a931b2d50b99d3));
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
            Proof memory proof, uint[209] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](209);
        
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
