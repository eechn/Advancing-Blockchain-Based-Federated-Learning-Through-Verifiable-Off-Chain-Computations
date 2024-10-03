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
        vk.alpha = Pairing.G1Point(uint256(0x062731975fc4fb1da05a50d84ceb7bb4c9caf6d4a1a6f116273038b37df9d7ef), uint256(0x2a3f5506db676f552ef925b6782412fa6904649beba4ed48bfb8f5a5ebe2d112));
        vk.beta = Pairing.G2Point([uint256(0x1ac51d70fa36eef8946dcb6ed58a6d1e1415f543dd6e432a0e21bf2b7acbf6aa), uint256(0x146a7864e9d02372436c91ef8e1112f82d68b430c5fbfa72a3233172cd278ece)], [uint256(0x246ef87732971ef5f60c38973761c4043dd4634817744b036fbb69dada8e16be), uint256(0x26121b18502814a3fe69f2e9c551d93e0f1f01b8c87b87a584b409d2a948c931)]);
        vk.gamma = Pairing.G2Point([uint256(0x13e42c43771cec92e9f1cc9f029ce87ea6a78ae4d6d430601742498d09486461), uint256(0x27332bb278803f72fb2f319284ce7ca740460a7ceb7368eb2576ab3cdbb1ea55)], [uint256(0x003ba40bf76962f50cd6507da47eae21e72b16f2882936e6fddfb1159daba766), uint256(0x2f3f3d7cc478ce65df21ecdbea0ea8c7af463fc9698f08664fd5bd0e42689f48)]);
        vk.delta = Pairing.G2Point([uint256(0x243a2a62e08bfe30c57b07bb4243c0157ff72403c5e50d28498c39c16c0b42ad), uint256(0x0e77aaf0b0fc1339be34038acd20fc37079bc7501df9d8607249f61324f1eae3)], [uint256(0x00c017b5ea82e61a9b319c278f7126e396ad91f786fa923f8ca05edcca502246), uint256(0x215b7132454404812d92fcd2aece129fc220eb55eed808c70548093b7eceab35)]);
        vk.gamma_abc = new Pairing.G1Point[](210);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1f92e4fd31ef9f49ee446e9a6782d5cbb3da65ab1063b267183b4a167091dc21), uint256(0x0f303518bbe7066237ccc7615d416b0cb25d8ca23acf92416209b013f70aaa20));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x22c3a50cb6a258f6baf82063882cd3a110163e83bc0acd9b02eba0991f921a4b), uint256(0x2653445da82ddeeb2e025851f639202b56784d82991e1b6c1427b40f8c1023c3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1e99f617172a380fb001cbb889887dac5bcd504e7cb09cd5657be90b71f8e2fc), uint256(0x1372fc0f0999e5c290fdbbb6b13ce76366501c62bf9464e7c5029ca6d633f02e));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2f58ed946e794b1bceff4ce6cac5fd8c30b012cc54e403b5ebf25957c1920d9a), uint256(0x2beb6d6e3d2194673d37bbe879a656dad3afab84295c1746e9bed2c6bd83b7c0));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2e5b9e4fe1c2e19a7f82bd258aa7bb9d303ca2620263f15fba5abd9dddc3680c), uint256(0x16104a8a4f93a9dd02a5de46d64073e3a433c666539f34e61954ff7e02cbad41));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x125a71d9eb155853ef78724b011fcf95dafdd6f4842fb3d2029c56c89393dabd), uint256(0x23364ec637fd2012e586b2eac10bd2c734402551eaa86b59547b8d4151a1fc46));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0989ed9f03827759f1a07bc9cf7c8357fee5312c1011b0e692c5342add9d49d7), uint256(0x16cdc6d9cb904f2cf85a957840327c1ec982b05cdabdf1ec053befcf34dcc75b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2008e932defa162a6c18f38c29943c3b9a8d06a9a875d1a6cfbadc138e15fa72), uint256(0x277b267763ed972c027da378c925faecfff6d4fcb4d0cb52216346f859f0953a));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2339697e852ddf666dacd7cc9fc596144b091c72a2689c6c65d7c3e611d1a796), uint256(0x17d143d6569543816874601033b7a0b072afa05f0cb700efa6f451d9ab6fab14));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0fd7b166f7024f1ee5b2b2a7d66dde012f2219184632e525f2eb78242a7d7652), uint256(0x19265a011bbea6dc248f99926884b778a42bf66fd05bf9865037a7cc4467bebe));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2eec99f6c9810fb224c9de801982a972b1d6423fc704924ac4c1cc3bea8eda33), uint256(0x15f56a0a0bb16f2d6c0319780a7d6267882bbd1fa5838d6fc61a711b9d8955e0));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x10e22c474c4bab0f6db472bfecfbc87f1831cdd8355b7aedab8cd4f820f9cd42), uint256(0x25ce11865a72fd015368f8bb742eeb899c443d7cc0ddd0036527544997a5f702));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0f252c843942c07e4a3a2b97490b61100ce29afb7578ec3c764abf576bc28e36), uint256(0x1d0c01c0532a9e4bfbc11767dbb941586b6d30cd23a3de458fd98adab5e296a4));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x27eaccea6eef437d39d6d7e2a734084a15dcd9edd08352b81b915b41ac60f403), uint256(0x0000715b8656eab15000d18531b2716c1c052b92642c23c38dd227a0dea81a24));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x01c82c0eabab137d2612b04d69449e4c6facdd3899d626a0ad2c202f868f9626), uint256(0x2bf9a1e107742ac0262232267e29cc7ad3cacacd6c2e29e06b2a0f6c18051ec9));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0b3da3d9dd82840388e9d1b554a235a73b031875425ec2a42e47ac8552510625), uint256(0x274332a8cc42d4a8b5befe9b956f175ee7807d41512fb4c7eda79cb495580646));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0869d793e89dcb9443f92badca0db67ac07466c9cae804619a40755851377e19), uint256(0x243ee5103de766cdc1fb9d3043f4624b8231c48e00f7448e2a5cd1728e0e5965));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1b807b278114dbb3899fdd07cfa242e47da7b09d23a6b274bde6a9239c1fabc9), uint256(0x170b0e9d6c6c2faf526db7e6bcd62e64f87b3d29b95e388a0c2345e9e82f6de3));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x13260b9b04f32cb71229e33a457e78f8450c036247cc1f5c0867995d95dbcc08), uint256(0x1c60e2e55a61493995320cbd35fad6ac00edf996279210d6ac112f129cd12302));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2c73ccc2095000b1bdade28a4117b1e8b13fe3ad9dc496e4da9cd6abf018735c), uint256(0x03178b4d2bfb714fed1dffe2933f1a345d03f4a877bbdf67ed425e4e235caaac));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x033ab3c10cc2eb6a55a9e938f3b1942c500f0cfb44c827f9442c65a6ff988daf), uint256(0x1aa452f4ed9d7f76b8cfe33c094aa927d08d9ab8f5066229b38a1b5bd1ec2088));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2197ec9d52ddd1cd8669b61eac48399352a04f92d358cd5ae910efa31b93daf8), uint256(0x2dbdcb8fa65d314891f996daaf87113e7d0aae1d81c5ac5f550dec36441ec0d2));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0ffb5b36cfb4226e3fb5cd8b7f3ad08d8b4cf8b9986c9efa19629a36ef4c8355), uint256(0x26a6f9356e102b6ece0e97bae871809407089971a28487b508f30435ac0cbfe3));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1dc4652e06a25d2c8a62e5ca13ae35da2a12304c8f2a894fc34e5da3e71076b1), uint256(0x1b8761c97c7ae92c42a399679c215fd8ec2562d1072fc08e5c014e4412e857cf));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x05bffc0b21f24fa21db4ea9bbdc1eee5282cd3017c0fe4b8be877de16c5e7946), uint256(0x07e986bab0dc7aa7e5cbf0b858bd3827d712284332a3ee704bda2f36fe1257a5));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x15662178c3fa6a4487785460d54d47fb2494ec72746a47b32cd80ed9eac25a3b), uint256(0x1c77d42bdac14fda2347169dcee364f436ce76030f74c08e104848ff83ad305c));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1c3b6420ac6c26ebaa02e0f107a0a6588ad523d951d8827d27c5b89226cf4312), uint256(0x01d56e15812cc9a22bca36f18bf91bcba4bc4346aac15bc626965139784c45b3));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0c71c26c4dccaa3b89568773837fc2226b24797b8725c09a52eaaacafbba5027), uint256(0x001f192e939eca6fa3ee97c8270aa9ae87a4c17acd72ed563d8ffeae30b8e970));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x29541b0176fe674a2efede65ed8dd09fc0b5421bf6f85016b9883a6b00e5e68e), uint256(0x12d761fa4ab48040b9c547ddacbc43f57d9cce3fd2413dea6a4c6c66b975b319));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0017adf55aa93b6aeede106b713249236a12b9d80e2871ddef1f775ada6a943c), uint256(0x027ece51e26e760f08890097fff9a45801d9c4708b1a99b2a16e0bfcb7c1eb0f));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0e16fde6cf1d73ae8aa00ea839161b88e2ca2d18ae448cf52cf264a383ff2c1f), uint256(0x0f83e21846020aa876622d060ca1b42ad8743c3e2fa1eadf29d40edd11dd1a14));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x09a361ca5a8238f97d8a214c1a48e9543bc3683b277e5830c0f6676d9008da94), uint256(0x2a6748b1d59ba7e5bb33b1abe59b0511b7dd0c5421e1c0c4c22961f09d5e9958));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x135885e08a506ab4125845c56f64497f17f39ac944e50096bfc0c298e7a53a79), uint256(0x0d0b4ccf4a4a74639e081fa15271f38cc35a399dc80b59a50813109328816e31));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2219a023aacf9082130a0b2e476b8202fe93b74e0f8db8f9de2cb547a5d9ea68), uint256(0x2e44ca2fabe983ba6c718b13e10397f129ac8d28764e6258f07e8fc5c79fd32f));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x23282aa1d6602a917335bfe04a6ac8e4cdfbf8d9d91947b6007009243fdf78d5), uint256(0x203320b44cb35e9477c771090bb40250f705fa0cf5a26e84a236002b5336f4d8));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x08ef9f0aae22a00e5009ab87b5066cdf210041a23c515ca470e2236ed19afb21), uint256(0x1d4af2b918c61708a71c4bcda4904228ada01ac802e4f6099700d2c3d95f57e7));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x02f92fa7dbf00a1ec56e0b8049222992296619a404421ca2516177c4a24126c8), uint256(0x13677d57cd63240b8b00448b5fb5a84391ac598179aa0fa28f51dacbaffef041));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0202c6069fd386b0a084d5a43f59a0b18cfae08434f6f4c4fb7a3fb88de9cbb9), uint256(0x1b498ce27c5c6155c2efb3eb513eec56bb3f85de98c1169f3e71fecb6e567ec5));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x10f6b0a8585725ce990f30755eece0c896bdab1611abac3a2cfc20744d7b73e4), uint256(0x13b0be2a83e07a3d1e2e0f10bca6e2f6562a0090c19522a388b88405836bb3b4));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1d05a7604e89cd9c8649660551155cf78fdfa1b336c515fb41a515036cf40f03), uint256(0x0b59b7a08c192893f8f63237385d1e2f8db99d753c7ddd8baf145a87ae11019c));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1503f87eeb3b8f00412eb965ffdd6adb1472e127434463a6a20efdac1ea8ebd0), uint256(0x30314164fdd43d24996ebe32a14eddfcf5538103dc0859bd43e9b9af6171d7b6));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x131cc6ce227b550010ae9b18a1c72f947e2f20149c6727de8d163609566d0fb8), uint256(0x18a50de4a4b6a00505427cda4a265b0ba4932ebfadc464292f7075ce324c6092));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0c3502ef8a6b20900c8f48f1c6a8c7d232bbea133dd00b05a936bede6fd15289), uint256(0x1ca96804f26fd2ba705b2f3a24725930f4e873ed3c4c459bd803f8dcc90d2ab3));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x111d1da2fa11333b8a74d346d173ad819cda00d41c1402a3ab3676a410e94e6f), uint256(0x2e8c1bc4278ba1fd48c341216c108c0704952aba1e008c36857dc41f69377d37));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1c8a1add143ba38564035d5549f379dc7ccf66e872c6a9c384657f6a7242f2d1), uint256(0x05b5e075cde9b273dea5f2fb974a3001b840ba07b986a991e831f26bebf3641e));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2fc96dbb9a2fbcf026de47ffae89ed5704db01d08f379b45a297d69c1e2b165a), uint256(0x12b72d544759c466dd274e8752ee2aed7b7d0e9c060b82cdcd8623780a224039));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2da35cb760d0e0d6508ea1786259ae94d2b926f0348707826734981866587f54), uint256(0x2cb473eddd2e37bbcf731c928464668e578179c54465dc982d6c437388622d58));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0cc2a6eb0774d5a15984e8a1ac5f604b8a9dd464309ca1cf2b1939c5a1e8fa85), uint256(0x26b504f6dd596b98bc63705b56b6fe7ee1d1aef8d7d668be29541f3345113222));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0d668a43f7484efb68d41666558b7f12a4ebf7f3d4f1bbfd8b52385fed639203), uint256(0x2d956f694714e0b76c005759d8a12a48443f69b8277d5907809b00edd558a364));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2f23baeebdb9a214db01cbde08b5936b08b7090852a601d183cbc9079ef38b8b), uint256(0x0e6033cab068067ba13b95ae36acd690a799a2c768d048a6a4d3736d59170779));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x0240a568af4355eb0144e4c180c96bc5d5c15960ad400e3308216b5aae631a0c), uint256(0x09cff40ad2e2d6ed1c3ef3be8db6be2a0ddd22cfb9103c775ad5e413da519021));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0a2ae9edceeac8095a6fc1cf892e9275d0b60552b5a51db56e6e383526a491cf), uint256(0x03eaafa76b175320dca499f3cbce91528507f1ea209026e18ad3a1043e473262));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2202458a1d318ad811f0d8363b288cda949cb1112543140c54545928531ebcb4), uint256(0x2435c35d6ee4e53a99d5067558ed147e1f5a383009755054d9db5ffb4c526964));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1733c4fcbaa12f22b8fb27b9e6c995772d3c332a2d9bd9d9b175113b000f488f), uint256(0x0f357a05323c079cce47317fc68376e8d2a97d6d0387a72598d78a9f7c46789b));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0a10b0b3c2a1a69557d441635a7b86dc4aed36ae8d28cfe4d9333360d270eed5), uint256(0x06d5b12b77c2566345e0c318a6a911de362a90c8303c5f07a6701694f02f6a8c));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x06c23fbf642ac81832d3c896ccc833a49f3c2a19979bcc7fd686dfd081d63ac5), uint256(0x1b3e8bf2ccb764a8bc87ff39bb9d3bf66abb0d2ad09582105854a5deb8f9e172));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x23d3b057634563f421453619c1dc5a8a7cd4081dabac9984d86a9dd8192f32fe), uint256(0x00e2cf1ef6e684e93f873c4cd4edc9b46e2a5c32315c4e722c075e73b3b40e8b));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0da96636fb7cf5554ff7c30d5837cea73dfd5a946f1f5c4aae592eb8fb3c08fa), uint256(0x268ea0e651720e3a05983b78d48af6a9ce73a92aea9887e398fb983e14457585));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x1270a3d08373c5d4d4cc5b1af2f5f80a038d7ea500680248d7303cf7fbbe203b), uint256(0x199d882535e2e87279ca62da31928c6724344ff9c158d2d758a5b80d9d0417c7));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x07d41383ba4e11fea64bf5a53784dfb94f249f96c14ddac2be5e5805b582ecaa), uint256(0x07517680a0d0b2b42748acedce61a91647586526b6b39587ce3817d381c5783c));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x182ebcdd4101b77144a641e3cf3ddc38da9a3c4385f75dd148bce1bb6bd70c23), uint256(0x12134343db7cbd1ae80b0293b52a104ee224d57eb52b44249db45067f1da37d4));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x17766ace27559eecbb293c0697967e3480a324b1cff5c8780b5447db65f2bf62), uint256(0x175d08fe08828230765f777667bfb96ef904b32cf1303cfbb93c1856e3ea16ee));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x25c59898378c08afd6c0c31dfcae49d20da30544e7ffebd7096b6bf9cd816b71), uint256(0x0bbdeb4f7128d3d5d35c00e6b96b02e5edd8900995b703b6bacc92b4ab5b6385));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x18070570c818d8f080c62b24a7a164c02e6a42c63e1906f2f3d123bd270b0d3c), uint256(0x28e314d976ed21105bd9d75afa77f5585a3579770af52d44d4b73ccfe777e62e));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x04837a12d5949028b755dc3a7870eec713015d34fa1a715ec0250bdb70820ca9), uint256(0x2e473997c0f1b110c4c7f6efb0adb9f51e5f818efb8773ec1af4a5e1d50b9aa8));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0390a4c40af68dc8b365444a344aa87230987a2ccd1911ada08a9e8a89a90206), uint256(0x0d9bd4add64313f28098287465eb8e980c298f3b10729977b78df2fc8213325c));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x0ba07cc94b3838e2cff6f171da9fc449a44a1829e39df530b0b3a07309e7473e), uint256(0x186062b63a090250c5f39343d530e4bb640223232165c667274955f611d0f783));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x090b7161b08ced815c273b50cda619c75584f504a90033120784504e68078484), uint256(0x14d344fe71efb92720601eb1d0ef9f9e4cc84463ceda6595bcd4bcfc83081e89));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x021ec2506f2d21ae761939b78b7b3bc5ef3fd00547e2c4d070d0097d68919c35), uint256(0x1aba07c31741be7d9b94d37eae7f3b2f4515cef914d1e503f8aaea2eae9e0aa2));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x014eb041849d512cddbaf94adda2add995119345c1a09e90d39e211e8d81bc45), uint256(0x149592681e730283f5297ad9157d94a73860dd73230f82b882c8fd0354d2c7c1));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x16aefac92010e940890a08d84486b898c45f1f299c3dbbfa27be8dd95553fc88), uint256(0x144584af4774845ee9bf287eebd17925b1e8221dc36bfd02abe6f2a48454236c));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0c279c8aa07de3e33b98cae6f062c3d2dfa52ce3c783fccef979fda373007eda), uint256(0x084f1cb152b96411f2d037c6a7c833655e8c7e8430aa26e103a898e3a7aac220));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0af6f9b30d717832f976db5918081cf2d559dfd6ddf2db2ef806fdf3965c2a9e), uint256(0x1fbffc7b9c0f2b08d2d044d809fefef5ffea3520bcc0e60c2000215405ebafc9));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x18db15cbb0bbc93a7c7fcaf77e81226f8acb06fd76c6d1a0f6de620d5dce7015), uint256(0x21aedb002e590c1f6a05f90a4dca5de761d78a366b83fd31b017df378785b327));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x10e506f795b0934b59c046987b4e9307dd9dbff001970018348e8375ceed39ff), uint256(0x126b90274ec2343fa4a3487ff506412c6e6b039e3183facfa96fbac5e3024989));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x0d47a1ed18b2e03e21ba8a0b8156926a8dbfa512f3ad01a9fa93c188e69cc92e), uint256(0x06aece4dade9206c0a0b4cb8b2aee1bb0a58367252685ef443a5020c61d40609));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x072dc4330c2f2bce48528d44f9bf4c2d2cc8d517a03b359015821fcb68688281), uint256(0x01f675273358af10f1afb416e62a8fcc08dcaeef4db3293f0a48510b47bfbffe));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x21cfd385435ac5853f801086efeb8ce151191c6ccad5b796f6cf66115515d437), uint256(0x257d42419cae56d5fe821647bf712790996e4b054bca05c7493af505caffd931));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x017a8359627829d294a06ac2675e49d48a2088c1c0560ec8ad5c5fb88dabcf79), uint256(0x0321f66553911d744166d985529c251118b76569242e458c6bc8a3214cd2e8f5));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2be678bed1155d3c6224b02274e5b2f55370b9d3f86ccc6e0cc30a8ac0ece6fc), uint256(0x251ec8dc7dfae583809f1d3f70178d22de1ac6ae9bd3abcb2fd4c3c66d1e3a28));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0a3567017a7f047a5c1df644381d0067f2a6f14b7a074472ef41149f2e5e467b), uint256(0x177d2dc9bce846369be5408f80191ebb45415319bebded72c48bde18379ef8d2));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2e94bdd8d22892e0d43b281cbcc887e9d524cadfb9a2e74763b5eb51826e6645), uint256(0x0f4dea6551603ecf14dd7497d97952a503154c1bd6c52f491432154d8f28530d));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x2c970d22ec3797b5093a22031aa9cbdb94357a13fdfe08207315d9444070dad7), uint256(0x1bba1820ee19fdd641b1cb5a896fb42515dd2b80b08aeb8a567f64e7c9471d55));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x10a46aaae3734c19b012d472019068e4aa183b3cf413f9b987873b47e3140ef8), uint256(0x286a8885731ec4cab111e87677cda38266244d9b0bb6ff23a9687b843cf18145));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x20699cd3499829f9fa9669304d4ffa020903d7af8937342f866a18413b8d78bd), uint256(0x1394278a8271b9c200f57e6f179079d2762656e9c23cdcf3a319fdb22ca447a2));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x19471168233835d691a2df17c79c91a694a0f7a5448ee4c54536dfe5cfe6c08c), uint256(0x1290a51e971cf67bd154c38b5abf969c5d130d61f2fede4efc9c0a13440df523));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x2b1f5e945597bf17ca84545f0af01e047780d62746291e49022656b820c148fd), uint256(0x1c3c4a8e14ab406ada3348a6c0a2a49c7592238f11d8f4dba177bc81da6ebee0));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x04d98789a3141970f314b1c26579e893c5f63c5ccd32b0dd2682fe3ea35c5901), uint256(0x23b8b39bff9e0bb508184facd7bfbdbc223eaa7cbbbeb983d71941b2ab90088c));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x0d26974c6b171aab85e5d8e9a64e8ad5da896fa293d993cec3dc0f77971e6413), uint256(0x1a11a1528155c9b88363f72ed137906f5b4fabf473dcee8fa4570b26c44d32fe));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x056a4edc24df7538fda6a195cf8291c86e02a4778f8930fee29fddcf8d0872c0), uint256(0x2590809964ff8fad8dd65d96deee3d292216fbd3242a4cfc3147515f9e8cb4da));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x2035a97c53b9d196397e9dba44f0f72b4277580c334958403d73cff01d9911d8), uint256(0x19cc413c7cbcb4941ea4f1195b2c66a8b3cc6dd7ae0199b4250dc613b48d70a9));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1e0e815f00dd87203a776d3168cf93437bcc7e019a432bab5a2e59e519940a1d), uint256(0x12775e5f093718ad9882ce7c9a6742f7e9bdf76e761dc79ebb98b4ff7cb5ff22));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x1830fc0a3211eed7c4fac157fbfc1fb51d0a5f7f4d25269172f2c867b9abca5c), uint256(0x221a881d6d28f6cca994d24aaddf61d54f1b143969d1b87c9f56d409891deded));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2da3f1f820a2763ea551383229e168a59b4ce452b6646e4335527b2e0ad2bc1a), uint256(0x159f9824d31fcf1b25d8cfc540d1ae69a4417dc560851ee0981bfc762bb6da78));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x1bf2d5e8c11814116a722b502fa2f72a68abe04131966acde8741931df9b169e), uint256(0x28d36cfa185bc60dac7a43cb402e258307aa70fc3fc1785c87006df53a06ad56));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x2d9001e4785363d2c93bede2f0e301ff9f5148d2b4deda5b32153ac26f9118c9), uint256(0x244721e846267f1a6a3415fc63c8ee2b919b2a298e7bd5fb5b921e9ce294db1f));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x09c222cfbdc6ce1c489f11abcdfd419c8f2473877b45d016273cae1585c075e5), uint256(0x18a42ae8970387026a319647b0cf94bbc6cb94ac639bf398f91bf0e5368c224c));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0bad9f2b89306e97feb11b4e5ffba3f8f152bbbb77ef0a1a51cf375e70e9337b), uint256(0x1f18abc3e3bfccb4918288fb3cc660ffcfe244398feae5a8d7cfe9c8e72b2045));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x01e53ac5915441ae3cff1f82c36267f9332eb1bd25b1e11a2cd7bd2ef7a5f4f6), uint256(0x1b2b8ed86f1e3ff8324632830c427c8f48489522af980fb75df8e3f20da80801));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x008af733cbefaaf8700905033224091a5b881ba2f3cc1ad3269f251c5b15cafe), uint256(0x200e46318f949bf241db9cc6c75fc590012410b3f5b5091c174f37adf37177c8));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x16730db184d22f6fc46526fb2fe3a5bfe6a85e6f6189d6efb6fbb848ea10dc4e), uint256(0x1ff6701f1837ec22b13b2315f2c96358a1460938a58b4111b8bb43912601a06d));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x0cf28754f96499f7cae52bab990c8960539c33fdb846d026f441fa011e1e808f), uint256(0x2f870cfbf222780006ae610a3faf3bbf81f6a9e397f73e1e14b3d3bc461ae154));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x12cca116cf48e3eeccf12e47e5a2818651226f557c1807bfb6fb22e63dd5522f), uint256(0x2820996840b4298f3748d321fd26ea946acd6ec314b0ead22353161f234e0d6e));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x2a1c24d964cc0e8d2ef385b66a122d6cd60c71b215f996f91560b96639c999d1), uint256(0x28d561824be4d27d9832cbc6f8eb72e7ac07c50e7985641fc729dea62f29ea1d));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x018c1d947604f73a3e7b2ff42148e73e6500eb4a1534134e5f00f14852c3ccab), uint256(0x15aeba2b56c37970117e660fbfdb10b6794449cdb7661d9b98b1ae1dfa183254));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1f4694640012efb60466f7ca091fb5b53a1e468ac88472463e5e441d9122890b), uint256(0x169c6d5ab4f559a924bdfef6b9d147e29cde7ddfd910570f3629b85237040fe8));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1480b30c65e1e0e5fe547e7f5d3405b27be3d1846e265c1752aab5e0012750ee), uint256(0x099f1214360d9ee0439179f802da021fd19a408295f15c5f9aa9dee4ad7a140d));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x18c99aa55d680ecc4fa4b62bf423ff8513b8ff15bf99497d5c5acb6a5ef46458), uint256(0x2fe08568497730ad4367c8cbacf77260c2174d12927ed6e1f1ab65ce6338ecf1));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x06cc993c206b20b9df2d43bb8503e7c57df69ef0d39ece3e43ea1f089e2005be), uint256(0x249d21c7ff242e04991f2ffe8021dc47058fa596532d8b5e972646d9fb2c1dc7));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1ebb8457660126a82fd67fa203f8f86f203911a4200ac03ad3bf582c01c162bc), uint256(0x0c59042e4db9b7d5d67fee8a2dbd85d41b14b3f5d0435d3cbb04fa63a431447d));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x1fc26c1564bf1299d0dae85849fe8697cedca65fee8295ff082341de431b6f59), uint256(0x06f6ce7189526fb8b4131f8c3ddbf5c054f4dbbb3320501d81b9204f9d09e25a));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0e9f4e3f97e5edc47f89e4c32fffd51debaad90760fdca9b72b5130fc47c2ab6), uint256(0x22f552d29b986ff6b7f0f367d007724993d9d0f100ef646fe77d563caf5b8ac0));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x1f0ad52a877aeeb1b5a269ac786079d89981085bff6fea802a91e6e84e00a5c3), uint256(0x07dfc9ef0f25a08cb89a1e261aca26a84fb0c9ab02f12216ce4f544983d90f30));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x0c6e75e1e30989526bb8c09164baddafcd528f730e30745e0501fd1ebf89f6ff), uint256(0x10ab60b17f10e14210f751b5e52150fa0bb9a5c667240cb9a7d6ece8ef1e6ccb));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x093c2c9f540f51015913512d149a5adf76cd40498b5f5a57fcd10f77c6624d33), uint256(0x15a0c752a68472828c0d7b69e3b4e2ac65d6a520a3f5c831e3a4d5e5a00c613b));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1b819611866815f17539264d538024ea5abbd4dc30d057d8f217e3c26f15caf9), uint256(0x207f0424c4e17adc6b04541a6b83c6184fdf113cd2317fd6408b68dbd085d173));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x20b15395d15a7d11bb7af083478ba3013f0f71216c78ab0bcf39df6e2f54000d), uint256(0x1a077e5a24a1fdbe47d7f71f1545d5fbe66678247966e7d16188c42e3a3ab153));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x0ff324bc64f2d150b59e272859ad7d27b08976b6f0ea1079ba10c17690e538b4), uint256(0x28438815f59eaa3a6f405c0951707721778aacfae5b5f1a4b10f95c5a685e9a6));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x0f1960d1d590522e6778f4925b3b71c9225b8dd576dafb45520f69d914aefffb), uint256(0x1a35a2c9372370a32fb64ee40a7d4a2b96fc245fdf84d8419923941a53a6bc33));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1894aa46a303ffe41b9f650dbe2a798c3f426f0c35071a3e7ebd52e5ef856b6a), uint256(0x26118fd17995ffff5dbc5c570c2ca0a0c3371e5fe1b7a2225f3bd5491e1bdf7a));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x2187a748e714c75ced68fb347b1ccce80961c5e3942a227b4bea866f11243732), uint256(0x014985a2e72950f6b2294fba7de175101592539304b0967de4fd0e3e5a1cd683));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x153088bb67351f786f5157fc57cef048047b8f4d047466a118e7dbbe5d2bc5bd), uint256(0x1da8168c93dacd85296cb551fbca78b84cd63184dba1b9f19a889a0ba8f889e5));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x17102acee27d17e257c65f9e3bb5a1e72bc9068dd48939f3e43bab7b85b16b12), uint256(0x20b544dc5dd58a96e008480e5b83b5319103d78e01fd3fda06bba75258d14406));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x25db99c394fc07a1570fe61d4417e688a5d568c6d009ab6b4f3df0eab8c5810f), uint256(0x1d6292ab918e926ae0baed3f9f6faca32d4de36128301b09c7670d825751b5f6));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x29d607c7743c8da849bfcc91c9ab24a74a3db59cad9d8466f8c340b05c823850), uint256(0x1292c0452e882bce41b62e8bd3f1b12907312e836e16eca74f9f16a52b35be9d));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x1dc5d6ed250e94f324a08427735439ab1fdadb6aa70ddafc76e6f26cfedd1ca5), uint256(0x29d01fffbcb439b6fc3afa4bae57b99fb4729beb6b5b32a594b00c246ee6c1a0));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x29f3f84cce4d1a43440ce67efe81938e3d93f1fb1ab7ea4c5ee5b41a7ad49047), uint256(0x248f57c99bb3efdbcc1695bea4dc09dafd61f847a56795e70f09f7c1bc5d2cd4));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x1fbe0fdd7127057ac8fe62635f9b124f93f2f915f7a774a92ed7a508e203e459), uint256(0x2a9f529b75567b69c0c8002473be499f914021d334c7f9ef24d726369a52f36f));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x1da3d53584744fbfb98856a837e7bc673a32f42a81194ab5d59fcc87fa5e33b6), uint256(0x1883c1c5d5244b27f46a4ca8ae5725065c9189800352fd4b689cfe4cdb379944));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x1f5111b7d869acb80fc0b86bd6c8315234200340cdfe845d2305f3def83c4124), uint256(0x04ca6f062dd88a3342a7ebc1a0606443f1c6d58d889cf6fd68599bc42dd91fc9));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x02a0eda12fd9a3a7e3e9481013ed0c764e344cb0d13114f7dd8dc102a2a68c99), uint256(0x20c73b818dd6ceb876b926d71a175cc61cdd87161ec1dd6a595b401894a788ed));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x16bb938afb5754538f04b3e0a57a8657f11c9043f5da840c81b2f748fe3c7ddd), uint256(0x2ef4551476590d0a885b4e4357a2582fd65fc3e39f10a381400371d14b05bf96));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x2b6891f30616996270b621c11fe17cddfca9b2d5267eaf5e025eff81af413269), uint256(0x2e2520d8c7f9796fcb20352775ca550b3c837848529e22fde9b0817269a73aa2));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x18d05c829a2b3f815d6d61e910f2dfbf4991c1ea760f704418f9702e09e32df3), uint256(0x112b1e8f09bb467897a30b6dd47847d7b82ea3af3ebaa0f0cb69816a7c661e32));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x2b68ea973788b638c9c1b88825fa6ec7eb1da4b4fd9b13ad7f51c1a9c069ca4d), uint256(0x20518538982ba2be2dced6199ec1505a189ea37ea450d536d126e674957c0705));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x237efd5444e4e0bb43ffc24d24305dd71c7b2dc58cee2f42fc27c8de6235fe3f), uint256(0x10c5de50e09cecde83cc999522f30ae1d214beaad468ea089c0264a893eb8c59));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x27e9f7c6c90a6518f0686b6a8c52d85ec8efce6576d54f3c298fb06f0b6652ba), uint256(0x207499481fb8d45d2f313d976df32809ecb038ce4e8d745f54817b4f284ebd5b));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x289810094490ea116c2f242fcb283dca8356ebdd994f186bf6554d7f4aeffe8d), uint256(0x255e960fee0cc53a83ee21e61a9d8e010bcc237cfd3746c682d316ae4999d4ad));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x269da97482876de261104a9cde7a23e885b2554e5923b4bf06375caecc28c661), uint256(0x09da22dbb080825575a2606922820af96fbe6a977080ee52753deda34ac18457));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x1d0710fec4d2d5641b0318c629a5dbf5ef4fdd872cf817103a078b9eaddc1776), uint256(0x23f7d452a1e7bf42cb1658bb050d5cb43aa334abf41aa67683b9e666962703fb));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x11316c941601fbd0d547135dfa0b708688cf4193de19a0ec22a6ca6d15ab6d77), uint256(0x303046c2a78e31626f60db779d15866809bbf446d274761a4b89b13f467972fd));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2414776a37d177510c884dc31a14617f48dfd13d2054c7f318337fb4b6f6856c), uint256(0x152a755c19b60619be5a364f43f4a54f870dce5e1d137b4fe3bda455f35aac72));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x25b402d0fbdd462d78d37026a46466cd0827bfae703679acf90d5ab421879eb7), uint256(0x236abe1e0132cfa90470e8ad65e46de14b77c06732f62af63838f80dc203b3b5));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x13231e590a3d04b1839ba447d930bc3456c9174daf9df25241f2ee695beafea2), uint256(0x0bb179d225d6b7d1709fceb14e57ea9c2d60ed9d5d406237f2166fdd395bd7a9));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x096f23ca6eb779f2004c1745bf73179063479e2c1888a9a8cde1ad3fffefcaa7), uint256(0x0c671f0adeb8f1bf6c84c83109391b29c7f9ca8c04bbbd6d2eb2ed14ce0611c9));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x20240f4992a9a7d4803ce74dc05f9e948dd172e12c696f82937e2044c1f6e6d5), uint256(0x2bb42e200cc939d020eef0f7221ee2f467a2525dfcb5ca8adf10552852f6d4c0));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x10f6eefaaad5272df7a785e7bda501f7cc231b088e587e5a75f5be51d18d386b), uint256(0x19b41399a2111442b7503b77a609c0a9ecdaa1674d98c7d231901c320f5e4df9));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x04ef2365950a2837c7e86d8af8d9ca9fc685debf32ff64b468238d8bbef75bbd), uint256(0x2e01db10c7ecd970072a4df6414e15988bd004782d065010e654d65ead882c75));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x00a7e921a3e62d651a89866a1021bcfb2742c8134f61166b53dc053a63c7a26a), uint256(0x20ba95716666489274e6d646568c7ceef257bfd69ef4047959446642cdb8486c));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x0f58ab1a3c24391f7a9b217694b2ab7625f91700b8c8c88b49d650e00d4b5853), uint256(0x2194f51c8ae4d789ec24e7eba3ceb5ca321583b07b2b9bfd25a73a777886bc70));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x2f7510d6b2669ab06ad935227e1aa8fd769872645f1288df41396d3d746a78b3), uint256(0x11f339d088aa919b9a56cf198b5ea78cde8a2d7ade7435f0e63d93f6103b49ff));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1bd9d2f0f0a366947f9d7661d9fb0f651e856777fc64ca1d04cd6478aea5df95), uint256(0x1fd076bf4baff0e9bc6e8868b628ca7299d71201cce02da41bede82b4a057290));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x017702aae624740c071fd8530200daed8a5b8e3f195bc03513d6cc8c2b641f86), uint256(0x0c08f0e0c94c29f7778bc4e55c96f4ab3cb6818f1b2bd673c589020ee3be4280));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0a7aa18d77361ec35cf02e2bb8acf9c0d2d711ef427a22e9d9edcfc6cec1c11a), uint256(0x14fbbe8edab3fb070d645a32c511be20ced3ec3394845833a7b8eec849510f2b));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x13406d6364f8f3082fd59a9a4b1e137688ffa22aff97bfd9a322c2bc9c24758f), uint256(0x01b3cb40925a5ef6334eb904c2a362f5d4daf510b323819f1ac125a434698d28));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x1baf5f7217e6f391895ea87d995ace46f49eacf0154cd29e0e1833e7a9a3bfe2), uint256(0x12293dc94c84242d4ef18f10a82150597d3339ff57563761c35a0e716607c23d));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x128ec82f5fd3620f02bfc135370dcf69808e5021e05cc523b28b6491d33c4f32), uint256(0x0437c8607af9d9215a98eb33daa5f61b1d0033f68083a680a0a1e7fcba516971));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x2a64b54b883f3a289a4c86ecb713eb662f0561beac0c7382fc0c524f0780e173), uint256(0x26ad01d8dae873aa0172bb298f0b6c5a10efc6d317483217423facbb8a22713e));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x23e6c1255d7052fad9881705c237c16e07e5282be2c27d3a0ad4bc5ce42cbfde), uint256(0x1ea707e556ffc19bd8002d4a1fc6adcd87e56b272fbf56263e5822d57fa309bd));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x2a7a35ea73a6adf1a9319f063337566b718a70999d49911975632f1425309e64), uint256(0x1fd25ac96e4b7b48b778b488af65ea36196d880aeb04c59d9526a2ac615ebdee));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x02bf999abbe32a26cc805516e16d6bc60e8c2693ce1dde556829f03c5c7b8f42), uint256(0x026d181181ff7193d15bd0532a2bb21e350337a9588d2f3e24046a83891945e0));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x2313c8db8c0b2abfd103833ed653d23cf4a4a7c7e5f94c92f47c30faabbaae76), uint256(0x0963c2223e1699762669ecc59874604249f1610c0bd01b089b0e62560887f753));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x101bb4a3e2d98b6b16622110854749238a2800eec411bc4daa5333f5916f581f), uint256(0x028adbbdb75c0b044491a0833645988424e87b586f697897b5b47c1882c8c9a4));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x2dc547dc169657459aa5a9f5667bf642fa48497be035e8573ce4a3ecc583f9de), uint256(0x1baf5f05b3223ef46350d3f92601a40284460fc910bc2fd26718a1b180231da0));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x0ffbe02ea1f386fa8e771e5502cc6231b5fede035e110c08aae14797863ca65b), uint256(0x142684f05bc3cbdff7bed52efadfd62d59d0f6e594e20dcb257654f49486af5c));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x01e0387ba3bd03a2154d39de0e610b14a2d97ad17865be4b8169d583d6a62fa0), uint256(0x225946f129314813db9163e19c0d60d3657850fd68c1eb19290b12951185f443));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x27e4b122d84101c4b8932ff9411b25bc50ae3689b7758b3c5fbf38490730d154), uint256(0x1430ce776b96da6c555135a2eda6b5506a4ac5f28e6540136baa2358dbbcb7cf));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x093ba5fc2ecebebc3a657d6d049505e143c53fb46abb4524a2fd2ed1ddea0d02), uint256(0x2e4aacd671b920ec96020bbf51decb559d77a4781af4f814584fe21baadd434c));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x1a01d06d8bef93968f0bbcf97fd6a29c0a6b9576961f07d36c37f79cdd8b5418), uint256(0x0aa059482755be187a8d76d58efabfadcf84308e978957888ef474f2bde5b8c3));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x21bc49c5aa329c42c441514192aa8b3fa9d2969ebe8bc829fbf149104cf950a6), uint256(0x1673d601038dcfbae19610c802e043e1190e59ef366606d74e2fb43f041f7b18));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x123a74082442b991c1bf816faa922a46da2169c8820946c16c42cd0ddc14314f), uint256(0x02fe024d052ed87d063e52b11d0c185568f44b3e6c5cd0ff03449669cd679e38));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x135fd2937b4b58206606bb449cb2e60228857c67a98e16be4c18f834fd3fbd46), uint256(0x11162b71b11c6a3a6811f652fc5b5c36f27e55103f1c60f242196a383cc917a5));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x20b104c6e2450b278a3c87fd9717d6f31ad20917665da2a4affc02c80e06852f), uint256(0x218d9810859aae354d125cad3af743f7720743f941838787301968318829ad57));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x175c9f13d700fc2c251b5a90c09979143d8732362db9b15b80c39a134c566c93), uint256(0x0dbd4748b5a303934e321dabec2431691f9526b347caeaad3a238112e08f3963));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x17848b9e62c1fd0e7017d5002bb8e2b9e6906772dac0bde73b3da82baff0d662), uint256(0x03f2daf382339ac033731402da6093f33bfeb931b89175836ff53e21ebf4151f));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x11c7db07199be31262458bdc1c0f799a902354285db2c38905fec23f7195a3e6), uint256(0x182545daea2058f6a47a48aaa3ea892293e5059fca9b0897215b279eef61e232));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x2f23b3d223496f0cca6d0b9b20f6c67d377ebeb56bca2cf363530012e124d1fe), uint256(0x1187afcc3d44f3514b879fb301d092772b36598cac5c4680106aa102b4885437));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x0fbe498b141c527187988d80da945de0d1a3270b4945bf0670352bf7fde13c3e), uint256(0x09432f490556970c739e82f4b759f8d43693db5de5d2b35cd1a65be1fa2c1fcb));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x1afc1b5b25b61e705144217e4853e88c17257e33a29e604ec293c2bdaef9116f), uint256(0x2c56c4c23e1f8c007c587b3031d733a1b646b02dfa71e0983c55765233090560));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x228daf4efde0e45a69e0edcf16820e221a9f0b1209a310434d9b6bc338d6ce5b), uint256(0x1a7e970993171ae3286fb87618537b3a46992748b7ea3b7b64212b9b7c2807f5));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0cc47eb39e93651e822a680f762a15825dd6b37197bc9916a6b484b887b990e7), uint256(0x26afdef8984c598943b5dffab2c485fb9a368175554426dde67a07b68519c123));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x0da9c2daaf27fa292c6c75382a66bb754105b8333c1270ada08a4a825f02b4dd), uint256(0x1febecfcdc17dc0ba055caabcabf1e407faf642f95f84d498df6163268e22504));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x039a5cdd7197f50baad05b6c3dc4baf70f31aa7b0ce533a76b47882f02d51a5e), uint256(0x124637c58c83a37c7b3c39607d235e2319235a82f73df482c1ae54343b672eec));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x1861e870b873e7f0b408693821a8b7e407e00a5a1aa95cce4cce32a82c4193fc), uint256(0x1f02acf0ffd6425648ddf14746aebdfa67a5534594120dd5dbbeb664d76767c3));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x1718283bb9b9af933aecc83aca7a6b914a836eddb33b590167a9477fca59f8dc), uint256(0x1765ed262e8b9ebe876541acfa9a0d06c92f8e96a901f886d615fbe80ff209f8));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x11e1002bb52180a38780200d13321ff944426cddb97203e9dd4b8331a17549e6), uint256(0x2025ee27ef2ebead52eac2a54b60f15645611dc55dd4534f67c08885537daabe));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x1622400c66710405f0b5015acbc8671702786c9c03616c783a397dbf8d3815aa), uint256(0x12ad0129c0418ecfcbcd04ab8aeb6d85d72accc8c6ee827523afb4155ce317a6));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x11ef81853d8aa08756e8c4e949cf705217db7b163e8cbe5d53fb090365234a6e), uint256(0x239e4037fc2a7761bc9f3a4991b470e4136e16299145477d17b0fd1e260f5294));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x203cc7f56b102e0b66324b24ba3113c32182c0179524c6211209c17696f4ae36), uint256(0x075d88ad44509fda350a6e9fd8cecaf5d428b155d278c5a761dbaf221ae9ae06));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x25b31a3f6cac705f142ed8cf1416f9ad91e12bbb8d24a2629a54f0bbf21475d6), uint256(0x2e2f984bd9c43da912c3a9bd8f767b1f7bdb38d1507a5f9fb357c057eb7dd4ec));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x1bd5dc4e94efb683db3c6206c488e33f2bf496c66f75eeacfb3bfd656f57c048), uint256(0x038a155ec402d124cf1fb99714d4d2afd606cc3e2f9e68e60f328032bb0c4117));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x2ee0dd611bc42074751790bd2788e38b237ff1a0b14b87cda00e8311127bc9b2), uint256(0x08d920caa17f5e611b4bb37754906f26ce767b3f1803ce30df9de052dc0fd95c));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x29511c3871cef82bc20c1e0553588370d9dd53ae9d8b880138ac8ca2ef2c811a), uint256(0x118991159e0ef854972f0994d9e3faa60ea19950e82bbfb48cead46842ef85e6));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x0a1720e0420321aadf6c843408762d5878645f023297de69537abe70ea0707d4), uint256(0x15d6c3fb12a69aebc86665ffc5dadfbaee90b70f9046c370a4c874729f9806a0));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x2471e96c0fd55dc48c32a0546ed63f79163e89cc79808f6a3e856f555cb5d9bb), uint256(0x1eec9ceb2149d14602e5d9d4ea8fd2c37ed6bfdb5eb437d6069561d138c1b5ac));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x1a2f6d1d5682479784c88c03defef5124b04cd6d10fa1e5e415b10fb77443b27), uint256(0x2a5579d72dd102abb8e71e266a869912d7493309a3e27354c9d9a1cf3ee4f689));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x250b5af76cdcf5335bccad2ac3284e0f3d66da31018ee8460257cc70134c32d9), uint256(0x244548dc1149a8ff7c33ee8a8c7dd7d71d103ba95e6f0c85384cfd24a493537f));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x0cb75b9ca00485d0e6131d6bc50ec4bff17bfcbe52c0015b77479f7ea60c485f), uint256(0x1a80db26dc99ada5c3f7df024e83acd17c6573f8f0fcb631856376d45dbc9e46));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x12be6cd11bb74766ee2a64b5c68dbe2e0c1b77c3dfbb36bc78b67f72dd34dda1), uint256(0x02315abca03fb1ca0ca10f86574dac27e784a653f3db767cf0e020c42e1ed89c));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x0d35776acd3455feca14af764ae81c81c1a4e0ca116e2980ca5c2077da9b36a4), uint256(0x1eaceaee80b7dee963040323a7b71287764f5fee7ab5d5a01db5f9d0a39ab82a));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x2a80f423bf196d23e9e406f625a9e0a4baa0696379a7560104d237f8d5313f2a), uint256(0x1e40fe876ffb5b6f09291f125a15726415c6aa3a071453a28ecd2eed8f3e06a8));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0093174320fbe1380f6afe8b782c05f23c92ae6e05046f0a694a0551cef79b8e), uint256(0x15535c434fb695fca3daa88bad91b597a1aefcdf5b69080e34af3ddca00d1d3a));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x015c24773bdc09511a540118fed387e5899ae05c1cfeb5aa3287285f4eb4daa3), uint256(0x20f0b04e3d2d862a523248ef00bf0169a73025600c040e424e95dab47d658a35));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x0c9dc717d096cabeae850b862fc97e3e161eeb1bba00027eb45ad1a28335f500), uint256(0x0ff96840c810ba622464df7be51dfbaaa1be28be87004037b749d8f12de5f1d1));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x2730b5a4801cf8ca60519e861d852b57bdc3f6dcff89589094d12dc64e81cf72), uint256(0x1d1a95f5060fbe95b7e17848e7d1a61f9788fde356652ce7bc6ac823a14dd77a));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x2a591c4c7d17c8ca98961f6c3233dfa72ba036f20a21f7b57d5fb09d246817dd), uint256(0x09b60e9bfe279b8fd0875bc30aaf9349d168cb093bbea91b43178ceee4ab0248));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x27d0e6311c163ecdf0e4dbc65d6290ae72cddfae5a11008ec5df938a06165efb), uint256(0x063beb959bfe53a6fbdc4e10f30bef2a06c0995d64e42f1f0e590dfe5417e5c8));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x2844bc0ead1a132955be60a090ee37066a3c610dc8313587e0165b7678487de2), uint256(0x27e10b4dede05d78c6367217b1a2adb2d1fbe4a0a174e14e7820a4ba5ec55ecd));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x1cebc44ec32bd94ec5774beabba6de593447bc5763b23a96db7d01608b87d5e1), uint256(0x2d65f1d1eef2e86f65f7af09a87ff01256539d1d654abcb2c2b81118e2e6d28b));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x0124e36e0c06d4d306dc56248cf5b23a702208a80916ffc5b2a9c02341d4850e), uint256(0x202a6a895c3a223ba85393ac1d5e051db060cd0a4834f17a4c69d4490640ceb7));
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
