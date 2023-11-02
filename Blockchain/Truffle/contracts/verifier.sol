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
        vk.alpha = Pairing.G1Point(uint256(0x095f97c3552a710e7eb958d080b175287ca8f0a85a471be43d693e41eb56a208), uint256(0x2f7c3dfa8b0f113a716ef3bd2a5f70bfa056fb90d4d0a42b404ea19c032281b1));
        vk.beta = Pairing.G2Point([uint256(0x1afffe1c71e0c85e4ba2dcd5253dd9c533be6107174ad4e3ac5b02ef017660ac), uint256(0x0df6b10bdd40ac292ab3e799dc32160005a92092dccf9a778f05e0ffe4b85d5f)], [uint256(0x2905b7cf992c71ae18be0790161746e8bc31504c09f1928d2f6e26ab6ea74bac), uint256(0x0fa00db626804c5c8a53cefa5069ea1bf1c82feb46390941af730529f9aea37a)]);
        vk.gamma = Pairing.G2Point([uint256(0x07d66829ce0f96648d6a540771d2c9e7d86e7f44d32961917d1870de23559bb1), uint256(0x23c43a7e7b2d768282986a85d8738107a0a6363f7c17ab6095a26c3632c561cf)], [uint256(0x1943f9ba4df360c3c3d2e2bb19ffca76f870e66895ff3804aa86790340788e0d), uint256(0x07bc64ca057d0216e9110478457c12b5c674be8a3a7228c61fb2a348700a518d)]);
        vk.delta = Pairing.G2Point([uint256(0x181302bb024687465a076dc9273ceb788229699ef7fc6864b0da7457a86949df), uint256(0x0d510ea6ad17db6801e25df365a15aecaae6cea0c71a44f0dfb99dc2157bf55c)], [uint256(0x15a4d4475af695c92ff80b0f064a045cca2fe36675ff2ae663a5599ad6f75686), uint256(0x198f65cbd26fe0370cd886974466cf3aa33a08a59a2b34e4541e635de26333cc)]);
        vk.gamma_abc = new Pairing.G1Point[](184);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x03da28ed072fb9f8acbc52d49eb10e8786d466a25926bfc28117530b65b214d7), uint256(0x0cc8c6700a2043c4ac22f7814f8c6052b554a496dfe561630b094a1cf1f2082d));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x07f56bab9f48c4f684814ad6ba53f8417f287020edfc36c3ecdeae584c7c67af), uint256(0x1ec3abe6dcdbeda5733fa21f713bee99aca3d0185b3beb22f79e0170317e327d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2c88dbf48e81547e86327c99dd431995ad327a3bdddfe8cc15f925d567d9237e), uint256(0x13478da3cfae59ff58370544e9cd050edeece008342c7bd40af72d12f90fb52d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x02269588b3a1e2468baf109d00421b4aef0a25cda6ff0c5d0ceab01be274bab6), uint256(0x1cd2cb56355e27779b27e16ecbffb6386b731dadbee3b8de74ada685ed80b202));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x28e0fa60f5ba3388ecc4c9840d2571263768f4e44fd8bb331caeae07f511ba5b), uint256(0x24487dc25e85ed616f5031a198f924aee04f4462eab123398701057caec6c165));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0ef4a445e320be54cf34c6cbc7921a7dde9aa5a84dcfe7254919fe88de198001), uint256(0x1c0c4d12e53c95510d628ef0630c5f7d7b836fcb56621295bb2758b2ab874f42));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2bb7dec9ce7db6100db040bda1c9ca3f215ce948c2844fa280c02e040fe300f3), uint256(0x1f72ef8917ff12118cfda923b186961f79cc76138c14a7b6ec2b65b8bf8ae0b9));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1899c5a59d27c99d083e1ca8a5728f3cf764977770920892c2330b3e98db26af), uint256(0x301a720f71df02c12697aabe185209e5810441e2c4bba819d2a941f25e5779a5));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x16ecacd0fee6e59d5a894cec09e99823bc5bfea539e7887957bd0c23c6738f8f), uint256(0x2d0bfcce1a9f74516f8abfe3aee86ea6a33f5409b416562719e8ac4c3b966186));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2bd75769a31c18f6cb24e0a976bcaa6e9cdc70fcc1c41a0890909991a85d5455), uint256(0x2406f94f6079f7fa330c340fc5ca781248a947c009655c4a3aa57cc442b48257));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2d96e45ea4e6b7b2c8135260f30c754fe08fdaaf8279d46834667796c24cc043), uint256(0x0e04de9536df425c6debe4ca090c18023e796d80086aa5951035ab281dec2865));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x006e62f302b8d06def6e5402bee0d60e550bcb9ca3bc79a13eea53fd4961917f), uint256(0x2d2b56385740fc9ff88b3007f4e5d696a1be38beb75cefe1aefb554816de1acb));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x184a48586b44ce1eb738a21eafc6a790463978e262a830d9a9e68848794f25d8), uint256(0x1bb61c89a56f53fc05b733910d5a9e511a5d040ebe2bee98cf43213dac4b8753));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0f044a9af759c56eb2110b5f221d55c441562dccbb0b660922bc357f886bbc07), uint256(0x1ecfe4796828d6b33c440c826adabb4f0abfd53345cdd74e3c142fc201df3aa4));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0830dc06a30c6e81938c6a54cea70dabe39a4437ed97680836115028538821c7), uint256(0x14444d2959fc7a0aeaf65b6e6856736e152bbf6562efdff77e51bb3118b5d1f8));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x09edb2482244a89a64bc52076b3738cfb6c1a91e5e63184d2f9a5dcb3696faa0), uint256(0x17541abe2fad2c56a6e5febf9412a895ced70effde5a3acbdfd80b8a497d2092));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x22beb282429fdec2b56d20b194f704e823311a56b153f05ef84284e0248617dc), uint256(0x2b8ac5b624e0fbe264b73f7beb32b7a18fa14576bad3dec8059377820636e5a4));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1b3fcab72ccb338a88419854b782eeabf6a3d13b860960534e61a96303963515), uint256(0x23cd12c2ecde1e4298e0e68d90fb8c70d7e9f15f17c24e08013e380120427fb6));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x246aa7ef5a2730c4d1ba9c457aac12d03ba6b3efff3ef8db57cd769339ae60dd), uint256(0x257c468cbc069c12b3e2fbcce4f66b4308745d9cbafad450b7b275e1cf4efe5e));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x19d1e7df04f774062e441091bbbad20d43c71b2cacbcf8f0f3238b6eba4ad0b6), uint256(0x1a039ca5d947bec6e98d5915e75719b18337478ab94e718592c4105e244ffccc));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x15234b7718694e362f5d590105c1776e9b037748bfd2f596c97d9a470250e0a3), uint256(0x2e43dbc32dff55b7d0fb14311d70d6464e20d3d966777911152d9b249f450458));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1c2ea3c86e20c5027818c2d7a9947c5221d776d5957ab2dab8cdd94e48e28d1a), uint256(0x189d65b6f19d4b89019d03837123af64dc953169afed78e476b991485084f0c8));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0a6e632c7fc5f304d275b7db4d8e118df628b00e5afa97041968d4881615efe1), uint256(0x0e1ce8c814900889ede9940bf6af3f4fdcb7cdf6765b3807847471fe670bb425));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2fd8b692c539e0602b968925cc531d0697c0ace4d31e08621999b662f20f0abc), uint256(0x23b6fe20a14a2338a525042660a3841705cb50e191c473fa647b2a5360f51d74));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2ccb1b13009cddf5c9a47917980fa34465015d0eda7703f674676996b1d9aa39), uint256(0x1e995ffdf9f0785dcfce2e214d8ddeb620046d0adf777f4ca08038c3e1460fa1));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x12d7bb1f8604251453a46119c3c6c25b3ff95edb3bbd22b9addd3a229a405d82), uint256(0x197926877095b5e87c2d1f20f31c18190e9333bca2afedb49f53383a414ef18d));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x27d832c6baef4277ec982e20752f131c2d7afac6b9efeadb5ea64cda52587916), uint256(0x02cad5827548d89a0470de1b7d1b37df2a534092832e64fecf4662c70a2ba0ba));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x009986fea52aa648aa9a266d27ee4023fa1047184d233b962c39c84dbb0b0dc6), uint256(0x00d2c9fc8a274083ee7d038770fd078e200c71e76af5dc4aa21240c049f328b7));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x26e5d6e2e672c26f00301a79d29ba6b43d3a015446d5fbd87c8030385d2dafa8), uint256(0x0d989c7111b70140ea53248a60394bd3f12de11b50025fe416c6ca461fa45ab0));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x101ccee579f1369b837c1ab67d87ac4239e933629c0103dcd166591a1309328e), uint256(0x2495bd8cac2a7813948e0178fea52d0727c256280939d099a261154750185aa8));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x23ccaa6471ca6fae18bfc72ac5b3c15f50653fa179ed6e981b579e5e04a1fc4c), uint256(0x014069c8d09fb341a673ba9b7d1862b511470ee709a06686447f785abacf2869));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1a100cea0aba8234454f3849c0d57f5f2815ef79cc1cd4f9dcc64f702ab60166), uint256(0x0a8dfd4daf6302bd6fcb35e3aa097c33b19779ad6968f13424c2da45e176329c));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x13d9690aa7e44b1c27f141967587334731bab3cc5cd978182817e2a6f428b392), uint256(0x208a625a8a4266d83e44d98295b60202ce5b7b13c21ff241ed4b7cb6dd5c5947));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x064c067e515f8a42a454df35cc46c2a99c311167fbca7bfbe07e73b552b13cac), uint256(0x273c5fdaff4c4da7e9311cc9e6505d490aa4dd631ba0f2c64a7a4b1632d94fd4));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x088a6e28aef13a0e60abacd8b97917ab9ae9c27a4d26a6ae44a50123171b9ab8), uint256(0x1dcb2107f688b79a936f6fcb321d073d789226bd6a7f456955ecbd4fd848e6d3));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1e6175b0eb9f2e30b3b362c4aef78f674b758a9c483cf899c9a0e72a1561e386), uint256(0x2e59b2b84479f92bebf08b1e822cdfc73117e2b8815b60292af64ddbdb53862f));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x2298e6a3e41517894d43f6fc5a02b1d674bd0940f4d8fca0a6144fcdd83c6753), uint256(0x0ef0c75dff1d15f7f52641aee2ffa233602804a32f44d1a4e744dbec643ce37d));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2cf5bfc03d68466ad203d6ddfb5077a246792eda4166475d75ebd9f43e073fdb), uint256(0x1b6c11c241d696ddd8950898a1fc9c39814a9118d155b328e2d30fd00b0b58eb));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x21b8dc601a6895168f74c32ec4d13b6ab6dd725cdfeb1c741381c870d91088b5), uint256(0x0109861a53492158e73cb9bbbba10f03443a3413990daef16b8020909d241be1));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x25dc13e1660ba8bb23d48bf53a4ac5fafe5939c178972c3249e81d1fc67e9fc7), uint256(0x107d0bbc2d618208311b7e49c5cc2ff58ef98fdeb91944860e262e7ee68675ca));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1c1a7b4ec6c524e01e7af8e85ead1744af69a33c6b2bf221e3cb8837b044fe2c), uint256(0x2686ec291dbf1a47c73444b4c322fc7982b66c6536ee11f51f3700bdf421575b));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x11f04fc1c66add13d6c5b1cc6efeb50e18e0c062c2c26f3e630ceee1b7a8c031), uint256(0x2b38c7d3d55a835dc9afc283202225b72b6bb88df96b68240072aadcb757fa0c));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0eefc8bc6737516c85e41c69df29fd0bd0062081846d65653e9cb2113bb039de), uint256(0x105b5a54b91ab10077fb807528a0be9f085339f9658e2d33b6f649402c59e7bb));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1c435ea6907f2df747f5feaf928a1ed8068715eecfdc19d0d73ae471fbd3ed28), uint256(0x1ec304b620fd9d9cb999de0d2d6d02168ac914ef9c82c32231fdfb7795d42112));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x10c3126f1a8b2c7bfdbba3d3486ea004d1e92032fbe5a3beab2fcf86e923667b), uint256(0x0c69efe1b7736660fc00fa01500e34bc031e4ac2d8788578efad0f968991acbe));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x13bc257c1c1dfb87ebed801bb413c7ea7f6c6ebc9141e52a9ad4c3a1dec388a0), uint256(0x300f4780d7f7c3fbd85d2a27e1643466a274d768e64298015b919900a616eb78));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x000a4d4bc8b6eec6ff1d4a60e434b9bf23af7454fde1c6f8e9176072b49f30ab), uint256(0x2a2ff8f071810b222772edadd376039b833d88518b6f40642e3ae1fb94081b5d));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1522dc529b17c98994d4ca679bdae50f6f95207f660c3d59171c3e62fe0d8532), uint256(0x0b7582c13843dbbab38b78384d682b03e07c30847a8173950f12b4e65e92ea18));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x2eafa26c7f6d6ecb400d2d9aef72ef1faea42d5af36c86eaa87e06ed640eff81), uint256(0x0ab84965eabe6ae6fe577f5585935d0992ac17884cdf75c2a2a5114db6f33e35));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0c717cfcebff9e0593bd9125fefac4c53085c397a6e675b608b8dba409679aae), uint256(0x2dafd6e3673af1b3db3d24db2af2299cf31b87afc0218e4e5cc7fa45e92a307c));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x0b192341a237ba9827c3fea36d396797638766d944bb59b5100694bd0ed004c9), uint256(0x2a6cd39500d40f8509abd28b5cd0349ff058db682197d2d2ae990779b7adcb2b));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x0a38fcc049b755710dc39f01bbf54d5a0de1c0267277d91cc20e7155ad5105c4), uint256(0x01bf2f549f4e4458ed49390ae7050489b9a213e827aded1fde1904dc1b79bb5b));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1ac6a3043641b6970a2ea3996754cfaf9d2c7bb10cb5185eab6d04f92699a76c), uint256(0x05f6e2f8384458129ac537650b0fbc6d7b17c926056f6d73d0e3da56c5906ed5));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1f638a5ae1e114cc006cc0b9e02947088ab5083d29df984d7d6609d96266f4af), uint256(0x041b62416c2a0ed2a83ef1ec5de8071cfbfdcdeaa83667ab328e2565db642d1c));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2e80bee2dc6d3c9a3a7e655b26a0a329e36cabe62a211680d0ba590e6dd682bc), uint256(0x0cdbc8c542e4fab00dc1c72798bca8bb7ff2df565b6b4c88a28426aa5e1d936c));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x043cfcb5ce652eb703f482b347d14fd58fb197a0fd693dedcddf82a5993b8f6a), uint256(0x11b4fd8258185d1023867c76c37662d9dc683a560388792a54077c1ba76751b9));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x07e5130bcd3d20dc8371153ec7b359dfb59309f4348436b239634ebe1381c9e8), uint256(0x078fc6e4dc272fd192c4089c4210955e75c70eec527bccb6051d039ef68ef3b2));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1c97d8f0412d31a1718d940f6875573361f12efdfb5756835a6ebdb4153e5a8f), uint256(0x0ca143a73284f8847e3c35090705655fdb877317518650e40fd04f83aea98f6b));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x248a5e12760c6f0135986074e15f502b34ed4f1730cc1528ffbab528abb41968), uint256(0x011ecd23f9bb0c253f1326256ae5153954994f0dd17f16ae98f87de7b07b3185));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x24bb18c7c4e20aeb42253e3c29f838a6ae0de5f309d175e82f15e842ccb55c57), uint256(0x15d84ecbc5eedb2c1872c43e259f623c758fa615c7fdaf0b8d2f2338a89818b0));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x23e42f6e3d3acff4a86cbebb635bf1a68619b8abb705ae982d4db78b14bd24cc), uint256(0x1ddf9e1326322503a7b41fc0b65ab803a5eb42f2fa03a35498e259436d98e30c));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2f4d2c06b3ac30cc66914fe411a6e57bd1a3b5c97c6f16b5b1bcc3d8b422f892), uint256(0x2d5a57f1d76e2a03c928014d4140385ce8ff7e59cc736040d2ea9360562d8ee7));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x28655df5e91602f70dffc9a6949cbb2902ee75b8f397baa786cd8c6406dbf914), uint256(0x0a98232a8db54c7320c8d71875a64bf336a991b445394424f33c7920180c6284));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x0146c49952bb3d247a386942fe1a440b38d240ac955dc5c1cf53fcb3f698b5f7), uint256(0x0bce9533e2b7600af7cee9b401b9c377788b38a783aec7c1fe0b2c30e1fdb6b9));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x09f01b314dff88c516956a7610bcd740efa39454c8c43e17d18b901b272e62a1), uint256(0x0c041c4312c5c7b4fad56635eac5108586cbb069aeed3a08b6c66b9c45f0324e));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0c4c4ce81938b839d3a5895e493e0fb1710e0f5afdb84741d569a0b4aa01ae41), uint256(0x23d8e9e953c2b7bca477ece585dff67152a860f735cc72d533a807c4f7041ebd));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x0ca9b78e4fe6be1d8fd2587c3a92fc8cc68a49650a21ce9bd806b0a89ed14118), uint256(0x0030b0309f9999523f1bc00bd6b3965a9d0b51f58c6375ddf5d251548ae8c383));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x008365e9b5f77be235878e9172049d8584e80323c4b637a3c49e6e888ca2f8c1), uint256(0x003fdeb518fe7eeee0e40773c4ce5217775c7f32e945e1ddd9646cfaebab738f));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x17f3a96595899af976842a1499452e37eebd3c5e4ee2c73cc914c93b7888d956), uint256(0x07a87d551b4123778845eb15bbedfb63aa1f8b2286f01a47799656be3fd3caac));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1e4656948e06bed0dea48df69c10893aa473e5326c10a6b4d8a7a6e140f2d4ee), uint256(0x11ed7fdcfad4096323f92b15854722824b0aa6b8d2e13baecd05f1e8ec92fbb7));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2ab0e0ab4ec31bc0f60a94c8137ec07c0b721545127fd5bb236f5887a36c4d8e), uint256(0x282d41620bc7b51e506e9d38ac8a14cf5c1100a949ed0d7cea93ed6076b257dd));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x140aaacf1f749cd4c9e695502144e68da770943fe0d855284e917ce9a66848b4), uint256(0x04ee8aa55e8d947da8b4c735b8aacfccb7e24d7bb54d1f3754ab94977e07410d));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x04f91831d2733907912fdaa607b244303dc2a1ddb77c43ed8a85d79848c6f643), uint256(0x0b72be5100519da406f1473e0e20e234f7560fd392c3d12dc6441f689b38f9ce));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0a898dfc700cfc375e6912d472e83307a886dc6d8065519167ace84cf0664c4e), uint256(0x14b38ad4615f7e9c636e993824a517f0eefd164733720d70aa18ebef4319cba2));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x004d00aa48fcf04a94037477f6b1eb2566c4b902876bd3507ef2c765f6a5a6b6), uint256(0x02121e287b2d8a6912a731c94738d86005f200013cccc5cfc7a5deae0e7fff5d));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x2fec996a732aefa92b4b052b7be46533dc846f46a4b91f64cdfc94e6a40daa91), uint256(0x0ee968bbe36e7e077729984d192e592d42eb51f1a41a6fee019cbea306c81086));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x1fcd9b49e14a3d5815a35e584e236892ee345c8d34cfca7627f979a6ab67177c), uint256(0x26ff1ec5314c15fa4a1efdf0a11ea39e8168fdc6cfa09806653f3f7e249f2695));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x17676799f60c66a3d1484e8057f5fa0399795d18c919c840fecf58596d1bed0d), uint256(0x1b5a20ca36f4fbc541cff608a28d31423b20bb48ba7c4e57947e589e0e2ab985));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x083fad03caf84aaf9d77b526b9fc8244a2b866aa54748e47987ea7df8ebd80c8), uint256(0x171fd0f8c16e0e3bdd403d25cf2421c0ad7b236a842bfbdd1235ebebf4e6accd));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x16e33c989742123c79f13ea2230bddf642f5d9d7171c742b22faa62af41df777), uint256(0x2c84950ce6b236ffbd6712327dcb426ea991f9e301a36650a61e2bf89646eda1));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x20393c667624a611e90bc71e86caeb540099f556d7689941ad01abc5e2bda48d), uint256(0x25d5e097f82fd2f8eb4644f67e8f722d596a3b4a88b9032c20123b267b507846));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x0157faf2a8b8019ea8d977f1dde3b28a7d576bf85fdbf2ebcb5b56a861768c06), uint256(0x1bcdf87d566ed24e56bec5192b4ff8b376289f69ae8addb8484f3c08615faf17));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x13ba81931649e25d554032b23d9bb8d40b5f56cab1e64a78411ff38431484333), uint256(0x04964f59823192b5772da9b42cd9164e9bd4455ffe41dac3d2e7ecedcc3075ad));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x21d3cb835e2002d8c1da1675b604bfd8233db2289bf549a0daa94cb5d0626b94), uint256(0x25c54401262169459fd3f7682386d58b055cde679bfaaeff51e5a26644c0b0bc));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x171726b070c2a1e9d17c122d60dc782a40856596c439e050e64bc4da736d30dd), uint256(0x208de297b4450e25e2eda91a9bca58b2b5310ad3fe7e744f9438e4a6e8a283ae));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1c810914ba5f72a93a31d428f0f91045b4b54c22f03bfad7fd4e136d2faa2863), uint256(0x1c5b6a2ff206279a46d6ff410b4fd920b3cb54bb3f3a78787b176598acdccfdb));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x042b3a99ee5fe770149e0aa77898754ac7fb6aa2fbf16c39320aa5824598ffdf), uint256(0x1ddacbe3179092929f38a4e7d2455bb71d6868fb29a64ee7296d85ca7ce0cde2));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x286e30742409b7eb6cfb3da4a6a52d2f82e7447b249e70b3c98edf36cbf31e8a), uint256(0x117ce4551c5134d0c27ae0dd143d27863ddfcc477374764c49baa25bb8ec0636));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x06bf63a7d4599e291e7a5a118df69d1368d92f42dd644e1ff8818f34ea602ad5), uint256(0x09db6aba39da0d2a08328807f3c909da842d969b5da2463a46e554286c5efc9a));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x0b4a17ec40ec04c615e5d38f1d95bd0838ac1764d400c48ba2ae317ee0d6476a), uint256(0x0e1a53596ee88032fead1289c1096927620bdfb8d1c421fb2313e37d11566988));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x1da5fda72f9db3aeee051b2efbf3d2bd195eb28337e439cb8d788be615d4d1bc), uint256(0x19ca3acc3d57210fc7e0ea6bab3ff1161cdceb21100fe76bffcde4289df732a2));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x0351337abd08c701f1a3276c9efabdfe5c637c5f8274a240011de046914e90df), uint256(0x0eae587801e32db1aec9e9133d01bc3d2642b0f3a17bca16954d987ce7362227));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x0ed45e2b5cf7a3c6d7d7f21ecd5dda05949bd560ae5ac8b59f44a7f792a3b663), uint256(0x1801bf439bfd06cf5b5ef5e6a351dfba05d8d401338dbde054e9fb4c433a70f7));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1feea99574d6c82bb25d1ab752adcb5ec4d7212ce78bfd5e6e266cf1da4fd60a), uint256(0x1ef1b109e79f3a1502ec685b9fe1e18b9a61a04878fc04a00056d80359690fa4));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x031db7d5f713052da3e56db9b4f9b7d30edc8cd79f8048d1dcfa5df407942062), uint256(0x30318bcfba293710bc1b8fa6c84985cc9bc451844b11eccf399e3af1f7a65e3a));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x063b3dd34825d80b1401ccaa37d4144ba6fe057aeccf5d4f0869b6fd350c0f15), uint256(0x170ada0670768105bc952c69b67f34db252522456b09c8cb65d9da51ee0b3785));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x0d5e57638c99de2295b76ef9ca674094d3caf28f78b68379c026cd485c8ed35b), uint256(0x00a9934bcaec65ae75d4cc0704ffcd8acf1317ceecd3dccc39640d53f394dff8));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x14b1275c40b27046f8f51137fba746d878dfafb15feef811696aced0cce668f6), uint256(0x21eb4956f4daa8ea59fa9a4fe9cd38ec88e86513ae4fd15c9f4c859ea4933e6c));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x2028ebc9fb2caccfca450b7d96c5fdb916ee4cd6d3bc1dca8b0588df26db7fc9), uint256(0x2a00e3faa472a42f77eda864bdb5ba56991273be866aefed4897ca8951244a5d));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x030def76804618ff021bc9e3f9aa856e2cecf8d20efa695ffd40c5c05b7a24ac), uint256(0x0cde4f1487095af1c0567f3ffcee9f0a12dc93f1ebc72b2aaa902eea0bdfce9c));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x24004662df9d59935f37fde67012860e4d81e058b503da15fe599ed38103c053), uint256(0x134f2808dbd19f30686f04323b2c593d6f25ea2ca6f46799ecacced510ddd1ce));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1409cd78f41b61705709e4081a8515a5b24ed2222f3b88b79ea5e8b4e51b2e4c), uint256(0x1d4d02c6bff460345e204cc078f5dc110628e2cdb1098a749f4dbae9beb91c5c));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x159cd2d0a8799662d2159c84a03e6174a5b6228b8cfc64dbb92d09aecc23be96), uint256(0x009227782628a888f4135041781f49a392c9231ce2f883ba8749565374656a95));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0ef5314218e66a8db370ec30fe058fb8b538836350676a4de395eaa0ad5d7212), uint256(0x00fe82ce15c2e051c40a5ea55897c0e5f24428d8de0e7b6ff9dc996761a93912));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x0b673cbc77a4792a9b0bc874c2b3af33fbf28225d3a6c71da570bbe041211c66), uint256(0x18cc8eb1e560619bfdc858d8668e71ee9a58cb5dc4d202b9086cb4d837f24c1b));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x123c593d5694713b4a71cbcc06df8e6a8da457ef7e4b4a753c682c3601481b42), uint256(0x1a2394840dad32bbedb7cc1d438ccdb26582c79511ece72e5e00ed4e677c937b));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1ed682272b7693348a79ab19e919a050796fc6c1b067e85428ecc6ff3599941b), uint256(0x037842f8b310b77681f078a69397ec5f182419fc435b323ee758ec7fb3912093));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x18165ca8333d4b2318e95e10cfc4c635cb8162da2c9b54bbac0afc8f0ec1c2fb), uint256(0x30100c8ed4e439bd703d96e63944fa4f225527b277a6fcf0754b2025e26abebe));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x1f2762ea96dba60ac10dc3a3267009e3d55f29b20532000a9122eee006c95e38), uint256(0x2c1ad119362bf71dd6e61ad0c341d979cde82f0f2688eb2f7edd9c4860bbd934));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x21a375ae6bf33172ec7690dd6e3ad95bfeca26907ad83ca58f27df2df8673585), uint256(0x0092131a86c877ced1c40472ac1ea09ed53422c293b2180c5ada5f4145040c6b));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x0313a2cfef8db778c663503e227c1c7faf13d6f53ab9ebeb5bf17189346a4adb), uint256(0x0c356656e9d357a4f4edeccc16bb8249fb3c70c370e6d0e19d898a78535c7432));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x2219b53d1184d87199d3d43099875f14d3b3d0069aa5e84708d8fdfe5dba385c), uint256(0x2bb8e247a5a7cecb101338a464b04ca9d6e53390c9febf6a0d836dee92cc4e60));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0c01a7d92ae80137d145cd7f08923531a619d7c6378ef127e89915eabad89c2e), uint256(0x053bcb2f897a85bbc902b1a25b26729f8fa9797f1a33b70fd4d2e791c017db73));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x2d9f136b0f0315e2a546cc8bde6952b0a6b60c5fcafffc18a1c42eeddf46506c), uint256(0x0c440588788eae48023c6669b42941dc850e8cb77f8c0d6daf0d4fab496b3898));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0d033ed18fe5d60521ea073d2692ae305823a752fcce7b54d2c4a9e4c58c55aa), uint256(0x1d6ee9f269df401a16293bf1c5be95ecb9f20a5d1c6f7d86581fc918bb769122));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1d54ab4cf0726b68c4feb079d3d598a3e42b8be543bd7b965727c697dcef6a2f), uint256(0x052d25460496378933ded742ebd4a1d9a141a3b7a6920638be7b6624e8d15298));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x028e4d851abb4563e9929a14a7154409153284e954f749670fbc4c78f56c3fd3), uint256(0x2f57ef047caef79fbf2c278af2f052737096e3b13c02956ffcc7f1ed08f4d977));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x1f4e7e42a9368bb831524757b0e57ec7323a3d82649dc6748f50fbdc11562264), uint256(0x28291588e228bbbd96614fe0cc9a3d542cd846eb38e670f367e9ca5a3fa138c9));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2caf8724e9cf7a8b18bf82d09f9251181cc4b695410792ee7b830b9d35771577), uint256(0x1778ed73bf84da12482fb6c374141a9df345c0580863206c4fa0f3a6d8eaeaaf));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x103b7b197f311f5abc88c1424303ec5fb4e6ad280653c782ac0315c46ccc45c8), uint256(0x0b964b1b105076ef2f44ef521232a99da0e4f0ccdbd6811e3ea9cf309e83c134));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x2f7325d73ca2649b1b8d9cd6339c89eb46ffea571c89fe9d30461d8002a2eb31), uint256(0x0965a0643bea06be70bbe7783a46aba9c6b2e5f49756820d0b47b5695753217b));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x0e2da5091cb62c6ebd2e58668b5e57e62f0d86857c4d7e78fe50b90e24b2a1c3), uint256(0x2c69b2788c30a1d7d9a718ed328d67c1484665ad1cc546937cee35ee2b9e99fe));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0f1ec9a272e18a5600110086b792a8e9c5e8b983dbd7e3f06d608e4c681a245b), uint256(0x113fefe803d8814848ead4b3cf8743373718c72473ab96ed23849281157b5738));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x2a537d90292a0d7b030c5df86970e24b96b9d737c7ec4ba7d7a3b4e19eff9cbd), uint256(0x0d887150a2c679cd9292ff51a75d74cebc7e6f665a334b4825f487eb04996cc6));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x1c2f1b9cb4633929ad65f851cd9f264f67d19fa030a1d0e421502f4c80e685f2), uint256(0x188479152be829141994703edac348ce5f51c998821e8a46d3128376f9b1a776));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x2797d58b16bdc8e60a42fcd658b050cfdd48cb8abb5fd442ceaa941ae15753e3), uint256(0x032b30500f0f0398b92f788e63cca4f19107a823d08113428cd48cf2a305b1bd));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x302205c051876c55390b95ae29351792fffd3e9d64f56f2a9c9048b14f9fa0be), uint256(0x264a53df91ddb34bb535b021f4400ce5f8c7ef995aa8e8fb5a5e0d4d7ff82ad1));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x20240caed411cbb98dfc6b1d7e71e37139890780b6116ca071d579cede0bbb59), uint256(0x2cde50496d52607b5a9734ad94fa3363b3af4be1ed9aca02f0f965c2a7d1ea58));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x0f9d955d6b78572ba97de126fdef861708a1f1f16ab227778440ad0b63c743bf), uint256(0x0331ce960318d0052b1780cf2a7ead706665769c067a9d90e70e18f7ee5454ff));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x14d920053ae606febce3fcda6ebf5b57fc1d3a91fdd538eb578810f7acab9f1a), uint256(0x073e656fc69173dee7ba7d0018996be0b9bd8512e25395bb654136fab94b011f));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x1a4f9230a3fa2209b4b9e942fabbfce49bc8fffe7e6bb75a59ea32fe3cf04114), uint256(0x10ea4afa64e8619b32b2c9e33dffa8d2888be4a27ef8b41db01d33fc5add395c));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x0e6dce8eb9f8eeb19e8229c68003672506e553f2962c47263c2067b7a14b6292), uint256(0x2d2fcf0497ec86db50b1358bf2d61464d5606ed5265c6888bfe4253c7273996e));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x043ef2be0ad7b818e20bdc8c914d222638f983ab2626275c10910b6130d2a851), uint256(0x2a7adc8050fb174561eb7d1aba4eaaf0a34a077b00229e78cb2f2907515e07c3));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x077e9705115e66adadf56c7a5ab8daa97acdd754babd0ed136db1309d6448a6a), uint256(0x281d8b25930c0149078cf026a2915d505631920b8100c8c6f006e0b58d4013d5));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x2c0aee96f533e7a25cb7f100d6908b30300edc6cd78c7c4a00f1b14b804e498c), uint256(0x241aeed0fd5f7bcaccfba9ffe55dc0fc39621bd7fd3e753a905ef40a15c9c34f));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x2a8264ab0f78bf1b5f8821bfc2c28d8402d241455396f3b2cd466f06fa2dd839), uint256(0x2ab2aacbb5c4fb6b8809c68a7ab8e31778a621ee178a25d372f2f33a6a7441fa));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x0aac816f37aa2e659c54d099c46918b838a81ca0ce3bae8dce8b9c920fd7e83b), uint256(0x2833cbad1b5b244b3d023060edf997d7e7aa49543712e80fe4286336f77361fd));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x19c22e778e829513a80aaeebec8d2785c9e8d3cfa8a532107b3a4e06c8c1730a), uint256(0x24cff2d40b7cbf058488708e29129a87c60fa6d8b6e95376f33fedefb7cee5d8));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0a2c12072aeba1a400ac8ae4d03e4b21c6e0496d79b2221e5aa72db9dd0594aa), uint256(0x1a22b85b3288785048cf50462af557cc85758f5a2e716fc030331ebae577d441));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x20d1babb11ad0f304d65b2f71cfdc6ccdd7101fd1e8fc67c2c4a33cc1576aa1d), uint256(0x2a2854ab2c09e5143f87f9f0bc4eb5b7fb475608ac221c5e0ac3afbb04a1bd9a));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x06cd356ad2d471f7e9ae69814fe7057d01e631587681d0280358adc2f4e84291), uint256(0x10bc51805ce15e9f2d7b9136fd10d1adda25eb632ee7a26a49c0f1b3078da86f));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x0326be42f56b1095378508753dd381166daff5fb88a83464635a54dd7ffd5e4a), uint256(0x055d6dec1b13ecdb62f4f7a0abfe55212586e1c5bc7baf943f3fdd7ba01bc8cd));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x0e9925619385d0eaef50625553a611543bbf65877eeccb1d5b15edf0cec4cd6b), uint256(0x1fc0fc159c5ef210870c8a5e51127059f42706f6ff01cb6c5dda4911b5e39a4c));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x260d0bd0b0cca3f99cf1cea1dc18d7dbbd81331e6d7385f7165df659460d0122), uint256(0x2da084601d1408a16fcd560e7fb66a512b922936f099f277127af4870a815a9c));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x1983d69ad87468cd1fc68d0afc5f0643dabe52fd429a9e29a33461d644f2196f), uint256(0x099650d00ad2f37bea5e19ded7094aa322ee15e5d3f9c3c5abeb78a6e4dbb3b7));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x05d1d9b17c6ded8a78f592f148d7ee8882aaeda5f787c6e077ade72ce27062ab), uint256(0x260c1a0b3664411c278edfbc835cb27e884ed2c02fc6429a23dc8997fee4fc74));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2e941cfdd05bed365596b51cb792abe775551b7d25a13e386fdb5c3a4873c875), uint256(0x20c3ef4ad5266a2aff7001e326eff4d0a7687cc459fc02658f72ae2067e36f53));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1a673c47dd2b111c4ef9597191532505132b0a36c2f8d84f60758bcc2b89119c), uint256(0x1a87a25643d957f3115594c14a178ea7a7440e6fdb5b1c6e6207ffe02fe093b5));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x18e344888b52084f7d8ef46539c7ccd4b369828c0aea4579e6e1bad492702fd9), uint256(0x1374ce9ec8aed1fcbf9e1bcdb52f2de1d78beaa3aff85777431fcf0844989b8d));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x0133e77b9cdf863b8b0f2269c720c327af805bf7278a887897667f998ef92828), uint256(0x2962b3097e10cf0682b6699c69048620010bf53815c4c2a301a0a1cec8c303b6));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x06b499997e3ffda8e6f4e461c53314f0204c7df9695fe91084125ebf6dad7198), uint256(0x2c6c948563a1d69b266bbad79eb581c6de0de3a7e3441f4a62d577148b086134));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x2d9a7b82b24ae12f6e79d03b18d172b7e341278e408c1b5319e996946106b3ff), uint256(0x182f97c80ca8940003cd54ff465b33c7d517faa2fdaec7a540bf20118d80285d));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x2228420ae8fed46171c18d4ff4645a0bb51d27bbbebbd8b3921775a5a79c9efc), uint256(0x04b5687730de62acefb61c5c20556a21d77ef22f9ba814e32ea8fb466821c78d));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x042ad5b1d7ff8be2aeb97d92f7b15661963d5bcc3a1969b686e162959560b9c4), uint256(0x072055524029f3114810bebf400f6e1bde9ab91d751e500580b46e31ac4384ca));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x23db478abd66754a1196d6b4b7228cc499dcbb7d6184b19178d016f7481cfa93), uint256(0x0b8115c6494e7cbefafdd3bbf5603f495f20c95968a98df2823dbc9426c5be46));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x1c37996d4a1b8ca2f2404e13e8cf488bfe914d8798983364619a7a5e652f1e1d), uint256(0x06d7a237039f6fd0f0c47e9ba4b20b31c1327ae4f86c5c8194d3022229ff2c31));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x045808c8931c4fb16e8650f6a6037af862956071bca077e60ced9867fc3ff5ba), uint256(0x26642109d83e042d59fe3a7b65579c601244e7d264de233b47af16f52edc279b));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x2449db685b331f559a30c22ea6b74b53b7b97314ee8d5596c49013f1d835be90), uint256(0x26f2187770f01ad07eea029424f77f310c1deef5d5feaee0ec8c56e8a3259edc));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x1095863720318630a916faa12b87488404e5037ffb71f632b64ee8a157b1dc4f), uint256(0x0bdd9683446ae0c56a6beae70f37fd94810295641b8f997c4a6d737db888e889));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x20376b9e95a4b73744df62a2f6353d96b26714c4803e4acf812e4908ea2fd1c1), uint256(0x098c8bbbb52bddaf50c2265eb0efce7ae8e1701600d766b992daf4d42cda85db));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0c5863e3cc10a57832a37f81b46e32ec88be2cee6bee137069387dd2a9faf118), uint256(0x0c99a58646cf6ef45559c0bcce8a496376103d8dcbc1c8bef0e92148d689d3b5));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x0098058eb3bac846d798a54a1a11061f11706a6dc3a1f167adc3e6ce526ed4b4), uint256(0x29beef7814a0ce85b0192cf15c51cecc6ca7604ead209140a9060ee02bee939f));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x08702df2acd9c1bccc9416510eaf2ccad8b5bcce84b99a2d5c524772445b7b32), uint256(0x04d783ce670da9a6d8a339b8162412491d9c4b58045c4ef61a814c14a485417e));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x2a24ebacc9c818fd45af17f23e2c54c345d11893d6d8416175ee3a1f9dbe04dd), uint256(0x127f5cee5aab462deb600cd3f4552b480eeec90c69b07be69aff964fdbc69486));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x120f0b8f5271d31017ed1627966781551bc67e40edce588dac542f1b2edce42f), uint256(0x18d56cb7cd04db9c444d018791438d799fc384078e580ab83edf8ddc74209b14));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x12952ee000f4c1f4d0d5c7d5d12ed5e15db4b481dc27f2af97e48f05e8ddde27), uint256(0x17d5dd51314ac9af79941becff563dd2f25c7c35d81120c420381277df6ef7b4));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x26b420a68410d722273b76705bae9bcb159e6c0988a4a1538a50b5dbb1529b61), uint256(0x235653d6ba1c0bcd74d6c9cf1665f89bf59e583e596a56a1d5b0f5c78113ff79));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x24f1d828b509514c3459674b2e9c92c2e63042c6c1beb1ff4313ab398c007bb4), uint256(0x0c49d8921e37c092682a1706bfe0fa19a0f1587cdf4e44d32bb184f979f6dadd));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x2d81b5b725ed5eb397568974a4fa189f4d5d2d5c08898561e8e7ad8ccb68001e), uint256(0x249ce46486a0b56402110f2d4c7904dcc7feb55d29c48b4e6028a124395f4cf5));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x26efe8538d99b8d7b1d879d9db7480366a8d1b3c8ca76d293de8bafadd6e216d), uint256(0x16c732ead7f9864fd9099891304648ed1af5e998e2c63cc1d9325517cff3cb32));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x119978b35a7b4ac301b52d35aa537799fab2a9b3aaaabe94ace610f8042fd7ba), uint256(0x28291d5d1100964c2d888a8052d010dcdf76816eb0c23f608d73a25ea61fd88d));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x21aaa8506992197d37930bd3fbdb6688e60f02b361ba13e974bbb25ce018ed05), uint256(0x148cb3cbd508813c114d9010744315007c9a4ba0d81cd9a6b1aefb6009d69115));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x2fff95b1770fac704817fab37029b694863326a1b6c18e55eb5f8c4abf3686a1), uint256(0x298f48d11216c4e7f44ec02c750c8b1fa56ad0591e723caa3b1525fd94d352e3));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x20b366bdc96dbc7c0f991f09d77a1dcd8f766457a31cec305026b9df94dc6d19), uint256(0x265348b3f49643c2bc1a058fbf0e27a5dda0862c359195fef505e0ce265fba63));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x29ef8713fffc1d8dccf99c078db0ddf7e19dff66c0bf0204979085e3021fd8d2), uint256(0x086b04222601656efdb618c12268ea3311cda74d74e14dce84a961166bdcc85f));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x0a7e0c69b33cddf7df3b3281f7aef41de6f21127017ea671533b80a2265f7a6e), uint256(0x202a2cf39cf47c940d01a6a24c86ef1e857fedad4e69e7079113dd5878390781));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x18440f32b06b4d10fadebcc68488b40b0412178732c363fb913433ca559f8be2), uint256(0x2fcb81db0621fdc3b03d97bed31ff193a174215808c8c6014b0f488dcd9457fd));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x023c38cbe00ba18db1673f3a2c74ca1c4012eb3476c2b027c69773af37568b20), uint256(0x04e5ed7c9a77825bf429d4dd6837efb529139bbc47589e7c14e8ce6d812bb1af));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x1140e467c3724e2a3e94e1be0c04c88098cf18c36064891d0de9d9295e534850), uint256(0x0f30a4dda863dac063e97f497b21e36e3d6ab35c826b020e8a17f34a564bb296));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x01f88c3d6d1df9a0a60c87daab000e7ed78300e982e101d6988bd091d01e9caa), uint256(0x0d25802d7f037df6d3f627892de4f1d1afda0f57c0a4429655e5ffbcfb5ab3fd));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0d6a784efc9e1955cf2c03f38e5ac04cefbf978cdb95e065b94574cac3e4aee7), uint256(0x1400cf12d167f8605a6aab5411f0f69b8fa3237610e88468e0997d47af0b6f8d));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x2dfa6bf18ef3fdeea3e9804cf8532faeb7294026c04651df146335218f4bae51), uint256(0x1c628360421a389e5c7b60021c105a8b8b03c5d266b190019db233216cdff0ba));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x2ddf7f6a289e576ac4ae8db01d9d3260db93e536bdd749ff120af8285aeb3a22), uint256(0x1edc945d22fd19d021e2ae6d9692824c2f76fee4b1d9e0dc8ab7127ae98dd91b));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x264b9b5a49f9ae802d0a985b3081270ef132dfcfdeb517294a4c4120959a8ca5), uint256(0x010b2d171d572cba36d3521f23b5490d7e172ae0a31345c7d6f702bda9facbcb));
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
            Proof memory proof, uint[183] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](183);
        
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
