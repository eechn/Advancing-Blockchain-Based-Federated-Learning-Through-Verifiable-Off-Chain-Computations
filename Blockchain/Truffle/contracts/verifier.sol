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
        vk.alpha = Pairing.G1Point(uint256(0x2abe75ae64f790cf09eb8e0558dee6cf979031b6b4869f4593db9116b4897f2d), uint256(0x25d45743a624164dc5fd917acc616dbb399b1fefb8402518c9b09a325aa04682));
        vk.beta = Pairing.G2Point([uint256(0x079074587365453f6366f2ed8313d9d7ef5f8c3c07b406f05510f6dcb0e130f8), uint256(0x13212d2a13dc764ef52432ba592e302bdf1e1eff60e80e8aa9740ac511e13edc)], [uint256(0x1a96aa235d584be69cd04805a926d554f17a933092d37669374cad9c6280fecb), uint256(0x070f2369e9076021a87cca3d0df8ff1150c1d6b87b3239b3042fd7d2984ea66e)]);
        vk.gamma = Pairing.G2Point([uint256(0x092a35d7c6aec30ffe60158fc8ee0db77f89e3cfde40c0e44c25235a00593407), uint256(0x2ca52416f2f8c47761adabaf624c154e1d1ea397a026a70bca69e5b21048b78c)], [uint256(0x072ba5ee7385b55ec4044d442316e2c769f5b3a3e5bd75b8148a516dabed49b6), uint256(0x01ef126bb2648ef866bdcc99d69e7ee18d345d9eefd1bae569197fa6eb45706c)]);
        vk.delta = Pairing.G2Point([uint256(0x1f900da8112e85c7fdb8edf6c33062144420fa8ff1b7a5f9bbfc1777e24db819), uint256(0x07c4b5139957ab89b813f42290d2e22fac599dfc8f11251fe648e2dd87ae5d84)], [uint256(0x02dc2cc260d50a0a7ed638bca106e975f6fe6d66384ae2e29e8c5f5ca0b1d020), uint256(0x13f872fe811381992de9d56b806bffb986ba86ce3f95f0b69f5585871605bcc7)]);
        vk.gamma_abc = new Pairing.G1Point[](202);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x072fd4221a1cca90ce96ed573f92f36fd75373acc70124fdd96cac010c4472aa), uint256(0x297558b8eb39eee965f6dfebe8a18597b5b0e4fe6401141d4e7672b7f4202b5e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1f28a88a33e033e966fbbfcf44932aa0e741c8e058093edabcd61683c1dc8c1c), uint256(0x1aed5d748c42df1f34ae26eb20747125b0d1a86b2fc493f483d72297a076df8a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x123aff2e4301f318d8da09de5fc443fd492333c5dd2e4d5f9067deb92d5991ac), uint256(0x266507248f0982e601e6aeea5072a846dcd0c75a46122f2ff2d27dd147da67aa));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x17dfab993d98e78390774df9c6bdbdc0e135b599e8b4be91c8b77c60bad7b01c), uint256(0x07e5f6b50f16ffb15ce082bd6bcc549a20416feabb3d333cf59a7459c7176605));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2c15fe76882b8b9be532fa40737e352bc97ec496068fa027c7f8f316811f4546), uint256(0x29206c520954bc2dac7db974773b7b5ba08f9c94a92fea159310ef7c49a3bfec));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2f7e8407376270e39c2fee0420c158f15b44b3471e1af3c4f87d01422447f40c), uint256(0x1c0f605ad5bf1f48b294c0ff517ff0adb9f85bcb823618fd60aa5d76fa903adb));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x30250c3448418d66c9b208e0491af5026b7d28447c6e6d997576c048382a6bb5), uint256(0x0633910e39e6c3a492c10be3ba1579605f0c99e060b1ef25a695606503e46ffb));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2005492f3c68dad7503185bcf3e93861e5e81558a96144ac922ab12dae51c63a), uint256(0x2c0719af688c0780fc73ea04d243a7492475350ca01d174ea48fb462ee0f9cfa));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0c72e5167986c80cad332f1fc3e2cea451a2e3ece73101220533895b3be35ef3), uint256(0x0617f585ad1304d04166bc89c77cad08f2afdf14f73b10f99e02645db812cd2d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1e2f9b4d400953b09e8cb781e2a265b459ddd240511619a230c16bef53169ef0), uint256(0x028c111daaddd06dba6503ee3e9422809b6007e66bcc83658894c41923fadbb4));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x15364da5e10d6e84733c3acebd2acb53b485b6188de81a61f6af99ec38eff239), uint256(0x1092727e6cb632de9e65992ce7df26610444cbcec947c8cf98ee75b444f3e63c));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2278756a12f3383ac1bf3a18119cc03ca638658d7faded3fdf8053dea2af96fc), uint256(0x18cc5acd275cc800bce293a8d11c1b681388534a574bcbcfb6242f55bf67ebfb));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x280b2de6dac12b4372232f9546cf3547ebbd6fabb60fffecd81120b000d4ea79), uint256(0x207f59e67e5c3098225647fa90d7d5e493245acf0269eb9824f3ec26abf4d0c3));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0843425e174a13a6e58168f7fdec0067882ead38a12886be133e35832aafe3df), uint256(0x252c8400e4efb13d1b2351a0859add5699921b03c3cf928f97ccc456159925cf));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x13175a913acd0006e36e6076deea7fec78a79c3844225e838c8b1caa699cbcbc), uint256(0x0b17084e8122daca10a1c327c8bf4669aa46889b08af0a2155cee1c42d3b48f6));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1550caf7c59bc3c4e366e7d16d8e4787ea234e7333b31e3304188b90ecb5239c), uint256(0x1dc4b3636f1be9acea55e3804e0815ea4b598faedf1f6f8908e45e1946d98f89));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1d0ae7cea2ca64c1e6de016d823a1292f59d0122a381805a066ad8b34ceac7cf), uint256(0x15881d25fdf6fc5352b1891561f71a881edd716b5ba3cfc7f97d5b4005dd7019));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0f7d9b753030290ad792a3b188c1db8c7115d6edb1f1db1032ac7cd9e3d72f4a), uint256(0x2d5a9b8bc42ed61d5c7b2b743be1b916a42b634bd60bdde24602cde298bc47e2));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x22eb7653916373ff4844b96da4e41025ebbce45114c04fb29dba57e00d3999d7), uint256(0x0900dfd24803cfce986c4fd591981d047106a7665eea56c1b624e973889b7da8));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1f198d1c2e100c1d49c919e7876d11ce733e65eb194aae8026a175600175dbd2), uint256(0x03c34aa13fc3e0ebc6f8cf3222a9204709ab31524e47d6a850acf009e2f329ad));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2d2f05808aba96d31d7f0cc7d27f8c0e7528756f7dce8b83b160e4d0b99f055a), uint256(0x20004e6929e67e6e5b02f086ae1dbc5a47991efd2469345925051d7c8f29691c));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0b75debd3740659501243992d52fb54e4cf4da14af3a878b5c60bef9e4d02e54), uint256(0x2ad7c028a408a9c1ac2ee1ed4c686f0526161b53838c9513497a7944118328fd));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x12cd03f602f5308cb9271d8337a316e0d1722fb3a248f8c9934ffb434c537def), uint256(0x141a33eaac5c74857d26a70a94fc50ccb599fe1ccfffd8ebd9ff7def4b8d7cab));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x260ea2d5d8e7edd2f564888994db0e70079980937dd750cad99de451f1c98825), uint256(0x1745f82336fe23b38888e5a107bd35d33bebe9b556d16c355fe41b3b8aab8550));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0901f1b23ae63614cb3ced428442e4562d4e67d53d0c9654255fd170fd1cfecd), uint256(0x10c86161a573ba39229c1a0e8ae34a536f482c23407ea0773ce8b8851bf01da1));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2c750d04f24b699cd377a8ff06e36540110a70c2202cd644ba36104f6a904ea8), uint256(0x0964878390513499cbc7f7424b4320f6e8e23d2f496efe9a5b9cee0ca2cb511b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1faa8945efcce9d4a82619da3b858a2c5325436fdfad97df0331c2a50c60fb24), uint256(0x2cdac92a660f6a51b29bc2de3985292788a633ca9bcd15aa69342c6d26522144));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x00c56ee5d4b1096eda09ac30becb7993503f6ddc32e236e6f2f89b83daa49192), uint256(0x1d71ee25e3eb9080171c5a57778cf580deba90fd658f84bd42c5888a783892fb));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2fd185ae23fe42aa8452ef6e083d1af64cb9c444b87a8fab6b8574cbe370bb61), uint256(0x20f4a0e3d63e5447cb303d4e3acd3d0f50c0a3443e387ecd2c5c70226a2ce826));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1023ed44327b13a885de491383c72f0cb4ff5efed352f724f1f2f12c373a075b), uint256(0x1ec811c051c9e256ab07053b690b1274d73432d93e1b81667298fb685f7881f8));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x2dedf5429aaa23543b510dc3b97a6618bb0304387707297c49627902514588fd), uint256(0x023d52476b47ef39ab8b0f16e32785daa6d980227a65a5657b92966a89cc0e7d));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x22d5fd61284c66c013f4ccc711c34ba4fea76437da148a308200779c1b2f7da6), uint256(0x2d70a22069290e39ff34d2b4576994da7d71de9b9bbba7024a1dc052c3346b96));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1e35349cb2f7d10947025c75144de9d149868eb17cce4a21b94d6183101af7a8), uint256(0x2a92ea2cd8f77cdc6e8c894bcc544cd820dfe582c754966f1225f096b38c2194));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0cdc53f695f43f506aa1f4dcedcecc1761ecb3f4768670767be56d3ae31c5c92), uint256(0x2d5ad08752ea2f437686e0d4381cb7730a9477d854655bb96aa330dbf7080229));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x037b878e7ab32a1a32158797618ee03b5e3f45a1a3cb7657844017cee9eb2d44), uint256(0x03e6bc8ab2ad691ec41c0cd2facdc8f54f68deaea8250a99248c4c05ae0897ab));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x14b27d4816e2dc3dd5bef824d404f6b1832fecbdd1f5ad67d483d5e548989fa1), uint256(0x166bde5cbaba4312200730cd1c7d753b2479e9df4583b5f81f548b6dad4f8688));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x04850641fb90487f4863bccf60498802c59df0ad1577f28b9720a45e0d073474), uint256(0x24c40a6ec3ce7eb5af4df0d0a6d249b5089304475f756c313365fd183ab1f1b8));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x182ba20716f1216d5458798383ee351a544adf85dc55099a4addafdccd4f9c20), uint256(0x0b5da0bec0310a92ba787fb36ec91d236b22eab2b6c202b25f62871aa12da448));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x25b249c5a022b1c5d3d906961ac32d30a86e53761b1ad4e6479993fff1d62118), uint256(0x1eb2a8f9b8c58825580d807ef0bdd77669fbd0c6bdda32026d8220c751055366));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2d85b2b488cc4e8623cd01ef71bef014fb1d582e86cb396ee7d61ace04ecaff7), uint256(0x24f5de7f2dcbe26d808cc0479cb581de06cca83cf634043f11b73614c80b1c84));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x269b817afa8eb6db5357c13496576c12cdfb1b91e715ab18715f8d6c9262f93c), uint256(0x20b0bf6142692460c7f1e57c6f768587595c13421be199cbdb18c845e9757d96));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0ac259d8118cd1a89fc9dd72459d55275b5771ff37f2f2bf1e379fdc6eda43cd), uint256(0x0f7a284e10f5edd364375ff503f13453e48ff6ebc6aabcd0c9c5560d9d598105));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1824feaddac46db87fbc7e4a08d4a0bf5b74331e2a5e30dc1defc858d967340f), uint256(0x1c23ad7f26c808d0569e07ec8d8a3c30fc845e319b842d7c4d52bb03baf910fa));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0b7f5f05f8009ab03f2a9df95925edfa6454418c7149be8cb080dbfabf8e4869), uint256(0x1fae39d6ac1f4923ff250e5c44b63546471169f216071e58f3ba57787c60dec9));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x185785bab27020de086550a05baf4bd5f05f459209904f9bfbe736eff2900ece), uint256(0x0852d8d3eaa6ddca083c3bb499077e2988494d49400ceffead4455a480f27790));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2bdcfc0a9403be527a818786e0dd55669bb4533332c71cd111c70741cca8e3b3), uint256(0x2f05976811c5d9f63bb2a375b88e645eeb4b5d1c01e89556806632e986089d84));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0b39f57cf9e222d76cf78fbeac78e02f96f1d4d0feec29c2cb9e457d346a7d18), uint256(0x107f3dd3d0465e1660830e1412eb5ca25eae10471e4917214e217c340b6bbd2d));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1f529985934c07977ca9527149eac75b6eea4e7f9de40666eccad9398a5bf7aa), uint256(0x2d86ada4b1122ac88987255802f0a8d22d5e66ad77a02a4c432a1529d650453c));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x07a40de29226a1f54bcdb283aa2d287c1c2363505b3100c6b3b7d7fabcdc0cb0), uint256(0x059ac82eb9b687d474adc07fdebcd32abc3e8bdee9403ba7c830ff622b54c264));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1d6ba061a2b41eb09a680f4618a4b14a54251db480cd7aa46becd26497660f09), uint256(0x225b338cfe502a8d8d6764097102bc789696cccff9a6dce649a8975aa50d4207));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2ce8707bfb675c9af4a42419c11736d70adaea0c98ded18d01b32d5cef446407), uint256(0x1f937b8a232c2be61e48204283bd9660a6102a570ff0cd583bd12a77c1c45d7a));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x21b2bda62b0325b156a4930c98b5876c87bd938745745aae81e3f56f1f7192e1), uint256(0x0bea57172d2f0b7d404a1e05cf7c1ad2cfb746932dc9976767fc33a67f956315));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x15497147cb8057ef18e89267df8a35fdd4ca34e08e1e6253d64e991606e2ca8b), uint256(0x0999477cccfc4c02f469e30dfa9eb421bfce0fc21239149cecf31a46cdd8ffb4));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1f98502fc11912cb94a8f098537c6dc6f94880e1ed2083257d55f1e57579bd1b), uint256(0x0251fa60d4b3fb838da22ae1ea1b99b41bb114c18c8a767016d9fa5d5bfefe16));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x286dfa7a9f20457ba474281cbc6df47adbddcdb24b082d214e2feb8eb9dc763b), uint256(0x1b9c0d28fdd1ca92de9a656592669909bc30096232ea86b2cee38f5949e7a8b8));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x091e68e559bba4e2833dc5615dcc8767eff3af0674832b0c3bc71ec821e24d1e), uint256(0x20fe4096f40ab81c51b16bda935400ff62db5504ad1de261d0f070a106767801));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x13def61e9d59bafecb1a6e529502172068cbfa45845d521c4c3c00cc1cd501a9), uint256(0x1a5839e7ba074b308bd69a460b67fca3081284db7aabd43566c228294d56bd0b));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x1936214954bf0d7beb744910822059b05235ea17e24e22501da1eaedfabb1a49), uint256(0x117194b28adef16be9debdc3fa5d1b9d5e88ca894ce026760a6cf5fabe9cfab5));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x02855c550d56e5286deca7a875e457d7004675a54479c3ba8576236bf7b4f597), uint256(0x14b0734b37799431340bbbcafe543be036e58488e38b1e6432466310091259b8));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0652dc05fe41da8570a76a37c01a091566da434d730c0e5a38b444f8944d6c75), uint256(0x161266d41727814550a58809da4a9f5194aa4c95324a9c3057f5e03f9eaf1422));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x10dac1f0aa7088c2254e097a38c094547b5840da81e0d3e6e30be7d025a67d53), uint256(0x145b625487aeafde4585f3438d210dc6b696192e85837c5bfa7dabe4eca08df9));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x257787e80caa4f18a17690f4a015c44d2923803707ee1168daf9673a5eae9648), uint256(0x14f24a1f0411486c33f884ff40b4512e48c521ae3630db713c74f17beeda2307));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2f54ee6171f6965bc3a462f74ee91ff7dae918cb6bdae507bfdfc1e225354ed5), uint256(0x1b66afffca499fe5fb4fae0f2f2cd227b79e07b836aec774d8a96a10d5be2121));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x24e665a3cdf5453a34ae3860921875bdb9020617e32729193c042d713dd3668e), uint256(0x2ebdf0f7a1391a2be622304659f14d4c525f1063aeb0afc7329a006d52fc76d1));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x0fe685d7dd31d878c6e8bec5c59cb2fa56d6fd4dd7c90872b1e569d0c63db120), uint256(0x044cba65751b32abfecf0bb6f3b977d2ee76e9c7670fb2a6f5abff5c15aa9d45));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2041a8115ce90687d9b037a98c476215366af7d6f1a84eb263f02c11139cca0f), uint256(0x2126b2e3218b0c2caaa6c51e1b0a71d16fea019af0d9b4ae70453dfc03db6327));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x0bde1d2fc7a9de47fb0cfe05e263760f88cc90a165499391e4d4e109e64d8307), uint256(0x0d6afa0820c495904d05ff476766776d96886817c1d8e74c25f4b7039df53818));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1b4c5faffde90d30b939921a90e4fffa40e41e0904433a03e69ad9c7f1cde698), uint256(0x297740ed59525d6ee34a93a2517fd570ba6017f4eaa055c531c3a547774e1382));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2c058b9303baa6cc1b08ab38fdf6bc3eeb0eee77bb7f426d6ed77cb69f56a9e4), uint256(0x279379c2ef4fae51c8d4cec674fb95fb05ecbbdbdb77627f879f6ac25cb34ee3));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x0d5958757597890ffb02d840f2a8b65ce534ec769372dc2984098c971bd3b907), uint256(0x2797f8b9dc5baf26739b2a84342d4e289c3668e34d15a5409995ee80c942fdd9));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x1e567f5dc8094d7c2ff4cc5da3a9350a4d266a6d9cddbfbbe068a3a0fc0d8c6a), uint256(0x212c51b12b7bd8bf17262b0f47df61b520819eb22f658439f00ca27a79d1879c));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x16acd144e0c4426c2c7a2f5b8ade14177bc9396a35b3e676fc81bf54d8243986), uint256(0x1e4e6c472f58dd392e7ea75a3574b5db080e996638db1daec8d839b2cde0809b));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0de7811cde363c7673e1c3e0fbead1b5c945598feb7333d0082dad91946a66f8), uint256(0x0e2e7490c37aa15e123391caeb37f291b6f2d6adf444cfab893ceb5dfea92c42));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x1f029dbde19401ea30a1094296fbec2d428cfd53ea706637eafc4cbc190e9eb1), uint256(0x1457830d4acdc5b6a5f747e518f5c9f3f1bcb7e14aea3e22ede9377d5e9e5123));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x09b4c659bf0fdba2522dde85eb577396ffce6782fe3625efa53a05a0175f8698), uint256(0x027b926003fd7e74ea40e385aaa36d40c3374bcecc549639d5237c48b7455046));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x10cba92c306cd37294bd46b6e9f16b0b4f793f5441c6db9027100efefe829a78), uint256(0x0eb5fa212792ca09a3e7e6d05ec6eee5564697e970c389abb1eaceb7bc880049));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x25216ab5e7ee8d7039d012e06560b93b90f68aff6a02e4a32e49cbdfa561c4bb), uint256(0x09d5df952d3847c45727ef15622aa128c35b5280c06193177369d04531b018f2));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0fb9164a77f0cfbde9da363f0d5b563830a9c498ba8e0e0ee300ae91ea285583), uint256(0x2e2abf5c8666f32a980f5b55bd61dd7836ab17d4859db611fc6eb721dbc7f0f6));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x090a0a6239652aa0f7a4ef0ec79636a33b83777333c4965fe65307848d27f0a6), uint256(0x29ce9abdf0ce052668db50f7ef21ccb0c79068e2aea88849c1a1fc44a94bad6c));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x02a01efc2ca0726392e9801c4c5e94b2239eb55098dc3719e247a595f273f12d), uint256(0x265e17bbd862a8bb1617d27e67f70e7bf7accb0e9b560558eb0a4a62e633cdc1));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x18709f10d66f9eabf909a0c8172e3b92110d431261fd748005d812fbab84e1d1), uint256(0x203e2744e58b0db88a8ba696b60c8cf3aa69413fd3dac9bc91398f41949198d9));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x09ad94f224a1910153dc6f4939e0e3d51fd6d9d532a321a7b26d0cc21ee1e380), uint256(0x0945b2d21788596195454a4a652d97080c58a9713b5358bc453564a64e8c88a6));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x001f177ae45139bb866f477a75b0b7f11d0e7052f2fa69bda846abadc2336b06), uint256(0x2cf365d154972cd4b866925eec90da5c8663db27f8eb665f54f95e411eb1e1fa));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x19191f9f832bede5c13c4cff14cc7dea48492dca8c5d1541b0dac323bba6b04b), uint256(0x0550aba8b5940d132395f53636e30870faf322678b463d49bbd3abd433b395f0));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x2674c78888dedf62b0a06309ce695e519362fddbe6b83ecec0f627931e123219), uint256(0x0e0a0b232d4b63c5a2a09c61486137a159858b8af379a45950c8ee6f5c424536));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1c2cbaeb30bd19bb95effcbd012f91e74a34e0d016f92a8f9fb89c992f044534), uint256(0x02a9ab710d8173bd4cf81d244b6cbdac2538f5a4307c61eed1554fdaafea85a1));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x268bb12acf0b59b535d08a7f513e2d6684b79a7c589a743473d485649252b20c), uint256(0x129829207120af0302a9f54c0f2b86c8471c6ca530edeee5cda54cabe040a23f));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0be5692507135f891a8ef7d2b5500f76e24668324e3e004bc617460ff30d4010), uint256(0x2d64dc262139896379ea4c27197db41caacb3bb4868204791ef13c0ad3902f1a));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1b0b7889d36e71e16ee9c8d4653436468a4c57b1ace7dc4a4800517461a7cfbd), uint256(0x1bb5814b89cd10fbb88c5c204af69d90dd4c6b52d08a59baaa5682f995fbcc03));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x131e55c571135d2c57f751ddb7c81ee0af18cec19ff7c3c32ebe7a0adf2775ac), uint256(0x17d3208c28ac9fe7c102504a43227dd35af67c412cf94d3bee5138d977fe0490));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x1183fef1980f80693a2606c4678402de0e4cf9eea95bec67bc2d58607203adeb), uint256(0x167ec13b2a7756542077dcec2353b99ff5733b5f2d8a66bbba5de51ffe5aee78));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x1a80666e3ae37bfdc234ec37d68a19624e9e55614c26ebebf0ef3db8dda1bdfc), uint256(0x2ab4eb1c17bc147a13c2283553a0da63a870936d297c09681fe80f76475a2850));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x00bb1b17ccd9335e9e262f848912c71dba0c07ce48c26c1c4b4c57df76825271), uint256(0x1566b8750b7408275ef8c526074563205b3654e1c7570745b3b4ce8b12522e3b));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2499c3f4def0176c2a7bf45ffc33e066da4e427fc797ca75ac1b8b64146e2e35), uint256(0x2156c9e136b749c3f62478a0ef602a4f6195a83e000ccee44f0498626745f8b7));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x24ed2fbe1e5b1642beeec53c1d4d73c0c283c2af714fb9922124912316e4c8f1), uint256(0x2ac92ed2f6a4724fa7e90a2eeba00761a467a7b576356b01717ee0e82ecd0f46));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x2f193097d1cd6bf64f737e152fc229a41e5b94ed44f4141769e29401a044f31f), uint256(0x104b425d2650d8a4d60cf294af683d6e538e2a33601ee1824b8c6afa8ca402cd));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x064b71ed0f31382f9985cf5350abf116a08eac67598cd506e20bb8a5dea2a511), uint256(0x24c83f0af26edaa6043bcb114fe84f251de03b7deecea3f23e0cd37d97027511));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x15205b59fac5c4259215c7ff8ab0d5ee660ab7d33861edbe5247e3dda1f1d887), uint256(0x1c91c6baea177b3c7baa730a81819a3602ce7458560aa2a6a62c9e2927d37b75));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x281513f590a12b62a1bc9de0815146daa6f2b7c0b73ae41d409c6c1f34c8b371), uint256(0x23bc71f21a20e00eac5b9e4fcd6a1b1ac0029229bc5e715d43cd511e40f2e8d6));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x034fb1398da7d4f777acd778dcf421ad8da928fb58839e4c8ec5eb6032072a90), uint256(0x1e234f0f8a4d1fc3fa3dc135d871c1d02520bc1a0509ff4600e82645852d0ee8));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x0f10d9b4b0bea41a91bf5499592a4e51130afdacc52d94846681304f1d3d4373), uint256(0x1c039b76f16641286250f7822147583b653d505cf094cee2ca74f315f0a1edbf));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x250db6ddb534993a75e132b115e00ecf24419e4b75745ace791dd3bb95902b6d), uint256(0x2553786bda3bfb48685c5ec67313376798b9bbf0479a540fbe73a919f229f133));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x07c0e1f817b47e6715b44ab5e51a9aa3d585b49c98ed6a282b70d473a4103c7c), uint256(0x290027c867f150638a82a7e2d27949603b1436e569d464f9c95882a651d36a16));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0f7a5011b08ea0dce86f87c185e01c98b5e2a281fecafbca0860eb82437b99dd), uint256(0x0900e0487129290f4da947d13ace773c4bd9c637a0095dd7c919588e8f7a9e13));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1428d8a18ce889031fbf16fd6076377a8081eeac5be5efc71d63197b4d263ed4), uint256(0x0323ff93351b3c805f5a64bbca794445387b125e278a7d32b09a91ca6eb753ea));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1b503385db77edbd3e701b819aedc35018df441b31a16982f8e93517b82bb8be), uint256(0x0324edd697079784a611cd285093da1fa04d89f0f62134f5d8d32399125c4074));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x2e50ac1eb0534dc6722f3f38ceb5fb4b05022db5200fde0320a3e7f214b9b8b9), uint256(0x2ab2b8f917d9baebc14e00c97b888ec4b69ee48684b5ca3963ca19edf0a290a5));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x0f62e376b90d160af565d5b85de1de7a06f686fb8887b058ca44a159a9f0a299), uint256(0x001a2f08fc13a623b60426a5899a249b2e3d912f7879db27c51c9f42af19e38b));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2e59df752cf12c3ce79b34dfc19be98ebe088f7d03966757f22b8dd6bb04e3fb), uint256(0x267778b5019a2393344c72979bfdb5d53d362120d8c032b419df9628fffd0b2d));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1012a8ed071f1723fa37d79329b577306fbbaddbaf9dd1992842b798bf1c5b96), uint256(0x06a8bc99722922dcb6e18ebf8d177b59c2f85074b27664b001efb4f902e9c7c5));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x1a9466525002296e2b64591c16b689f4e861feba5ceed3bf892a150dddc64139), uint256(0x2c3b37ba63dabea6c31432646db41d8a95dded6be9c58d59bed94ba75414dc90));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x1bfb155c04c896dce17e96126ca80e415d0e59245ee67d124db23535ce02fc9c), uint256(0x2b9888760e48368a343ba31109ddd45df5f864bd713bdb4f43b5e17f1626f985));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0c880f7f8bdbec57fb4c74fd3f158ca6bfeb952afca5704596246b8ac3bb35c3), uint256(0x08c9257289d95401ff0602f404025106f0a946b7143d91343767ac47c259a31e));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x15cd515a6aeaded199e0bc006de5b66605e323358b71355a6c61b6dd747eddf5), uint256(0x2d5e1e5a17fad3c6939b099991584d99b913fe2299871211bc7a9c527e3ee4be));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0db7f930f0f8d30bf3ff125e8635fe78484cb1ef67f356b873043744f25ba84d), uint256(0x13318ba85de5268954478c1d94321caf43a5a1daab7c50b79ec69595726e1f31));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1b4c07e7fab0bfdf5f69d78c531caf1d1649d624372a0dfe689b14c6bc5e9e08), uint256(0x096835510488a7be72ad23c519dff76a8be77c596fdd3eca27a78409590e60bf));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x230faed41eaaf5a953bf42c9ba08d26e83c14b2d2c5fcdab2a3bc27b12d7ed7d), uint256(0x266ed4287272f917d39e770335f4bd4aabc34e1a8d2ebaefff2ad212a233d9d0));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x0f80550d54e62a86f152ec81925eb9f8d897830963756e0ed08700993e3dc993), uint256(0x016cd91adeeacc52faf60c7ec445c316af4d3ae7f5b985a7fecb8503e5b6ed16));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x1284d4c3256f3b37c0ef567c9b6441ac7b635f7e368cee5e5fd22c643ec99547), uint256(0x183173bf8bc2ba951dfd301b3c06fcae449273360fda6bb628e340c82d138bc8));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1dfca92b631f945696516b409b22045e170b469f4b3c3b89d3601473d6c1ccf9), uint256(0x00025ba2855e71a9bc12c5335cfa552f27e56c1901ef2076118a2ae3498679d3));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x01c0ef7e1e55ad5486483be27fe49a845166f68fbe94c4af803f1c59068c4c02), uint256(0x1d8990c63a420a60c8df36090840b8bc844c70159efcee2091f0a6b9a4b90928));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x19acec3d674ea75ba507264ee1f9c36240c23e2099801b8154fb63f352991cc5), uint256(0x0e24a4ed5c4120cfac930a88887dec641ae0cf75e57c43d98bc135659adcc1ab));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0741680527a54acbdbc66a3e9a372a9a3a677f5c162e3e797486dadcd343bbf0), uint256(0x0395ca5f0ecc7a066ffff134ef7a76809e7bdc3064798c2485256655965ec0e7));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x090014c8900ad8bbc502cf3b48246fa37908fbc1b075161d026233dd69a36b73), uint256(0x276f16cfb47235f2d347cab79b6e63cfb658fa8d89947a10d86a4bfbf0139821));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x2d80ad97a49ef182577bb722c34111cc09b704a8f2494cd7408b100ebf48a48b), uint256(0x2ff1224b42f511a31621927eb5ab1b3dda04b9ab9f434ce78af75c2538873d95));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x18be0b6fcdd9f238c8592e91f4e4a5392cf6d48306b3b43539e0dec4d9a2c2ea), uint256(0x07ec1e2361165c66d0db1983c35cba7faf6e027bc3ed3dd81beefdacce09ebc8));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x2264432cabc69d1666aa397c753d3215fa45486fc6966444f746770eaa2c5cfd), uint256(0x246ddb8764da81db6f56e3c49f127c601e1eba7962ba764c8e583cccda80c9de));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x2296147f5c3e6cc007e476ba2ac5d8e8115e85d5e9a69d3a67aad5767e5ae9fa), uint256(0x241a00769b173e04320d938f7ed9c19e96fb83f3b6bef5b713354c2cd9ac4203));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x167214b20cb1a11d901a93bbe15cdcb2af54eb858f4e62393f7d11f65cff75cb), uint256(0x1ad14533e1ba5461b7f5147487d7af706722d8127716cebdcc97243b6e88b182));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x05e4a92997430942d7f73b5035b81f79de27ffc2742394ab8db5cad7d133b73a), uint256(0x021f800dff6351a20046cdb3b6d499e0c5202cb47c3e3a3740bd94a4aed3fa70));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x2c99c470e3fb30def4fec178707169e1177e0a9d9584208c3d293e6311be728e), uint256(0x18761fcdca52102cdc520a2e786ed5d48242536019ec1eb289d5200e985a6384));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x0c7f6e5aa74a530e510992972f05effaacae428221d101dc3fc1d72ee4027f8e), uint256(0x291924f23c999a06cf310b2c0ae437fcdd106fed386fb6c6cdab7753aad2119d));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x22281a8fd998fd47679bef6f46154e902b810f3f1479ca41898854643acc6331), uint256(0x23d266dfaf48de2c8d1bae1c59b4234fc15e3b46473ccf513d9129cff199a841));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0631f733ad60d7e42c8b2e6ea5c171f104d37b630413566740e0f4b839151b7b), uint256(0x12a328c2f3d7dafb478fa2ed43639e015afb43e3c77e16bb6f055cbd0289c494));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x295676d53bc4dd98b4bc49ac126f01348da9012e888bb9e72be5384936fc179d), uint256(0x1d116446f178846e49cc6ea40e48f21bb09c3351256c20ec38c10d361b62a70e));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x090a1bb3a4e78bb535b4892492f77f5ce400070767af98049604c1e574364d6b), uint256(0x2a09b332e9d97dfbe687792ae185f450ddc2e9f2f047ea0bf1a27f34cbfe0630));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x1b1ed78001fcf47e9eae08f7030d4a27d6f9c3f92a350af8924b6b1d71247d7b), uint256(0x257e83b9b2c6b1f0722b28c4b98977cea690b5bb4437e50a42dc7bba4852a0a9));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x0c00c644d530a0601a35112fc47f5b94aaed557d0533b2bf2fb8748ff252b9f6), uint256(0x25f59ad8fa8c8aaa0dcf52af0d50cfced5dfafdd9a142135d7cb28475d51d8bc));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2de1a7fd51e20d267d040ed3d5e664db948b4512bf7ae5a05a101890636f164f), uint256(0x1b453ba3ccb06581dece377066e3c5443213485accc567c1a4bfc82f56b2a5da));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2f6fc6e5917e4104b51d5c82746b68794677a0ba5d93c32726d2f2f6ef0112e9), uint256(0x157ae6c35589bf3f7151a197485129d555e38349363e777133d2ed29e75e1606));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x174e1072f17cacc1f95c59999a343aaaa2b65f28428304e5b25b19b32309ae1c), uint256(0x222bcf954c3c6c37de33a5539ae9480a5e40de4c15a639dd037ab36cefff3e0b));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x08c4c613fc4105892a5823c555b379b72cb14103db62caef49efecb029a2155b), uint256(0x0a4604a5aa8d38f59b01ccfc74916a47d88d13dd85346bef520d92ac4eb99dc1));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x219a8d307a9ee3cb5b516024a567508bd9544c6c7fea806037b77e913ad5a2e2), uint256(0x07631765970e907213d040b2b2bfcaa538fb5798349aa1a24a80ac96c247fb96));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x08df5b40f357a425921bfd8ccb1df78d0c14d4128c4393481bdec16283af2059), uint256(0x05abbe578d83644c43e74992479e09f1d84e1cd83154846092955b29ab825cab));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x133a25dedd71f1e7edd722e49cf64a8a1b0c7f5d97d2eeb4db7a1670049e93dc), uint256(0x1ac3c3ba6e6d36b93e120e0c4264231919ccaf0b69bdfc81e68d15922aacf766));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x2a99ee5cfde9ed08a471da348776de49bf284b2fa6a5d3ac5884d30dc47158ad), uint256(0x1fbb6f78ac839a1aa9b1f43c98437c435f7f4c613e6d27f92a982ebfa7319054));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2f6338070f8c6b1a3d7c8f52fd5cd581e7cf4d021455f11bed74c565ac2bbf2a), uint256(0x266988d12ecefd4887ed472db97795238de87aef6bf7c1f0d54f397a08496e8c));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x1f63b341869d4fa13e70f9710886094daed77086359124e3e82333c67363eaf2), uint256(0x180a9f11d742c19639f11df1a5aeb7ff55b5b4acdabbdf8ea07687d68195e3e1));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x01fdfff16998e14037a31c28cd622498d6b94e9d24ab279a24e8918202beff14), uint256(0x0f15843884940e15b2616fb3277102fbf34395c5469afa780cabb14cd30bec5d));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x03b5bba84d1f37c1b4192350b4673b82f741eb6eeeaa87168ccb67f48d611649), uint256(0x14f68ca4d19b45e1ce3a5354cb47a5e47eb65f2d5158c8a1a1bad8d2b9877e7c));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x10921bcb889ab9f6c26a528fb1f36f288b8d1ce92d1149457b697d03b8829147), uint256(0x01b0e0f44292e47cbd2387fcbdc2fb5bc4180c8b4558289a8447c57114cfb0a7));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1e178ff55de3ccc7d387fdaa4a69537768ad724a1a57ffe1f77977c65464cf5f), uint256(0x0c6fde2d3b002ffff0ac2ab0327e17eab188d36aea85b2f3eab25b484a694a9b));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x148e80319b48b52e40f5d6e5a430bce8728b24eac147db68663b4a768a98b191), uint256(0x2aaa546eadb2acd0fd8e720c2e5a853d17eaf6401139b619c88c0b9f5101e43a));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x10306c2e43e86aed5a08555817b67c2c7e887238a6b1e53001cd4f72c1595251), uint256(0x02695ae08f5a55735ab0078072af9e008660440256d11735e157bd3b3df6c1b7));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x281ad530e0adeb4b5b8172987a72932e741d3a7f3b56919d3b814b406adefad8), uint256(0x2ce1656fde7b8806ed35426657dcb14a93121bec62d558a04b3029b8d231a04c));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x041d5ed83fe34b5eef7937c861ff8c4efb31adfb242d69c27e3be9d265ad66a5), uint256(0x19962e23483027e8a629c1dc250f7210a545eed5e00e451b86b1e83e4d43159b));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x245e57862741a93f106b9267cc24f909e027dc26e3c37cc858abd0d1be628a00), uint256(0x002249e57864081ff1ab29aff2cb7d52eb9d32642e2f4f47480b2bcdd2d13a26));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x2ae4b3f63980f4d542fc260ee0c7b3e37f44899fff1e633944f0eb095bf8a6b1), uint256(0x1af21289917cb300f2021371d6bbd84f19de188876e42bfd91388f2f52a8ea2c));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x11606a9ad1aec93802d38e4ff8f8319c6354cce68f1fadda2430b43ab4f028fc), uint256(0x2900e8d8b07c70e6af7e1ffa286284b38050b57d63c5b40a107ec45b94422d71));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x04ccc0da1d81c1ea927a3236c7debaba7c20b986172d9772056370b7a18cde75), uint256(0x22dc2ef75f644092042719c730f37a66ac1e45b6ec85a9c6d1f18ef5cff8afae));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x26dc9a405d3299c767b73262f7ba47296b34e1851f56313cc6530af3a155fa2f), uint256(0x0ab45bb7ce4751ddc42ca9f9b753cee828a4c9d0b978f80e8a0a5ad229f5a0fd));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x28e07d5c8f1088c2131209efa3100bca6fc270e8a6e3ae937b9f74e43fd3c9c6), uint256(0x1b3191e9683e5f4340e4fee744637c58057fc8d4f5d125345cc54320e022fb65));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x12dde6ed24b1740c3a368b6737344f3c38ae3d86ccd44886f6e67240bc8541ee), uint256(0x1f3f29bfd6efa18d21e4c59b90a5a45c98fd0f43469fce0b3a9d8de3edf919de));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x222b92ff34642a83c73ed2ac2391f61bdfd4c06c8390e9fb99f7f940cae3c321), uint256(0x06358c544acb257209d99a8b601cbdd91fa27af70f8855d06ce378c2dc22ff05));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x28f48d0f015aa1939bcc5c7fa9434b8929dab4e14d54753e93e8f276eededec1), uint256(0x1a923804f40281336d987acf430fbd7873260969ef634ea3d0232027bdd46dc6));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x141a28d2064961cea7d8c9777a96df929b7aeb175f2ac1d240c40d276f41b9a6), uint256(0x15673d910586dd2b46caab148a3d14698477902fe04b92298fd2c9c375dacb92));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x0b028630952ecdc69ff625c2436b612cabc71aa7914bd1c6e6585e88da5d5172), uint256(0x0e37a3364e14511c76311e991c7c216333438a0aecac9bdf6d02f6d2016994ca));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x112bd703ecbe9b931a7333930cc6b86cb62797b069c5e415025cc90f8f148fa0), uint256(0x2147bdd0336a33aed6991af04616ebc07cf27a8f94a8c8d2be6f5ec8afee0f7e));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x192e8b6c757f8b8b003bd8f8790a134eaff90424d3330bb61f78af59776ae918), uint256(0x24434aade35dccf87569caa76cd39f0e01d5958d72a156c6bc7f1287a9d85f22));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x00a4a3747b0376c64e661ea1cf97b3b7ac336a338955619297852cdc3d67119b), uint256(0x0be5a4cd54b6ea7b0599a50fa9bbc73940591316cad76a9b1852f9a2d054d26c));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x0d1edaff53fbfa1f1e41cbe0cf42263f99a5e96b1ae4d4c903fea636004a7a6e), uint256(0x28d000a40409411fd45584019ae9d3275f3aa17cea86b17aad35bc26268b793f));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x19de9f45f08024b38a0ff7b0ab88ec4562389746f3f4ac4c3bf3f69268d5ee01), uint256(0x2912a78cf79792ad340ecbf574eab8c347eacf1e3014774d1f7314fa83218a4e));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x11030dbdb0718b46f9262194850e015c6f93b1786992d517874dac27da176d2e), uint256(0x2565bcae9ace45f3798627ca3f4ed7bf731c2918ca681e6817082b8668fbbd8e));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x0635fb7d72f8110b368a12024403e09c6b1da954a87cfa2de431ffc1294b2956), uint256(0x08bb3551f2f1ad4c451ce42fc4c0d9299849fffc10d4dff34a50eb2317419017));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x02b6ba5494fa6c82af6d9406a6c639c9b9c30fab4dac52fdb8da6f8138b14556), uint256(0x1dc9bace51abcc2733d21fb2eb7923d45596a9960dbdb7bcdd18f5ed7db84623));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x184501da456dbfe67727715bf29f730355ef549f1cc5de2db2b66d8647cb3d62), uint256(0x081b91e2044422e79fbd1282bfce289320d4f2ae929320eba10a9d57b26d616f));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x10f77ecdf16503ed563e054ac3f751338526088d758a96b7e527b977b8173407), uint256(0x0cf1bdfa98d98ee51c4284a70b18ec2a4a431dc3624613f2b168f7fde412c270));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x1ba0eef5384e0549265202da0ffb3802173541cdb621b88f0cd100bd95aa7d52), uint256(0x2ff9ad5dea7685298907fe64735eb5dbfaf95d4e0b4f1bf57e61ef3d05039759));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x1d2644fde6b58d264cdaacd45b5e6c7c325206610e8541ce37af92bc1d3e14ac), uint256(0x20b51ec4ad54353b3764d3d6a00953e9c095f47c9b86f9ed5516b4d6990ab07f));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x0e5e4ff61b0ab7a04663107c448cfb55ae795f1b3d1ecaf717f5ae7b466d151b), uint256(0x1345f621a3671b3f8a29dddbb4a59721c14eed8c327e0636ed2f3e583e1b035f));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0fbd2e2c4b5019b5eff746704025750cb83a168512b88d793ac1f2044bd8b09c), uint256(0x1edb440b40df424fc6b0172007115b6550c8424439d4cb387461ab8717c3f430));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x11a556dd1b39743d7d36ff050c04a95cabbdbb9a38e4cb31c6703e8ff8124b64), uint256(0x0842b9c941657357e3cc5fc0e622f9d54e23c1bf3ce3260866d3359dbf94ba94));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x290b32d2352379f4501874ae458435eafee70eaf991fc46d705ce3bbd23c3eb6), uint256(0x2bf6787f2257f3bcc41d259f4453c1a4024ecbde86b9dedc90d87a76f8fe5924));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x0bdfccdb4ce82b2faf51890fda850fac41ae97b46a3293be2179de8bc505fcee), uint256(0x0f085a6d66917e52600e1ad3fe34624012beb58ad5d68a6c57cfdfa3f5d0238f));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x2ef7fb2eb8d3895630f65e3ad931b4f27edc8304a688c2a7c6466fead3e257fe), uint256(0x220104121d46c29a62df1b4bd5bf4473c70957b3c9291dc3784c6377784b0d22));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x247dce7509f2672b800f77a3d404a87386f69a1ad3afbfe5e1abe276aa771f6b), uint256(0x16abd8e191d2765954dfad445a956878de7c2629819cfa308dec27b06eb0372b));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x19278743f633abd667698662c345483daf8cd58e83a7227d46e6522f5f8fa62b), uint256(0x17c3e893bd1d55748104135fcdfc3206e79ef32c4326277391ca1dd040065a04));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x28066c6152ea89db4c4d97676aad04549195175e93195609dac92fb682b1f85c), uint256(0x04bedac958a1c62f46439dee09b765125dba171c3e60361e6f59277b89feca8c));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x14dcf80638e33103c273094958c0dde555fcb24856ab9320dedc00a22d380ac5), uint256(0x22e2598bbd7962afb65b3240f499684b273da750fa48ae20054e2ea625fc4bda));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x149cfeff8b604fe455175b9a9613d2bdb24a4bfe5b54e2d6a4aed8131bcf0293), uint256(0x2c6ff74b7899045b025f5a7e9d6340e57f428d4fdfb8ecc4f03b792165473cf2));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x16d8bca35c77e7aff62781dead2d9dbd0a0667d718d1db15a7043cb2160cbda0), uint256(0x270cbdf3fcd873dbb63e098ed4ceb1091a839a85bbb84658bcd49f7a147315b2));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x06c7b3af65efd57945003ecc7c219680b83e93866dfb438bab6b3140edc966f2), uint256(0x2c324ebd7b0863d3bd0f20b902614bd34509e98f59c3443ef0c9225f508ebdeb));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x27dc0fb2affdcf892188846bfab52e4c8a284d76480c58795acdd06771389c1b), uint256(0x29a55f26f3f69a48c6281f25de653bc3cd884b02fe726f40961fe7b6b08c23f6));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x0022855728b98826294374350bd4baf2f27bb2e4fd2de590b903ced455154686), uint256(0x146490ea64e8fddada057eb1ee49dae944e0be385dfc88ac26dfc0b696db1ff9));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x01ee13cd45cc8f944002053ed83b9008811d9985b16429f40c103df5da0dcd34), uint256(0x0ed2e806d89bd80367b46cd433c74d621d698526ef398c5f6a0dae7548aa6473));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x1c3938403f5ae607198f8f601caaae7fdebaafe4995888d14689469aa6010139), uint256(0x2b84eb825afbeac850dd778780a97249106f686b2eb70fd34790725ba2f2645b));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x2198cb7106126c671c733cbb106c5805400a661fbd42d4b750f22ace1b7ebff2), uint256(0x10b8bbd7c01af84e489cbdd4f9669c30a1053e49d990505606072366c34a7542));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x1eea770e3a581d9c9b91f95c0b35c336b5b3c09ca5eb3d9fb9c5ecc925a02ce0), uint256(0x0af34d0425368e7895e695419e99e880a5edf88a0810e97add341a55f201ada6));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x0d89dd2cd39d99dc662e8cbb782a2402f29a96648f955a6a5d98f0dd7d33abe3), uint256(0x2e35cd3878f5c8180d1adf79bde4e6b11ed1c1917f817f1b766e24acafb0aa3a));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x0c6032feec0bdb1fea79cca77edf1842983b8392c660008d52ac576718caf278), uint256(0x0e1a3e3da2c72bb0799890d6ff277e169985e038ba6d1c91c2f004ed470c43ff));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x0540653d758f8ab41472513ace8e50489406a3d89131084371e7bbbbb2c29494), uint256(0x0707984710e2f9ef9bc7e1d78c1bc1d97dc4dd90c64fffa3605b6cd2c71b8542));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x304e404ff68d8990413a1f5978b3353ad0fda2f75fecd9f710675c4b249036a6), uint256(0x0d87f12707c6244e22370334dc72e662bd8b5785ccd020861bf04c76b79fa25b));
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
            Proof memory proof, uint[201] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](201);
        
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
