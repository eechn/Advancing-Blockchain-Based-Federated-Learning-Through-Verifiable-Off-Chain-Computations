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
        vk.alpha = Pairing.G1Point(uint256(0x22d4332b0c1352bfa52560ca45d55bb24110496857285321b519093c0fedef3a), uint256(0x0e1a09b5e5f76145dc516954797495954e335b7d779268ca65bd94d0130ce93d));
        vk.beta = Pairing.G2Point([uint256(0x008f1a7a5feddfd2371e82520db2f69f57ef608855f23d7d4bc07ffcc81af688), uint256(0x2f822a3ad35ae78b7f3d195a0b349370fc262200ec478a8420f4512648a2843e)], [uint256(0x07288ebb99b21940bc50ed13593fdf4ec90cda5f5eb5ca9dd325778e6703ead2), uint256(0x221179a2e7d63b291c3c9381db1870de50b2203a39d2c6df6efd9dde2efb4738)]);
        vk.gamma = Pairing.G2Point([uint256(0x2ef1be72725907d3b590d5d25419de1735bf7634e27cc8dad92aede8f7378de2), uint256(0x00403c8cb860fe6c6db64577dae2e08ea3c9e57970840b7ab13b9c2283c0bf05)], [uint256(0x23973eb77ee1a81c64b224b1e4ec1af61835d252a139d81cb5586f4b776a2f05), uint256(0x2fde2406b5212d4ddb7e5d40b397f0d775fb861ae5ccf771748f65ce63440af7)]);
        vk.delta = Pairing.G2Point([uint256(0x14937cd5276a6ec52d88a35fb544014f8cc36f3b4a31065f48d8d9209c4331ed), uint256(0x26da7643dcf80d2cecded3fffeeee0b2aac50d43fdb30cede6357036d4b1df69)], [uint256(0x0a77308aa6a2047194f220bf78d50587fbcce5cc872a48ef2272dad837ce7212), uint256(0x2bf5ba103f71a18d10827463a02c59977b31da6e7b4ec9edc3e9c16005a546d4)]);
        vk.gamma_abc = new Pairing.G1Point[](202);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x082f3d78063589a45aa764e3486ff2149f1df9d0e210dfb368ed802172604206), uint256(0x0aba5429ab79a14632f7cd1e8d96daecc997d1e6015bc20a64221959fb9063b1));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x114fcc87231ec273d021a8b33466cbeb4cd1c3c31690e86f0de84d33cff855fe), uint256(0x106668ae7249c94548e921c67893c7c1851d1eb21e65b185ed16e4ea17fb31bb));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x28f0378da965771ac38b07a303b2bfaba1ed4b97a67481a7f3a3ec1b72460939), uint256(0x1bae51161a5ce3532ca5b124aeaed162a68d1d5cee508a866c3ee0e35fbc7a69));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x27fc57975c42ec505b486f541ed36c2f79b8d1fc938bb1217bd17d6e82dda537), uint256(0x22c6e975cc1326d9a47c6efaa2286f5481df19867813f4457fc0f0379ee4f257));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1ddecaff9ad4d491ab09991ccbb13b81fa64322fb9a36881c1d427b13d78ba50), uint256(0x2f49f77b9fae6fe41473ad9759d86c844f5c4ad1a4f9f2c6b7195a5fe4011163));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x045fee193f93e915220dbeb9b54ea22501acbcbacb3e4ca7529d510f4f1c3ee8), uint256(0x2d3e6f31d44be6bd297daa2c731efc4ebb2e3e3ead133333373135719ce78b09));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1d3e8d6e3dc2c3b9828a6e495e6fe30afc28680b495bd5d53eaff066d835829a), uint256(0x14fa51cd543bc3b30df031349793750c19d3165c46507c30f0b0b4939e9499cb));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x16d288323b2acc8745e899c26bb8e82f53fb04ca62cf9db8edbf37e08d6a4f01), uint256(0x069dad4fa849fbcdbbd97ecf59d17f057b09a2229a2098f675c459793ebe70cc));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1cec9c6942aa82b1da6188917eb0222eb11a5611c8062365b7655468a29bfe43), uint256(0x2862f773b11ee83ee7d7389850f32616e3f8548b7cbf46ab6b3e4a52a08b8d8a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0fe701ed85a055fe2c814d0c8cec48b6faf01fba4e4b9906c114fcf39bc86cc0), uint256(0x1031ae8a5250ac0b74c6d72edc93a927b340ce53ede638b6b85894be7d10c108));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1b64f2c1c318ba564731f95ccb6f9666cf15ea9d8a74a65d4b60d0db11a0accc), uint256(0x17335907dd08ee7d928d74d17003d323df4bef4fd4066a4a47fe78e1ec204a8f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0a0ead24024f96b48ad142615d201bc1a41a69a5b387e278c62d6b038d40eb91), uint256(0x17b44be9447308a39c804d687d026f6e9c3709a52bb282de166e35d3c329c075));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1a56e709665223484025df06e58e505bf535bcd5a8ffe398abfbf713cfd347cf), uint256(0x28f3c45b50583305ac1bac7671b7a48c4f0600fab1cdc9363bd14c4f286e5e35));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1f48780a272e467aa764988c819a90a6b804f6d39365890ff08bb8510bc72a37), uint256(0x13a7b56f0661fc82c5f152bfc779528075046d65c5f5785560431813d5551389));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2dc62ac409fe65118b8305cf49f4172b5165cbdf12617a74390a06c00e042205), uint256(0x1b2b9e84821ff1f98cf43d65ee7d68028aad17f34b9e50146c27d35a6afb9d3c));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2574bd2300906a347a336e98a968a4ced70921505cafc3a43be61275544e7007), uint256(0x08493f236194264a19325a34f87e688e116075ef469bad05846a1190247016ac));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2071b524f27b4308168a15c489d31a8b6918eea76e3e3cf2b1f9fc33e56a0a6b), uint256(0x108ae41fefc1065b18b7c31325e4180894e32e05a90a0b478201d9c04fa5d39b));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1ca409977a75d776f566bc34764a961d74431326dfea6139e835f4667e99b702), uint256(0x16997f2a802c3fd1152146d65355f94a2b965ba4af3d6ad684ff7116a8096f3e));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x01e13bb604b0eb9b3539cf3c33fc12601c615ba00d5544a8011b133730eba7f8), uint256(0x0074d6175fbc7b306f974a8fee86881b161f8c9cd4eecc09aa4bfec1bf1d820c));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x054a11908b07db258d5ed4cdfd37e560c507d72193c9f7bb8ef6701b780169ad), uint256(0x201d8d2f7b804f7adda3e466ef280fdfb214f9f87b7d353af5067859226d694a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x16a44953a53996215152beab762044dff80fa2204061afb94070be730c9f2813), uint256(0x1182003448fe70a9ec96150c523d4cd2a15549b7dbbf67f29b51e21cecdd54b2));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x11ae701ef551321bccf3f4583a37ffb6ac64b49a70b066c8abaf25dd9c51e348), uint256(0x2890a5c707e27505384176f5f46477c78e6a4e71d8fa789ac5306ca3c2e7fec3));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0f618184816e895eb2787c34db39fd157c12733625619eaec6beccb54b0402ba), uint256(0x2847ec0c5de6aed01c15bdbd9b51f2b4183379af47adc0e406c01fb4f7e290eb));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1cd48532ea70cdfecc82893a204603936e21790a521233ce89160bfe88f4856d), uint256(0x2fbe62f9a2df087d9955092b63bb3ea7dc11967ecd0a3c49f631c22a17a14487));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1440f398b7ef875d08c0359804e9443f26ed93b0637f208cda60b8f8f72b3f8c), uint256(0x175c9a6ad04c3bf5b128d71d515d968b299f9a9caa176ed69e4428786fd4e382));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x181b6be39d2d3a0b0ed422dddd6ed6803792d693a68a6f8f912ac4895163d364), uint256(0x00fce5676d70bb4c13230b0b5cd765251a7e2f66afde86589364cb6983d6971f));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0d7c7ea8803bc4411df0c849e81aeebd948add75cb1930ff0a978da4afc31fd5), uint256(0x27f734352bf4d71e844da8636b4cea939952360777a06df5b68a45b77ce824b1));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0967efb777ac9c2ec7c4e8832b0aae0910016c777454cf1c0552672de361c57b), uint256(0x0f122f3dc1b9b06ddb04144e70ac2ae032c024a2c34817d421ae4c2da09ecbcd));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x187e3c3f1b1742dd5e3e7b0e561fa8cae5b0f701b0602534a25b74f5be53fc90), uint256(0x2a6dd5de971ea5b6f9f9fa36c22052bab04ad8f8e3c46ac66800a5d7079b6ab9));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x033414ec16e5e441a0a49e5141655a5e2296894f1b3e6b53de271eb8a523794d), uint256(0x0b70ec78c03f2db7973c46fc04cab55f06b02ba7a7bfe022a6e5d1ac4a157b93));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x042fb8081501e10814be55fa685ac3dae8dc75291a1caa31a16a2e678a70244e), uint256(0x0fffaca4be5e9fcd23957215dde312300a6863bb075d51a576eb05f58b0bf726));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x08cc1bc2cfa3b3feec80d4dfdc95af80fa794a75824cb54ae2549ce49c023cb7), uint256(0x2494840415460be12e5c26e0495e7550e059a2c309dc9313c828880582fa2c61));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x040604d14edaecd534caa6dbd46562d26a7ef5c23dee174b9bad580ffa1b575c), uint256(0x02d62190067ded504fbbfeffe2593409972b581fe84235200c820ed206dc4dd8));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x272f67d626863d01af1b3ec8b9a7e48fdb09f69f1fe44b7f6a1fb9f45544dac2), uint256(0x0fd229576b1abad5043464924fe7a0b8e5e5611a851be752224785dd3d64601a));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x26eb9ada52d46b02281ce27f5f6d87abcdcbf378bcaac25782d24748f2c15603), uint256(0x0477e3f86942b014d4410e164237ff313f9ecf4711e025f7ee398b2510e6e8fb));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x17cf6e8e66d5bc86d7d7e43769e7f7e3382ed788fb288b50e9aa907b60eed5ea), uint256(0x1e9a3eb19eb89b8bf8ca02d8fbae04837e545a0e1b277f02b52562aff7659888));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1040cf62098576fbd73c28f443964518746890529ece30f84144f2153f82a074), uint256(0x085fefda6ecc367717a2cee8db52f5797f41447091e1309deb721f0b0bc79941));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x02e00ffa08c99820218322a12404df8ec6bcb437cd16f8c1a45a1e79db5212ab), uint256(0x2974c1b68846069e43460b1c911b80c0e763988f5d1bfba24a27f477af4ab47c));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x18a17b9ef17a909dbe9a44bb81c95ea72a1215b676ea661c85fd1dcec2c8c687), uint256(0x224baa0dd9be0e6aa0e0b3e4beb92345ba874d4a9cac180ed3b290d5a76e3667));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x0aae469eafce12394617de4eb5603e0400e4d41cbedd90e9652dae26eb78bf32), uint256(0x09cc1477f8284abf92fee2d841f3a917d9fbffdabadbc769b4e3b55bcb1b63bf));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x10328e3a59aa0137280d72671c12ef9691a70886292fe74f30af473f9cc4dd41), uint256(0x12679ef710b37fb48404d981d2854000eb1a32b98282afe1b4a4de4905143d6d));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x09bafea9b8d3d84840cb7e77819a5dee1d42268e66232e016046ee67ab23f86e), uint256(0x2dbbbe31a06c3dded211041e17b29555d86b96a407af376306255a14b7293cb0));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x10a42a187c7e9e487e831973a21994c5e44d67a2e748ab9147e3c693ebedeea7), uint256(0x0c044a2128c933003d0755b2a8ee40c25c5b2f024a95acefa13ebdb7e70db620));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x02c7fefe56367e4a22e3a0b4f6b871c295e50d25675a040248bc117f9a803726), uint256(0x10da032f00cfc6a395bfd0ff7b595132b475436da51381f0d234dbfc758bd885));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0d4cfb9323871a43e6eeaf27c934bfaf769a347e0e7b0a00a81146ba9cf06665), uint256(0x13501072dab3252c3bf04d93b9367e33a448bdd6da69c5d68b197ab2ba65326a));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x014685ab773c2bbfaa80e1d6b38378c0e1d5c8f1b50fef6be6e1237882822251), uint256(0x2920bf849fdf477f4dad2c73a4ca84ad69a5655b54180ae8742bdb11ae965718));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x0de8bc11ae3dcdd19df14d26ece6bc2c4a940d70c669168cddc3188ac04528ee), uint256(0x243462fa6f82ee03744aa811622f358fbeb016ee375b53f7da85dc3dff45dcfc));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2a732c9d1bfd818412121c6de242a10c7bb062e1fe8d1a33da66c0d3d8fa28c7), uint256(0x202163b6f7e12d7a49cc3c4ee73339e15bf1bcf73eb8411e469194a78e3a9258));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x253572fe9b235c80cd68f485ebcc03264d0bf89c3a97719549d1431afbc81367), uint256(0x0e4ac30da035a7701e2001c364e0e3df27dc63c32fe9f1bcc56bdf52e4d1aa12));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x236bf0e7fbb21668710a3d9cee0b3cf632ea76bd27ed228cc24e6d8e800406ae), uint256(0x19103916b47f9f404524a7f0b0d473d06f49783e3a46a35ad1af7bb6e82de78f));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x009a262f9de431122badfc2efd5b8df5660843d5f1c5d66a1da5ca361356d1a4), uint256(0x20c84f72c7ea080d6513c369a3e8656b376b745c51abfcbe9af242495f332cf7));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2f055e3cf973d59f6ad6ada50aae9e90633e300365af9f6021b89f552383f6e2), uint256(0x2a8bdb7ac23419aeb3b942a6486ad98533892a996a84e051b08740fa222d6cb3));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x15c0da96425c0a5422df6999b631685cc1a89a3c5d549fc816ca91355573b147), uint256(0x2cd87eb67041691bb8a8ff04d13b1ab11f21ef35f734516dda48fab449cc317f));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2320eee39255315de31dd11c9110b9ff4d39f9bc19c6d723136d536cab946270), uint256(0x2a06a823786897b1433d352144ccd355ba7f0bc060d8f3aa4e9b8dbe59445ec6));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x1943f763f5001145898b4656caad34d348d298993ae300ba9085cf87819876e6), uint256(0x052eab769e0fc4c894b69c357a6e6402b7a0e3027a45ffaf95ba89517c027ae6));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x13ee0ec97d9591772b9455bea4d17f7e34addc46abe0218db7bb5f6a7bc6bced), uint256(0x02b962f42e3eec82d6114733da27985dd5a350dc6a785a1ca2c1f3b8928fb11d));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x26d95075b58a2a7fd7b90f74a877884f1853e9eab4916178727a515d4557e38e), uint256(0x27b4bca9c9d3fe84f502b58473eaf40f9113e30a7ade148d82776714d3b4dbd9));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x032af12103b03ca1268165175044ecb51df923a603201206cfb8f7bdfeac0b23), uint256(0x28f2757f0f478238cdf0a991616bef11413bbe9256e893cd7ddf41e0f82438f4));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x151ec461ec9abdc84d4bcf0815cdba88aa94d63a2f7a7d4155b97014a959a8e0), uint256(0x08ea64c53c2c8c53759de54abeda11ba9ddbe1da5bc509c7eaa5d938e0a5b8d7));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0e045c2646a31dce759419decc41cfc77d4a5c9ed5d085927f1cddb8f6c97351), uint256(0x1b6ed01003dbc22c6db06d615abd8fb6de4633bee7d5f27c1a785e3fb83c7ae7));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x2a77007411c274e090bb924d8677da23e21a5b313ee082b0ec564de8b4eb1436), uint256(0x2228c023dc79e5ea82e2e58d1874cc45040aa9211a419f8df474fcb3d17e9f4d));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x21c8edf78231871c248553a8d5b3c4b462c1338987b6d3d4ec178810b95ba0f8), uint256(0x2f8142c28397b4d20d1ef4e3349b5313cafcc74879654313c1c7babc7e82f13e));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x13ed3169acc19dbfbf4bccd142d733eb761702ff31a830e82dcead53f10f9564), uint256(0x1c6aa30a3b70ac0411b6a49c3d6021e512db97abb09349d1ab0e47f8b5990ceb));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x00caaba607d151c9078a26420f5c186338fdc4765e0450ae404be271b7bf1093), uint256(0x0d4a1fefbe515672ed0a379246226e517e497a31c7aa42180b1f47f2447cef71));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x06aef385368b82433d8a4edaebd762b19646b78802aad3bfd36d1ba1f3d08029), uint256(0x2eabc2aa84b622d82c459e6f34cd89f5a084c670f0542e9a5fa762d3d92ce88b));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x1cbcec8b11a62ad349631ef0d4a46a161834633b3b21b60d7cf9b7237aeb6e77), uint256(0x22d57463074d24c2aac0989f7f83259b630b3ddcc09196f5822b0e62610f83da));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x139749ab4cc6ae42cfe0c64e3423a02e5349fd14b046272046b020cc656197d1), uint256(0x1fcffc7bb38859fe32a15b526a5a29fb54be729391058025c5f139510bde58e9));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x29ce966c9c054a73368e3b972efed4c923b77510b82d8dba68b6b83dcb0ae976), uint256(0x1429329899aee28f8d46913f558829794fb0f7b82afbd0fda01d75e6ee3185cd));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x08170ea73b49cc34063546267714d754e4221359bfc0fcec7c94def182378eaf), uint256(0x1a0b48ecfeca00bc64e219821df6baab092c05c87e76d800739e0d5d9df593c2));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x07396d3fc1b99eccd5aa919bf49535372131ede2f41f002ce622a4587acf5354), uint256(0x12c65280d5a6a0a1066ac99ef25779869a7d68bc2c2f224fb35c04c3b3851b21));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x2fa83326e3a4ecc965e415e1fb8dfdea0fb02c9a789f022992d3ac397619295c), uint256(0x2eacaa8127c78db56a498569e96294b083b518b890cff0ed7629584c036e054a));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x26076d0faf2633a13d698980ce9ecf58ea5c2973737ca24131a18d83dd5e90bd), uint256(0x26026d3d3bde54c7d6d9068949f30322864b00953a7ab439dadc2cf6395aec47));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x060e638c640f53021e802eb1059f74b45061418a3de28345981cffc951de0dba), uint256(0x2626786ffe0d906c362498f8a6d27450b15c47ddd5e6d0292ccd62e50f3db45a));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x3015701f14d32bcbe108fa08497bbdad74b674b4cb82c0097f97874b83e614d3), uint256(0x24fe3ab4c6918c01404ec8fefeb5a1a618791b157171bbf208e5e21165c0c483));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2c7d2bbb6e19636fce85409afbd249f0f4e9721cca9ecaef4edafed7c090680d), uint256(0x19ea5e33acf9f4b94bdc5369c633c8d0194d582065498abec13769eeaed3954b));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x072ede011cb24b9ccb48c1b509a1968ece665aea05175d71f5907507c399c059), uint256(0x24d9852422b10c7d83483dd305762f291cc23b906b1b0f292a177f7dbd06bb10));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x268fe1a7f66cad02e25f2d7fd7a1c8817a6327551897301f2f51b59fb43cca8d), uint256(0x26e3a28f17bf7e504cc6aea77f488196d9bc7c221c96f6b61b509d35b040522c));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x154d742f4711172db8edc26e09d228f6695a0b7b113aa5d1e863c3a3a43d3f33), uint256(0x19bc52fc43f4e90793afaf72091e9865b60104e6396344e038435692dba537a8));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2378fecbcf15e664e2e3fcad7d29b02d76b89464fe732402d1a918e52eeab611), uint256(0x0491bf4b86a26b51467012554b1264c0d359e999a684cb9cfd2e293870b1e0c4));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x20bcb7c0ac5f8812e7d52bbdb39931a10d0736829cb65c0349c1b6f4ffab46ec), uint256(0x0d430bb5efadc52fa824efdc62501e11759a361ece199d113064b1f3c49e8444));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x021a248a1c3878574d3f2a49857be50f2e1b855bd3a46f22e4e331f073f75b05), uint256(0x12fc1757814bdb35f59e43d731b808aef4ceab25eaf5b15340b74c8e69951441));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x06709ea35f309d4191fbc46a260da0eda2cfdab67831b735555a3e9e77c80b25), uint256(0x08e6620bd6ad9a2c21d15345a6579a9df22cfa9676efacfa7fb9ce0c0629dd5e));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x1014ce01fedbf9d5cc9dd0dec1e70089fd06e066fb5a747d4414f15a76d898c8), uint256(0x1f14081c1ea4130875a5eb9621a9acf1b25e346eb666bd486e8715bc8f75c119));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1271e54f6fcafb5fdeaf684bacb8eee6eaf30e867661ab81c750036e6d775a69), uint256(0x262a12a4b0fb08e41a011801c8c17241ce55a1c8c4208ebc28e0fbe19b5e11cc));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x0df241539e6cf283f3be06ae47f3c9a90236a259c34fc3b39ff0b5cc2b80b56f), uint256(0x04235ab3a176de144045f322e3ea16024e49cad92d24f9542549f85cc169282b));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x19202c0ed117722d15e7ad7ea81e72add0c872ed68e2506b0597daef4e1a2ea6), uint256(0x01a1e3967b5250f0bd32700256e50120c319a79a040a267c691349bf76307345));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x2aeab49e644810e4606bc168019a76a60e36d7ee573a839c434bc0586a78fac7), uint256(0x257327c6c881b40b167853ee8ce5614aac4fcf97eb6e5fd5a826ed740bfec823));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x1827e8dbb929659f30da835413313615fb7cb26c9f5803f2413ac3f0ece52f99), uint256(0x08112123b4109580ad71f1d46247cef4d948a9342e4e2a0dbc65dc3f992c790d));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x067c3049ee409f2b7bfe4b72b06439f8843b5d7bf0d07542cab3c8e98f95bfaf), uint256(0x17790db15a413aa056f6281d654861d83ef3a541bdfd97330d71fa8b714349c7));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x25452bc82d0709896bd54ee253207b90223d8724b3d59f0a4b5f941f1de1bd03), uint256(0x154fda5530f3408b8192f7a2fadc4b353fe0afde47e000dfa3799709ba587196));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x0474b67ea72421f1e987b2db5393a8cb909be881195a101f753a08609e4dac71), uint256(0x0d4bd4f7c91f6ed94ce2e0af44f41924e4c5c76014f65057ace9b6dbdc440ff7));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x27aa703e6140bf889db186d24795b82aaff7e6a33ace18b1852df57b4d822259), uint256(0x28dc09a083a9823271405c298048af6505859b4c2ec7250f50cb30f4718e1909));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x27c6aa85b363b513d6d6b428ea0d16159d5854f8ee703bd4110f934c6b00bfa7), uint256(0x0fc356fed86933b536eaf2cd84b8daeed33352f22705f539970cfd53cd227f09));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x0f855cf6ec81c84a1e599e85b7a9c851719815cbdd54591929641b0ed25ddd23), uint256(0x08aadf07432a0b858131791d027ab9b0e32cb746ea4ef5a867464685c20d1986));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x06c3c20fab12535fa0da277b84013b2e0b55ff938b61c124a9b698ee40ca8123), uint256(0x2ab6fd4dc3d272f72013bfe3f292cdab7ab3dd3e9f8d6c7e9152a37ad1cf2493));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x23c43d04d1979c0cd0755b7b1f2d75de2e52853226968c86e56dd25bc7f6b187), uint256(0x286e6524e3885199190564bc6b5f2b9c5ef3d3f98fc86929390824dfdc25d69b));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x193fa7c9638718b4a4fb10ce9d337712bef3c734d05faff42fe93a6226a45052), uint256(0x10329337c6889e9a41328cd939e3ccd2bf0cc3a375c94e2c7b79508b64f49eee));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x299fc4a19110c8f66c2e8c0cc8ff5032861aef138ce9f2d82f8327cbe42db0cd), uint256(0x1df1e158f07538a6f9a6200a09734e096c9238bccd6a57362b40c5e108885e02));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x2cc18ebb37eec913161179210924da71b10ea9d13c76396f290c5efe9e84ba89), uint256(0x065dc8de78da4e50d3b050c83f1d3a4cc71be3f98bcd44060354f47b5650f5f4));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x042e49ca9ed51bab398f74fff596d3b3473877df1532f7965ecf7828c53b15f7), uint256(0x01fa42783d3a7ea904d2587a630715497d18f1ae92671398ff07d3ec3ad83149));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x06e26b320e83cf142026007c9987c30c4bdad3486391f168b96eabe3ac06947e), uint256(0x0bab25e20ad0caf7d028667f7c5cec6a6f5d4d0c516ca20591c6c6fd9a20741c));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1014556cac05f4e076f0adeb9b1f81b862a3bfc9eef3f5a8ec2df8033ded9ff8), uint256(0x1e029745617012770d0e6b09b131c1a9524f2c9715ee89b76d54a2bc4d1abb6a));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x0dcbc0a43b757513017b5eca60ebdf00b5786293df354564cddd8fe58a675c05), uint256(0x078e1616e556dd36f9db5fb9dd308cf5b221b07283ebb4a82c6e116dfd357d75));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0744862cd61bd307e2d2f502ef8373f464fb14307d8e949a0c0f97e347291e77), uint256(0x2181256e930dbeefbd8112d0eff85d31a1c1984c4be58d4fd777f4a8cda5ef3d));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x20ac1549a9934a7eccaf93172de1a05a183111e40fd0e4c457c6fdd279f363ef), uint256(0x0e53d5c49fe3a1c25a14453f8174b8b91940e799c7b1ed5bae3c640b74ac66b7));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1f5d8927195c34560f280e598640f141ad236df78213d32030dba3bab2312370), uint256(0x09412e3d294fca1f0776daf07c204c4fdae1e3394ce43ec58db46ad6ed81a288));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1f971cb9bba1fda9c0ff71e3ca4f035aba3a5b17b9a0a7c189a191784ee4f4ec), uint256(0x159fca45eb0a76aaded6470bc8c0d6b01dba02d6b3d98e0e211018ab3ec55240));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x193d1375ad53a7ab2086c0cf8c6b3b2bfb42c368658d75b64b5e376aefa966d0), uint256(0x0dcd1a25be0da368350ff09e74d8a470376a5b89d7e921ac6715a243cdccd922));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x0936b795f6f8fb072f491fbe7ab03a38457443a527809de8e1fa3dcd22b1c631), uint256(0x15fb30c31d03e35a1af7a6f7f6ff6558a3046e24af7ff6a1f82789640afc66ae));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x152d26ebcc05e9e9c0edd94c91cdbfa43dd76b5f8eb427a3291318e253e49c0c), uint256(0x13d6cc6f57b95375faeb00014928111628439012ac3598088dd0c3612daac563));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x25bd71d9ce184bcaafa3ca752a5f53e149d18b9fd3bc14552083444f0adae974), uint256(0x3027e35b1292115fd8aceb5adc51e33effd27cc6955034f34ec01a44a248b2bb));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0198f686126748023911013d22606a2fcb3b0945a614ee45e240e923497bd116), uint256(0x26adb10707958f69f22448fc47f564481ee5d74e97eba50940ba25cc1eeb2792));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0e972f6524f9fd9461c451c16202a10f8a7eb5c53613519acbef0286cb0b691e), uint256(0x2909c81366bd7291f2b296e95b7634e19ece2e3ab896feccfda1cf436cfd2e7c));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x2895cb197591fc4c5c0dae3cca29790ebd72ba18b7b5b3a95218f63a3feda811), uint256(0x021ca6f97c6d468d5e96b079153900018585b4cf36a7f40940acadb424572c60));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2ca14f416ef89b068729ae1be10ab246abae75b3a7b47ec4103d3e6c80e87282), uint256(0x11c38173e56172f6a580a8e1448c62089c56fb0b78956d64e05e43c4bf6129b4));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1bfc33ad9542de557d4582937548f50cd3d83670c736a1cca0f03f2431cd01e3), uint256(0x28eb08c3d6bd16ee28817738bc71ea5cc6f107155ec24ee18f9ce4bed53fe567));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x2923c75bf96a6b1aecde54a25486551c2acfa9dea6065b2816696f978dbc5753), uint256(0x0b05ddd1921d5875304897b805c8a59ae159d1dd8a3317142728895faae5e7ed));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x02e886e707894425aae854996335ed1832f5719e879da49063340d3d6ca5ea51), uint256(0x27235803807a4f87db2646fa6b6e86432105db56fa0cec9fd51b305af40aff62));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x27c4adaf6c2feb91726a96c36ff9366c0a3b2965836e51e6ccf2d627d6b7d5e9), uint256(0x110cc00446c1729c18b8abea4afbf13775e33e9aea3c98378ca2c4da05fb51e0));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x295113685bc24d4b483e3723ff5276fd64c9a3c4e325afaf31e8527af43dde7f), uint256(0x2d1fe62ac9a6678c8a4f2e38650871b3186d1861461e8357abac97fbfe96ecf8));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x213358e9b5735f07478b6fa126581e988d6be261d747a2328dbeb52fcdd060b4), uint256(0x1d4932e566eb2de809fa30f1239d8b6c945227ac6bd886443d22227397bdef53));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x282a0afc61474f057e9bd284799183753bcd6159e397191330db4337b03fb5e6), uint256(0x0ef76438076c48d0ec1925722f2ce06d39672ba1b90bf5b37f63431dd279c0cd));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x13f13338421a0f6ad184d22fe6690e3538a9b6300701cb02711dd79e375d18b1), uint256(0x08760fa81b759ee9bc9cc43b86bb8f96622a54e61ea482c4b5796c7b1026e34f));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x1fc8a312864f7fb07cbf4876c5610afda2c3521af68d0732c91609db9f0ba68e), uint256(0x2968d9bfb70391d439145c0c5e100c150dc29f5964c4b5478216377674cba82e));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x1b7a96d8fb4ab971aa7ab877e2887aed15f9a7c90d9444445e035c761318ff8b), uint256(0x1f67e48b369886a379a9d57dfd4c2ca378fdaaeb62ef98ac1a708d1e64aa7308));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x20a9fbf937444909f553ad4e911947d68b06b299fd57ab75db80d6a3ed9f4800), uint256(0x0d28eaecb299d30878f561101ef682eb244fb0a9d87f43fe08ac1bfc5042c42b));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x1db952d45191178b0163f5fd5199ebd748ed19d23230668a33f51979b4a9a10c), uint256(0x0ce5c185238d8c31ea1afcbbdbfc366ceaa74756367b7f31647c67c1bc377b9f));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x235f8aee1e979240534f581423cb1bf78bc1d138610e313f248675f1727e78c7), uint256(0x2de4c3a157c53549dc36bdb5dbd86f8e2153164ee0fffda30edbecae037547f0));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x22f31aad19c8e420d8d477dc6264a2ba52784cf4b8c37b459f4b8c83ec311abf), uint256(0x07de6886e5e01086ef24e526001e847c998c6eb60fcf01f7a20174b773f18daf));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x1ee3ece4230e3f2f013b1976edf0cea6cc9d8a08217efba94db8c856ade3d60b), uint256(0x057cccb16be07cdd0f7dfd4fc4e49fa22300aef0557974f4774299af967a295f));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x1ba1d1eca2aeccee9fa3289ef71bdd5e44f57a4970123620fcc9f1c2fe0f5b4b), uint256(0x298198555d7ff2154b447220c7d15cc51fe6567109173c1e7bdbeafa1743df5b));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x1a6cd0fc0b1201137897a8b6259c2d1b533b437351fdd0b861d20ba2c2ac107f), uint256(0x2504027f15c674845cc4ae4861d6d735420be8c180844ea57724e27bfc2d3b10));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x176c0d748b5faba2b982f897c986535d6270a98b75a0881d90613494c0e69720), uint256(0x18cab8d3feb71411412ed46d32c9698cc4098464c6aa6459a11821b829ee8bc9));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x1cb43ee4e0e89711e17252ef7fe24710c2b0cedfda243198f70061b0518f3553), uint256(0x133a613fd0b7621dd7caaa5c047251cb5a36b5e389ce3f2c335699f6e69a77e1));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x04f56c2fda40a99ae60261bd615ee7b1996edea7f66bdbfc3061b73155772a3d), uint256(0x23ef990a6f62f5ce3585738cf6dbd9579ecc385c79e0d26dfa749886051f1a1c));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x12d1be459fb82237cd669977401d032e69f1496ff18cd8de79c6453ef76c29ca), uint256(0x00588a287fe9dc0be821b350aa3791c57e23232db12d9524d97b742b56f0d643));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x19ad20ac8fbf3f17129ed5768c12baaa499ab4b62a51c32954342720c1ea0870), uint256(0x2eaad1790965e14e5903536eaf334a6ec598028fc01a2e7fb0c426fcf59edea3));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x2bf06b9e802161d578216f9dcb4a5c2d1c10aa5101ae77eff21d76194fa5a39e), uint256(0x041725b0253603e9237b13041de3a7882df78ce871992f4257299a7a5f4695f0));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2d934ffeab92d955428f74bbf37e7fc46bde510ab224560739e19b5eb17d8810), uint256(0x029dd9d219c730bc48b93eb15f097f8dce66b21c03b8932a97df486c640a1eed));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2a17084f0a0ebd4f256ac6d62ab72c4268b5af879dcca206255dec19b405e63f), uint256(0x2ffb9eddc85b51a8bf93fc2508e4c640341b20f64c6a952a14d2cce83cca5506));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0bf5737bb60cb0f23c841e60ee64e8cf79f68f864d58277cac883b8c157291a9), uint256(0x00466ace878e12c6f9ef40890695a94b0be2c1847df48aa065c0ab1402ee12e2));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x15284c8b3952afaf72bafd8cbaa463e89a0f21efacb6a4f97822e183f5a4ebb3), uint256(0x16811d2430b542ae12209582d408154e56a47b247a32c3eb4d8fb8b7fbfd586d));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x2956b4d7f6bfba464cd6a209208c597fba4cbb6079cda540de00e06ca1a8ee8a), uint256(0x22ec484f95075351caccbf115b2256a8f72715b407a78bbc453ee05406287596));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x1019638b571f24da2c29eb4096f8e4fa8bcf2ece8981a6f821950c2399aaa996), uint256(0x2e5fc77d7d5df1a2d91bfc3d4d2d56e186fe7aec6da143d4d4f42731084385a8));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x0131cb4703790247b3bea0d36859adafe2c19d7ad240910fd4cfe91827011367), uint256(0x290d49eb648259ccd8b9b023bf13ec14de28678820fb271a0367947f8f2251d7));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x1f97e579acbb68dfa80bc34d185a6be116bd6e89768ff7d96862d35332bfe10f), uint256(0x11c66e3df3d8bf1bcb5b727994e1b66147971d5f348da40e1778a601b52e8779));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2d1be549fab467c96932f44750008a2f258d8a64c06bd6c6d05ab6a454c8356c), uint256(0x22bf53f38323a037e2abb32e275c7be52ee953cc545c5c236cc13e95f2518acc));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x244d15f69b301b329e46d65850b0212a2d2147be7fdac4dd6aa6a82e280808b0), uint256(0x265962909f766f7e36104515b83179265b784823b246f44213c9bc799e766167));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x111d2cd28bf5c1fabb7a875297afa7ccfacb0c62eaad94f16d38b6f18ca6ddc0), uint256(0x21d52704390058ce5de21b8e16a82eee21d9efa2a5375d6ca3d5e79266f70f05));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x24a11ed7cda7c908f422ad414bc228c7d71f1be65f2c4a225e9fbf170779ccb9), uint256(0x15717a47609f405726a807d153923fb695dde9acc0b055e7b2b7f9475782b748));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x24568c24213eac12e36c6f5b37e5709cd2963defbaad9ef0a80a093b458f637d), uint256(0x16aa48982e7a7ebcbe8a5a372009a43654125df46dde8000c8145f184542e18c));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1ef7d366a28f3cd471c3ce7f4f36e6b86eee2a5492c9104e0e25b13ddb046c41), uint256(0x299105e7a3dfc7963237d70facadb76d7144f385ac2fa108b9d6b1650df86c32));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x10e7f114f8cc78ffcca88fab9c767beb08e205901d4239f1fa0e3a9a0648f15f), uint256(0x2329653a50bfcea3592d9e90ea70e4932319a189936c729ad20c52ab57b8be14));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x0b7705243c028f50916757492ff7e9305c2c62df3610939ab4131d3203b7ebe2), uint256(0x165b707c3d9d4180cadb8c1c69804e0ce59272167659d95da7cba160361b8af0));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x1459c74ec67a7662ab3f44ff524126052d9fe798ae2d1c99137d11769a60b500), uint256(0x1edb8c9d3930f0983b4bc5ae2f1d1740381e92410b1efc6b8ed9d9f205f1b8c3));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x1fd57b762b393dea60dd4f91b223a4fbb96999d7219268286d12e062a58083b7), uint256(0x09ab35819dd7af44ae60855f9d62e426c2258d08c53d6530e09029186e0293f7));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x2c90bfd50f0829b310e99c992b3056135237b1fc6f137da5feca69b21bb37999), uint256(0x2f7f4d76340a57b60f283f56bc2b3c4a1d92e5780442cea0dd690c573536eebb));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x203059a5e2da55c926036936bb253baa842bb54c12577f409de73f73621b70c1), uint256(0x036422b3b7896a67829c2f9e0bff589d1ce97ce1d924fc355ffcbb6c00f6701e));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x045b9c77cb41e785d2e6698f8bff50f93d02f2722bcf407131458c90e726ed6f), uint256(0x0715bd8a2518a6733f43718a7b3028b5665a98959f541449c0db9056630e6beb));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x133a3b5ad44de78b4e0639b3c9cfe9f81cd4cc8c1aa3e5c3216b48c3ca6edf4e), uint256(0x0a18ae33982468156e06c99bc42a47b84ec930c8a6e9e97d95bf3a3da9be416f));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x1c3eb4187992684cc535ba7003c015147f53405da454ec701365bce467dc08d9), uint256(0x0d55a320b56992f4f82a47299ee3a590f139922334c603891f452c3656d298bd));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x14f5666253187c895b441981ad557a06d73fc263a9b4ca90d43605cb2f80cfbf), uint256(0x020006d7d2aa803710a54e7a643fb4d45587c947fda23762f22a80583dd353bb));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x06dc43464d10b9faa5892652603eb4855d26c80503531a39a31d1a49fe6d62de), uint256(0x2f76b394cf660af794d8802187c2219aec013e2e3e60df5a9905bff65211bc36));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x2f4fcbfc8755df930bacb2803858d0fe88850127ace5349060e72ec10e8dc2f1), uint256(0x0f0f5a7adf30f88d813b3430fb52c2b524b85fea747fb9364cd2e0fa8ed80a14));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x2f9af80e453d881dd1dc1895cda33ce254424bacb0c0286c72d28a52fd230f0f), uint256(0x29923da2599c82803039abc319c865b208af150e7668c04cd9648fb85f01a935));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x2b37c3f27615a0a1f332c6941215b2aa82f5eca44fb8977843a431bfc5f93786), uint256(0x0d209b70fed26bc888483778045b62eff7c6987d759f108b68195a43bed56ffb));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x19a93e1655666e5c448133559bf2bfaed5d68e79443e582fefd4e48abf814918), uint256(0x1ea0d9c96cacc7ab853f89a564ea18040cd93e4ad86ffca64f8f0d8eb6a28cdc));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x04ca71c4ca8e471269b85cdbc051f2568e6813d83df058b068fbcc88bf04f46b), uint256(0x017a28c798b4d95d9ad3120b4a7903e3b9c9ff51a33f43f385f9bf3ae954b11f));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x0813f196ad18c6684adfeb8c41aacccac9c08bea57743b65e897c17564708c3d), uint256(0x02aef2f5029a43cd223139527a149cc242c90c447776c6a4de7cb34294101c8c));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x06a4ec7d43b5a29ade2c87b46f5b0e2d7f03cf52e1d74c1527ab12f79bcfde05), uint256(0x0d80630dda4b5cc9a729720d9161591114be666f5e7542615dc2b3135a32d079));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x240ef687c75c59ba0ecf62e41b96ac7cb83051bd64aa5c16e9c46682a185ce74), uint256(0x284f37f03c40eb77d4dab906cd2baf901b379e5e01e7374be72f83c2680b5143));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x24055b0e996a2c6ca7b1d41dbab951e6238150501b414c1ff16d8ba0c471a768), uint256(0x0acb805fa550c86601fe3a622c7c5481217c9142acf1418677b1534fc3015f5b));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x009a727db562477e4cd2375d764e94bd4baa58daa82887f9364d7f497cf50ba8), uint256(0x0bd9b2e7e9594d9744a56223f2a63ad95786f30d42a6eb057d73b6151ebaa134));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x19922731acae5ca8a57f7f4a4629a4f27ed3219d73ec6d04d97e6d562423067d), uint256(0x09120f823128631a5467df00c9924dc786377adccba48e03fe7ca23984584f74));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x068247a7ef31d079956b6053bfa6c71556dbe801aa93c3d441f2f14392634301), uint256(0x1d30b0bcc140f1cedd6850e6b9c6759c02d415723541332517fa9daec89ea2d7));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x05a41cc1645fd72ead3f7dfd9fcdc5d88685122fcb62557f4a7966076c5e0722), uint256(0x28b8255de8bece20331a48b969bbb0ad3ac13b8bf9ab162d07939f91722cc390));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x020bc1b560f3c4044e851dd1e7344df77a7d627c1df6c6edaf1a6cef9ce3d08e), uint256(0x2cdda190d7db356d1260c8b237658a0fe7e935cc11db748bd3e46e07b2387170));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x0de5de7a3a9ddf923266d77fc10ce86c5f929d0b679216ba0beb70ebec01c1a5), uint256(0x143db888b530f589295e2c44a81a1de41bb47116d4ed6238b225b24c88a78b4f));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x2f66d9274d9a698319e030f20b1fe9a18347c4660662aed4ae0e73daa863fc0d), uint256(0x1be146464b1dbff1af5cf050348c65452ba6b1352f53e3543d79fa349d0a5f28));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x02b2a28b5cbcc6ef6053da1f5ec814755b9a2426849a2c38cfb8c2e6a5f408e2), uint256(0x09c472031ff96b66406ecce570df9bb85e46920aaa4af2a225a0cb1308da26e5));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x259f2e44ce4447bc2b9aca9a502b522abeff4f618039b2a4c62f1d76826f1dd0), uint256(0x0045fcca80704e543cb08f0499f4ff5f15f5a704eec5cc3946ebd4ac6486decf));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x053599a9d4a1b6c24084a6a5ac876db5d7baec0b24eff159c4cb5359f5c2edd1), uint256(0x1614dd2546342cfb3b8d0af7b7d417643a3a5e85ee4b5589b8d9d5b188fa9884));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x110e3b8b019a7d3b436bc6f5ce26f376cf6d471df3e247ce64ebf32787942795), uint256(0x0e4b24b39596b27f28493e15f10b1dc974e09428806ab5e401e1a93994df6c19));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x1771dcbb659c8170b04124fd44b2d9868bbb47fc138db2f8157305b6ec24d62e), uint256(0x063daab19ee4442837b06bb0d95d6081b3f2cb59c99d37196d6f7c6c7783e658));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x0aa571d0728a1b627eaa41353d242aa89dbff0b2c53be22f086b8f282f1efb0a), uint256(0x16e9171b5b465a7fba226383c6774d2305711f7df4bf15399befcafd1e5d9374));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x28f09179fcbafc99422aa1a76acec184aa61a210aa4fd115ae9f33c57ebd0d24), uint256(0x24b2d2d8cf1933ba2e36e6ba35ac2a02b3fea68ed3ad0e63d7350dff9b584b28));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x1f3bc23a0d4dd4027fa1a915f161abe412c63e4e37ba17cd07b7f2780cc3fb42), uint256(0x08c59c159101b0db52cf96662f158fc7f09a8cf038d2bab0b0c65521b6cbfa99));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x1f7d50d01d8abc895022c11085bc434e501799c4075c17fd4cfbc7eba967a67f), uint256(0x2716a2b27e09701f1694e84407124b5bc42b9b4f65ffa1c3a1495eefac987620));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x0563d804885fb2cfe92608768700eb922bd5ef1326391bed8e26acd6ae21faaa), uint256(0x1123bdd958221a6f9329f369ca9cf17fc5162b5b5a3d58fad87257552015d91f));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x1670e610a1cfea5a4bebd4f042d3512d4d15fe40d357b8f579877668d4de6d49), uint256(0x0d5212cf71c68358a508c5d0fb172ea919f119abd7c5efad01a383ac76b07100));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x30633970ebc640994d3cb25e2c56502581c60168daa5506d809d5f3af5b6761b), uint256(0x095c15add379440f33fd0370483101df7e607dba156caee1e7f6d9ed2eea3310));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x01d7229e3f22152fe56999a7fad51c847724de002c658277882f6fb8354b2b32), uint256(0x18636fc05daf2db7b60f4ddbd130080051b7c7273670240c2f729009d27a8a1b));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x1260514b6fd35ac50e01224b7875a7f10769518492f9b8d90434e57ea847f3fb), uint256(0x2532ab439ea06c373e95c1640da57908b3bf2edcb526883be75d6b02dcce643a));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x1679c44927db29ab70db9ec331748a0fb19021ca38aa68ba2159849f8a8c8cba), uint256(0x071ef91b0f1a47bf7cc7801a692aaae5a4f21f3a9bba13761619aea563b971fe));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x2ab03dccbb73ca05b907a66a65aaa9238964d0e900399822ecb1c48e7c20eacb), uint256(0x00d33fdc0547b581ce805b3ca4e26f4fd8512c77db076e01d9a78798a5c04fe0));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x1a81d9cffee0738adaa0bd206c627c180d73d5409db8dcb04b4b1af97b5858bf), uint256(0x005d699b9bc992bd493091affd41524dcc6d39e1e20ddb385fc9ff27eff469b5));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x001270cdac82c28aa8afd6a25b0c3471987c6ff02c80025bfeb706286bc8fbd7), uint256(0x0903d7dd3500f8eea5a0068ef47f4a8840db8aecd14bb8d0d64dc465e8a834bb));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x274bca8bbab6543dad97f433ab22abf1b5cbfb8b57c3340058f2d475bb5827c1), uint256(0x0bb86210a084e211f9d23477135c6262d9af7cd95d6a4f7a67953c1c869c4089));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x2270976be0970e9f620cc792943a063863145d660d1a61e0d133c4103fc60083), uint256(0x1015ee6ef902751682f79a2afc81202cf6f74325b9f60464cecd3a48d0da4815));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x0e43c941b6096e1d236817b0f7d3cc1fb652b3026c3d9ee8fd9cb36124e5579d), uint256(0x2893796454beb74765a6836c0aff2eb3e4be84ab6952434957c4f953c49b9702));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x09560bc68a7d417c49a93086f7f49ef28ef8d1a117c4b03506a06a1b8332f32d), uint256(0x2e72d3efbe5d40b0179a41b2ee1bf94c49efba98d653d25c5e2685ee671f3c2e));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0271d1b385bf96fee13726cc1b1b3d1f359edf2c67ac34eff20acf9e2b9d6321), uint256(0x2ab8e1d5767fff050a6178511209a4edc82d8675b12ec357934b04b9286b236a));
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
