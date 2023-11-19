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
        vk.alpha = Pairing.G1Point(uint256(0x05743e7feefed4b25e38ca6e6edadf0a4c60aa9d34ce05ddd8a7754a3050ddce), uint256(0x1eec2db4babd68523b6077534b0c3e4606c00d4ac63f8b8add0ac47a58ac3c9d));
        vk.beta = Pairing.G2Point([uint256(0x16d755f5b3a36fc214d934d48e8692b38ea5ff550c2ebf3ac492c36446aa2041), uint256(0x0285fe713fdd4fb00a18d60d34533e581ab7055762c66851221f5c2aa1e9e456)], [uint256(0x296e6735a027e6531a0f757af792f0704c751ce7cc9b2507dad65a58d33c12de), uint256(0x2d5d19ba396b481668b1b1b29712e9e9221d1177d80b638884377dad001591bc)]);
        vk.gamma = Pairing.G2Point([uint256(0x12ba468dc330205bc15354719bc5a46257dde0e94a3b78c615125302e4783709), uint256(0x2efff7137b24a4924bee4e3e9aee8496b315cd1d03a1c0a1e74ad0db67c08158)], [uint256(0x004547c6026fe280a6f7afa168c2f2394a2eb38c792cc5008cd78d323b44dc4d), uint256(0x09084a5c08659e95ea9aefc3a1b27b847f60b1fd53749a0a13d0a19d2b0160a3)]);
        vk.delta = Pairing.G2Point([uint256(0x026181a75ca7b6a235f5f87a1111ef254ac558259b9d2fc2a6c9146dca2ca002), uint256(0x2db77f3b4857982f6cc91245120bf651b28beba534d76f642fc99dede1ddf594)], [uint256(0x0109069e21cc56d7ccf046f8669a4c505763fb5b20f490152f7d0f41a201bfff), uint256(0x2f8b0173b0084a8e99f71562907e9f7273fae947a479aa49e1ca5e2fc6ad6df9)]);
        vk.gamma_abc = new Pairing.G1Point[](202);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1310a1b3b11cfc500b55bb6a5acf5f407c807ffbf8a49e19189e7d3e3aea30c1), uint256(0x17c80691f62fa92bca93f290335bf9bcedc2308b1de882b5e99c79ee15de2b09));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1a395dff4f41788c2f254bd68cfa7ad9fcbd1d803d0a9e247ad53da81ffd27ec), uint256(0x1de9a2e5e9754a4cd839fa762781f2e21257133d82f70c332a7b3a498470c7ea));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x146d351845594a3701a04866fed9264405b4b1e4fb57874748605be03e032ded), uint256(0x271019131a87cd3ce84b63b9870fad9b2494709b7cb99c8a83becf15af218b4f));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1e9bb68ad82a461b0d1ad37a453ff9516e50b73cf0e7b5b65e8555d691ff34eb), uint256(0x024a51edb9d5ae05a19f1108ee4f2d24fa1ce8af0179f349b7698cdbe1f07e7d));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1a54890c81a76cdca884253be327e94a078d3eac6b30f9f55f9f0893acfdbf78), uint256(0x1df164efd74fdd3b80dcc613d973bf78c7acefe624da20a6e56138c2772797d1));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0ebb009e930249252b43b01840bf0a0a1d56fd64801a9bf5b15c89f8b2e1c91f), uint256(0x2e32c71adf2fc8783507de973ba6946b8eddbab508bb0d06f5557876c72aae36));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x01c8551e99254c464f8a777c97317c383f992e7d62b8b94ab4a7e4698bc1bb55), uint256(0x1a820836fa2a71b6d9322390e8fdfe3dc892f6d375940f0bd21bd29ab3a6f938));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0e4a0a87be73c535d491350d778075c203eea9cedacb2fe12379a2254bae854d), uint256(0x04fa543ad20d0640b5b0ba95fa53261962758d132e6dc5dcfa6a0a168388d146));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x007c6ce20a905dc50b9b04b373ff24a3c1e33a313863f8faa5b0ef256298c8b7), uint256(0x17f537830d2ea0e275bd85eb431424e27ab1abfd0d0aad401105e03e8595718d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1495ee2bb6cce793838822ff10ac5534139e04615965c4de79aa77f849bd29dc), uint256(0x16e13df086a6d2331f2c53c4a8d5dc653bf6e64158b28ca9a1fd52fc4cefb05f));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2cd013deb0608035691b37be6ccce1bcbb0ba52decee0d2a90137b1ffbc00521), uint256(0x2c32dd2f5c1a1303d0385b2721b961ffde78bc901f5ca9cdc596babc87604feb));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x14866ef830985d8416f1adfb3aa1f4b16dc75cff0cfcb38768a70e82870749b5), uint256(0x26746d79a0bc01fa63a4b2a57fc60c8304d7fe3d8bfa5093cc7d6410212da221));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0349d8f529587f594631ba6190205d9d28ef0a6b023dd86b303ff677b941e26f), uint256(0x01f620337f1c2a3e897e8af468f5a8c1586c5bc9ef887ad251005a38728a3a50));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1dbd9f71bf696ef5d60f4b2d3ffac8e9e6d20b8dc27fd7a9501569ded1838ccb), uint256(0x11bead958b93665eb3fc1a6014c30fa082865ff53620641895f6ff78f80015cb));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2a5ea74bec80e937a021f6b0a5661eb7f646b67ab7bc63214fef79b1a88411dc), uint256(0x19223bd4b225eb59a9fee6425d048407b486bdecf3ad7c0a34add4a5ff3cb794));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1a75c7529c880e1565622befb74e4ab16fdc6d0278d458a5088aa59a26aefb4e), uint256(0x2485f68c6423bee248257e992fad5d7046fd9cb909130b89ff8bfc511703ae72));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1a0e4f8dd7b02618fb60dc3ab20e97e69f1328c79917aef1b204384e8c088a4f), uint256(0x1b6e8156c33077d50d0890bd27ad94fb992dbce08bd44cb1334cece3889c12f0));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0695b397a99b921fbbf28643231d65891983e51d5f58d6aa8ad6a8b645af53e6), uint256(0x18358722860e5e8f71d834975ff013f44dbf9904b04fe85c71a49b0899ede82d));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x038d7bc5a93c8a96a156eb8380a9a3a9dda120b314284597f447e15f85c7cdf6), uint256(0x2227b6d8237cbf324752babf286133c718b26dd5c1e05dcafe374453538ec3f7));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x27b0fc5937c30babcb6c8804bf15ec1916ff1d8d65f88646d162a7dff4db4358), uint256(0x2349afdc943715aa877535c869c5b4cf1fd5a1e2f1866ccfaf2ad13f8e5ea05b));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x13b499f0c333d70945d31aa83fa52899e9d18f1bfb4597d45bb00507cace88fd), uint256(0x14e7ac2d01cc77d516ba4f443d432dc059e46068531a73f6f32fa2cfc227ac24));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x224682330042249f1f2e838469415fe0ab55e829e5ff6fc0d3deea4ed2118d02), uint256(0x2ed3aeaab5d446b46a427ef45416dabde7c782fbee73d754aa1133d19fd378db));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1aa532403ceb3fa3431c0697583338dc338dc7318db71e6356b2a6c639d80f5f), uint256(0x20d6adb41fda8acd2640baefbdd15f21b8600908f8d78e82344dfd6abdb6e7e2));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x04fca7981e1b82a696a4004cca8eeb9023e15bccb0a58e29309ec2f86ef4ff69), uint256(0x0a820416bb824655ecb92567d06eee832801a52f3f795f810340aea2df658dda));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2bec61f0cee0c75f30eb94d26274c0bfd31a197467461460e8a89a455c01cfcb), uint256(0x234d749f829858d5936229549bbbec639bf38cf1d1866dd8d8949f3121140c44));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x01df53c4cc1ab4ee0864ae47926480591e198fbb026b9971a35b8b2cb7223e11), uint256(0x0d8fe30d99535fa164f1720aeaabed6375e392025ccd0dbbcdbffc724c41c01b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x149a5eb0758984d921dd791895af0d9564bbc30ac893b568747d14810066d31c), uint256(0x01597b06ca092f26cdf607ba48e38872a77dfe8670d4e398bd86c469fd899b21));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2bf05fa7c048fdf3f9fa291b27be46457ed1d39093344e7c61deb7b63dada1e8), uint256(0x20bffc01477f546eba1affe2e5c443b251655117fae9ad5dd75487cb15d5ec49));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1aa4d4817586c1f7bfd54fe589b614598fc45b8048370702ddd7d62ff92347b0), uint256(0x10f67549409576fdfd48bcc430fbff01f7f27eb2b3db45b5896ad977794dd51d));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1f8856d8d78853384d7e6670ed5aa8107ae4d442fa3add08cb9be0e18d648ad1), uint256(0x2119f213e699cc60b1058bc14c279bda297c3b0a531c22da2aef32c70e14f405));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0f2001ce3247dd4442e4641e20539de2037d1d7c14a9fa5adaf4480ea667ce61), uint256(0x0dab389898ad92bb933cd345dd2190b549ab8ace726ca78ee36eddf6b35f01df));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2967c20ad765180c072ddc86848653665ac4377ff2f6ba7bb57a98bc72e9d00a), uint256(0x2900251390ef1326f98512b9cb2ba4e0d861fa2f0e803c1f65710d9f9de7365e));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x12a88aeaa93b1be7e2d81ce726275526401f1b164eb55ef38ab5b17f0d2f290e), uint256(0x119639f32c1355e06c48a39d060a0908f885b40d2b31e4e530b9931803f76486));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2a091d2efb540c662d548d56ebb5899b9ba94faa49cb4f7e55abec8507a21085), uint256(0x214323cf8a7ad998f6bc982df15480fab86ef86ddd17a4095e9a62d8619bb9f6));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0046852954cc515ba73378bf2409edf5322e8e01d28c11211202b63227c526cc), uint256(0x27439287d7418393f316777925af12f9bdfc4ec122e9b16cf1e6ba470f87d3db));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x23674d2cec07f2afa284267b126905764508e4e7d16fa5d42aa40cd68722318b), uint256(0x0159dd53082875516527bfc04c6d24b3ebb445ba76f385891296a02101507839));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x28aab349ec928b0350f254b85514b41a74df40d0a86042cb806fb89a93d3c988), uint256(0x17a6c8ff0b1e59d52a667b79a280f407ae1fba573826c6c71adb6a267bb8df1d));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0f367a4489fb6e8d27d23febd6da638379afae724ef0dea283071ea688a670b5), uint256(0x2054e6083dd13bf5a5c2cf300b49ba1bc9362e540bea79fe4426ab9e31440e14));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x02a28116e1f4560ede5d033152c9ad0fa06e58952fcd8387f7cea4abe103b149), uint256(0x213d365c02b7f8e5971969925fefa70f63a840b7f83ef8270e9be42fa7f99f85));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x13246a44248bcd70b8443f0afa1f93c10d1e31f4f7ab20940604eb4365858d9d), uint256(0x1e6a0fe68c2d96c5e7d2ea846ad493f4376c13dd610506910561cdbeedc10f38));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2cc14f23cdd5a7847eeb78d29799d266b001f905138af41a6f9253621c606627), uint256(0x11774e3f4218b16b93f9cba214f94fcbd242890998f6a3ed3ec0bec467c79d0c));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1c44b4e8526a42adf671154978c7c76f45f6047f6f2ecc8bcda5eedfd50ac3f5), uint256(0x14de6edf5cb3bfddf4495e062715b71c2d512b33503aea75f839b9165bfc8852));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x16428a066ec11f5057273faa8d9cf83f2ccdf64be82df16ffb8db10d9de7719c), uint256(0x1625b23782d77762be24d4c083f6bccbc412c3d0ed8cf6399df45cfdee8bd583));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0232de7844e05dc3300db833d45cace2af594c06ba679648040043d38c5db58d), uint256(0x08d1a7542ab1058d270bec660d16bec6edace00892b81e3cd5f9ee769391b353));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1776d0f6f439ab245e213ecca0521b5d22ddc1a740a64b37c445bace0b0d3394), uint256(0x215a172a02967c2b2b5c06617706c85fc72329c98d284dd39131c777f1e2c56f));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x11355d638b27a3605076da2a29d2f9be664d85f7db4df889a40b6cd7e6b50c78), uint256(0x14bb546daccc7575d7c8588bed15d4bc60d299788092eb123e30baa5c9884c9b));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2a7cf6d04577ab16c4849535563f6682c0a0da0c88616b438e6dc9664b059ec7), uint256(0x30051aa46636fe4f7f7091232dc8ef7dad0155eb81d721a1d2b395b64e001f14));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x19d82a6baed268a624cb9b0eae10481783d3c07badb00295877764f5cd41d62b), uint256(0x0e1c22f61a878848216184eb20d2f5ed7682b1b837ada7819f2c62cb61946393));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0ff6a6caec39fa1ebba2ec17d478f04e988da47e1e7e17aefab0d348e63558ec), uint256(0x1b3736f43f0c2170e5d156d519f9067f96927ed156fdca061b5ebf77b4e3412f));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x10df9c88ece30757b443e4bddc3d451eb8e909b6f770fc1c9454e3e97c72cbb7), uint256(0x1950437242bd7dcfd031ec22a22d674ca9a3405a7386d8ed9f83356334846064));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x204fb9c139cf5869174f130a13fabdf0fcc8b1c8c5b484093e09bdb7aaadbba0), uint256(0x0efc346b6abebd392d826eb94aba8e01916889bb2c62fe6e51a67ad8a47e0e8f));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x27d3d02e2844765d7a74f9b96c7edef77c0c56211fe933e6bab529e97f716555), uint256(0x20b17f989e0d2d7948fd20a2ed8b9da6c25bbdcdb98aa0d37a71c6a9b2e79ca4));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x137c86dfa242b62da0edf58f6a8893c82279b6d9a308e4304a990a1ddbde7e4d), uint256(0x0435e152599c73165eb698c2a704ec93e66108600a451d9a80a5f6cdbee17d47));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2642f109806daa73ed7135f6860c62a23ca9c1c8011349aa94d8917ba4cd54a6), uint256(0x2e15fc535ce28aa824806006ff3ede4915c3625ef85f99d5dd4c414ff5bc2b84));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x00ef498b9a67463986f6c3344f69148bd42b7182a2e7c25ce5a0174c62d7cc65), uint256(0x2a991b4f5941eb8a1a8e6090266c439d2fa53279c2a42b7622e7a0102737ef4c));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x10d456720ae9e50d152fdb28c9bd488fb83cd99207602778caca5137d9211889), uint256(0x0cb7ee0cf0ed9ed151e1df796ba4093c33c3a0730c1ec7eb3e6d32edf139143d));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x2e40ed9747373af6e13a2e11d3a918234adc89dd5fff517698e628837523e3ff), uint256(0x256c742ea58154c39f0f6a5b44058c54020ad96713879c6ec1403393179ef8ad));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2a3c6b5a9b575a6c4cdcc469e613b47daf20c14cbb473f26c775ab3c24320cab), uint256(0x2d5b4e96a7e6dd895c066136ad560649bd75343e77008f6e102b8a8701b9edd1));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2d5e71adfb15d53bf6bd9e9b14f19196295ea80258116a2f90398a43953ac6e1), uint256(0x25add021d3f382d37ee376b3c759cb45d4d42f536ca69b4ebfbba95d6b439427));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x186fc9811d4f86e20aedf91e3d869026d049ed78375c720ee672b7427971aad3), uint256(0x045f0d5b0f6c9b4e395c4550400dfcd9e1f6db8e2b9e1f0969f9ee1fa42279d6));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x07c55c4d9d36c3f34c07faab448e1d52f670a6882e8ad22e3cc7d99d52a0cc21), uint256(0x29ee34bbcf51c1ae88266ad4dbbc7afed106c017eaa3a90f177ff6d4027d930b));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x09d64dbe49c1b521691780d4fb90da1769b50bef238d12886618623b31190694), uint256(0x1a968d51886917dbedee5df9c02f443142e38c2a1d670e0130df58cb5961bb84));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x043f67bb12bfe88821351fe8a46f7e23708cc115c09552990ed455b40ac2ceba), uint256(0x1c7a9895b2f34384040a29078b1a774c0a44b979ae590844833b0b9fc0b8563c));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x286b3d090d41cf3dd4e35871def18b6e56f24542801841f94bee29f983f82750), uint256(0x153e7a62f83c422cb9ab7a5d00381a41870ccaa71ed6986221b6da6d54abf25f));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x03488a14006070705ef5d2581e9a323cdcc6ee5ca3010b8b04cfb90751f5cf6e), uint256(0x2ff921391cc02e32653d058033c9435aab5b951327e9b757b06b76c24acb37d0));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2e7b390bfcbbf8a15dd6167e0a8a89b01566a3b3aa8a4e0f58a9c17c7b075596), uint256(0x0aeda2caab99b27e29d119f2b7f0c29c2d159e905f605951315c81105a1db100));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x116e76d1a05045aa16ee79109c50cee2d5caf0fbfea61edd6bc167d7b39cb84f), uint256(0x20a32d87ad40d78febffc4c8d95e4b0814a1e16e39c110a2d40f87404ac8dcd4));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x00061f0704ffbc8a8c3e327b094e1bf0161da5d13286967556c94467eddd1f2b), uint256(0x1c09b1606ec03abcec84ada6445794496155d60c1f17259605bfef415bf1d027));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0e5f23377a7947e08eb3928939af03ff55ca454cc6eeb008726e008c3138ddf3), uint256(0x1869b124c4048d80c359c6bd712c78efa5553aec5c5cf87faa415b39f6471183));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1c4e978a21b865820a53360678c76f3fb428ed81e8e24b1fdd34aac737dd1d7f), uint256(0x14f1286677a6db4c73da7f733df2d08a3553ff0639ec301c1ec12d1634cfee62));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x03aecbc00ff412d083cb5b4e41acc45ae78080212abf95166fe94c4db0f5e689), uint256(0x058f6f026aadb4d2cd9fd9b48e9db07c3e9001bcff49923df4dd89733166c9e3));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x23d398a68892c2badc9bd96f611dca133fafd2ab61ca1e94ef957ea9b0632943), uint256(0x07d1e0ee95aacc666d9eb90822bf178fe4158ea24b320e9afe17028449c368b6));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x075c620e54d387ddb4bf6d7e4786701a1aefa0ae83f1a2aebb68864a34ef4fa9), uint256(0x268cda36ce5892f22ddd6e4ca913b5af052e50108330ae29f2902a32f666b707));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x07ef2e32e8051bf4ab1edc083d84107475545aae75ef71e0584574ca41d4c65d), uint256(0x108c8ea877ef9c1e218df701d3b4b031aaf64acc68e26c689a241d7f84850512));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x02f13fd1448ac9cee6e12f0427d99f4b5cbd73201ea87edaf1fc5a63dd5c2032), uint256(0x20af418826b58c81648d0e5366a3c2ede647f0c922643227c2f7b5e0b35f6560));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1083d2a6a5dc3be52da5f751431ca2e1fcc78d1b2eb5753ca5570571d456720c), uint256(0x1a2911809340be7a652d51c8f211ddfa3d8de4bc91550e8ccaa415987ce34631));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x081f53260b9ceb0ee42d7f48c2d5ffd8146dc05b6c584595f26a3f4a68b8b5ae), uint256(0x28045c98115cd3b9a05b91025d5b7c78c2e8f847d770a23bce19c2ee055026b7));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0cc171dec35fe0a7c484661df7eab2dd832e14bf663a002470c98ea1a718cc13), uint256(0x2b8c07b9e7c0e327d1a7c980e64ab5ec631af44c0921964ee45d6a00b9d71241));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x13a88c735d4f52054e8c874747aacc4feb634238959cb994bb328a02510d7e5b), uint256(0x0a46ea0b9eab91c037fba8aac86434283549a344f45444970ad4ee3cc4aabd2f));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1e980033e322e6d2897a899b966b266c029c8f2d3524092f395cdc6da9777099), uint256(0x119cec536358e90f87474a1ed1154ec367cbf2001cd305e82832e398429224c6));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x1f7a45aff9c4018b07e5d5efa32196ed469bd491100e105df889c944814940e0), uint256(0x2b3dc5c2d8c52c67e6da05a66e2aaf2456e0197de65f3fd684307c3126f9754a));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x02dbf5573d5b1d7d9253e6a8803e2eb9d7b63e4213b96496f0d4047a4561c5ef), uint256(0x0c1595cb42e22f728afb7b664bb0aceab5630eb4842293e470546125efc805e2));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x18865790cf52daf989d1543ffb1b4f29bd8f4beab2465139dcc7c777634ea626), uint256(0x0df5fd0713dfdf4066e57039fe1cd3caf70fb509db5a0167c250b988a3a98f3b));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x01a20cd525b69da9369209840b10b00cd4b2f4bc34bae42d7f0ed3db432a5355), uint256(0x27ea22023b5f42d3fac1e70afa57e6d297c30af1d23f4998a7a8ec7420a7ad9f));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x10e5d3d894566722ddc709c6d5cf722a5e7a1a77a5984f01f32aa9aebd425750), uint256(0x1b54a10d81428d7a2bd897e9003a1d52ef23746bdbca22fed6a6c8ee6b152e7a));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x2a51b915be61b8f932c9c5524b85f94d8e239b5288141f13a3d346e59bc965e6), uint256(0x2379f66e7c10bf7f7dd00c93fa888eaba7905220538b9bae5d704d4d8e91a959));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0e830b66ee86e5188b7e7198735ca0e0ef0b9fdb262a2d79d57ea0b2d892f80c), uint256(0x241f0688cbbceb5e1b858de502fd3102ea1bc3b9f46e49dd6c8dc709a7bbd0d7));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x22ac1f46aa7a96d6d4382e39a02f812adc350360b02579f43948d066c5d22b5d), uint256(0x15c0f34a83970229c47a4444df45b196cfea3f411251ba59ace83d08c7bc758c));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1340eaa3f882631c8108a1b6620b8fb757b55b78e3c8ad2d8d0cdf5884d27a49), uint256(0x0843cc0513fc22d49bd256de1d0cb21593459571730804230f3a4454c28e08ac));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x002f4deeb0c8d695f57f1b3f830b304053524e00a29b22c3bde6f01b4b1a33ba), uint256(0x1f4ef96e37a00ffb6fec2670d76cdc7a5a4528f83382ebee924308f34a8c4dc0));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x1648a19bf3ca1eea1b92724540f9655c9b91ce6221fc18ca221b2062a14ce4c9), uint256(0x187b1a90c32944a1426b89071c3ba8561d0ecb6a0541efea200f13250792f29a));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x11b8cfae86e6127a68692ff8a189a9eeba6fcbfb36a09e0e8157adadaf8cfab0), uint256(0x05bb786b6dfb8f50f60317acf4c9f57ac5739ee68ad4a0733b00dd4af8d1b8ce));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x29d07f1137152760dc3b9d8bfa8ef0e57122e20f10d9e95d0a50e41435c40a5a), uint256(0x1d3fef05972727ad78176a2c6796fafff5ea4488179234919056b1622f31de1d));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1d62934af8e9cdc3f7691d3681225f2c5ab67fcd44cb4fa51f40078620df1fc5), uint256(0x0fa26705012642d1a3871f3212e4d811468bdb94456c6dcd69230118ffbc2b20));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2be965b417274bd723ce725863fb8fd1e66c21b72cac52ac12bd81db8664b360), uint256(0x2946b4a19c19acc3db87d17e19e38b3c5f4d823da9dc8ff1e52b516bd8af8250));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x1e935da5351edd69c0c82640f10b9e44b53a237e5d77a5abb84360a0bab47d55), uint256(0x260c8e1a3189d2aeeeab9a31bf2df982c360131493a3ca2cfa71fbaf31f92a0f));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x0f006146a63087249b47b1fb639cbe3d1b7bdba4575e8d8f0b597708d887b5e2), uint256(0x13901698a1f4d81301e01c0f39e8e1911b61df3d5ad2db29919df6ae6e2a6e2d));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x1ea05f2dd7d1b8f021b7ca6ccbdab6ab5921b75bb04108ed10928c7f120a6d6c), uint256(0x2227baab08b38fbf21bc39972539e0ba1dafc33d0df341a06cd9d2195d83d557));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x2bc5042045752f51c19f427f28c39cbca25173266dc0a6d6a72fce5b5045000c), uint256(0x15c47e12f15c2f4e6fd2ecf0edd6f81497a65342f353b482a45639a5115f8416));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x023e160d2916fa89abbace45c56fdeb5de3811066f3b3825323fe13f4ecd0c87), uint256(0x2748cb4b0a624fe24e13646dd86027a325acd72ea245422816586fbee1b50fd1));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x0b788738c6d5cdbd6ac3f8f86efad6601ba6cea056fcc3801f34287f25b92ee7), uint256(0x1297c5b32151ed88db39ad5fe649d37042174629ddccb6564d162fd12378cf40));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2d121d01993bd8ce9658b0c85bbc944e5c688a851a23f0259c9a6f3d35d3e67e), uint256(0x269c090a314bc244d13e2330878908472b791593d5e0d435d00ce618f8f89613));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x18c5a584ca3a66ed0ca40a3461070a673dc41e93ba1cba6288c18a076ed3d83b), uint256(0x2ef160b96ea9116de801a8335d42735236025c443ec58be379e1eaccfb49aee9));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x273f10115108b31cabb3fce9acd216063e6b2863f2f29fe8cd844ec1c417bf62), uint256(0x0ed6be734a2c22bd74fb75004560f120298fecbf5f0a98012560f9dcf82f0f65));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1f64327e3b07692859a814fc32c69650f6b7ee43ea4d1f08132fd445f8c1d49c), uint256(0x2af5cfa958ea05e1d0be3d3a62c9bb376d48f1fa7bbce38aa87a496683af3512));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x017589ee327c5c2cb27700b7ca9bcc8b3df0785fbbb896db06ce2e1535050f77), uint256(0x13c46f1ec06bcdba2fc02357cf17b24ce554d40346e24e349d868c9b9d4bb0dc));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x280f4a9eb92e19a888b7ac4d9043f221f9e7babb76e8e6549f8de8af8e424384), uint256(0x2ef0b074b7599eae44ea44d16e3fea2068afe88e07fecc8f55b6a84859e79be0));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1055ed7ced72e5a77bc82c8d853a2cce3dda0d77006aefd0226ffffbb2a9bb88), uint256(0x0b0729607ddcbb105f9d5a56901943383254835c93d2ec29396f55d5c607e0e9));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x20085451eb060bc20fb5923fde5963c215524fcbb562ee7f84d443f521014063), uint256(0x16cd030ec096571f6a2d14427b05cbbb322c465ced0f2a7f9beb130ff91734d5));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x166a2bb94b418a627e7ac2ed5ccd1ce1b784e907581061e18a65ad09ed75a26c), uint256(0x188c60b4364a2d325f8377e203dfce25ae400f8bb7db1fd9d06a827ffa70b35c));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x21e93b632c69a83deac100c87c63d057a9a87a1482f55aa36dc2d221c8fdedc4), uint256(0x0bd992b5a7bf9765cedd1e395039c4d8ed98d0d0bd01a9d06b8ea944285a0c5d));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0da2981002bb2f3c616a9ee3e6f633ec490f11522e988682b35a8d8e477f5317), uint256(0x1610fe8991b01437b0a7a37ef09cc46d672c9fded729e47ebae8d2c6fe1ba61d));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x25a82119243aab5de5e64c54e3c1f5ffe2a4c516ea467da85b14a03d159136bc), uint256(0x2ff51833f1cdc7ebf38239ff1ba021bab3c878b53db57c88cb2b23cc321ccab1));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x29875fd935f117099b560f6ed4c43e4975d44690617dc19ff1c3cdc86c62f62d), uint256(0x09a46967a67f41ec5758bb1f3135e4bf618cff663ee54192cad85daec3376d1b));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x23e1b8c75a75c8f589de378fd1f2377bfb59803b5c26c6032b5f470be5474db4), uint256(0x0fbbb48f25949e82c66801d6b896a77d05d0f89e8fc84288ddacf4a42bea9a9a));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x046e6f04f2c75920bb6a6bd7e65cc536dd31e3b9c92a73842e2185b47c54472f), uint256(0x07eff33cc4b2e885133f17c2fa40a391e60d9ab235b5f3ca6f6d3c0bc8d8f4f8));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x14ea314cecae8e90cf42c3546933539dc1bd8da51ce7f97ffd5c17717be4341c), uint256(0x012cede6cadf77bbc14e83476c3c26a7de242ae32868184fb077fce2c8c7c77a));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2cd8b4e14dd84b44b30ef34f5d628cb4cf7eb54fd4eafbce0c1d5c87268e72a4), uint256(0x11450cacd5a5e559e4734ea52c2e859e0371fc63e9c9eccc00d415a421145d92));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x11164e41f9d94cd7fb2a6db6c8b80ec2016a2707ee7a0b2c555dbd10eca56061), uint256(0x2a6ae0b52c4eb4b580ec5e99b04447a5c7cdf522fb1f8dc5fdfdeea00ab60886));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x12244c32ddd8ce3f22a037b966f39636fcd1a8736ef9a2fb937a374f1123201d), uint256(0x0bbecc5fde52c29758325a9bef867939533a916f8f669024bb27e77668bf6740));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x0d58fe254e59e155b22610ba4ff29fe5a038350bc730d9914c4c893252989639), uint256(0x2b3d4edd219d137f8cc3cf4699e1b56075724eeb808b33cbf12c9ab29bb46752));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x149be4f7127ca4cef71cb35b4b34470024da34e25b4e0390a42e0451b466a26b), uint256(0x0a061079f16cc94e92037670f35179c20d905155574ace31ce0b38f42d47f980));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0394ae261af251139aa0717dfb0eb48bedc30d118f8d63149af270c681d8a98f), uint256(0x2bd94e4368db128170b02b7a2b5f1286b12b4a4aa497ed6258deb05d48d41326));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x1ac6d29f98be94adfb96c77e6aac242a735eb4dd8cef30cfc6c7a201d3c3480c), uint256(0x248bcbc3f84e934a62bfd92d2370d5bf2a50e82ffef56d9dd8c58cc46fff2239));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x1f7c1e53b83496d22ae1716cc741d17b2beaf3b92e8f1b3a85d5a3defc66307a), uint256(0x08a60c600cef903d4f68049f9580c605d95dcba60d5fb2230da5c173ec0d1b5f));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x29b4ea66c03af0ae0208fb142f164ae9b8ec3b930bfeda0f8391126a31f323f8), uint256(0x2eaee77050ed61133a0351a6c1682b0ecf2cdb525ccfe7d28ecc6b233b16c1d6));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x020c148cffe150768b2c7c5b11db2feaaebebdaa065088a393d78ea30d4d589d), uint256(0x1c15759b6cf675c6946d6699c4fe25e8c76b4c007e725b47772a1b1e39c0d37d));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x0d26840669655e96b2bfe3f28e47b9e1242db5647da557782144d57d361ba34a), uint256(0x2a934d1752f05f759d06ca795c133c80909ded404f70b4f64ee544d92a783e2d));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x0a03fdb582a38c47087aa01cdc38284bf6d88840d55711c84f0b060d78098c7f), uint256(0x1a135e92655b7001f65f9425d55008fe4503aad22a8dd7fde2ab8ce9621b34ed));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x194715767863d1c49bafdc1052e72849eb92e1250899e1011cb8c999739debcf), uint256(0x19f16161f20a55efa858446e0be41474557a0111be6c0fb9f44043710a11d999));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x10fc5bc85d5e7feba054c14a3c48b61bdc8ff1df03fa2eb7a473af1fa6165ff8), uint256(0x1c2af59c3dceaf4d57d875d8cbf1eb70ade2ec317db1b12b93dd94fe2e2594f5));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x17349013234ba8e5f077d7f5a62e150282f38f2e7a1648110a216bb6360ec4b8), uint256(0x296540c89724212d8f15eb0196a6374ca5bf977d823e8f4e345b794d34e3c141));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x17a0e9b618e23c94b76bfe6ee379a1285f8ebbb853dcd9a2619b4dcd4aa2e133), uint256(0x0d279c8f97085531e0f8854905d1dc0387a1571874b0ebadc45f98d87cf1ac55));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0625d344ccf30d4183130afe51a882006d495566aec42333be59e85f1ab61b38), uint256(0x21b3d9aceea1bb5e8370433645619bdb0fb0f6a5b115ebbbc3a0e95c5d636bde));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x2529d1c8a66e00acefa1ddc85ad156b1de65d4a20c26cf350de7d8f159090956), uint256(0x087286ad37b37f8ff6ed6788272ae5140b8fa976d17586f08c5c195cf48da61e));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x1a8985d33368c39133933d3e085c194a00216be4df2a8afb14d54d461dd2c1e4), uint256(0x0caaf435efbf232982fcd9332c2bf0da6b9dcbb7c55a6aa949e31dd9961f021e));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x21133d5b89ab6422be283b6475b5674c5294ab3ffbbf4f1903a622eecf0afe70), uint256(0x0b35b13a7296a8ac0922efa212b1477d4ae63bdd703f4b4b8f9d683847fce621));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x096852ebdc652f0c50c9d9e0c0d1d7dbd2225861010142b1326b01702d1b9ec7), uint256(0x06a4bb21b01c88f027baa5f4c738df8b748d1387ef6c18d63cc6940ec0ba0431));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x110f4d04f1755621bb870641126c27822652fac7f3e293232e8d1eac3a2e47f7), uint256(0x1b39bed3b2cb79b3e9c64cdb0ddaf37cd7d17aa2fb5a7b54a3c0b29db73922ef));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x207c73c585ef0634f51ca263d31af4eac50aa27bf26ce65562a5f4f05886a52e), uint256(0x27f8892f853b9ace446c5ef84314b04a93d959b1953ad9070b851581f4a2fac2));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x2342575a5173ab3bee4ce65f9efc740bc9cf47569c6e231ba9d449f8a8be6233), uint256(0x18cd9ff8ca9b3cd89a82dfa00e2a3acca738027366a842af528111736e842e03));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x135401169637d7b278f16a5a3c9cc95d756fe13d904c703ad0db35bd8d601afb), uint256(0x09904bad508bcff0dd1b9fe14fcc917065f642fdc08a965d1e089f60b0ab1340));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x0ea3fc23c1496808ee46d916da71f29cbe4c721ba8b20485f973edd91567c054), uint256(0x14004f3229e77452989e83af7b1d1fc7c5cf613892967f283110d71df6ed78e9));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x006a5b07f61d0b2be7088c94078535783500ae46e1bfceb0a54d18f63b32e4cc), uint256(0x29b0fe4cb60d72755da3991db9e67eecf944b660b40c0e08e2f6e72b65c4c717));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x1bb20cb8bdf3a2088f5fbc562a15e8b382a4dc1db4cad034c52ea27c3e65b066), uint256(0x2edd3153af66a47c5207604735bf0e71b0152eff711da5d9995084388985d9ff));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x1b8cb62436b343b7e9529f27bb106743b7f961758c8eb7c5d3c3d153d8ba5a67), uint256(0x05c02248662dcd22748acc2f44852b7eafbbf6b0504d80e3f2d34306c8985223));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x1142135c7d6892fc2707786002ab61df23251213a2d4911953538c9c9761bda3), uint256(0x0ff2d8550e4123642fd10f921c09ac125eb8df3b3f10854e6ff3f14ec74f4b11));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x106f6cd78efa1a1830bc804108470c8b1c9e10f1cee482ca13fd46aab4432f3a), uint256(0x28198f8ebfe53d87969d047bae88d2ee6aa66b75664fcc0b1461430884426432));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x27b49d8506aafaa89ad3e9c319ed781289880dabe2e8ade0aa722dfacf6efc73), uint256(0x042d553573afb81ec0e553168c1ce1311b1fedd47150ca0c884ce58202302508));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2fe94ff3a830fecd85bbda4bcb593095ed0e5a4a2c1f7cbe009070db5b649b96), uint256(0x2d4f3a920fd83a0dd138c51399db603ea2b8123d2279e0cd7021e38f126ad1cb));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x1adeabbd10527368c3bb02899bba83ee1ef1bf8dd36599bab70c35baea8f700f), uint256(0x055ed0ffe336e4278cfa8e2e9cee4e7974ddabf5599127e8723daee6592f23ab));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x0b7ca939b21098a2c334b43546c631fea9283cf9897dbddfd92cab25a23b38c1), uint256(0x04d3315a4656126b17bb9ddd76d3bcdb874a1c9507ccd12fa60b99d9dccd043d));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x223ff1bde419c6ffde40a39394d3cca0e0ccab4e851e4ed8def2cf6528dc4f57), uint256(0x1c8a86320aeaf632ac0856b628bd29b913ac8a46cfc042334dd18e09eed1acf0));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x140f1c4d44f9da5b4d684d763d8c8ba3edb5ab414c452fc3d3c8e58d2623ba2c), uint256(0x0892c9651cfef48868f121fe5de4d08825d4ad4d649956fdf2c409e175cc6b1b));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x2f424ccb7dd27b0d978373956e1189b7c1b8b791e8319c1b610148fe18beefcd), uint256(0x06703e8f1de940cee02855c420e9d442a9b8b3fe0a847b9e27f390f64259991f));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x14bf3a0984b6150191393ec6b23ec4488ce07ebb0e4b04fd8cc79e6673e54ecf), uint256(0x1c32cda9d3eacde5eb2456bbd452b891c1a15e94df95f0ab295ce926fdded88f));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x129fda977ef939b62b3ace5eb63a6c6f535c49af2be06e243690ecbabdc70d58), uint256(0x0bfb94ae83f96796e17f7e3ea0cf781e2ed5067fe0fa594e7b21b41c7b27c1dc));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x24b9fe9e7763609070d9eb41058c06e7425d9916033227b31187cfebfcb9d7cf), uint256(0x13659ce5db6d26883b61176e4a15866ca1a575bdb3baa9660b9cae0df1d35f7b));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x27f3682394ae62ade6930af00d76d0e4aa4774cc861f850c1882c649ff21a7c2), uint256(0x06df680a71f2e8d63092b9c4ff10733eca8cd595acdd881ce6e3a3a89824f3dc));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x08f182a3f3394cfe258397fa00d5e4c688e25b7ee8668384ac46a3935de8a7ec), uint256(0x0bd1fc9db733c310a0a530e2ead8e1923f515729fea12345b89208423cf912b2));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x10b0089985ca6aacd8425924adca980e13b33115380daa3f64676a660feda0a4), uint256(0x175a2a13a053dc6b52c4a983a0fcd1d8f3c936b7b3e706dca411dcd2eb4f86d4));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x0e4d31d2213a3ef40783a80e2195a6dae096fc96f5ba544ce0eec65a9ce11079), uint256(0x0b49985deb7adc3ee9acdff088b0c118ae4e512ff4ef060d799bf3e9bac8eaf6));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x21fd017f57fd5fd0ba090a8c83180a1ef825e8570df88b998dc92b25c1347f1c), uint256(0x0f3cb7d5a36545548af1a5519b3a4ef7fe5c3114b1ece6d9c70b3493594a58b7));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x2e2aed1026870e322bd2a1083ef7b3ed9304646fd941bf00585ab164ff7a7a2b), uint256(0x1cf267369a54c21ec4848e832148683eed8b3fd885fca025449b485b7ee7641d));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x1572d40127e18b0b0864b05fc387508e889fecfdb584d26a23aaa3047b51ea20), uint256(0x18f170bf19c53a5177276ebef0a55edef948774ed023d6a4a0bb104195eaa614));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x2f05d3056108b3762220c325b74728cb0bf0a57d81fd99235ed180d960f28075), uint256(0x2da755bc51eebca96ffd0f30d3696c7d7931d37b8fe54c1b6245d83653fadeb6));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x27017df7aad1f17b64c1846b5990fdb34da31260f5d6a6fac91f554704cc2c8f), uint256(0x09e8468868a48d5443c0f5b7418c46f6c6610cdfa5166bc3d9bbc41fc1aa3478));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x2a92d2f886995122b8bdeb3e4d84f0d1b9f7a111d3b1f41969c32d7f8b1a8787), uint256(0x020d119aa2cbcba0dc29ed1b9477bb51e135556e8c3b8dfcb08e194bef55763f));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x235cedc878d55fe9bd81c76f4fce46559f0fced462b27aa83e166d0b7e886c7b), uint256(0x005057b8cb73526d7c48ecf2dd5edb44c7d1df4986b0796a0ea0fb42b6e6e1c4));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x1d3aa54e099e979342cfc6726a26551e4bfabef8daa2e2d645f4d7bd47d202e6), uint256(0x053b2879569eea21a8538db5dcc65ec18af5b9bcb1e4d0a685981ff4b781a667));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x037abd0406a5b0f21b300917c89a8838dbc8a6836338ead56f67439cdaf0475d), uint256(0x0e692c98439593c2008005dd49ed58496bd9489123b9e6299eefb49a52d3d6b0));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x1d679a5b052e6353a34d7d71aa574c5571ab4a9f32d186312aad8b34524f6959), uint256(0x2640265c18f6e9c6e88c53cfbe18887dcc70c55d106e124b3d9e663eb32deb80));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x17c7ef2bc1d7c944e37b15f498cc556e89c498f5c22a3677a054ccedb8676a32), uint256(0x111832a80da69f2248d41debcf6b9450e4beb7f05a14308ee0676a334504dd75));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x01c3a390ad4103ac8f43988287ab88f52414f64d6b1a0f2c6930c42ae2913d76), uint256(0x25424f25a3ad6b10daf2d90b5f0d185b0ab1fa02f7fe82e3656adf59cfca2750));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x17aec58670d0a1eda7eb767b0fd95ea5ac150196630bfaa6cf925e964ea2fcb8), uint256(0x0aec8b15aa375b2058588038cf21d7a0c13522a61b4fedee1312c81fdf13e34d));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x264cb93110df78427eca3b894c31d8c87587bbff1487af71abaf0d4886236254), uint256(0x1731486f6aa25d146a463bfe106289f8bee63c431a29a76ed9b2dcf61003a13c));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x058e9b093d9f9c1927f89bcb3b51324f687c69398211762de21ed9a8f2c4a2e4), uint256(0x15080b961d66563d6b5a444e84d933d1495670ae9ef66356233b22ded4cca5e9));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x2fc0fd85ef2d5b6ce3c5fd3f720743d652ad0f21b6794738cc6f9fe2c7f8327d), uint256(0x2a9177e227ea09b3f787f1f7551cce3b4e0ef151c2637c018fc3a280e952ce3f));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x0097e705d6102b60193523ce97fac8480689defaeab7cadcbefc498e9af3ecd0), uint256(0x213ad2e263e30993ffe5a633f11064a1cdc28cd34616ea9b0d36c7ab61d6aac6));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x2363f885b4de0f2077a97ae9fd863a330da55f42ced7ab691db3eff67201b137), uint256(0x0c709fb837c308ada8c19b441f58678c84006088662b9fbef666153f6c474903));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x1a019c0df059b7fdcef85959ca0b271babd3d7f193442d2a9a80be2e6d76c5c9), uint256(0x24564085b87888ac941e5a6520a287e60eb3c8f73d6c0f65287e0b09f47d838f));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x1167c321225979405947a702de3d2a517816440c52cbab4ed3d7b2d69a22198a), uint256(0x2f2b3f61836b6f09e40f98be0d9d5844bb0752801b8f0207727894cb13462623));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x27220cb6bd182a70f21aa4ab326739f3044038576ea4528658419c436eaf8a7b), uint256(0x09edd0eb340290b08faf627cd36753d2e84866d76408c06b10ba6e2e27a75a0c));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x04c11d23e15c555b5b71f423746f009a7bced2a923c01af0ead7ca4c442b1b11), uint256(0x06ce77f2461eb1354c61580e303854f0ea726230a2a9817136dc039d1febda76));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x084de5e54344a819e65dfc03d63d9c4d23b998a85e23bacdea4e46285c552330), uint256(0x27f4ffd9d488d4caec3dd379f51c95ad43c08733a38acb6f25aa29bacb609102));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x0de5eeaff753576e557b315a46e2cd30a06ec979311b298df35761b7403c4005), uint256(0x27f3b6d94da68e490103af4a4beac58bab184222542e1553256a297ea8a7a113));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x19bc8140a9aaaa8aeeba39616719e56f7677fbc26be33ca0250f96cce0a18008), uint256(0x0574f4828ab580364e378d5ef48d2507f91d085388d93c5bcb1918919b0fb391));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x0c0e55911a0e0d9fca018530f5ce478d9aee45648588749c82aaf8d85df2d591), uint256(0x0d7a171b176218344d8f0635aa9283731bae9a9692596d952e171d03f7290d2b));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x1383cf88c230f9ef2901441550f350fa186a2e67a00235b6d0bc45b55a7c6e04), uint256(0x211fa989c6e353a545d75fc94ac6db6881deccb1e345e2f6b4f06ed7e7c7f9b0));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x1534aff53bee681ff708fe98f94fe922c180557d5c4c5fc663a0c3506759ce1c), uint256(0x0bf4ffdb457c40c1d81c20f1e67f87a6f45a256fec8a36e0c2119fb7723d3a85));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x1dfb2ae76bd054897314f48730e28f0e44233af8bcdd8bb53833fc94c8a67a02), uint256(0x08591150705911967092748d2347b0d493c0fb4af2b4b6b911fe456575b1a694));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x14040415787eb614c07a3b681700592be2f04e42ec2d07bcd5b575617263565a), uint256(0x186ab7c463747c874659d9009c34d5726165859e882b50a29a0d2c61ee7afe29));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x24b1903e56d127eb41e461bce73873c7872b337cc7a17c6c614d196a61e0cb6d), uint256(0x2dda1ed6af70181f20a517c4a7b9e8255174f9b28c74d1492a8c8193b7d4cf1d));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x1daabc11027d7282d15def2e526f3dfd84e2471602661ea77ae36cde2741268d), uint256(0x040b5f93ebc3ac8b048654fc4faa76bd456d3b25d62b917b7490b83547dc4733));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x1389451c5062f0b6838ba90e8aab0ece78146f33ae90f8796191512d59575181), uint256(0x1c69f5edc8bfcd102a8a8732cb720ec53bbf50552e5fb119221f507097680152));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x0c5f7d968f1af7b3a7a3a30eac1682b0da3e2fe8411be3a9f02782b37adb4d9b), uint256(0x0d0aa9a69dd432572d707cf894fb950f3d015d41aafee11f2e866c0780e4d9c9));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x0f5d516d08088455c41bc324a994bb1314aee2f9b3a689667912c2cc3f023ce8), uint256(0x06ef39b1c4933a2cdbd7d103a1f1b32eb597aa23bd9305e27877eefce422cd1d));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x1725f1b49755723024f650bf337dc4466031e3fb3f34d7786291de16a75cdc49), uint256(0x2f85ebd88d9fe17f67d347ebb97c536a59933a143326290a13d420ab6a2afadb));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x17453135a5117a2aecc4262835374416a36bdaa4c2ff54c2fd617ff81618096f), uint256(0x0097a47ae12decf6b514693f6bcfb00716c1f3167603eda135f7df111025a94c));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x146b5325ab1728195568037cfb46a16c3ad392f31d9257014663cbebefd6377b), uint256(0x022ff40950923c6d414128c46f29ab0464d0a76932056e2a0bb563efcf4630c5));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x07278b3cbe2a1110f51f8b5dbdfecd25d7f8fefe6d661926dea49bad8bae04ce), uint256(0x08fc8f9ad835875b459d3c0060a23df0eec0b184f68a3c80e584fee702502207));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x123b781452c9b99941fd3408a7c2108f8c5acc56f6ae271064d560168a10ec5d), uint256(0x301e3176f6a876a9d918a86548b58ad7b294e797bd91911bdca0d8ff9a37aeb5));
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
