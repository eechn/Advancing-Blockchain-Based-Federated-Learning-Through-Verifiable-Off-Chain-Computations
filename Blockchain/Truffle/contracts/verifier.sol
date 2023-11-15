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
        vk.alpha = Pairing.G1Point(uint256(0x1f7a1ce41a2bcdbc42cbb6f42cae380db0b2a9d3bcd542eb93ffc875e7a2da15), uint256(0x1191cfc462532ad199f3f917fef2d01e8326ac61961891014391e50a5b9a763c));
        vk.beta = Pairing.G2Point([uint256(0x04abf756692912186f80f0f1a7dd38f0682ebe290af80620eb03eb73a47bef2e), uint256(0x2eaf47aff40ab0947a085edd00f09256645c56da2ecf9f09744fac48bb3f9efd)], [uint256(0x26aa541298debecb59caa98baaf187a0196fdb6c860055cc8b7017f5212141d7), uint256(0x069809648d5ca239a09db4abbd05c2736a320d07752386bfa5221e357d2d3133)]);
        vk.gamma = Pairing.G2Point([uint256(0x113a039a2f8370eeb3bca5eaa46be726a5445f2bb3cf5fd02a87f5f20ae251f8), uint256(0x0ff1121b8421a60e97abfedf80dc2616b5ceba15ed98b1794e00e3f23d4ab378)], [uint256(0x2b720afbe8718d77e6fd58c1294d400bc6fc05761b2806b4f14b3903a90e89a9), uint256(0x1d3e39394f33f73971005f0c404a0328fb8de7fbb62e9b9693dfc24fa19c1451)]);
        vk.delta = Pairing.G2Point([uint256(0x258f38ea288ddafd8fbdcbf15a7b811fbb37b48017dc1735c47b261c396e4135), uint256(0x2b67ef9d0be0381d14f3202615e8ea86802e05b6bf114a26a78b71cb61128c4b)], [uint256(0x2e80a106d5b6ef3e12f541729185b07f090eeb704daf9bbb7e37daa4c02eb4eb), uint256(0x0f6dd34e847057a6fe9fd47e5d694b4d1cae9bd741cdc6d0699b640bab6426ee)]);
        vk.gamma_abc = new Pairing.G1Point[](202);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x06dfea3a6c45deb1dcc0dda3c6edce4ba941ebd4123564ce43da8dd26bdd5791), uint256(0x22de825e9c52598253bcaa038c6e1880503dcfc1b61b08307797136bc2aefbef));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x14a0d9edc199469e0d0ad2eb3bfd479b5b66023e201e94580b3c9156f10163a0), uint256(0x2687449dc19a55b9805edf2420d35fb79115f5d4032d5e7d13d2f63d27e16be4));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2c04afc2e6331b2d862a3085fe27927c9f5c9675d2377e2a4c6b60ef1abbfb3a), uint256(0x0b2f4fe3da45d2cdba0bbef47b28df3df73c024a3bd068bb0dd2420b6f2f43a2));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2d737609496df9e132035b772d390f2e3b44f40d5126d104318fecc8167d7776), uint256(0x0db5c771ba39fcc9b3c6e3829382d537a84975c0333a9aa368c149c54ff6bfa8));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x25a1ad452fdeee63ed91f91735f969688d9ffda2f2e972be7e1d99ced14edf72), uint256(0x0da59f20d1fecbd22f3cc7c2e8bf9340616382817c94df43003a801b7990ff77));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1cc9ee897d9ab557314827616102a3069cc25983ee8bc9e6ab2084b2c5232812), uint256(0x1b86f3957524d59b88618bb99de2b90215b91764d6f3593472a73c09b503f705));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0554df789bd041fd0548786c8771f95342a1df6dd51436fb70991380bc5128a7), uint256(0x14f54849f69b3c3dc91ada7a31c47a83e880e676d3fc4854046251e4d73498a2));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x20e22cc30dbec9c6790f0d306d80b079e0ea810fe8691c316f40f097c6c8ff96), uint256(0x0155957044e400e181b82fbd1377f97fcca66217df40d3343704970baf5f91eb));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x108b001b77379b71133868d63cf466dd21758c26a4500c78062bc68b6d62ee51), uint256(0x0e72f5f6da80110655afad0d606c573b4b882acdc021925194ebe6ec17d5d413));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1633dddb687149907532ac140a6030f772d0a6006c35e5d108c177643fefbde0), uint256(0x052747d9a1f1c32234692e0607e685d542dff5cb135d9e111ebd50bc98be9214));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x18acfbc8b0372e38fd7f6ce3a74744a625fd27463c125a5cfae25f187aa73285), uint256(0x0614fc19a23e649abdc82bdd0c8e3a30545c283f7117d12c3d7b061cc178c916));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x22d312f75268dff49ec29c001a8ad583d95791f45b8771df53282beb26a5b2b7), uint256(0x0e34a9a826a9f73255b293223113b783f581c129b2165ba37a357ea0c5a5590c));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x26df0e3f27cfdda21742d64ce78a16957c5177ba92c1d331a0ea7f129590bf38), uint256(0x05db48b80a4604e88a5fe05cc8ef7efc93cd5dc05bb41c3568c4385a3073c05a));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0f115d16b9bfd61c09c639e3d3fa6f1bad88c150835381e0288478b04ab53930), uint256(0x089670fd7b048c6d5a78d1d1d8ff45614c651e2004e97f24098931de8ca479c9));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x192f56b40d534e81f9c4dc82a6724f49946b2c90715c5e98ab54eb212e5b5f48), uint256(0x056b04468649d7d73d2bf9019cd37c4950a744a8ce9c1a4026869d50bed351e4));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0b1e5d39055571e01c205d93fcec9cc150ce7ab6406526eb43be6397dccf7850), uint256(0x02b8c6dc3ebf6c3b28d61a843941f3c3be154d6325ff9f04bd75b523247d2ae8));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0105e77b189df8389bdbc4df6ba28bcb4d167957b7b368fa24b31b0a07099d97), uint256(0x2154d1dfa33e26b8525a78276bcd5891019b1efb9e57c1d1bd2b337892e184b1));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x29e4147efe0819d0bff0c05d36569fdae6f3d92151e6f593cbc510d6ff009fd2), uint256(0x290a299792911c1008ddefa1253d65a5dc80779e2078346b97b7540d6faafd9b));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2f7646585cf4383fa54d12c7ce6be0ffb9df11e32737ec54937b7804a7d9f989), uint256(0x0bd31d665d1d7f3d333b0496594235e380da10e44c8074a421cc362c235242e9));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1f31995af83ce51fcd4d11c0a6190797304fe784d8bf5f6da05dc4d8c9437799), uint256(0x15049866b365544006df621d41e8cac36bbfdceadb86946865a1f23bc63c28cc));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x23be8f74a5f1784330632f8f9ab935fb55651d863ae854883ab0201e4de30cff), uint256(0x0450ae5433670cf651bfb324d08ce2ec8340a1fe68cae6c63d955f647afcb63e));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x22c0fe427d277ad8d4e1e3d2c39f0ce8d0df4fbff17a23e2c08d18d34234ef36), uint256(0x09d675f422e996014cf6e3ed58c6d94cf1a0fca38615fa0cc240a7a03c91acbd));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2e38b2d9426595ab8ea7b2c4e753fe32f1d02ed0885fda0cb83963e8c47b990f), uint256(0x1ac4e4e845ffbe52a0b9a5c59f4f2ad2b658aadec94d0cbb700d1b78f87f682d));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0c91e9df6370eb81ad69cd563f1228f1d06947175745279b464be4be729299a4), uint256(0x1f6b14956506c180e372bb470712ac0c4794be891c063cffc0a8f24496054f49));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x262f913d8de4eeb87d56fc6f43474d7245a1eaad4dc59b0f0b333d60f07e2658), uint256(0x18dd87f1255a951241c0472d6d960eeb87dfc65230b2541d508ff675eb688ed6));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1c93b25f3da0712edd948b91ca842b5ee40f285a42fd504db0794f33d14ffa9a), uint256(0x0050c1d5efa23310595d926e37ffdce2af5ab06933d9c81c7cc6af213e8407f6));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0302d78e423985351cd765248f36788d7e435311aac0c75ccfddec17a44b13a0), uint256(0x1f2e75b0759de90ee8723849c2bfb0896a7e0fc9dd01af3b44c3e56f48f25054));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x10e063bdf966aebc96654af8fed4cf057f31d947ce066defa7847bed77d8a4f9), uint256(0x24647210823cf40b2d6a8af29caf2452a31ea6fe772381ed3ea5d96635d9413e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x02b4eb6a7f309c26e44c1723f8b22264d5a53e4fa7397a16e1883d7eca1851bf), uint256(0x06e9545f5f59c5e79b5491feb1ee1abf04da141ed1d2bc01804fa4e61debbda1));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0eb75dce9c35a31adfc162c6ad3d92b1d5de07b8e272357e63571c59f8ec4b09), uint256(0x276c450c8161020651517d9b33b2d86011eedc5f49798ed79dbf694a8945c9f6));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x28c54cd7b4aab548716ce35cd32c6d313b0effc320a4cd75334a7f39ec85838c), uint256(0x1d8fa9c5fd52032637477bba8fe6900b542bbaee1901d410ddd12297566bb166));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1ccdfff860d0b6aab94bff6d629deaf7b516b3c6e6bfb88063c1d8e9315a6028), uint256(0x0f5dde8e5009835d9b2adc0cba7cf0bc9ff6139e8766485f665e70c5f91ba986));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x14b6fe83a9faac80bda2ca93e3e98aef16568e8458560db829dec0a3ea757ad4), uint256(0x1c9d2c7c40a5eafb26856842c647e39399fc1c93356506f4905dc6f9e4b8b61f));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x02d0ad866a1c1ff36e6c49bca923c0f2a02b4901ee78d6ec4c8768441909c24f), uint256(0x1d95ea0cb2949bc3fbd4d64da67e34e7110d642f6a7081615fe3bbfdb0b786bb));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x271c7e4be91183da1b08a3493565c649e4c8a1f69621405a7f8b368408180793), uint256(0x10c63497474ac834882f77fcfac075f8e8aa374f21da8af2269c8f9656e172fc));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1a3333a48ec06e1f355f9867c40a4a97d1494d202b18b4b2dc364720e6d7a461), uint256(0x2e1f743ab369ef9d447796f6032725062aec944e5e91e54f56986a758a751f58));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x14915bc3516251a2f5cec4634937609c13311551a37cdbc8a0d42e74f9de7b4e), uint256(0x0b2911e4099d853d90d72471f69595f11ae4bd063f79006d44c0982dd1f11968));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x03c520a78cb35d5a49783e3e61eb3de696a5644655c6ecb78cb967e92131d47e), uint256(0x2a8bd17e1778365bf00f9156e8951e3b40cbedf4a50decd4683cf0d7b1440dfa));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x099bdc9a4c566769301e88e4dae986bc8d815e399d9c235bb961f8d3bd2831e5), uint256(0x1ada6cea1fe71ac63c7978f032ccca25ad1dc3c3512f360d9b44cfd67879de81));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x1694ea595ccd9768a95615bf9e844c69a8631c0a201ef7fdf736135b2ba45a29), uint256(0x1b07c0a6c75c87b7564ff63878abfaec844dbad13a8a406203ae53cb6d2bdc62));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1034c176e6c8edebb9ac68b06046bbf2d7d075bb8fa03b895a2704559224b6ba), uint256(0x0cdfde4e65b86df6b18aad4d88b3c621b3803f65933670e837b4115eac4156ce));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x07993ac1bb8a0d20a2b6731cdd5290689778de2195908ece6bfde92f6d0fa27a), uint256(0x11fd3db498e250660988729ef01e304c3f9469e59a556a21f468000a11eb895e));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x25a1f4180cf96856534e76fc73f6ea530fef73f0697e3dbe5961b30b7505ef5d), uint256(0x09308ffeebe7a21872e75a6c8fd0cbb00e4860f777220cf30ea305f36fc2f6ed));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x23acc0034027f39767b45a04f833125547b672e0318ac1ca333df5e549a0a57b), uint256(0x2a0d776b5cbba35080eb3ea2a5e5c9bf5ef06224f7098659755aceddb4cf6a5e));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x2b7158c145dfea1d070fa112f3829008c375636dabc745545c622d80b1f59e2e), uint256(0x11f1bad3d3ebf4009d1fb03af52620c6c67d7996940cedf13866774c1aa75ce5));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2ed8df44068ee10f330ae096045df06303a9fea6fdfd28216390df5e73744fda), uint256(0x2923c5c1630ee6bba9d18e78d850987a4b93821db123aa1f6f66e309e56e75d6));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x218ab2fe6ed39a78d4618b591b7abb402793dc3a1197468cc4828d6e9a1e4060), uint256(0x17d7d26f62f154af57d843fdda8f493a3714360789e1d7ccbfc4a4d09f1b70c8));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x26af453d0e6bc7aa6c8c8bec404ecf09220251135239007bededcac350733824), uint256(0x0e9aea83ec50e3c82ea5417093ce37070408eb02074a36002dcfd3fb145f0760));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x03f07d76c230a58bab4b2ac8e048da510f8ae06366c706d18fbc5fd735884d9c), uint256(0x0c840f3e6d5b3112c9b5a1fa02a9a644ab0217819988daddd1b513bacce5b787));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1df518dddda8070116e200cb3570238e034554eadbd5216096d4d2bca37a53b3), uint256(0x05b84cdcd61437a6f268190a9697b588b1e7a7f3b563dd57a0d638330d764fe9));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x274db5d3a845140d9aa11011f5f588bd9d39ba11d6099bf560958a03fffc8904), uint256(0x20069717682bd488fec5c38df1e8c5dbbedaf9082f0b68762c9fb85a3497072b));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x039f1e3a5af79d9d1c0610733bebd979f3ba5bd3508eb36db317d82fd079358e), uint256(0x23d34b2f1ee9ca9860438d2282a27dd8e3913668fdbdb8ee4b5125cc0a6abd9c));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2cb08e6a83d8bca3dd351c99ae517a4b1eb6de7286eab3cfa009219fdd262027), uint256(0x0de5237638f276ca56513fd137d2112b4889906b3d7330fdf8bd261a7c109b02));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2633130d1c95583e312f21a783f0378bb2bcd3d75c73e358a8c7211bd18c0311), uint256(0x268d59ace78980d40e2fd6148dfcc63685bb37d919b48d634ecea0c70c880623));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0799162b6e5d7768a83a09c5ba3cf19ca95ea149f16d9ecef172afb5eadd8697), uint256(0x0a1843955a336f3dfb97d5ebc28519b4fc1fae449347b3b3fe5c77c0162f2c25));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x19707b0a30a051ff0398029d4dd1848bacf82b5d7864355d89782366a0a883a2), uint256(0x09ff29cc9ec5f4c488aa678a108ae384830cdced11c015d2ed692ed3cf1c1b0f));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1950beb6e9e5942d71b097e940757d8f679d5c81a6a16adc13ed17af35e313ab), uint256(0x2dbf4c3cb00a8df15071af4f893a3ac5175fc5bb11f41a960a2dcf221839324c));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2f45c2b6457c15e1a7cd59766b4a86699fe849ac85a9064ff3c4b804103db9f7), uint256(0x0be229ba55b50bec61664a8bdedac8f0bc0533b1edc2cbb2a32c87587d1d6bbe));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2056a0e80581d42ab84e61f470c4b117610f59f9febebb376c66febd34f8a384), uint256(0x0109ee79325e76cd9c323a7b1886a90c65bfd87fab1e862d84b24d0e4471917b));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2c7654a3ced233cbe20448524b024622c9970ddb52efba421783e1da8b195e11), uint256(0x1fb77dc57aff51620ac1794a2bc29546c3f27d9792cbc86704ec3fedb5b66d89));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x2dab069dce2acd4f15a0a8984f4d3996913ad8647aa5ea2d67177009141dcc8f), uint256(0x08d2eb3e983e28a73c75148752c2b7748738315f8f4cefec1dbb5436093599f5));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2de734f9d3802414fc17c125a95e27f9af71138df2248de01a10efd9f74fea36), uint256(0x0f7eeeb6ba794b4c00b790589e07b979a896f4960cf895e0923105e6623b4974));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1e8016c41c43acb577164fd5dad82cf66dfe7261725527f773c69f541636be30), uint256(0x0367f42255bb8816428210765750471b689ba0a9d999d4c02ae856e301ec962d));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x09bd96213d46bb49830aec8a89624aefb051922e73565fc3cd7335120e479b95), uint256(0x26d5f527e60cc58bb9735199cd6f55c1d2dd166a820058cc912bc610b177b95e));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2a64196afd72b1a5b5634bb48daba8ee7a0e3afb4ab80796920d01cd8e3196cf), uint256(0x0ad92e56f298d7ef814e97650eafb138b1fdeb881bc73fb479bc7767580debf5));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x246fa122a256311b3f08440dd92ad5cf68c3e662a96c9c0c2625238a7e931355), uint256(0x1548bd623a7af9c7d705474f90a3bcd28f0f95c3d0fb0eb436f4db33a3ebd876));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2e7ef2fae8e8581823a2b1e6a887529e86559e0d643616487141953df04bf5ec), uint256(0x0718ae45f5bace89e64ca37f419a5329dded72645eec7ee0b73b9118e4f7f276));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1496d80d355330d018146193df32f12e89b19a4a5a77dca880575dd10b4df4d1), uint256(0x2cf1c724ec13e1e1dac090031bad0794f0ff0aa753d3aea45b73c4b9ec7c7b4e));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x12fdf268a7bcf11cc6dc056f6b5bfa1faf94e82fe5922bf826c0fda8c827e503), uint256(0x0bc1cc3f42a87f9bd3c8ee8b8eddedc7611e5829bd8e75e8f67fda435ee6abc6));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1755db3df73027b66f0c8fe5f2b1c5b2498bcbcdb88d6051ff490477cdbb6b0b), uint256(0x1ea9c72a031ed435b507f7b57399ea72ea82b5ef95e840e3a46eb1a8ad9de00b));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x072427f4007c7fdac63665a689590fecc106c774643534613920fd015ee302cf), uint256(0x0705ad534e20e6e03949a0195c7542941506e6f1c680c3d3d78c5ef32299503a));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2962e0c7c969cf319cbb65946e38008f76693edb9c3ff43966dd01346cb0db45), uint256(0x00109b535b3ffc7d05b9d1f3b2491a5b9f110413fdd3fdeefe20fea4447deba4));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x052e7226c3201aabc264c34cb4390a81c7262a2e9718c21d05342e656dfb9762), uint256(0x0e4720eb8e45a9046492c15688af89252f07806d4e7c8cd3a824abcf47ff2090));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2a46fe9cb40e6175429c1e1007e74140026032ba7b48756973aa04f3c1550b4f), uint256(0x2c81327d7c0e703592b384f7ee77a86d6a0191ab0d83b80511c702756f7d1c4d));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2757deb75a400ca43d4545dccc7c7db632a6526c443af91871bd83af0fa6c049), uint256(0x145527b3c46ba7ad18b1cdefe7778358f86056eca10cc4d4e93a595b9fbfb2d6));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1222c2d54ba4a8e71020df613a962bd9fb18922aa9c949f48f629dac312826ef), uint256(0x0ea210e310a04dcd880e8685cb504e46fe0938245513c970f461138ddc067666));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x22bf67609bf8fe5f6c7ba87cbd0eeda97ecf3911803df5b90c4a25c0df8e5c76), uint256(0x18020648254e5821d94728cb59ba45f6ec8fb28ef4116f217667b6776d5999b1));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x272d3bf2a2bc478649228d60da635b3cb44db6cecede47e81276fa540e2d2035), uint256(0x1a119e1e5c5ac599e2dc85a1142ea66f8333cda64bdf61109e65728b41274718));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2744a1744df94da878954542427b559a93a352922f153280e1506eb5b86b6a8a), uint256(0x18b7d57c74a53661c0278f86215e99bce80ebe6e91f4d99771debf0dc87f6225));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x14f728b34f3b6deb40cc9dfab7a010e86010b953dcca3063b0c58f0e47213840), uint256(0x1358dccea29867e8e7a49749c895dd8c4f66e146d61d539ac8e1f831eb79aaed));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0e46bbc94af3116707cc77f4622e1fef35b7371b6d716f76282296b5982792b4), uint256(0x052c0e81a1345278361a7c529ef96c43e1238db1b66be344eb3523066643c9a4));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x21042b72a61b1c37498414e771d6a961b8099404a601b47d30d04964adb23893), uint256(0x1fe9b215871e8649835ca028777ce44b5f99491a815f423ae2ed2c2b80911426));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0f0db1506c3fcf4d5423623dc9561935895e8bb375009eb848963bc798ce8e7e), uint256(0x09e88d38d17b7375dda5de64c5aa89484e415cea7542f66cc665439026c07cb7));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x270f8e237e2ca057d6ead4fa16fd18db4584c7b077d45e0154b9d6141761fe09), uint256(0x1f2fe43924b015abc9ef7c3d93ecda748d12e718dbf26d695d01863e06a47edf));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x02c8c59c3b10abd95a30aa0fbdba779dca42a7c861a294d3f620592a1dc95317), uint256(0x250f968e01f50bcd3c2a8b430f72a46da472e241a61b4a07e620e5b687f89b70));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1b7477cafcc6daa4205b6390075e9d4313ba6a1f2e415eb94a05d2f129f864b5), uint256(0x01a136e498f4216c2f156d446656164885c1b5324439851a76389fdab99b31ca));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x0c9eff8195b7c0133c6a195928fbfe26dd372ff0dcd58613acafa416b0da414b), uint256(0x164eca8e5ff3f28d05ce902f76591aebf2b087714054d096980afa59f16b6be0));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0b03f76afac60bd6c819415e39435c6f29213b9a9f63744baefde69cc8cc600d), uint256(0x3059a4215217e143d23e79ae1faaf84f38ccc7a1866d0de446b1d77f8896f9fe));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x2452c63dda27d863dde1f009fb112129f15077b4f1bf24f3904e32859484a2b4), uint256(0x1f18089b43a17a6e27cb73959b7180e5ae692a4ec7b8cb3123e1bed9b51f26c8));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x1d1121b53a334d0b6abca067fe200f3c9b4f29f12c802716905aa995f91b7eef), uint256(0x115229a4a6f6a4c9f1e0e30349ced528069086bb66d47aa8ae1135c39d990a25));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x29532c61df3e5c06b1cf688c3d03f015d973565ff221aa37e55d51d6a2c33124), uint256(0x00b98be8106aaa059cf3bb51a4bd928ba2ebc059c633af6896b1f6fdc2dc1db6));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x02cce42b64c880803819fc16d8fd299d2d076478eef7a64f5a413af1e6aacab9), uint256(0x07aa3d120b7d049b705dfe84119c17eef6022bed2888df9c723f8c80ce71c329));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x2fb199c93dc97b8f18225ba4f33e132dcd965786ab38fc5647d8abf98da3d89e), uint256(0x145082b0eef473cbb987c6e5b2a16e86a826c6f558f1e699f076d3f724ebe7db));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2a6c677a8acb67ceca30314340afc0738e3506057ea478e85d8fe229ea65a1b8), uint256(0x23418f885d4d39f9b58470ad1884e244923fbe38b3233d2e54e1225acba7198a));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x1b5b44a994b35b89cf4c1e8febd0ee9ff4eb83de3045fdada0530163a460aba3), uint256(0x2c249a64c4758a395ad735857d57e18ce772f2bd0395aab96de08d2cff73a330));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x0343091c4e15eab16fb0bd36ff4df8484649e8e6cf7aa7d093263615968238fa), uint256(0x0e1f76e5661fc57d035e219b3ef75da322403c367df6ddcd722a085bff909537));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1b4b7971f785d734128b3cf5f90c562d8ee4041f18c0466d11cfc14ef323ad1d), uint256(0x0173656d3a6eff9bff996265b5ff1dd464a80a98e7063c5df361c75a0f691daf));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x04b67aeb584024c905f9da7a446ee294f915d99a769d1ad4dddde4d254a6f3f9), uint256(0x0f85d2e31fd4f6b491ef68257da14eba4f4df5e22c110563bcdf58fc58d0846e));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x1c199334e8a76df7528bd290481284acef3e283e6bac7ca2a3e7a0d88304ea4c), uint256(0x0d1856755d82d637c813c52fe40eca4412212d4498d6d125d7245946f6db8d3d));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x0c1ac81d05600f60e39ae6e6af1f31b6ddaf9d712311c0461d42f45773c1a577), uint256(0x0dc8e33a168559d67ec42d7cd3d9ca5decfe4d13eecb9bfbbd53b5b28d40a6f1));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x27931d77b4127ee5b71a3a323e148cf3634eebc3722886d03831657fc2267e19), uint256(0x20ee4ab8e4e7f4aef61ad593fa99e497c41b6f7d46cc3c71fc3f123d3b55a52a));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x1326e3b467bd6b56d87445021cbe707d701626fd9e17724f0d430b4a5cc76686), uint256(0x2c5e20c00621bc4fd0586f374d839fa96bd5527599a15d81081834626e4f7604));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1858ccd686a23ec897d01a4fafd85dea468352b2b1fc581980dd00dae7b8535d), uint256(0x12b8b5ade05801a67dbd6d4c55cace5c7fa5bb05f1335b8bc5718fcc67edb366));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x1a6a2932b1a42fa1d6fecdae8db249ac5b2d6f97240181e3b38ebdc11ef3095a), uint256(0x0254b22983aa944a0a6bd942e4edbb7880930544769bacefb07dc64b0ed9092c));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x124eb03102020c83376a9143f95c2924d63f73c1b275863aaa90b024eea88168), uint256(0x20dfc5ee2cbc309bad1eaab75d209abf18c12c3501838dd66ea9e9a8ed9fb476));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x0f0c3e49ec3d889618446769d5284b6ff1385c5996029f41e71985ab580c9b81), uint256(0x01b0d49699d947b52ba18ad28773a89b8e538302b520fc2289396b0c743bbeb4));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x25ba940d4d85276d843b07a2eded708917657a4c47b48e398ce0f6a4e0639932), uint256(0x05ceb90d37b315b86c831c4550b55423ad89bd0b484b3cbdbe245e67969383c6));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x283ccbeb65891785a12479b71bddb2d5eb02c93ba1076f24f77effda816cf2fa), uint256(0x20fd8fec7fbf43e6c25ba60ce395436fe3bbbc84a54833bebec644e9355aaf93));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2886fda5430b41a6130156d6075fe9599ef3e4821b97763cc5808e28790bd8be), uint256(0x0388717889d012e234276b56e3f54fa53172f59d6ef629a159e846aea2d422ac));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2e8706f237d1277cb8c111f9facc5a496a213e99a4c2818eb49c98b407c7b99b), uint256(0x10b8a14ba4438629c039d4500dd02d9be29b220ad6cae6400bb6a00e33a6ad57));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x0a684ede9195782afe26538a4f57fc9f5199f1aaf1505ab839d69f527a860b52), uint256(0x118259b9c234b46084ceb52ef19eb1839763adec8836a1910ee6c40ecdb32d51));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x11d388ee218fcef36a334c3524d58e0b5fb1683d6185d7652c0b9023c1f306ee), uint256(0x1bae36a347f75454ed94ffc10d052407554a8870f74846ae7f3aac24276efdb4));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x1e9b4a5e4a1c173d6ca0142e5413768c7324167fb78682065872aa80624d4b39), uint256(0x071a582c6260155f5a6ae20b426abb3f867ca85e3007b027b2a5ecb0e0f9d81d));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1e8b22cf2c2e9742375dac44632db33c2de432e3d88aa5fd2364520e0888ab81), uint256(0x156a0da37ed3d550dd3e89c3a52452dd0ac7624c56f7392e7091776767483047));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0f49d4ba6f4ad3b605841fc16ca9429d7335048a66c48a5d7ba9131c30faf062), uint256(0x105dea662b3be85557bb0d4458df1ee50806867c8e9aaba46b80baf552b026d7));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1505b2703004f0aa1b8bc4365cbe14d69ba6ca34c8704648ac22e0f7e9cb4c5e), uint256(0x0da7db4dcb47fc4a4dcae66c2961561557a2afcafaf74d133166d0ff7c57643b));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x24c39f4e62d62aea1e462856b917315e43db415a421168b6779f1c9c5ef08fe7), uint256(0x01a2f03fd8e876758ddeb722e83edb4698a8644d78ce48efc4229892546b606f));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x23c98b280f62ec4384884c323aa1e4a194cd2ae59304f0daa96f8d8052549e86), uint256(0x217e7a37b3c750d0118d8535ffc5fe4ecd5adcaf6c12e349709d47ade5ee1df0));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2c2099e2a8ae949e113580ce699b274f25e8204f4d34e0be697edc7cc44bcb94), uint256(0x261731a8202793da88ca53ca3b6448cea9862257079f210616a4fd36ee44ad6e));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x14586f0bd14b126cc5ed28fc62a93daa22c7a4c0eddb2bbd92855ba0b073884e), uint256(0x183456affcec2abc3fa0ef695a7f458e436556ae439e5cd14c436ca3e28b781d));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x292b20580599dbb162cdda68aa74fffe67fb546cb48d8c70e39293f67b41e7be), uint256(0x2d8faa1c21ba3decf18e04d63f4359184322deb1eb1d2e53501b404383929c09));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x189a7b784dba7e232f9f57f14b42b17030d5dd8db98fd456d5433e8995268080), uint256(0x050f7c08daea6af4ce95a8edc12e83202f27f69e1e4b4f3dfc61f8bfdd008591));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x06a7eeb29f9b0fc7522c75c143d2383f28b394811f4df976c18e458ec576240f), uint256(0x26295561f40ee8d7d6ee1dd8cb4fb5c888a13c39de090e8d28d0c0571eea42f7));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x0187e7399809f91627cec4127cdd1c60d54a1956d47bc02d927ff3728e297ecd), uint256(0x0884cdd3cb10166863961f544751e751254cb9c811ead011616e83aef784c318));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x26d467f94aa9447ae1cfc07cd055c915e2810c44a6fe4b20153597f1f81ab14b), uint256(0x1f4ceb69e151fabf640008129f9bd9d9d419255c175e226d5442cf57c77178cb));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x067f42f8f289709353e89ddd5ebe767eb74d3fa59cf60a6c7ab30126d3326c9a), uint256(0x0934100d909a946ac62e202b73ce09b19f771efb6ad9a02043937b31dfbbc14a));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x1f0c8c30150df405123f8aa26b9ae6f12676b5ff833537b349af067c700abeaf), uint256(0x07c509b180fc0b4452a4795c42a866e074c437e061d28f1800dc0701abe4aa12));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x130b69740bc27e21d294a28c88e734a42452311dd8b78806dc70f7c9dce79452), uint256(0x057ec4699ff69d95894a69aa8f27f0b1e55cf0356b2d00bad55d86fca03c3f80));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x21354de02fee5624eba04358ee274aa829412b6f9171ab1eefc0aecb49230189), uint256(0x09d5ec2cfced5b7ddaa28755c3e0f070851b0c23a70b8f3de6208cbd755f262e));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x2debf7fae79af2dd1e3e5b9ebaae1517ae152ecf8736e594ad5fcf57ea3bb7b9), uint256(0x056f0771c4ac3c270702beb063bcc410f2d50369ba0341100d6204ec984c3432));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0b8ae52f92079e60e99642aa79bebb6d9125a76d1694ec0e5b0cfc36c73f0716), uint256(0x0f8dead6c68fc6cf7a1817547a63ab88e968a42d6ab321a499a22fe22f2c1c74));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x12430a3cc054ce7e151d570959a61a99893d79f83b79cc75ba57b214d0aa212f), uint256(0x0db891eb01ed0bdd9b0e6718a57e242aff83f4e6bc4785df03aa85af847fef52));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x05276e4473549791b5afa6b851d76bde134945b294fbc5ec0394960edbfe5def), uint256(0x2b1aa7b22b8344e8ad61439269c818b2bb26180cbbc53fc79d40be7965d4c2cd));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x23e721bbed0388af9f16386a558a2ea55397cbe46cfdde8f8ec4c82af651b83b), uint256(0x00723072d11401fa63bffeba30a1b9fa8cd08142a649c76b71c6e3fcbdfa9ca5));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x067b16d5a82abc4b353c5c5acb2f399cae201d3d83615977db187691bdb98365), uint256(0x1f2326695ceecc70c29c2c670f995d43780b6a0084e422bcf8c4a7580558ade8));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x1b8a613118d634a46ff9678b9ec38b4a8877c4c33af074cc9c0b23d623c71fb0), uint256(0x0f1a83beb3ed5143fe6112380fc2e6da87015573adc037f687064099b3156f09));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x26561e10000288fb5d44b6636b8c4d383809880e618c454fb8a1e624c0bb62e9), uint256(0x11196d31b68646f3b754671d918f7e63747e0e1b0cc4bbfa37698b636c852c74));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x153c4de533799a485280e39e3125383f7e478613994eee8a77f59d5128425b62), uint256(0x302a6b4180a40d99a6e6ac5432767540cc4de65f263594cdc279d832d7d2fda1));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x2243945f26e7ffc9d96c584d97675ad009ecc31af7cdb819c10872fa07b414c4), uint256(0x0dac27a0b4b511518d083eb2cecc3ea7902a77d55002ca978db17a308910e581));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x252c57f18fb5fd74534ea2efa7b09ee93aff94b7329049879febccceff159d6d), uint256(0x212d9a7e3c8686490e1b1a8a3d78be4bca94b057c6d52cd394147e7e29678e90));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x2ba3e273b9805eb9d056a229bf3b4795c81d14b355816fbc87364cd2b5c579ca), uint256(0x202ab655112d4eaa50460c01c309fdd89bacaff2c9175979179b483fa8c89f1f));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2b083e2811f7f3cbddf75c3abb563a16e9f136e4fe1c3d9652a948c2bae2e5ab), uint256(0x00df259d9df0c4ef1c3b0f31e74eb87f66e188546ff8017c0964ca01769f7d21));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x219ede5609186830ccc1cef195760319412a4d418ad285f966373946836e230b), uint256(0x2535ff512039e140160b4dab9c80edb21cd98c7727ef465a59da84e890c383d3));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x0f2c7e6d712089a84e38d6c1a5026b1de050b07f997fa548eea60119e3376c5a), uint256(0x14d7360ccb38550fd907766fa1a5f0422cd6a2c78804884724de11d403f5316b));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x1e5118ee0c5719501a88aef29f371f3bf09d45b22df18316921a1020b32f7eb4), uint256(0x14e98b623d677601bb324e2254f856a3eea7e464eee3b9187ad7ec0dc90e9644));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x2b57ffdacd5ae33e398f11f145bdaa5c7d9c46523966336782eac482de90d53a), uint256(0x0c2c95c39ccd75c868dd1117011f8ce68a2d11add87bb826ed45398909f4e680));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2abb8c5c28e78ec2d2d2f8e35a4221bd3c7eaa2996035585f3f0cf6fe1fd61fc), uint256(0x25bb51f2157f7c234304c55d8c052be5983b84be5bf8124fc3682ad29f618ce1));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x275df4ce54542a51d544e5c6839005831870295ec7bdd322126644d17bc63ea7), uint256(0x2c7d0ce0296eb454f2940783c10724012ed0bff1aa222b26c57da523c6efd943));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x059b190007c81b701b901ef1cdccab77d4e5da85699e2a6389e8e0936293740c), uint256(0x084b4906b2e3bb28c051bda768fbd72a6f2d44095d59c731b788e6f5275d9c7a));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2d15a96bb305c62d493747d518dc18c9e8f73d715f92fbfdbdf01a137fd7f618), uint256(0x2a85c7a3116e438d43d3ddbdeeda5ae07a6ec15688ca03521e74801ba1a74f6a));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x12467ad4a8127a5ab6f861b0011dec7a5c324ecf4c8bb904bd320ee3342ecd1d), uint256(0x145d6a42ad0d1a12b921dea512ecc265a635c4e6a0b719630c4959a799d2e2af));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x30230f332cce022bbf32c0287c7f2704fcb9a613c2e95f416fbd2cd76f835a5d), uint256(0x1de385621b9d1ee277c0a5c5d2cbf311bc3a037868215170fda764d8febb3330));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x27ca8b09411c5314322d4a562dc1769ff686458df5b49e3f7f295c0e2a160506), uint256(0x0d6baf9d478619a02c845420b1491d67349409ea52106663cccbf3478bc0ee9c));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x067a439734da69b76248b21d7ba81787b06bd470b8fe1537f8200ca2e90311d2), uint256(0x23e6c69c3eef4684bec6aa6abcf7d920dd31a97af7daf9916ab919e78c9dade9));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x16cfd7996ec783ade28c4e2779cfe0aef01503ba8ad67c63e3b09f12ebd316d8), uint256(0x1b5d1e349c28b6d94c45c622c9a8c9d7d04e2f06a3c6d9fcce12f05cd7e005d2));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x08850fdd92f1255f63d56111c74955cbd559027af6c2f351c034af411b808c16), uint256(0x2feba874ff1c393b471b04871a587838e3e02efabbd66359a126fb45c595b455));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x10a1dc4a6f0854cd53e4c7bd34a2c38654852ed74c31ade405d14aaa878ec980), uint256(0x22213c842531de6c5aa74e9cbecbce295d7e37e118eea2bf5fe96d561701ca48));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x2c55291e793339db8e136b51b9f9fa91475529157534371477e820f8592bee64), uint256(0x2c95ae7842df27c70bb83f37d891f56cfe91a1c777cdbd8639524cd63a790e09));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x0f4166eaf207674e5952e93623cf574086c46d536506ce4a17ca42c3d8673d9f), uint256(0x10eeb6cf7de29a9eebe30f3e005a286af0fd38a0d4cce6460492e37b6e9ab118));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x170e41562d5182de2892f1dbdd01b5b439bf7661ac1711cede89b32eb381fb84), uint256(0x2d6143b048ffa3095c21105ba76b491e6704be8f9d74bfae95f872190d1e44c3));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0b7ecad099397911392e05c1cc53532b5d59d5d3a7b10ff2f356f5b0c2b4e048), uint256(0x118a7e00682140a881cb1f8aaadcb327a781a957c1352d251db24ab311672d66));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x23a22726322fbd7af21d83343efff233244c7cb2b71c6e9b287c2e1c4e74695b), uint256(0x29876146564a81b8ac2d09a529b7fc110384501188304a6faed3c1bee4935349));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x00806f8acd8a36defae8eed9182a428f99f63f4cb61004e1341078a2f898b455), uint256(0x185703003e15630793f65a9bb8c8352a4929f0b38427a4ecf34f76da54ad6530));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x01650b2913bf3a80fb853e9bbbf5c528db6f17f01fe0cca4c011e4ede4ef992e), uint256(0x13ffa93aca2f07531587408df7f3d604997e9114415305136943437d34fd8463));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x0cf725d50691713fb27043829c09987a265842afb5e29ed61326cabe9687083e), uint256(0x183fc031c4c525201c22462f9b1650cc7d5ffbbbd3688e2fc250df8e5b595057));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x02f04a20566a0ec8299aa451ac534b3594db2525edc9b9a9499963b2e0897303), uint256(0x07ad846e820e8e6a99c06bc61142b0c2a2a6a65252713500327e5e6b66642f5d));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x1d202553a34563ea88219ee0e91192bf93f01a6f9dcbdce75059e9a9e474aa05), uint256(0x226cb5d3207c9091fd1644e3f762dc2bfe1e24ceb3f85b1d76fa19bbf9c9b60b));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x1dac05db04d3e44f68ddea0772ba8a804dc9be722c727378c6ebecc2cab036c4), uint256(0x0344f88f169751c5aceb6c6ca25004e6f47a67f3a8127d1231b42648f3e43fe2));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x143c905e0ff6eadc2e7680ed187f528b38c021da7f642892430b494f91c99626), uint256(0x0f3cfd7bafa7b6865d1cf49003a1917c1ed0fd8e3ae7abbabd5c442329987124));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x21f1754a7e66901126ccf5e56f34aafe84f87c681035f3337aca9f0c397ba6ce), uint256(0x2d1efedd64745fffa33941c886f48dfc182c58b09f3a4a900150914a88df0441));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x1c6ea71f7f2f96a0310d57acfd5b2de437dc0bf29a227e46567c195101a1cfd5), uint256(0x18e88ce62740eab1acd7cbfe8be29cb1be63b8b17b3ad9f0dfffeac1d73748c9));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x09b6bad921d30c8b3a9b256c9cb7c2e11a2175c254f5c92e8428c33a0c25ae90), uint256(0x02a4c8e623e81301ed5a5aaff22e4257ee085d42d1836f81531e8d1c3242b98d));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x18741030a7b423686bc1263d98aafd72a79fb658a95de5be70f1eae5d69b1045), uint256(0x137c1da1ec5a77d0ac2dc1af279cf40fc4b05e70f777b22efff94ed256433b5a));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x12eb8eb12d9ff1e0c429768b5e0e96dde19183454ee92d7d6333cd31e0bf0c50), uint256(0x23b1ad0ca24a8b0ec1e129376729d955b34da8ae4a61dda6642e50114a0734f1));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x07d46e2bd76a8fc9f1c8695428b891bac97a8e87abafd532827d195de972cb98), uint256(0x29ec0d18c8721908ca87a6ed9cbcdd7647e95092fefbb49bd60d279540eda2a7));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x0571f92c4efb254ee0ebf2d1ab6124d6ccdfb05a00ad5b66bbd2b4c34c005295), uint256(0x183df86b996292de51aac05f0bffc12ed8cc9cb0017ef949319d91ffc8070ea4));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x11a2744195072e6a230e513955994f4a44bc839c5c09cf1d74354fc83c907c8c), uint256(0x2f89d16339030d91a5d568344b74064885027d030aaee2700769b1756bda6683));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x28ae274823edd1c0cbbc40a59afe4d39f51d51fa465f393d21623daafa4bb881), uint256(0x04f3c8182c7fa908afaa60d1a2cd0c11264bc5f343a0faf4c5908a1bf267c548));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x188534b8952ba64b2f2e661472b1486873a5854799238c100e6ba8835b842127), uint256(0x0a4709c9c517ed59a0b116a1993adb7431a19c67ef66bbed79b774119b2484a0));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x2e65533fc83b543329b95d007259ab7990b97b9840f2bda521618b44b04a8a5c), uint256(0x2ed44569c2c1822fac5523bcbd0ef86fd5faa2d8d6faaa85657ccdeb9af543ae));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0d25cd8ea043ad4d32765024f56a5703074842667d78c28dd2fec2cd4b1caf10), uint256(0x02e5aa1e1463e077c13df99c4face999f27c783f9d388b89ec8552b2238b5bed));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x2383814c8cc77805e43ded39d09fd931c03087cb38455e8de990e1cc2e683ddf), uint256(0x10e7bfa1a407e83455fd290b69bc0cc305ca25c9d12f4f957fd52273c3562945));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x081378b6a8b15bc21f3358cc5579f0dbb1afcbf406c1af2551af63735ac3451a), uint256(0x1586ee4b0376bf2a65f8c59f14bd2410cec2063a0415ee2c2aa1d18efd36fc70));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x1f565f0c64400f9b002932156ffdd09bf4ac89f555195455f80bf97bf62db806), uint256(0x0117c9c4aac8c752d4f6518cff9b9c77e0d519264bb8343051482c19c511a7f2));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x0c1a2525b05ac2f90671a203a5859c0e53638859ee1c9e6b0c2f1696850b0316), uint256(0x2d54cf06ef154de8e6066f855b2939cf408d04aed27ae4b9806516c02495c96c));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x1b9f8ba15bd152625b2a457e44c431dfaec531b091d9bb2303f5307e2a0ced63), uint256(0x123d1bac4ed8f564bbe105d4025597d685de443920d20e87a156c5656e5910f0));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x191736f11ab025e5177abf197d2a5f1a97f59a816cdacb59db5a87c54ed5498b), uint256(0x106ce45c3b35603454c1f04b3636cd03389355fbfe1c15a3ac262446f9ff8376));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x095b5f0c3a89b2cd2d2f003570f2c500127b4753f9e59fbe42f3acd125293288), uint256(0x00608c77c266881de38ece1da3bb998e525204c103e02b92ada318519877d9ab));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x05b6d5f67219d45c7b676b2c005cfb58468f8290fd95bc68214bf4c134aa0295), uint256(0x0752fb0b2ccf0178e0106a69b708cb6af22e859df31e1bfa61288376e95cf630));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x2952916ceaae1ac7d61bc08b8695e9a4fac6b42f298c0d68d74df1c22ce04e1b), uint256(0x18a1c91dd4da981dc9468c8112f6ad6e9aba08e79a9762bcd9f830ec8c516163));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x21ea6e80e770015aa310b774bb21219f9c0ee3b12a18f494898862db9e5ec515), uint256(0x0fcda6ee61e51b8b2180e67e572252a02ad75b1a6e23d68fc686fa52dff26a19));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x100d11ec3f460107e43e15c7d9dace6aa82a3533662637d82e05016842a60103), uint256(0x20fa5d085aee88d622dd44294ac15b028d106dd15707cfcb92f3ef5c6220367a));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x0557d4045b295d835e41b5de7cd1d66a5c29aa22ebf531e6a235112352d0c3eb), uint256(0x147548dac96ac1223b7686cd7a8945ee824df51087fc619e8ca61fb72c355ffe));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x04affbd92ee7d1b9b845ab836512a480d49f6a94c04313da90c907541fb6b457), uint256(0x29a184cb6e756149d268564c06916a6a62ce09868bce2c9245b0744b3c788df6));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x0e03e483462dec3cba22b82bd4eb50479a3fb06e5f0a13e4d80fe2e82beafd83), uint256(0x0522887edf1fdcb7a896ea6e2d35aa58f545e9aee1f8d45bc9b4d26bf3b65633));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x223010ba5bcc884d1e1048a9ebd1165fdf3203134953bfca263d9dbccbac907f), uint256(0x29d75991fb75ef8d4164f0979d370f3f9497f02e2a259e57268597b880fc577e));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x0f069f909de838508bd0f7836d29f1d3e39147406c138902c71b04472ca0cee4), uint256(0x2665d63954ec57c0fed751f99ad6f09cf65379ee2565ced7caeb554a304f087d));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x15982c5d4a0f813f0fe30952a495e0922869db7aeb6df255d9c81bf43be0c75e), uint256(0x1ec002ba1c5e400ed1a28acecb1ae2e511e2af5e690d488378f8b9b3f6899032));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x1e25945013d411e8f20025592502bbd2ed6dd174b23a76314e258c88de056dba), uint256(0x08585456c8533f4add3abadcea767898687c4ae7c3c97794c2197e8f47db54e5));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x282d5cecf1a20c59976f3a37b9f5acb86e583771306c216bf12fcc1804967950), uint256(0x2a1fbdbd17b5c116d0bfa3e8904cc715ab1702e23327df3d7b1867fe5a542e93));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x17cb640da0da50e8b88f8637f2ca59459f033388c2791fc1d317d5097ab7916d), uint256(0x092b0fbf1b0155d576fe2707c069bf17d029572870f953f307e9239db24e3e7f));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x08055e8a5d09d334f4db46dbaaa2f8b0adca2668023d7652a6519153c7482cb4), uint256(0x2cca1a6f902827d6d3ffeb588ee47da6b90a1472c7d888276ea287db9393b26f));
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
