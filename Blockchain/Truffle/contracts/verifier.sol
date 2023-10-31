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
        vk.alpha = Pairing.G1Point(uint256(0x100927b49666acef7913e56c91e4974b2f307cb242c748c286644f3c24c57593), uint256(0x1ff023ec32e5b5e3c3d1a50d4b7e89c44d1cb762ee7c79585a539ead868df6ef));
        vk.beta = Pairing.G2Point([uint256(0x169ac61e7522c6ba863044f736f513586555d0d32715be59b9fd8033fcb3f795), uint256(0x0f416d676a65c5ad6f5be4c509b981e49fec98ca3d911ba6817f7918ae524a09)], [uint256(0x128d6a29d834138854da724ea3fd79fd78e5a518fb94f495d9921e2164e56551), uint256(0x218e62f5be8913887b1194cdbbdc15e6f2af4e28d562bdf2fb0c1842040fd827)]);
        vk.gamma = Pairing.G2Point([uint256(0x215127b97ece480248ebaddef55424336d8253f00c214920cda84d7294215135), uint256(0x263a1fd173354d9db37b0e662fa7fd6758dcde289e176931720e3eae286fe1c9)], [uint256(0x1e1776a0e742b79329fb79e27add247e25fa68e097b159737fd6e34d6bf8a269), uint256(0x2828280dec52e2bf0142e86c7a6ec0a7c1420fb34903966af50cb499503eb614)]);
        vk.delta = Pairing.G2Point([uint256(0x0976fb933d75a0ec30b228f0b1dbad7c1f484065f9b5e4a86013ebfebfb67f79), uint256(0x204e0cf55beba5f8d3fdb975c0e9f9bf862e433ebba66d182e2b2bbefe0e0714)], [uint256(0x26ce5ff3f9a6464511558a4940791817e2b73e2c0e9f088686a0242c934c3a67), uint256(0x15500650e8e9bc8402a6ef493cbefb44c44fe5fe08b5004e8ee42c9231a2f0a3)]);
        vk.gamma_abc = new Pairing.G1Point[](184);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0c0bc674119cfd6cabccf5d08fddff8c45401b702cd3ba38753527081006fd12), uint256(0x1ec211e48e48b451f7763a6ff555e80661e03f7f05d4282efb25ff8cd2d17f7e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x27d4cd248a21074da9e1aed6bb0cd523cf61d27f14e110c2acfa72ec28666c5f), uint256(0x2b72672c745db98d039da070548bb57db9535f6e3e3446062e89579a0fde2f88));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0588319c95349487cf05e651dcc2b4bfc299efb263dcb39a6605ea91856620c8), uint256(0x1ddc2cc930daeaa9143d88fecf947f5a5009f7d2cd45926275562f0a9ae9dbb9));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1b4ca391f2d93e0dff842adcf62732c8b90930a82835d0e3a90de4119da8c05a), uint256(0x0e95495f69747497f9c4d75e4cc1b34e6148fdca7e7ae6d24158d50fc3179b28));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0d6ae77f018e4b72938d2be9b7df8e2a880799ac5e1ebc4b131be92532bfbb72), uint256(0x0fd0fc4d9f75ce7fd40db863a724462fb5944eeb0692ec9c3298fe33a7dbbcb1));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0dc000d75f942c4a66d0c92eff73c8355dbce53a2345dd773f26428a0a8cc1fc), uint256(0x2fd952292ae62a7c266dd26cd7e87914a3c15fe0a2927e37b6fb7081450d7f24));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0d424bca4bd21fdda72745ee1628709e77f591a4a1dbe71b1522a8b364ce6062), uint256(0x266c8a90b2ca86708f6bc3a6f2c0bc826790c1e677b1b10d392d2f386fe14f22));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2a11df8e9eda00dc6362cbba85f544e56c33e64bb818cbef5744120ad87f18cf), uint256(0x04454c5b782dbfef0d633548900182d670e11a73f824f30449926e31dbbba4ab));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x291d7bf31c54a5f9eae73187d38e047d99648f28265b8184117f190c266f7942), uint256(0x2ec6d618eb096ccf1834abcb7ddcdd9e500dfcf32305e62346aeda1e2a80cece));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x060351829887c90fb1b20b2847e05bffcbd45571e84da5029fa9cfe3fb1b18f6), uint256(0x1327a28be6101360200349f02a9c0a0115a7ee8b5bfeda34e3705c900feb19d0));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2e9a5536352fc1e5955665fcf16b185278c309385574c9393cf3dbe6c124e134), uint256(0x2ebad922f55db7b568cc0b113c2b0a8e20aca996d84bf6a9c2a6f5794f7f7edf));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x088aee3b8d3cad034cd9bc2d9f166ab292bde2c2e983c7dbdfad6b44fdcd41d1), uint256(0x0819737884e5e5961d7514a19f33abdab004fb5711e5c1be6bbe1154246e9681));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x071bcaeb9162dd2f296c14a760bcb74938f126a75f76d5340fd831ecced499c8), uint256(0x2d8b0325274e7aa25de7a52455e9a361748a74955c394e8e365bc76901fc08ea));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0bee3a3c5812ea14384f040d9f6b0fb17ccc5a141f68ae52fcdfe3a09fc53d8f), uint256(0x0ff990d6251c9b4137016121d0deb20430efcf2d9e387746b4bed53841ea121b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x13dc99395546fb5ff81283aa4f3e193b5fc48afc1059dee1bf7a464654ecb293), uint256(0x1fa45c92f0364ecc90c5efb3e3c843a1ebf414970bba32c2a7bf0dae1e8ffa68));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0a48d1a2c499a00f7a8eedf53cf4e063ecc28be37d16bf53eb79f9e3dd9f6130), uint256(0x14604de39504da25cc1861573109a9d3ca831a06d67b4d6757877b480b3aa1e2));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x19bd3d91d012267be941adc1196334530ba5a8f998f96c5d38682ff55ca74687), uint256(0x2071b0008e19e29fdd7d27b4011f62e9a22164d89ee27cc4cd6d13fddddd1049));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x04732862c6899068b1551c8672dff879befb8635f3b3d870b460ab48d8223c5d), uint256(0x1040e1d3571aeb5f778a609694900ed6df6ef707b219463e7b1e9eb047e920dd));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2d8a4756381e6474c3ae25a7593b99b4b66d77872dfff933440235f89bd078aa), uint256(0x27ba49853f0f2bcb949a20ae7717f97a0a0220518c6f078de7ea9d7254185d3d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0165208a6c1aaf1c064214907b22343d2d653649e013bf538f9b42c0a728523d), uint256(0x0630ae651cac0fc11726bc418db03a7ab6522ef9ceaca417a9106502e2f5ebb6));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x00095f9436948021758a42a896d9c7a26752b79eb65ddaf8adb58676456aab88), uint256(0x09ff126191f92fdadf72368ee8044eb5b73744c5b628d21742059a8602c7aca3));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x04ab44ece37cba3e624372d3215ecbf1afbb066fd61766f1c4c25cb1dbd20bd8), uint256(0x24ebc0fad287ea952517a79f837eb4ec2e5b3c9cc1ec7d1dba8aef6db50ea80f));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x11e0b62ac01c29025c143c166646af7779b6622b273bc650f40ecf1d9d6498eb), uint256(0x0aa8047c6576afc89f27d5875b63aefd13174928e297454f569a355ed41caa1a));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x128c722822ff1b3c9864a9134763dc90846c6891fa2871be511879cf844ecbdd), uint256(0x0a2ec3561501aa6f312842dfb120b333edb21ae8ee9b88146036d2ddfbc0f511));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x203690dca9c7b9ccf5b828291e30a8843cd91e7d24570a790f527421d1ff9a55), uint256(0x27bff87c886f948dcc02ae9946c78a51e47df01d7452cb44f9676d723331cbe7));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x237eae4fce5f08cac9b4fb92f95922586fe8e9713173ce0f754ee7f1dd43c78e), uint256(0x0aee4e850a6fbf11b39666eaff09ff50b5158f2f941334978c7ff9491ffafe22));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x20cc8aff256b992f49c24e485ec7edbf1d0c29edfb1772fa95c6b1fb7e0d1a75), uint256(0x21abe179f680178f1ddd7d2da6d9746be8373b2d436b1f458e124ac6d3d2c7b5));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x21deb8257ec286552a418db64d88e3fa4aff9bde484df8b892ef6a20f29e64cb), uint256(0x130b638d38c7b1c82f571f94189229c75be6b01d62f8ea4c45afa106ba77994d));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x22453882554a71e0ac0565d5d38abc2d58d9f4207dd3a8329587e84d374be18d), uint256(0x2903b246bf39144e319451eb4343b35adc30d4567a63c5c30a1f80a7e90dfb97));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1d7b3f738d3a3790a34d7b132fd40a861b532d58306f2b0aa8602f854047dcd5), uint256(0x0a464b182a0df0d8c7cb4fa6d567dfd8eaf8f7dc6fde1c7c940c308a54fb95cd));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1508ac3c3bfd980dbc1d83b2f66addc1502db4ed9a320a933b8c53a6e28a6c5e), uint256(0x13b1371e885736bda69dba1a8153810d7ee2a7e0ce21755c01c6952822287669));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x050efa20dfec2e3be7248b33c79750f06969b1df84dc4acbd159b1827f0aee97), uint256(0x25f80a55ce633e8df315cb067ece0b4b4de63ef782b001f64472db3179919ee1));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x2ec3a6012331a05345caa351cdc985c0b87ef72aa2869f12f9c7beb682d84d32), uint256(0x24718c14380d87bd87f0bdf06e64070919d7e3dee58aeccdfbd845cabdad63da));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1f5185f198b660e91add63e0b7bc16f22b8dfb97fce0ce50416aa1d26b62b80b), uint256(0x139e76b78e288c13115f2fb5e255d22d9560b073e93c4b6231a6970887cb3645));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2c7047acca537ea1d94e002b71f84bd386467413ea8f2a8bed8f697c24c9ff29), uint256(0x0a9f934b2bc143294ec26da310c4da71090ec11e60d8c69e607b805299c7da0e));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x00f8cbb5bf3f8828d66d236c86ad26023a202ecaa9fa409a71478e9ac916ef1f), uint256(0x2ab9d1166c25b5dc2dd5d6099731d131b1c7abe7122da3eaa202591e709282c5));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x128a3fc4725e9fee27dac4f9bd1789503d94e04824c73ca54e2f4db6dd33e585), uint256(0x2c409746da33e5e2dadeff19e55153d36620d0cf6855c65fb342d282534a2f3c));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0d181b55aca13fd1a7652efdd9bd58f0e3b0113c476fca88d0df934a746d6107), uint256(0x1fbbc34da9d0ed9c06b229b609dc9746fb089a646726902b3946c0a06e370e15));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x01bf1cb29252eccd8f87a87d168644ce4523bbd3583cc18ef31e1cd404582fc1), uint256(0x1a7f83efd68bd853aa4636a56c3534ec8c5d5b7f132e865549d3c67d794e0ae2));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x04eddbdda4b458931c91545178a93988c7ba3a4315fde42f7f1d376e988a3aa9), uint256(0x0cb2f7f8df160098029c8bc3bfd026277fd4ed1b51c80cdecbd13363313ae5ba));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x092c52c22fc66661e596b8cbe41b1fc206a27488e219a27e9b58e61c6be123a5), uint256(0x1378b3f70e8513e841132fab00f3d22dd83f7edc53c8d64aeafa196ae67f7943));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x05a9fa4633b6486f85298d28bb4047341c74c0cae0db79e2b5a5264a981c0815), uint256(0x0c6631e362184018963f1514653f91f8cbe4636e3b7d3f451b811f6321248444));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x05f08f3b0d0cb478ceb67513c234ac2a11f26770c5dd1db86d49068732e6d8b1), uint256(0x0759c1812da23374e75663a5cf5cda8bcedcee12feb68004648f67305b7c5dfa));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0458bb4e0c295ba08d87b647e117d7c1b18b1e0a0bf13da87b9af57b69d06f56), uint256(0x19684fff9c4432311f68d2c8ec47e37c61ae62ea9e7b182158b002251a01803c));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x19be9a23229cf854e55cd3a2562f7ab362923a1d46ed8b547d6500441cb16f4f), uint256(0x21472e41b20b96d658884db0e685a73306c2968b7f0da7f405464955bcf74f74));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x013ec57c0693f8859fc7587c894d54da4dda63f146e9384bc1e955fe9e9aeeab), uint256(0x17f3f1fe6605891b7adb332e8bd57818d7e5ec2ed0b9e26feb0cf5acab2234a2));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x08421e756df4d0d77376c6cbef08b99852aea059dd910adc903eff53ea75db9d), uint256(0x3050557559ebee2e359244cfb94fe222c40bb4d90dc557faa8a60cab91f24375));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x27a48420526849c9d235226a84ba14c0a07ec8834a819b99ef5e9a4aa9753a1e), uint256(0x04aac81442e469c06d0616abce93a282924cb77dd20cf70390f0e63b042d235b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x2cfd1d12a1b65ebabf928e482e98602a00653646e5904c6a9cf1d6994a95a4b1), uint256(0x25c3b25913f1f9c25d5f49e68b66a7f8848a98ad76d200b60f91c0fca495f086));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2d3885c19b2353f67704f2c802d8011ec167384b9dcc380f4162f29ed4d1d131), uint256(0x26002b3a393f64e25eabe7cb3756a4b7549269d767a07f7cf7f2644d49d70b02));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x251c9057c26403ad6d7b7a7c09f0a9fadad38b6edfa4274d7b8bf821973f31ca), uint256(0x073cffd7542df5471a8c3beb93a68d490404a5379e2d5e785f299eb424524042));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2c8e9cc16e47562d1354c3a09996df4823304090dde73c8d3cb457eca6ec49d5), uint256(0x02e66fafb9eb5a20adc18a726d2f7a4846e00b81d11dd9be88a8866d227ce44c));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x23484cffec6d168a7d56fb735eda2deda54e92c1dc3887ef2fe8cf62226830c5), uint256(0x12749e1f4acfb8e4676c4eadbe1f69ea5ca73ef123064edbaa7e393007179815));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x129c490514667389693769e992eb868437d152b2fa888514d35fbd1013bba95d), uint256(0x01f1689b4dcadee17391682186597d89eaefb58ff7031334ba4e1a7b063a4f8b));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2d1329c76fe6f80ce209f9ebac27c2a616295165d29fe215bba26484b909b3f1), uint256(0x19964d4b87c4636b29fc2b5d09877c13f7b43efc3d8156320ad1f9d7e83d3916));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x19e7e51a4b8ce092402f9c16ed5e9c8132d05e577988ddbaa0bdb196c275dcc8), uint256(0x07384bb3ab8c5115b9011e03a90fe19f6088a8b9d767f9bddfee48df48d0b986));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0960f17fdb99d6806b0b38279e6bfac8c76d0bf89b68dad85f193e6e7e8702c0), uint256(0x2dbfe6a31cf46ca36adcefa864771bc5a3aac9e57120a786d7108d51a74994bf));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x199e47a266358cea458076b591bc11650fe17d5fc1d93658d1c0444317c5e2d5), uint256(0x10adf5f0f014920880730b57c8a46243e4055aef4223b5a220aa83f8b3b73b27));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x24c01edd26ea98c4030103b52f147975d36435876736b24e32a891f823b19119), uint256(0x064d74083cf199ee4dbe7452d5c298ffb99e001c40fe15d6cccf4b798bddcafb));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x203966c847b9085c3354c15783811ae8d2d924c97d1c906f6e7af196be0dfbc1), uint256(0x2158a3e8bf623acb93c6f380f25b5ff14417fbbf63bbbccdad9e2ecc9cd84a9e));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x20de251324374bac85704d5b8a777bae23f0356d34f90d20680e4a73a13614e7), uint256(0x125088bda4b789bd5eccfa9352154baae41600c81edf92615d420150bebee5e6));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x24f280ccc9fc1f53768a76719945e8976e647934690abf19cd029cceaeeb3a4e), uint256(0x06f2b778ece8a56696ea9ccf8164ba3168417ec762b0aa2bc7f10ca1e9b66120));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0096243f758cff7ad2a7508b6d78c799d8f0bceaa9249f40066f7bc001e4a10d), uint256(0x07d948e4bace90bdcab60d0ec60718bdc84f2dcb552353b88f8f35425f12d9e4));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2fc49f33a5cf593036e3ffdbef3c8aa68332a89ccf117613163ace7834f3f39b), uint256(0x00797a09a4fdf341574804a76ad9d6f6568de31143242bf006f657489672be9d));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x088e6088b4622e6fbac6d211d82a37a0aca23d27356745fa351c0c64e251a7b5), uint256(0x21876e860590b269ccd0f5ff141ceafb7bf43cc675f2430e249d52dc28cff43a));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0b138aa56508aec8b69a905014e5625def26f37292b12a9785bb8a2d58246f09), uint256(0x0dcee17aecb29763e6ec9c8a9f486f8f35b722b124185c70ee292cf4c2c11cb0));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x15e1a68706ae72d34badf533e86a1bde7337d9853d5698cd6e5390166bb3ae98), uint256(0x0df3f23628c4d24c934fcce1cb52013b1fa95507901316907dce5a0a354c6c31));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x27c4280a548c6923013c3fbbab098b031a3d2ccd670d9a772f0a07cb8f8bd6f0), uint256(0x2391169aa907a3aa9990576e9026a7140548b6d53d8ca6a28516557f955ae0bb));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1431f82d3998ec0647d8d3a6ebf8e551b6ee3686e04059b5b36f524a19586a28), uint256(0x064d057e009fc6f8e272ebabee8067534303015403a57d30cbb356db88cf6ea2));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x2f876438ab19d04aa682ca78c6802297a874d1c3fa423439a85534f743ac1176), uint256(0x10e22616525fb35ab8b8983fdd834caab4c2f8362403c6eb413c0a36a9f46f31));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x171216fee7dd0f3d5d7c132ea78067f56f66aef0e6d4aab05368cb4c154ff1ec), uint256(0x28d31af636b103246a6c59be9f8b8f77228d8589a806c08b3cd41b66c35575ab));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x2fd4931aa699f4ff8824d61aa27d12e626c14566f59444018a81a40107a6236c), uint256(0x26d62cb7fefa76350fc436520c7cc5be9069c6e4b4e1679f36f5a7d9023037a5));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x05c6e70b21b66437f782dadcebd1b97b2d2158695147f4c09ebaec5e210ab54e), uint256(0x253ad9b6f970676eb031b65fbe2d38b3ec6a77abf6f3bc42da08312a5f1b586a));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2ad54c6d3d7ab017ccdfbd842a86f9c85c747a1041c161b300d8b23cc5dd9ad4), uint256(0x0185f2bf9df72d5ae90e4d90286974a8e99010f80d73bf59df1c738276b18e40));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2dbfe71f5b28cd6eeed95031bdc07be685ef942be8b2bc2e7d2f66dd9db00fda), uint256(0x0f8e05e851d2ff23bde9a9219d41806332d2152eb1a6af4ee33e20e7b03d3b5f));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x147b2758bc9aa56b1971c8f2f9a8ee37ccd0d3a51bc57a8d04560dc0aad2b3f1), uint256(0x2776771b9b72ba81bd326b77a41bda74261aa5e3f5c5ac841fc0645465d49ad1));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x0f3fb4044657a69e164e6b0b9ff45141e9274198b3d89fcd5f7ecf23866189e5), uint256(0x00005fd7065650bb2a31284240dd0daad467621fc8e5a0af0d03e3b8691982fb));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2bd4aad46462827612d901259072cf40de0c236262288a4593cd701cec80ae06), uint256(0x1243634c11efba9f1fda250799632bf1afd0e44cfe7301e22dbfd218d96e5971));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x021cf9cb60a98ffe5e583e6d40b025d0e67c8cb13efdacf41a900e64e8a730cd), uint256(0x2fe176f3d965e28bc12bda2efd83cbc34b948ac389e91070c97be0ae265da08e));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2539b3c2ed812b0509af707994f5d86c89170fac845abf4d5a8a29b11fe1d3f6), uint256(0x0d31b158730e4d081838d37bf5e236797e2745a2dbf23945dfed4565855fb6c4));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0639008148f3a49585c965b5fb31bae1991db7136513f5c10b1ce34cd61233cc), uint256(0x138f105ecc12d0283a5c787d4c179f01fc9878448a5b1c87badd42013cf59b2b));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x004b6a62855043bdeb7d83ba46429b695af73b2209b2bdf90b3a6764f5edba97), uint256(0x082c5c276c3a933c40e66c7c680de9a3fa6d79d8bf3fe8311435410cf8a7d6a4));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x0f914a671cd8bdd48465056fa6031d081db36c055e0d140a744a504fef95690d), uint256(0x1036c63421d1f745c07b44335e98c7f0be1c743cf74cf56153f244d4cc5b74b7));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x19cbacfd578a3f5a785eced09ea5716cc74f9332f15828364bd7996b19037f73), uint256(0x1deb66b522efd6de22b364eb8f92f483b5e812b340f6fe0f9b0628b9e86637fa));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x213e6bbb283894bf21b831dba02eff32fd58ee4f2d15ce5a6cf665f2ddbceb81), uint256(0x21a2db0c648a755792efc1d5a66721f421984e0ea69da559d8ff2792fc01916a));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x1fb31281301ef7e406cde5c6ca89b4836350f214c0c2e44c903d536204638ad8), uint256(0x0d3823eb3abbf98d95cf2b10e45cb2f6fa85953f6d7bf71f65ea6be26f817c92));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x091971619b9a5f3c7eee1e569fa5fac696e5df7fa750b5cf07af8a21c963ce8a), uint256(0x180ded2f0ac398c8b0b7dc4244ba541b43844331ffeb6d56c65ddde1ac43e57d));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x07634b95faf7a2a0310e0c69c64192624232932591c87ff789712c003383f1ee), uint256(0x2bfcc78abd936332ee92cb4a7b069a4ab7951db5dda3fad0338ffe187014d71f));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x0ff70156c35b1d084c0acbc70ddaa5ce375f70665a2122fcc1ffe557196c9d0f), uint256(0x239e663ae0e43401c2aaa406ddfab61152d99f882e353e38f7ddb9881a76372b));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x039fd5f6bf56b935a4bb51b40d14ffeba05dfab1c20863102b7c13191d7e114e), uint256(0x24a29b3a9ed8e1082cdd8529bfbe4a770222d05157cba9e788cc910d11ebed49));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x08a26d0cdc6601d3766cb253f58d1ea164a196cb7b64212f7fb45bb27dd3dda9), uint256(0x0cd2760b8beae8e4e275f4c9a50c8ef0036620af83bd6279e15990f6962ddf4a));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x010d954529bf8bf355f2434d4028b99da4e67089149caff55709b605eb00197a), uint256(0x2a048fb8084f079bc39ad99b1e342897e29d689114259fbcb362be2826b84990));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x28d64cf9d526c4bfeb2370b95ff2d39cfbfefd51b352c8581c689883712de614), uint256(0x2c85ecfd42d373b0f342dc37f54485717d160a2a1df53ba07b8547b69e29fd6c));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1e6aa8fa378bc1167f4696746a80f3f25bee620bec964ebb08b9ef09872dc0bb), uint256(0x0cd4825e5b87af98a20be6368ebda128672a0a7dfefcb2a1ffc588c9ba145182));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2d78946490d678d94087c490a32e6160837de2a160702706cc6bc09eda73583a), uint256(0x0059fa8172a20c8f799c4dbe3cd83084287b018ec5fa0ea154e740df5c0f8aa0));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x2c16c801f1cbd7fd4e21b5956f360e94eb33259439254a09d5c79ba8720404e8), uint256(0x23b6682971f96f3c1f486b814089136b76dd0307ed7e7a4eee2af728cf66468e));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x2011a2dc2237feb0e64efead5975d01c498a946c572f67cb856ee744ac4edcfd), uint256(0x2ab71a38219b3da2ccd42cf036c1f1b73a6dbbfea30759fcf4f52b9c9011156f));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x26f05a6e3f91f5fb10dbb7a8401722222846bad63bb05f674e6e4620fbcfa05e), uint256(0x0d015e1ff27388b6221e7f6edba5dfc4e7e6682ba74aa7c0c3cacd3a107e1c64));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x03f6ae0995e3cf943f7c582fcc8aa0dd16f97e038d830ae5fb479e274439a9b5), uint256(0x1dde670880bcabe4d9951322b89616da71aaa6c340d2121f35130fae5ef1e3ea));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x26a57862b0738f4439b36f7099a36c1cc2d8a8c186bde324aac3d752a94fb448), uint256(0x2d624ab4d31aedee0cb158effb6ea779a2a6a6278f11a5a627875f26855743df));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x19d35608662ca6e292e4abd85f8c35b276f5a8048f7e78b782d499af8bda91ea), uint256(0x24d27dba284262a8c3dce1b91b20392c96cb28a50105e0bb9c0865e6094c4956));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x126174ad7792a8299acae3418ceaa49c5b34f4f4c4e1a2ef5ee54094f6a8565b), uint256(0x2c63ce0374b135a7dc5c0b544e01c9c0fae62afce8596de5143b44c1fcd0625b));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x0e69cae1d2d36e24eaf9c65afc515e779949182983fd7e7b681a3b2dab2098c2), uint256(0x2cff094119601e39ef95e3f396640b8d0098a5a13e337f3ee2b732fe5e8da251));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x2140979a4e61d78afa05def350503ff54a063a11729f40cc7d19ae24b3a96d95), uint256(0x2f213b566a8b0f8e253b727a08c417338adcfbe1f25652077f5945a3ca54aecb));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x00da221430c50cd2dd8b2790dcd1a357940a64668d31a4c73bd25870c2252c4a), uint256(0x248fe3bce80d716811aa6369e15e768e7cedd13e42ac50276330c0faf1885546));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x0f040de45b421a4fe6fe5395851c823eb1b9f3d69bc7800e6f90168462d10017), uint256(0x0af275a7397e7b3658d0b34bc0b77af1d60cf3f7ed3e026afadde0f8f48198b1));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0c338d1c9070c6789f4b7b22673d67be56846789486ebebe0d01fc64f02ad28a), uint256(0x22bf6da9e40234bff3feea2ace6d8fecd28449fdfcc44e09b5b8e5a2b2720cca));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x24657aede2eea2b1649a40f88d5e86e76ae74a168707c0415df2966483a2b7db), uint256(0x0fb00bd9f014b5db3d3c5c9c9599cd479a12b8d16c548e6dc052ec1adb1e07dd));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2644c48c0134e7bb365140f64927572e1e00b472aaa4916916d1920e7c0fe2c9), uint256(0x2c1d50be530df0210dfabfefc3d751f0c2548bd76b3e376cbda7d35252f06487));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2034a4fc15184d32f47d1ddec4ce99e17d5b0ab2bfb19bd1c28895734559e0a0), uint256(0x0fb3c4c2d329cb5f82cd42fc7d47d2625af186dfd128e02732a9b4b0ac7441e5));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x144b18db65f145ad1acd81a28f3a15a25bb31a1c06a65c89d8695d33b10a9e34), uint256(0x28ce402c4afa0e97179b34561540363fb0295b647f6bee0240a520304b5ac062));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x0c84595268e98c685aa04195c00512e06c7d9f8b6f7201df413b8f69ee7f3563), uint256(0x0db06a574010b47ca56c29cc6480c93e21aaac0226cf3beb896716f53cbd52e8));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x152201087615155b00197e87edacfd055d15243718b20d6eb7be76535110ba32), uint256(0x16dfd18ac95a3e346138f32f93556dd6317d3dd8898b3e31e318b23edea0c0ce));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x022ca1674576e4b07a5e21f4fa4e78d9c623dd537ce39ef6e8b61735db5d7246), uint256(0x13fd33b3b86c71bed36f163f039e5ac43ba63f126cd5f524be240fb348bae0d6));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x00f38301d263a9d7fa2d6fb4bc1f66565ce25aff213c6b37a9ead2a77db6fc63), uint256(0x0db6ed77961febfa7131940555dc4dd5010d4fe33af8a65c7e1d658371a68631));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x05c949b0ccc0777171b7e2ff13a4a415b9f5177968ba7c93024202067f6ae001), uint256(0x04f96e4142c233570af83b7c112b6f800cf6a576d448eca8037d6342124fc5d6));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x260b3c5a617393a8bc15e6f9a4f464c1751fd29f2f327a7a2231e8fd815f340d), uint256(0x0d386b9ffe08cd51e048e21d95cf5519270632388835fee331fe6ace34b7ad3f));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x11ceea0866e91f493314a4ff08ba8f7e792d55b8305acdd4b1a7c6f08c50ba98), uint256(0x07a638ca996bd8bbbe4d3812e16386a6939654b0da03861e1a0ac64fba485c96));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x1ebfd71c00f57e95ffcd99dee6811a904a909c892677297e39c24e69154da5aa), uint256(0x065c436f5a51fadd7de6132b5da3b1966fd5feea7bbb7a536852b5ba980809af));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x079fc0b345d3295690a41731e533288b0669c90fb4e93310d28d0810f919b6a0), uint256(0x1bcd2aa892e84effae915ab42c52084a30afa86d483398a0b9ec383c9a800da1));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x0d93a336e0c5d86f72cb3f9c17bf2c53ed602b3e6b969dd71a479e36c8e8042f), uint256(0x22c877d0b7a8a09dd7c3ae2ef4b5e413e08cac0a807e010614361f344696c134));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x2c3a579a27500b51b4a2f173c1c3a247c248c21d38587b0441b8cfd9ad110403), uint256(0x1e04ffca3e4819cf94006b4a2a276a0da056c856a861655e8bbe77a5c494dfff));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x06f9526e7d518e6c6eb35bd8a228b8849a4453528a59d1374662ebdcfbbeebab), uint256(0x30575d105985a55ab06a547e5848af1ef081972c4282c71f92a134ee96f36f97));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x2e36f1f4f40ac83230bc3b46af874615df32a121384f83c222a27fbefc9bc8cb), uint256(0x199cc490620caf863f5204c647b753916003943f88725bf790a827aacfcd895a));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x07b646923a1c5a045b3c554934af5b3e9e69d29d13e7469218ed380012c14ea0), uint256(0x1cdc4029dc7c1b53451a3d4b926198253e5ef2a820c73780753962aa72e7551c));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x13c3f993df84af44fa8b72f1540650e93146e50411a64e35eeefc33cf3d93b6c), uint256(0x2a47f2d7a1fa050b867f4414074155a71fcd5a935589696f29b5f53b12ccbf67));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x20ced7afbebce26112eb6d93cea549e7d7ffc5668d7ce5762fb7a2f4fa8b92d7), uint256(0x22867047454f50e7fb36823fb82fae70faf02e18779cf3b4b9c54b17d8fe08e6));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x0b33e162b024134bd4152b6e0f6f0974b652d2b8956df55028b02380eeee7f79), uint256(0x08437b9837d48256ea3eaf7bb125daf34567c533cc3d55725686d46b4b8da2dd));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x2472b617e4cba140a5bc9ac086aa80aa39c8fd08473ca8e269fc1d6b83988166), uint256(0x19329f62a264e5224bf9bf80c945abc8a7aa026615c2d121b795f47c2463c34d));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x0b4a1aac8bb0b28c4c2fe7b390c8d7136338deb08dbece8d2b3a13d843d7b892), uint256(0x1f07c67f3630da948ab8de2dff821ea571cd33dee21d2a663e98fc94c1a2f4c0));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x23170bf483ab0918de6622de2cee66e477d2f1ac2774f3199f0ed01514186245), uint256(0x02b035f59945480dcc4c6ef8efb56f04aab96cc9da9b62fd0ef323e0ba0052b8));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x3003486d89294f9741b63ff5fe0759588c797577cd519e4313b50a68e52883ee), uint256(0x1ee42c7e21065c6dbf5cc13a25e9a6cbf24c8b7b6c24e61db72193f3e7a0efce));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x24b0111d083ec0450fa45e8f47ad2db724dc801e0285d7e786ef6252f100315a), uint256(0x1ce2e123705393526839ece77dba33abe0611c0f5afe46c380c5dbab44f20a4a));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x288706265008f1badbe29a417a47db300b1ad14965166ab60ecf966684b705a9), uint256(0x014cd9182eedceb68913559e790924f4efbc86631fe593ccdda6c72163e72681));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x1d3117fb60225920d5d70ce881b7a5f561b5a6dfae9ea7d7f811333ba46acdae), uint256(0x29447bbd9ef824ef7b541a2f2a3d63ceef92b39a9d0c8e9f3dd5b1c141128720));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x2f87e3cbfda3d683c1ac32181fd469b79490cf129e5c1d082e0e207943a2f632), uint256(0x2c3d1ca4c6f62015120c81ab7e71935f17e3c7686f80cbc597ce7202fea2fdd9));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x2a6f2b814229f3536e86e0be0e13008750ae9a2a20a61b69c918f05af6b254cb), uint256(0x2eba6959b06267df9f4204528269b032ad5908eea7d8c171830f3cdc73885597));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x1c3241607c704b4eaedab5b672ce8f6af73451f3f6d369670e3555e7757a34f4), uint256(0x001b949e8667645fc533a4075ae6352daf648f6990566a4f070b7a92b841084d));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0a0553645a4e8d426ef3abc34219f416374814e8812a7f7644673fa9e060d22f), uint256(0x1f76e0eddf96bfa213299375ba267a919d64588758dfcaf5339004efc2515fb0));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x26b1545315321ca8bb05fd1869d54d20526e554f86fb8cb92deebc0c96c939c1), uint256(0x1f464eef1eee8307afa23b49f8420f6fa07f9111409e52f81fc58c9915ccf741));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x07ce612f756a138e75203ae22782db7f5a51c56480eb0c86a0087ee2d6751359), uint256(0x1bd740bd3a94231e76336e747cb71f8515c078e7cce40619a05e9a2197b95ace));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x1bfd03e891e2e185612993cf820c4d31676194143fd5fa3090d6d1c7abdc0740), uint256(0x273bf5b219684026942a72501c29ec3541b7c68c649c452603d22cf0d2117d51));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x20c7b108ce3f9d4f55f9ae850f119c44a72c3ed374b0fa057b25a5a02e864db6), uint256(0x08586302a3be95271beda6dfdcbdf24f94cc57354dc26678674d17dda5f6d142));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2acf43a145fef7d5f104330fba97e8fefe981a897721f7a288645fdfb8ebd7de), uint256(0x0e07aab8680305b8c037054f9d6e8d1a29d3e0cf0695c3cef9c174757afe0225));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x19f73efbc8196cf50b68489dffdc77064813dfaa2cfa528fb151794506c65f8a), uint256(0x1cb0623dd77d419253ad4cde5bf5b6a2a06d916cf06a2334fa5c19cb48ca8a2a));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x28fa81881c1f1a6168c729415eccdfc619ef10829bf90cd2653b481663e9adee), uint256(0x1ab54edf92c183daf7bc5450072cebad0ba6429453e0be78fa8b8067b7e21d04));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2cb1d3fe5483f2c269b771f4b7539511ad8b9606a6f959df8e7de405ff017ab2), uint256(0x03e08acb46dc7170e286033f3a35c299a7004132310065d8d63190055aa19138));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x0138e4cd230b97c1981c8a5c6fa6cdf6cbff196ef19117c43d7954ebb07618c1), uint256(0x25c085bafed376efbac8709fde5d0600a4b4fcd2c232e862e96ea12913604894));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x099872de7cd0d4b27bcf36fa7a3830705d4080a2fcf7ac2a2bb4a2eae932631b), uint256(0x16a1994951fd824b4a27c39ef4db5f921a8e1b4618578f57f4e782810f7f6488));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x086d5056d11e79cb263db54abe152f2ee33e59765c4072e32888913e105f0f13), uint256(0x2054b3e67641c0cadf75408c3623e9c84c1f2d1a73da2eed4baec40c5830a269));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x03679663d404465aab15a06e5888c4865d593f80bca7f34355ebd3d3eb88e396), uint256(0x010b9b928abdb41779f0e8f94c14388964ae757ad330886799258318223fdb9b));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1cadeb69d5e15e0d680e4e173b86782cc94682eba5cde5f0e23a65047ed7b598), uint256(0x2ad6db964a73c86c5817371eb7b38eb1855f3de0586e5526fa7e018e4c4377a6));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x28ca8573c9f1097287a4bac184ae49595618bb6022d0e761a711c86dddcb1182), uint256(0x0d98cf1e641249972e344db3625cee7fde3750ba67309088d0abe182ae748b59));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x279dd1b244876dea64232e6156497cd632583f60123d6011e5330aa998264b93), uint256(0x0adbeccf14ced719e3a7371966babe6faa1182febc1935ddb9892ae2de0a9089));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x17be9e7df302274a74a0d0bd64166942bbc90b96c9861fa57e3681c7ac2eb71e), uint256(0x17ab4196a5271f37f52f88c0b3e547ef5a750d14bbf8b9c2027ce4e43d047477));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x20a20f03d25a0be1d2f606b794a8b371d0367faeb91df42c1f302d1f4ecc92aa), uint256(0x00849c1a5e516a057e56e2d2bb0b3ee833d8bf7bf7b84439b065ee03d65906b0));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x274699616444c0280981cd6f746511574202b2ee34d2da209accf8e1f610ce31), uint256(0x04dc74fb8026190e2808dc34b6d95f74ac2076f8b93591de1aba50e18b7ece51));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x0448817ed0c0dd1d5e55089700f4c2cab32fac5492e0008393067b54edc4a525), uint256(0x292384aa2677f4fbb5e69d757bf187e2f353cc2b8c7ea707cf328c38a42aa683));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x0cedcea76feb243822799f8ff268dbd8aba7b2a96178965caa15909231d78728), uint256(0x10b6e3b6afc2526abe873de008f21b1f6b9ef7343896f6c4e3c32fbe2eacf1af));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x2efdbcdae4a9bf47de3431c178da049c846de02fe96d4ff3f91bbf934275c94f), uint256(0x0ae320f78f070f739c4c8c692f260640f28ffe48d88298a4d997e8d50e28c8b0));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x2a3b7c3aac306d84664328ddc1cab073306512e477ed267e603d1a76d4773918), uint256(0x05c53c2c5d27424ddf7c80fcdf4e61ef57c951152ec0e693a827a5b1aa4240b9));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x2a67a4488a087ce259d2653dc206b52bce423df7c87e3aa02e8ea672556c52a4), uint256(0x1df6c6a723b5d29104f6e415e516cf6963bcdaa56b4d535fcbe5d64726b47d8b));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x20ae645d6f5bf5ee8635b44ec1416acb30bb7a8ca12ba957564ecd990d86d813), uint256(0x172191b485cd6a2c37335c59c45788e8786a3f20717716c8628c6ccf9415ea53));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x1183d3efb0e45b25c07477935550558cd9dc05104f861a33696a9c6a14c868ea), uint256(0x2d1b058cb8230df77ba203b6e3163acb24960e45bcb06e5ed26e86d5aefce8f4));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x0a2e585c5ac607e718bdee78fdb2eef1527cc726ee9de9cc810d85a2cfe97b60), uint256(0x1a548c04e46b59603d2ca38b1064090bcd6103d5da4c761cfee932d78498b1bd));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x106818e0c9f6df62017c28bfb3c801d109f9168b9935a7c9344974b70359d8d3), uint256(0x07a271131a3818117c2f55572caf6a6c2f8ec5875fb21da2386309079ac7cea2));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x1dd341ff0d68b5211d8546b709a6baa9fb7869040e903318557574eeb2572a30), uint256(0x08ccf07a7bfff2e59c53689506f499d8377e262987977be702e9303d95a3f1a8));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x110cbe64833c304dbd8ded4a46765d6a5ccba76542d08323d2fd254e84f85223), uint256(0x00027f8cf50d78aa23c9e9e5ee874605fa370ca3f1d4d5709c385c38aa224554));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x2f9d69c7079a58d405c3ccd27923424352357d02b79fdb303596118064599048), uint256(0x2b62474c4c53c75245d4f6b7e2fb38582b0d4ebe992dde17aaa865d48e7bbca3));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x0c10b9d06df0c9ebf6625539f40b4f946f8762624d16b8c80f21ab079c4b2b35), uint256(0x221e71098e7d92d9b3a6af04c87916d8a6f8431f7b9dd35f057d2345a092841a));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x20a536420757620e336883ad5039e8aa2feac7ab83208a99a90cee572e8b78cf), uint256(0x1c5f2b210432f9b71894098717d850c3c06746969ddda0a57707dd44b3d71cfd));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x0819d6c1e47c69d4fc006fcd60545ddf40e4e82d5fda99948b327b6b2aef8531), uint256(0x27143ac8f97b25068f1936a9449800d7177776ea9ffed274e81a5735e02733a5));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x1b2c4d0ccf381b2086fd428a8db337eda3ae1565e82e92af11df38702063acef), uint256(0x0a3279cc391d4d0152d9d606a066fd1d69709c2521d5e43c330b4274cb23df30));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x0a4f8a60d6242af708b6b3106ea7e57bb3de1c40bf7372058d357c885d9ee95c), uint256(0x023ce0dd2e080bbb47ce6f5e87a47ba0b19dae3ce65c9f810fb866c338602aff));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x0e94d1e047d2dfe63562effdb8b22668c47ebf511f4609369a82cb0bf747e220), uint256(0x24162d0f3dfa021a63d1a5694db93fa56efe65a9b5c7249b5fdc93241faae90a));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x1edf4867de1ce9111a84274d189ae9cc1ffbcdcf19690817db6bbce7c589cd47), uint256(0x2ac40ef75a6cc12d50daabb7cf6820fd35d637203570d7e052fa4ceac88bcf33));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x169820769bc0db090c1dc2c8973a31fa550f28e9859faec55d39c625b49c8992), uint256(0x207f6565ade2e2ab390d6c48cedac6486a71844cb064f4e944fee13c6ee04edc));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x0ac2e68cca8d034384f0e929f5c8ab75c12246c3d0167e7c97deecce36442ca5), uint256(0x1597ca251bb040713e7c7b5ff393c16673750f7a923ecf841d23fcc00000946a));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x1245faafe82974ea24854170b4d8cff9d3b3d2a90207503399f094737bded623), uint256(0x1623e837258e2d27c9a44371dd890ec887f28d06696efe5abe975a6223ce130c));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x10d213c51d248120f2b3d9f293897f63e65c444476a1096f53426fc508178828), uint256(0x19a90f4077dbeb6fa564c3e4c097dca46875e04bdab335d373aedcab93bb5a5c));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x0bdb23d332b25cac5a82cc231e288816388d211605c2ad5a3875a967d31c8c47), uint256(0x17482719a796dfa49391b38150ffa6e38d39cd28bb6c76857a8ce3ba3a48a100));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x2a8c9e05435b6d1dc807ce3f6ebcab487c06264f56e0e5231f1f90af7089a1dd), uint256(0x2c45158b7a42a247187894dbe9dcc2d52d7d13d74b3210c3dba96048271677b8));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x047fb3165d795ae1955c631e3ff75a85d8c2b543093298a4b078a86f86399849), uint256(0x09c7c548ed6bdccda3d74a59a49e8aa3ce23d7c0b1d7f6e79282f2d56c612923));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x28818d6cd17037f87fc530afa213717c623a2cb32c7fe36194ee0e6de7c7cdfd), uint256(0x2e4bea694aa7632d5a687d2650ed6bdbadba2dd0351855d28bb87121b0958687));
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
