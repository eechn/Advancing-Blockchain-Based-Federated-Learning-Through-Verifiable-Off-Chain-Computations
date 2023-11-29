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
        vk.alpha = Pairing.G1Point(uint256(0x1243c4d0ec53e0fc8563fbe6ac1fe1be39442b480f67f78886d864d3d72169c7), uint256(0x05c9e30bcd9299dc4def9bfe5282ab41a2794bcc4c7a691985b12124314dbd37));
        vk.beta = Pairing.G2Point([uint256(0x13e0af31431412e7b07308b40773e6f751cf44fba34e893ddff96127f2e41e42), uint256(0x071ae5bd29d0c0a7e5c8c4aecce988ec4eaa36771a12c72202bf3d64aaf5f947)], [uint256(0x0397ff35855fa6068f28fd1ac378ed43907f3f41e3879c0018841d1cb80549c1), uint256(0x2dd93e3a0e7f8342244a1639a7ea28325c29ed99af3092f725ada122012dccfc)]);
        vk.gamma = Pairing.G2Point([uint256(0x23d682a9019978fc64b84079d753e6392c12dba58ec55eff220fd80d6fcbfebc), uint256(0x1c3dfab3fa85ce4464fca8c1b980a6bbf05ff6c461575dafd45d7fe06cb2f960)], [uint256(0x004054d38063739e3758e95e304ba37a4190b6f195cdfb14e6b3998c71b9b7cc), uint256(0x279a39a85313b406d7699edb9da12e40301ed4c3a1bfced9f461ab5cf3b80a1b)]);
        vk.delta = Pairing.G2Point([uint256(0x145ed7e8957d265797c70a237d01d29ba98530db0c235b1e3c426764cde74582), uint256(0x252bc2ccf34f30288d076aabcac92a7ba51b45230dea3eec6368d43319a1bb76)], [uint256(0x0393f502908e6dc330fadb51c92f159de44f4a3dce07609b74073c5482278039), uint256(0x1d4ba4953f91df9d075c530355e29ae26f535c06fb98adb1f59623f8f4605a3b)]);
        vk.gamma_abc = new Pairing.G1Point[](210);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x05d0d5960448d497603ab343c72a5288f44e28e35cf757a301dc02dd32985c7b), uint256(0x06b1fb8112f16c41deda67204f122d66a43c08c118ed28139d19c07729ccb8a8));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x222341804229d7701544ceb5a48dc33dc0a2aacea8096562e00faa33ab57aaf5), uint256(0x284a46b97e77c257fd805648c8d22f098bbf1b31bd5d9f3deda7b1e4f1758d8d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0d94edb03d21dc48c0eafb24c4ff76b5e116b8f789910df30037ed7e66a2b968), uint256(0x03ada859beaac71b6a2095a05bac09d2fe2926462215adcbb95b4e2d3c223da1));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x02cc7f305d0e9f2fc67f926baece1f7f0255b07e47e0f0c2f32c141152244b1f), uint256(0x2709590e24db5676fb1b0609c26fed3538adfa069825bd831483c4a76eb3c431));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x22edcd659ea0f768fc336039c98acfe26f7cc8a99b0edd6af4ac7688487f0b52), uint256(0x078dcfb39dda8e056b5267cf6360adbcfdc105de10e297337f1a604ede1a0a26));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0958d41df24e7eb500090627d4b21c4852153d0e1e4492e0a27f471c578f72cb), uint256(0x03262031f30976492271026a5989e88f1aee0e911464542605134367cff9cc6e));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x245861f6e3e589b6e73c0afbf7075101e98dc02b98d0601aeed88e93b2461f7d), uint256(0x11a1a9756f62d8c3820c358b11c9ce28baf5544ba17aaa5f5b25875e86627e4e));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x238bba668de776e799225c8232a66f02b174aeb117c875bfda699c8bb2917980), uint256(0x2efd4d3de07cf2e6006b0d6e3f18ea51731adecfc154239ec7d312757de47247));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2340bdf3e5ef9ba526f297858503882a4feb20e4aeff33c4e5478a23897aa07c), uint256(0x081cbb3a29ee9fddafa2b476bd51f057fd4e004fa31be747669d38e33a73efe8));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1cc645b86cfe45f57955f834994a61f9759fe23eac6a2c95045d0c34eaacc9e3), uint256(0x3026242a895f8f8df98e32a21ed8f78116f1faa597062a0fd7b86e7e399c8691));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0951fc9fa7ffa12eaa0e422a9fca5a50afab286220ce36c1ff573d4bde2205e5), uint256(0x01e4a6af18d7bebc191053f9ebe74d209ce2303f2359833230d01323860075eb));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x087f16e89cb7fbfa362f5fd026fd80dd6e7a48847364ac9757d750d13b49159e), uint256(0x25027ea42450217baafbaf50a751ddbd0624cf901ba549e93fe5d699ab2bfb91));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1d6f10c499104161d2bdcd0042fe2f93267c0dc5da9fd349513b8f19b6c28546), uint256(0x181ba476af6bced31e27677c92703d76be01d7559a285923ed90d5c509acacb4));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x10ad9d3663c1d33adfa5d98c8d17283252ce9cee5b844c31aa748831861d1c5d), uint256(0x2cb3a6c8fb4f4a9173e660484ae7078e834b6250e5b9b6f8cc1b9b202370fd82));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0801036a30fb2a0ac17afac9b99741847ec086815197e266723aabb6fbf3a3e9), uint256(0x114d25322e396929c1f72de3d521dc9788c9c5f29f0350aa55b6434e5a1831cb));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1dca66936b5e2dea459bf2c1262e3d7a2f4ec4796a5b919fb7cf5729ce77a0cb), uint256(0x2428cc057d761a0d60693de65ddb494abf2420c8562d4c26d55dd28d0b870c2c));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0c1a5c904c7a6b675a25a2b206110186b19f34a1c1de6c20e46d39b7595f86a0), uint256(0x035eb33328587d66af7ff6e6c10f7b593aa3d2bbe18b10249c976cd58b49edfc));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x00c90d004946ba3d2c5eeb04da97806dddaf75742d777d49389ffe756e947afd), uint256(0x22f4a475945d9408e3a0ce9b4b1fe42267239ed936efb974ac56121c5fbcffca));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x165628db3905390bcc3fda6b0a37d6c6a08911438cfdabf03ab84eae0a04e0e0), uint256(0x23ad03de9e0daf89e7e05a619097d56dadb5bfc6cb61ed7c936fdc5b509be53d));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1dd5e9a86819bc10df643a2eb1fe3dfd0a2bf5fb51ea6c571f25ec23b75195ed), uint256(0x0a3e55d3bbc8e464d1eb2d99ebb23083885d0625940ab1b85eb869dbe67107c6));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x159df03dd0fc942af79a8c3544d7663c59fc84c7cc48c07413b66afb321de56d), uint256(0x20d203b3f7e901efc9aa17aef51e70babc0726f354ee34e1500a57b9b083a264));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x03d366f37e382842f956dd92e40ea27ac5583edeb8f6ddcffbc5f6cf35d645c5), uint256(0x0ab71775d83183df683bc656e9405202a07be7b1b173ca2c9b5538b905256ebc));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x07795aa95950f260af80ecfa63df7e28cd5779a9ed33e3c3a531e10226135bed), uint256(0x302a929880e03095941065d10fba2eacfe79980f93a48063d6a3e3d375765d59));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x093ae6a6dc653516b9829b85cbc09b3cc59433d3c5b966d6b5d2d2703e775354), uint256(0x07fe57074cd622be298aa40d869cc67305ff825f7ce2fa961acff55fe4586856));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x22e449ae82d7a4b54efe37b4415542ad412d0ee82d56a11a72739af05abe0b26), uint256(0x21c0c45c89e38d657a9e0775680def256946df6d20a965ba2aa119ef35592c8b));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0dc2e9fb10b8588f7bbdbba25c461bd10a02ce1d25e2c73d7256e3c64cba9fe2), uint256(0x2cade825f37c24d7f2a6ac23c223dd087b4f48f2a4efe6a1fd66bdd22fa37d31));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x05ffd7330cf873fed58e8cff7a419c7b49f57bb49dd01a3847ee48e3fb257a07), uint256(0x2a73129896e1d154bd4c9b6225ee16e7b18da5aa5af8560f0c4a04a203087ae4));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x118cfac79efc85ea6655c7798da3b9e5c7f741ce504ca545bd7241427b34e2bd), uint256(0x0ccbe33c5187212631b8898eaa1883b90f12a97a08751d32a19bf7fac93c3a8e));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0043ab438384b4ee64b4f43a258bd85fa1d0c8657566427b453d86208de20882), uint256(0x1255fbf155b2a0763b5db6f0073399740e5c2669658aa56b9621738aef288605));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x247bda62efc53fd03ed26961fed43b5150cb1e334f3577f939840179fc12e6c8), uint256(0x2480b5d359794fe16e4f8c6b36bfeb93662b5d47f8909290eb797fc9308e84a1));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0c4c13861f6351d8b7de215f4629054f17c7fa9bb61d34a7ec8a9fd8e49f5fc2), uint256(0x2df1edabab5fe7eca81801f6405c26c48faf4d8978ace0a213332fe72245590a));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x24edd62cb5594124db55187d8b3a051de5806b9ea9ce7753326ee19fb8b49eb8), uint256(0x2490fa6302429941747b6df8d11217fd788ea2290d52f347804ff807c2f4252d));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x05d6aa60de12379ab757965d8e211aff5f03577d123592e2636c3365f3feeda3), uint256(0x16be677a1a757cc5677053137ee548b64df1fc98fd285f8de43f7f25040ef648));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x05577cb3cc5901605115c343d35e1c729224c1a9e5aa4247be9def66feb55720), uint256(0x129c3c9b7092781267df00f23dddfc76b4ea522cd4b57d7df4240ebaac37e993));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1a4a91e6e7d4b39411dfd7bc488e8a1e0e0dcec361ef1f4d2c14b8f023bb05f1), uint256(0x080d06261c26d1a8c09ae7ca5dd07177c5405e3e7c7bbef5ef9a4c6f94cf4f4a));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x26f3fbbfced0ed662aa063cbb86a0fa3b369240d43f6e07bf0dce6cabe57aa2a), uint256(0x268cca306de6b0ffdc4ffe605ed59fb9e0956b41ef484ead610b178c511833b2));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x01bc867c7e27222b7b50396c59ab4d23b3251c3c12ee7d2393752d14d1db4eb4), uint256(0x04345c0b30f9ca8f4a410a68032910747f6522174bc4bb51ab23b72f931a3f6a));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x0f1eaf048e18821f3dfd88f53655addfed31176c3fd0ef2cea5991fd2a7edd6b), uint256(0x03febee6832c1be7d1dde6657d6281dd8b263df7366087ddd9386ba17c8bb070));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1da84c438e8d0179a9a2f13adae18f8662caf52b1caa43453b5575ee9bbbfcab), uint256(0x1dc01d93ada54b223e3d6670cf8ef89bc4caf60e665cf09265316212aadd9432));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x177f3e09d5d1aba71ce6b12e179a62adf21ab3619fa5361fe7e433370a503e63), uint256(0x11fdd3ee83ae1a22cef433b89dd8aaba5753533ae5fcb9ec629dee83f82ec39a));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2cd53a6c358cb15bba19bdf63f1642dbd64f8ac9429359eae52fd104dbe520e2), uint256(0x032d91499488adc23fc94f8dc6cf713ee7e987a8ed546595eba3886b34afe682));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x14becc253e5cfe37cf96fa63840c8283871b2a4643d641215d302a96f63bbf4c), uint256(0x1837a35378b1bf347168725ac71adba95782a4cf5cf37d9dac9898257a8b2f5b));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x252aa7fc2b867ad5f08bcfdc3b0fa8db245524b08f380e4dce7b25150fd6999d), uint256(0x2c454c9a58d744188a2d9cad5bae00aa8bc412e31638969a057252008fd1e5a9));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x248627ab9204be3298d6e1761e2214f8946077aed72138acfe01a29bfdb17cf2), uint256(0x2607849bc44bd3e72dd43762bee452aa49e8ba0937d7b893ca3511f9cb302d6f));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0f78f8a1f8eebc810283ed85db60b1c2c1f16149f2d23d436206803ecdf1c321), uint256(0x2c65621ce8b38905ce5b8cf57df404924e9765fcde1149eaac64fb6b032589ac));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0b656c08632d70d82a0f3003f8dbd5013238024e74a14e0484e56ccc5cbdc764), uint256(0x2d38a7cf65efa16aae019a46c22818ad859afa225be91d4e6d772343fb7f5bd2));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x077afee0f401d5828ee6090099b9fb9b79d7f794edcf579258a355faa0159fdc), uint256(0x0239f47917eb696621decc91ff8755e65b2e4aceb5fab324c614ee5236f24e86));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x1c05e704ccebac6b6ea6b582b4e952a12e96c7690bfb56b1cf35387e875dfb8b), uint256(0x1d2ef0fb6d72ba0cbb82ce08c9e43c80f199b9ffc66e5d4cf7fd9b414e34e8cd));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x10f8e198559177c6e63611dca035b240fc5817b353bbedabe4d491c742aa86f1), uint256(0x0a6a08de469e2346e03f3daeb30286c0ee261fcfec5a7c07022e5f7ba065b61d));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x3008f76e86a2d3fd5848459504fcd7f6cab75a54d3610c6e14edeb3814677b09), uint256(0x198ca13c5882e503e3a1acf478c5149ba83181edb015895752d8289a33b520b0));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x14fa63c597395549adaffcf788896f039f900e6083ae608c2bfe647abf7e4bb5), uint256(0x231eae6ff410b7489d03f55469a22a77739ac60f86a330afc6b2749c03eb915f));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1b75eedb26cb887a5e8cd84369d2f5cddee9cd9f215a2679ff0ffd3ae2677c50), uint256(0x2939c517ce233467f49d76e4d48f409ab5b8cc13e229796923e2771ffe4c78ed));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x15eac982e9ccfa1e59a5cf968be9b3a3e053213c6a26c5bbbc4d3f32fec91980), uint256(0x2e2d4c3ee9505ee848d0e0db6b21f2840708f22ebbf156f29b526004c370f068));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x16be20060bfa73887cdd184c5d5b9eda81ac6c5268308abd5b5a9637f466454c), uint256(0x10ca0573ae977245ca2072da0ad2b4602bcd2c41bcf347b4baa09d197c65532c));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x285eb736bc688dd1363a4536d9294af5793d917b062fbdba75277a34ae147f0f), uint256(0x156a2d619f21d2fac64df96f208403e60c2c7ccfe937b0e93ca158ea7d3365ba));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x1917009b7c360609cc70895d9adf2700ef51edc1e2766b8f44dcc2db550cece7), uint256(0x2ac5426436e83b9d6fc08768b92bd7051ce346caf35cedcdfec5b38927ac340c));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x16368f528d49059303d4bd358305a31c2db35264200b8a400ad10d082fee01c3), uint256(0x00f4298c58045438db77bd1e30ce6a9462c9dff7c1720fd97e7fba55137a2ae0));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x25a42f2235814abbb53030c2309bc05d9a071aeacbed882a5067b2abdcdab5b5), uint256(0x287b8587cfaa9e935667d4a95f00e72e46d3b527b6f6db507d5bf1fcd53c613d));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0ca63de563bcc8e31966b6b1d6eb0f23b772c381bb54997bbe61dd6d9533e34c), uint256(0x121f4423a8f801596df51d19e449070c8a9830aefe1459dc395f59f2812f5a48));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x0e39fb3cb79b24a8a161d831b59bd86f98afabcfa27d2ccd8841b57b95eed2f2), uint256(0x1788912a817f5ec4a674ffa0afca12d9d3e4b700a16899c8cf60ad891117cd72));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x1146ea950304b8fa2a87d51d593f28d7bde6170d689b70bb1437a5e171a9d9e5), uint256(0x03a2946744f23eeb6c8a5dd68361087aac053b91c0e28f8c93f85a3f6351153c));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2d6d599a8c5e5aae1d4d15dafadff6272b7d10676b2d20e8904ce9e82fdfb6f0), uint256(0x2dc8dc0f37f990fa64815aaae13618b3febc54c2d46b3b69a64d640f650453ed));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x1122eb8cc4752dd98bc6c0fdeeeed4813fb2e263509248b06f81338a32a1a587), uint256(0x1be507fd5e310c75d42ee6d62e824a01f3566b6c6cee72408e7fd7de7c791a25));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x021328055ec706ce62a979e3c9edc0e07fde2f1fb06d654416c0fcf5f18793cd), uint256(0x1b123d328a87276098acc9206da72116a640a83fbb57f1e7e715c5e7e44126a2));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2ef1de6513b8dfe5997e80fa559ef7b73d1a2c0b48a6812f0ff10474d286ae20), uint256(0x154512eea1bdb1da5b932e030600a51c902a212e97eb7a90491d3e320161dd72));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x067f37d610286a7a3aee1166c331e0716502115f15eb22a8392520ae19ec41bc), uint256(0x178bb724ff1a21a3c1a39c5d3f072b24333c04dea3973eeb581e78839edac9fc));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x10694233a5d5814a5422b1bf3e82a697d00bad91769ab1c537cbbed56b863984), uint256(0x20525444e38722d6046ffdcc1dd1cfa3013a9d80eab85bc2314978eb984e0807));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x29af07c0d729538f81d47fdf796a4476b8360a0813b12eb663e6c220b359b3d4), uint256(0x0b2b833df31aaf746c6fadd002d301bbad6c4d4f982ca60cd14c2dc9d3f409af));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1919564b6e3826eb02f6c48e97c5538193630e0fe91001d4d10d527a456ac6a1), uint256(0x104e64bd7f07ee580d153e928e0eaceabde5fbe7da29b7afa8c99258280f6450));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x15b1e9fbf6deb25327f56c8b650cb4ac9b86358098d02f45781d91b90eae0ad7), uint256(0x05b4e4e5e8b517638ad361d8510eedefa8deceeb8cabc3e02041189250c5572f));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x21127969a3795c93403a9718b57e64d53bc664cba6103b011b1cc7cd43de6338), uint256(0x282bcd77986052d51fa009a4ea06b0b7e2f76db60cd5902ea909ee0757670a09));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0b6000b20a46ce6e7d9f7a7a129f8b52c93e1de7b1336339c08688940da6212f), uint256(0x2687998009a63b125649f6fecae0fd04acda7fc8fae0fed8e8a74b9b286f9afc));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0bde5575e2ccfd5e12dd47d83ad64be3f7c70b4c6ba1dccda88259bdf823106c), uint256(0x219223973053428b02a25bd0137090a801bf1c8911d282d2d2f9c2a666b78f01));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2b72506aa840eabbe2be228e43b95191d6ab31fc3bcd0aba518ffc5771f1326d), uint256(0x095abf58127ae3bffe66b6402b70967d0f990c783852f263d74a17d07e2f44be));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x2a3128484fc47bd0cd2e77aee7d4174fa81d2ad348704395e9f545d0a046966e), uint256(0x249f4f668d958bf99d0fb52b754f76c26264c88514c69899c9b5ca96020a27f4));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x16114e6d7bc7f24f8ccd30150d321012190cad6f8a46ab89a61994f4e05c3df0), uint256(0x15d02dce07e48d502c804e4f24d8871503fca33f3f6c3602907f69544cfe24fa));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x01a6b83ebdd4e04b69b8869880cd6d72404c289500551a5f0f73c09e6e897618), uint256(0x1841122eaa2cbb2becc2c3e22b9ec8d5c2c96cb2862f85e2bb9bff8a946de756));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x07d68aa550f56df87eb269e327e6e699066f54faa26ee401a3aa7798cdd4f87b), uint256(0x261fe96311c771956df3eca0ced3893f76bab36795af49cf4aaabc556d50eb9d));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x25ff4682b03d3e4edffa4962ef7aad3460925351b265aab3693525f4835a73bc), uint256(0x1c5c0bfeeb4516f7181ccb17aa5a7ca85a8ddc901d354b4bb6b3199eda5d954b));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1b024cae0b9db765c6fe574f6df8990ce61c13370ecbf3952b8c2e2cfd704b40), uint256(0x0461fcfd3d28f022eef33cc14c04cac905c2b295ce8a423128bd74112c0281f3));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x22b92dd01786a9374d6f7aad4e2c6f2be6ac6209c909039caaf9942057a2a879), uint256(0x0b69af242ed2a1b437c102a6001ce6cfd1865d89d8dca67e383ed2df5a385d35));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x1b68be2be93c451e111b88020bdab4f0f7a492785e3502ededeb7040d7fb07b5), uint256(0x18dab3df72682ead9654844857d1bfe5448fe8a24543494e1949c5ed7ec10ed4));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x2cccea7de6744604da0eeb12d588ed081176623649dacb879b5934a3c9a5bfd9), uint256(0x18e61098174da017cd02222e2e628340bd2712b6023512a75a7d8543594c2700));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x26e20a2208f5cca233ad94a7b9009cf5e0e605602177d4ebb41e66973ad1d80e), uint256(0x130c48bb2491c8a3b89226210fdb24b48d07e259905d3343179b98ea60468d9e));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x0c49eebbb2f88cf6f5e96a7c2747e4ab42b7f6a7eca853d3a53e261e2db81cce), uint256(0x27bb7a285a6cf2219bf759c7fbed4864fb926147dea7ad18b1dac732e56e0717));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x22f7e469c0c515212d59efba83abf73073c9c1e400fefbee555b91bd45ce2ff5), uint256(0x0973b62845a0a0b7e110915bfd052755c325aa631316fd83989c4840bb9bffbb));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x15a30d15515576539ac347605fb746b74c18469101953035d913c2a0b5c11dbc), uint256(0x1641c1a8040a37540b68f8d4a14dfefb916454285511dfaaf0574669e68c48ea));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x05c6362b5e01b1001d38729bc723614952ff2aa6000efafcdecbdccd06a165b3), uint256(0x136bf07d1cf5ff5153c46c878f25f4840a8595223a3461057e9bd23266711e8d));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x049d868b5ab03dbec6bf78f753d68495d3b9bdda2ca073624eef5ba013e4c15a), uint256(0x28dd8d727d68d15b412115f5d47b907642b946a59a60dc4fac39b1367a3f2a3d));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x2c8026616d6a3720b318f5dafe3c5c1843fb925275155deba0c3fdfb16ad0977), uint256(0x03f4cb0da0dbabe6cf2565acc5021c7183d58edf4667dd915c6036343c65affc));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x26659b12d938ee1b399ddd7b4723c4e7609b65ee5532b99580be828749358ac4), uint256(0x15d80719e2aa91e13e96376f48d0030f2e2c76c9edf6aadde87273a2b79d78ab));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x2d51dc310b1c529f31f23796f5b9115b2785e2ab8057b8fe197c6ba935cc9399), uint256(0x166a6820033e380cbac9265e90b9838b5e2adbb5b51e0742bc85e94ea4d34d2a));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x2cbb49a95c6401b1dac3d29daaf6902f9af7a75b2a805ead07d97c37b12780a8), uint256(0x0d69b1225c05f7cc8915953cc13bd9de3a8c425c0eed4676c9073c05e7b5fa5b));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x113b38544b6cdbf63263479724b24f8da782948cd9beb82ad3ba134ab26bc9a0), uint256(0x04f5ebbdeb828a3afe88360cbb0222c013a0cd0b8f6d0a006aa3803b1fe74caa));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2570c768aff697a45a2f11ae95eb92ca8e8a7a27074bbf66ff5afba4efb85c04), uint256(0x1cb9994afc500154de4b628dd35275a37e1d58c973058e3e5e6ff137b82c48f3));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x303af76b84a1a7c8534da47e90a96fda8f565dbeae0947a6d8949880372c5d64), uint256(0x0ed9ae4f0072ed9b4364e46cba1954e91b7a63352e6ad9618b6c8cb90d7de06c));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x00f028ab832dad0feba2e7175826931d330e5faac11a4fffd6a0e497830181fe), uint256(0x02e4251c49fdc831c6b981fc08011292b82ea5166ea6dfda5557cef6a74b68c7));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x28e91398c6bc0a5c14ef4edab34d3aa3081a47d8c99053037a5283b7edc150a6), uint256(0x164a297270cf435739ea7066d39594ecf27553653368222f9ffc7ce18e8afafb));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x17dcef91e6c10a3ec09ec6c0abb94073120977cc6319edc6f0b179b4ccfaf7f5), uint256(0x04efc903df9e5a898792f128fce1eed72be1b4283ddae911a16dbf0781326e93));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x248e2c5f6f1af0ce06107b3bbddf0400c5e9b9e9333660250136eabfaba3ade8), uint256(0x1af8decd7fdb7c8e21a04c9ecac69e56f56f2d1dc4015ad1ef63deb0491f8f45));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x184ccb5cd984dd0f96d9d4ba5f5f0157b1086c8b0bbb6c0e58dc7fc80580c585), uint256(0x204da6ad1240c6b16a122004da03555029f2171e32172baea5867d5c2cf8a9e3));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x194adeb179bfec1cb7d6ac3232e7f41fbe9e797a7f7563d3b86bdf8b0d2208f9), uint256(0x22ffaf3bcc532b0d93daacfcdfdbf84d00c48ba69b7b22592ee0f62fd64d3094));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1cf53767bada2bf482c38023ae95015b51231b27d7b4b832b94c188e338001d3), uint256(0x14c8e7321bf27bcfdc2786d1499b2848d1edc72ba8d35eba8a2819d065d4480d));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0f4481779f86e236f94a249e39c27c6a078b05a4c47525bd5d98c76b889f7187), uint256(0x1023d588b7c192be6e07888685a506054c229538986f063ae84d0c24980a589d));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x2bd48e673c885389bf78ca7b88dd82231d9a5b4289e6dcd1823111b39462db9b), uint256(0x2dc983287cab1e38499aa665a1cc4b49d3c9566f8e8ceb53f2578bc918ceb310));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x304cd2192188be9ac1b7ea90b1555bf3a82b362e92e6a0baca57a9c8117b52b9), uint256(0x2ac6b1bac976ac13f0268e144e37f439562bd4e36393275f367440b59efb702f));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0565386214560385729f36ef1ce020e5ffcb340ece85df90ac6d9226f135e2fc), uint256(0x17db851ae02db98b45ac8acbeff1414e2fcfc5f6ab12b05e70c4952f9bc39e4b));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1b7a88c996fb6d8593be66739a28ba23bf7938bef79bfc14e5da8bc92d84bbb1), uint256(0x2e3f403d9865ead070644fdaea48084e1e3a833056bd1f9fa0ba00b61efd7e54));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2cbedb67fbdcc7bedbd442b718c3829700318576a63248333c363b3a4451c9de), uint256(0x03cf7bb580a0b79df8707201e4a5a005f7707d433c46c7ea2822a07a51643aef));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x2d9a63ad8f72326cc18af2aef435160eedb025b7706595b00b7224a6bba48fed), uint256(0x2106a0fdf6b29f41b31653035fa0f4a0d09947ee6ccbd7d1b7f635322c16b5fd));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x2667f961ec4e2adaa2223e05a9bdbf9776a521025303ac4151d23cd04d603c92), uint256(0x2c370ab16c0d796663b83542dfc7250ad91a6705eb7a11a42760383039d74220));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x22f44a256d9b97b4293fb59102cfa22c213ba6d8b780aca338f0a6a6f8e79a6d), uint256(0x20ee43d7378402b20d9e25c255668b0ea00e44a8646cb979e930e901f77211ed));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x137c75c7fd849883d191c220d24c5e096f6316239165a38b5ca40b018c0b8629), uint256(0x00fba2b2808f6a39ac80f348588a0afc320949e14049a19492b177ca80c294b9));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x11f96ad1b4451f1f52ed38d8e7ae559044120c925d312d872ed801d9eb54ceed), uint256(0x0c46cc777a80e38788701a70a52d4e5dea0f13516b7ccf3615086f0be667adfd));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x155754257e470b5e83c6f0294e483940945f9b4227e067a03ad79b8d7f73a01b), uint256(0x03bc34a5da79ecbae9009bf583b37f1fddee09c1c4e17037bf90fda2ad82f7d3));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x0bbf0d8bd6f229b8c7ee04d937e00e2990548c368a87de05023a68355361b57f), uint256(0x2e1c7d0d3721a9e16dbda84e65a689cc21080e66dd08924be2b7fdb5801d0edb));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x1d068f519ba81c9ed332ce3a54ae3519a09b9998f7ef09b1c97d29f9d858969c), uint256(0x26c85098681e772424522b2e9c803e2bc64abf72cd0388b7d653cfa59e5252aa));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2f83e54bf0894fd6335157de4af04857ad6c315ff775b836efa2c853266831f5), uint256(0x0b5064b3cdcbb9c1c754475f262b648bd0a95cab379dae79a1daf7bbdeb8d861));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2244f9fcda54ac6ab971bd90b5c3ffb9cadda3ef93df604396608529e690e8c5), uint256(0x103cad0041112f8ce85ac51d90b389521b595d53f7b82750c2526acb30cb2c08));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x20d961ff9f6104d2357eb27ec6f4c5ade2d3e26f06fded61f413d64a3f142766), uint256(0x0d058e2f5f9328f1f20b98705b3f3df0e107c668ddaab2cbb064b2c187923271));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x270543f48dc17d5a589273781884a2f9954e8d9e8a64acc58a787130e14397be), uint256(0x24cc3ff0024845a8d6a5452655e503b4ba1068a4025e0fa7eaa9f2d07aaee0d4));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x06064cdfa045a7df3730fdeade3ca376d6b71541430489771b719efbf3500288), uint256(0x2a1c6a92f4a79bb909aa181a968405e6cedf08d6e53800de7950d6e846695759));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x1460c5ebcd1d1bf05cd67a2f0f00cfc902e0711efda68ef1ecf9f7fb86515ec8), uint256(0x2fd644ee861d70de96197045f7c884f5256f613af56c67dc0b11639961b02519));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x0df563475215e9898c39fe44caaf2555f3a02f0f80f41ea6cce35e9f733ab860), uint256(0x2d1827aed7e8bec92f836336781b8a8f5b1bed920e3f772dd635cfa18157ba33));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x0634220ba292c592afdf83c176ff160c1a3df5e5bcbe2e03adba3f1629bdb7d6), uint256(0x2762c110e8ee7dd77ef7a0d223bdbb277cba8bd74e056e4dfb6fa92a345df9d9));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x19082e18a520b2596b73ef5c037fb5937a7ca3cd35a856b5d1726a7c4f1ddb34), uint256(0x0b85d0c27035da1a3d2a0c8eef0960f230aa0586c0bc44bf0217c31811df22fc));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x2d833006578cbb7024ed4696257ab60f11e24a299d79160a383e0511fdd1eb2b), uint256(0x0191a043a706a56cab1b6a07db5406938d18040d007db5e3e33e82df7c240bef));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x26b77ffaa541cdb49ae89d85ea9c72159ed051e8b74468a3ec176ca9ff920cfa), uint256(0x0d32571fe2dd7cab265cdc05c443f04e5c7bc0027cad0537d001fb3c737916ba));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x20410fe1c732b52727fc1716bc23c56dd611e28e43d95d2a970e7749762b0f81), uint256(0x1bcbd24fcfd38c046ad5c4a15db2e998356585afc1c66688fe215faf6012d922));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x1cdec8a4b756df83f42479bba30596bad59dac119a14d86a08b706082bdc2ea0), uint256(0x2e53ddb032986c43e5133fda1ba7aed909f00b3d2c3e14e8b460f94e87ed7326));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x2b3755c8dfd9811d9ddaee5626012d7f76805b6e715a6f495ea09e88e1809a1b), uint256(0x144b39e3210ac2805d5d0f666488639dd4c08225b8a80e00d33d2965178fca9b));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x227ee8d27f2e18e7c844cb2583e9704aaad2dd7f1ce31296e436f673c4eaae05), uint256(0x0de761da5c7c0a88d6271496f639976f931510a2793714ac8f9d183cf77e3999));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x197267f684b6d796d3d3e531f3b432e49652e2018f0bd3a86a8a8f3799d14e19), uint256(0x2926b0f5908c9e3b23816b89747fac118b85c22d8551ab66c6aac4cb9f315a3e));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x0f41494d01a44efff5c34beaf778d2c37edcb39f872024e1d20352069404be73), uint256(0x22ff6414edf2440861ccaed048ef5265d066ea833cbe6e946818c8d24f5d3601));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x0934a0f41b7093b94a3df751fa5d79df907f63b08646bd323e8d28ae3fafc880), uint256(0x16f947e92f6a45d7d9b1e22686e30e8b310d41c1c20f0586c5e0b6f1dc3de7b9));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x2871abe82f753d78669bd44a41a2a662a0431a616f5b9a8caacdb85e9bcff68b), uint256(0x14d824f6e6712fc300de4d7cc867df3a2eeadc3d225bccf2dd2a7cd5324cba51));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x11fdcc25c7a0c511aef5d71e8d55033d3c50204a4acab5e0eff16bccf793213f), uint256(0x12d61d946b2adaffe76ff0191cc05907a0953985a70117048af5c9c801c2d553));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x0bcf18e2180ca9d8e6fb1fad0f2141ee190e8c62bb02c4a36895bf163470c9d7), uint256(0x01d5b45a701b5c95318501e7c692bc0c36a0cbd4df5c9bd3dbdbd5204bbcb94b));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0b867f9037ba73cfac83125f5ce9095eb8fbdf6b6e7dbfab4e9bc4220ea6fb01), uint256(0x2ec60e07ff46c44585455d87fb37b5324a197bd7673f6ef9f8cdf38a7b52ec99));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2dfc86d206623da98b46808ba319b49e862df47502d1860525442969c3ffdc17), uint256(0x2d0a9d451765e858afbf824b257387effcfd6839c3d39dba5a9994280e4475b2));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0c8aa044bc291da6df0d4c141c5598168f8f0fa1ef5edc1c7fe7a0fab7f68651), uint256(0x21b1d13a9dae4ed153535920ae18612ddcd2f87329e95b85b8ccdbfc9f4a1ba2));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x095974df73c4dbd058e20ca2feefa626ae143d562aa68762e38018b46f26ca6b), uint256(0x0d2862a28c193c5ba3c87862ee3ae84f8eb5a749386a5a2905604909cbebfcd4));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x232552feb31dd1a1d07d74731e9b97ea2bfdb7d3a9f74c4ac0863a89c2ac5f26), uint256(0x082f2ba14a8d190792aec7525ed40a4664442a8c984d83989a5a7b185570570d));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x1a47aacad152dfb8262d39fdc645a1cb661ffc815bea09c8f0f9e26b79373680), uint256(0x2e987c97d503b65ba9aaf47c3251675a464c7d543a7223ac6a63ff027473503d));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x0a460cead71fc9fe86bb0b27e853011326ff031fed92b6e043a5396cfbca835d), uint256(0x1c95ddacaf7cdb58a74cd758945c59c77d12c070564a349362d47e29abed49f1));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x0333ad211aafab908b3b93f5742e24dda9d14d208855e1bea7284f6b98f42e5e), uint256(0x15bf2a55724a746dffb0f2eb81a93b95ac4f00602ed2bb7dfff1839abf2c2813));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2b736e6eb4258910fce86765782c183627682c664a19ee47ba72af6ae4d52a1a), uint256(0x195ff24bc6d3ee7ddd3f396b53381b72eb15a29e1eadd0ba1489613b9debcaba));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x2f286480e32368224788404ad08b77489e609dae96bf45491b1c39979179cbaa), uint256(0x1b8dab775cf8f1d8c6ebcce3ae2ea93ee8f3e4b5a43b03b309cf8776acf9bf20));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x131daaee2fc5dd8aaed3cb1ffe5430425d34d92987b4db37eceb0bf1129b3b03), uint256(0x2bb822cdfd5e161f112be703becf21451063ed373fedf01435fa31a9011a4b51));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x25525e3508bbd59740e6b1dbe6eff6a4f2feece480db36a10faf97cbc1617561), uint256(0x226f40dbae52ba4ad199c1813ed8aa91487e0ec44c64911c58ff14e7c62cedd3));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x04a98acead698cbd35d8715c8d7c33f3fe14e71a6425bae544e1744f21860e21), uint256(0x24b7b390ca8aec28fc598c76c4292ca6a60ff2e06c8b846361b6493ebc6b5bc8));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1a1f66160b41beaf99dc08f8d90e3f23daa50417badfade6aa9ceeb5f4b913ae), uint256(0x26bc958135a8c9b2eae9f3e5821254d22b5a28de0b94840a65771057370476b4));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x28e6f0886e7698647258367a7464b293361b1899e1fdacad241ac6be3defe6d7), uint256(0x164f2a9f3057fa8ad2f6fc9eaa9e4af94824d91b21cc3528adbf617485bf32de));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x2f49e83e9f077a47d8b9d0ef5a02dd1a227f0016f381b2e0e48c26897860dc8a), uint256(0x1f1c164b6b9783ab4393629f89b2565dcbbc87af7868678d92972267e696762b));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x12922ea88e3ec33dbb7e49238d51bca24ce4a008f13e19f16b6feb52c923bae2), uint256(0x2d960eeaa285c6c38df2a43e482ebc7f6768adf76e0ffe16b08ce9a1089f70f9));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x22b85826604f304b5228afcf8ba38aa3263b0966c5b5efac5c5978d506e8afde), uint256(0x13af2c8d4b87d310717ae2b8e88c5bcc24730c86d9da6530bc5534256703d0b0));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x0ab93caaab7c94d3c7f8f8285ddea4da2483d15159b1ccb8a38714155d2fe524), uint256(0x0a1d26fd4017cfcc33cb0c84f169f0030a2b22e9c44fa5d71725b660ee0e4033));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x0a222b434c161b1a2c19892521e15751fbc00cd49ae720f618ea328b2034ef65), uint256(0x20874e20523e8dea0ba3804584a0d5b5c35aa71bef14e821b7929cd4afadeeca));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x0b78033d241b0f5d4b036af2d0685e3179dd3ec4bcda34813e3cc08a43b66472), uint256(0x2a6daf3928f721601672c8027e53afea848d69daaa5f1237c8f64cec5eab8071));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x0a7dccb5bfcccb7478984b4673fb88128ac146e334f3845c5d10e90ef63d5592), uint256(0x1e8154fc1f9791305e631edd1191f4ce4cae7c85ca27f1044ad1244a569da7b1));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x18fb9c3cf58c054af70fd25a9c27db7d41719444ad7149464889509bfd3bccbf), uint256(0x18c933c0dd3de436db865c2d42bd7930d66e2dbd54b637cc3bb6882240f5a532));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x2c8f8b747f46eb28f4dc3eec666fc71c2f09a160bb5a7eb73a412f080470f290), uint256(0x1e0c995af1e91434e7084c91606e5a793005ee4e0f87251388e2c0c8c0f625e5));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x2dd66439d7aa6c852f4c353b0b487fd39e07df1c1b331952c566d05d9b5bb706), uint256(0x1735eef31c09e431f0fd46f86bfed3a5cfe2cb31dd136cc23753a94b1813d63f));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x224a4e5b4f85fbca82dbff2734f5ad5e2b66f049274614de73c359dd5cfd5499), uint256(0x205de51fee7f7642936aba5c0db14456cd8af9ce7f6ea04421085550bc849ccb));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x293aea76124524d3bd521e4a5a22aad6fd485d6b22451777bc6e86c3aecf9a89), uint256(0x08c33e78c7507859ad460082963bac66d9c408f81ed22f54ff5c3b6c167e6f20));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x17b21b34f7aba960498be21706437a73ad657cf82d1ddd368ba2c2e86135ec11), uint256(0x2a1fa8033074795fae79f4d5a881c61ef34f24a42c1f052312159c646d460d16));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x0c0207e2a4fac79a69b9a22b06b2b808120de59e0841b59c57633289af6c2805), uint256(0x28176978ca6632b0fbf4564c4681cd2bf5456dec2ddc0d2a22d287912591c367));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x2a3598fcc19b6c8147f2ac7493aea608599693ba0612aabf737054f0c18de556), uint256(0x162d3389f7b2b3a32db6eb3d262241f2e4de86ed683b8a11b0c46d560150f982));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x236da1678a2beeae23a3f1e619130afd80eda9ad375a203d0ee70ad71758a8c4), uint256(0x1bf419c7fcc005dd6a714aca2ba6ae6db0e946e6a49e0f866e5d228a277e5e05));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x22e39981874bf5ce0ecb5225db57ab27b14a076fe17afc3dfb1e0879772c029a), uint256(0x06405907bb0c7502991eea3f212d1fd88d0f04cafcffbb3c967fcf1d5a008084));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x2f5fe1e17a1bafca46c442e570c09343a8e2e87e530cf093936fba29124c075c), uint256(0x1244dfd362cd832087c62d4516cd5a1ad85270fede767b619f1c0af5a9cf7f76));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x25581febba2e31d0e9167077085dc3abc94145b1d870b4454867ee30ff6e7341), uint256(0x260413c46009f981650b84192c0b1de1605ff7d2bad9946c9ab34d6cc7cc1937));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x040fca49a2918b82df8bcbb1bf7988e14b4b9a83222277201b6ab5f9a21f7c62), uint256(0x1b75b442c9f8e9a5a481e1982fd4f6621cd5cd9faa08f3529d1a9db755bbbc50));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x3005b68c059cbe72d3cab39538c9d4c1a4da20986216110967930a093e750a98), uint256(0x061134bd718b700fdd77db6066c0174c3bad99df2a6e8c427104f8789914e47e));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x1b837e1093676c4f4bd75e7754a750f8b65da9dd9261109e2acc698903afcc71), uint256(0x2c8782b497d5cba021bd6bb773d80e6f2fa61d868d81c37f439a4d0339a7845c));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x03f4fa11ee2e4d78dc327459a9d1d1058e1b41248bff3d2cd92591d9e9064b08), uint256(0x0b5ea1125d6afba6b3ab935abdc6a2186f0445f9e40eaea971a9ef1de9cea363));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x195463f8bf3b7c79bfc90695eca156da71d50f702863262dfec49c0310041f4e), uint256(0x2908c612f3d1bdc3636f31e76eefabb72d971677652cdf3750724515f62dda55));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x0f492e3584b46e057868d131ab21aca29400983230420eea71031bc1d434f6a6), uint256(0x0d01d9df7b2b0deb5070fd0b7c18395f04dbe50e9007f8eae1fd40fb30ae376b));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x113b3753ceb46ea5c7ad638c6b7f85bd1a1219f3ee27055318d6fc413d82831c), uint256(0x2acad02e3b4f6d16848754f21cc61124ac2038f3823ad06901330c2d0aea42d0));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x0e01e51776c271a79571a4446b6013a63cefbb64a9b42fa6e66c5e6b942b44d5), uint256(0x2ad4ca0478607ec1c12c0c89a4b866764eff2b0cadd07e3cb50dc5811cc10e0a));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x1acd4d551989a08baa5d5128a33982dca43994fc4bfa8d0c2f45566163a63793), uint256(0x2b76dabfaaf33e52ec7d7075fd0ab30c162e4dec90f1d3c5d5a77d59dca42b03));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x1a4c0b839d5106b9f34ac0a69ae80eeb2078d2b8b62db8f16e4851a946ffd99d), uint256(0x1345f2e39e364d67f1ff02eda4e6802095d74683c3181cfac00f6aa226cf7408));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x04f7d53faae461b8d91cf3aed1130009788bdab17c91aebac317a9afd08b0f25), uint256(0x0a9ac769b11de94029c95df54f0e7eeae8139629234b185847a537717ba916c1));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x093d55b0cbfdd8e3aa63f9ecc458aa4274fb4b28ee184648b2dbd168da81d18f), uint256(0x07eb9483439c0139a4ef17cb481e871e4ae48982b454573c7c173b567426d7e1));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x0b4d8b9fd99aa3fc3562c30a32e9e065fb5039fded242397e9153fa49a06f1ab), uint256(0x2984ab34eae9eaf6b9e0fddd5cabea0c74b93e7b02f8b5f80d5492380303d3d9));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x27d4c5f5f9016cdbc7f7da7740792c9013b123da99420d8e1cb0ae60987c2213), uint256(0x21e1d7dc16bcd038fd8550261f5c943e2e47bc9bf3fbecda7aa0084fca50eccf));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x0689ab036b25e304cb474f5f216eb5cfbab0984fa9ca8066439b64ba1a48347d), uint256(0x2565a24eb1ef0ed147acffeabe5c0b9c57602e7fdef2dbf934f84bae459ce03b));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x161e576207751a099759075d9b2488c18c705fe19c2be50e2366c44c5b97467b), uint256(0x1bae23549fa3c06fdd4cc63b66a348118b0140ef43aea308e4bd78fdbaf2e8d1));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x13538975579f11e3de552a055da1b6760aa75a88eba0c7b06c3044accc574079), uint256(0x1392630f282df798a702cf21dac812d48c1aa372f234cfe1210de07923163c5b));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x271058c7c4bd16d5c92471ca60fd623eee05111cc7f2a0ca83dadffcced6c4fb), uint256(0x2baa51ddc3797d090d15bed0a2b830570a8a59982b53d98e4b952d23603924cc));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x2a10f33fc61b8de7a79603b993c63ac4e0fcc7ca5a48cf87a4a17d8d77708fbd), uint256(0x04a7d66fe2546aa7f7c4449d5ad91de18380ec4bd93546dd295685daac351801));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x174eb74778986b7eb751692f32c6152be0d82526f154a01ecc6c8cc5c022b615), uint256(0x0b209743560e6a5d960e9f3f2fd920da22faed8c4d15fefaa94833ed6c4e0c05));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x02fc709da052216e195a2549e5c94436f71adbe6c10b84d011cf3c2d02453969), uint256(0x0076ab51b8a40dcdd9c427b74bd66775dc3cfae560823fc8875c72a0be07741e));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x0a984594777229686743de8890fe7982bd05d3ebd89cd7dbd32cce22431e5670), uint256(0x215107797a1756f1d424fe0339e81f460c5b9b8f57a579eb7911ffbfb2cdef38));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x065a71ae62d02cf4eb95a23c03df6bff11cb90097ff2b990ea415f6328fbf97e), uint256(0x0fd8c5b8cae64918234e9ed9a4903948c0b3730bc18a0781427b3d0fd430b73c));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x079706f8827399358441ab7b749068aeb1a56f2b7d65a542e3ea224b31d2d017), uint256(0x1d108a7a9aa1a004ab79d4555a479c110da93fb886198c785af337f7b4178baa));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x0f08d16e238f608d06103a7c55950510edd5c31cb7e48d1b28b293198629d71a), uint256(0x02addf8c2ba30a68fbb03eaa1781ecc23450a0672b71c08c768aa4697f0ef12a));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x21a9640b9c41987e92f20d9541d2a625be23d578770738187b7f80cf79871156), uint256(0x079ba9bc3eba79b6e8c3b2394874112864b6123120a24380c813142c37223344));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x25ca4d65a5d038835ba1ccf0d0be0c287bf4c9bb009f9cc67e8ec0fff74f8fa5), uint256(0x06073a385e18e28fd113dcb120a1b30ee4221d7849d7fc47d2db60eb00a0e295));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x21546042712c10d18dd2ff931f506f76acb92aedff87c121be63ca6e810201fe), uint256(0x1f2bfd76bad90af5e2553d71fdbdf585bece14c6119d3e126482d3f2ce1d2b0a));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x26aa5fe6cb86d9afe418407a0cf66e2b652baca7a16198a21e2c98ac106ca42b), uint256(0x06a0ac2582a174eb82539b976ed4c3d22fd7c7a413aa001bff6c6fbc304d8dbd));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x10befa32495caa1d85f97b7eb81652066f2fb47ef2397ee9e392dc0ccc55e397), uint256(0x0e095f1de23841e3f1a55410ba2f837f0488244f4e23f38eaad7399269453420));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x023693c82758363556fb23877a349aa22be18f7bc516aeea667361eab9057b08), uint256(0x09ac09f7213e22345ada6cfecc90a140619471c5de9692b9519b4599de8a0ef9));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x1234d6909fe6466566ddba9ad3577f1d32dfa08b48352e0bde18b63972e017fb), uint256(0x2b8954688db1175d029639e1630054b62214df334e2d77497039886e19fcbd80));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x0f585a5c46aa3340f0dc28719b84ae29300243fc05fe7772a04853dd7243cc15), uint256(0x278b838b2727594d2b04b86d2ad09c2fa9f2b6ed721425176c7415c777b21a3b));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x25b868c0f87d02b0bc527f719620505c1346982ec1e51ce60595ebb7d3c8a872), uint256(0x016654da9d256a6b5045e5c6c79cbcf24ff27e112048ac95736e280a052e2639));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x2fe833b3fe7b80b2835e53a72f890ce902cde5fd0548084d5b55cfaa8edc9b4c), uint256(0x02e44b440f8826bd4d18498299834f767a85fe9750ee5b3b6d0ea8622865d83f));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x05bdbc3cacb36cf4ee499ec3c768c4ec248db1d5d9acf990cf364639d758e9b1), uint256(0x28c1415f44b6b4ee2f593d8caee0b731f5785641134a764ba405bbc46712a130));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x2b5571198a37f675d1fe6afca237058e4a7b13b404683ca28dee5eb2d2a7ebab), uint256(0x15c905265368c29c4e97e8cb4b60ef3c42ed86033dc6bf687711bdcc4ace578a));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x25d35caf1c6200ad58e0875f1073888be45881cbe874bfbe02fd44fa6b64e922), uint256(0x16a2ff9e2349216b5108fd271f55127ccad66ad5afdd018c0ad6a40618a22938));
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
