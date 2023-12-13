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
        vk.alpha = Pairing.G1Point(uint256(0x2764a3b83bf4e93b7c8f3dc64e422e0d90a4ee1f8e749d830dadbce89672078b), uint256(0x241e53d08d066aa339341770d2a8acf8cadf6492a2348dab07d9c8a4f4ff499d));
        vk.beta = Pairing.G2Point([uint256(0x2cf4b1ffbb3d5852d88e8a33d860ae822a17297d8906c4d9788c6df49a409d08), uint256(0x1f6a2439b05376803c18c475449b97778b5983cf9634821f2acbff6e2c9aed80)], [uint256(0x20e05e7474e6a233eb8a7c880a60918c415ca0325ac239f9af0cdef6becd9b3e), uint256(0x0e4f898e60217d6d9ef7d2536b4236b36a35c972b422e05008b90cd4f1eb28e8)]);
        vk.gamma = Pairing.G2Point([uint256(0x1ca98553d4b440a0d92645e43e612cf01ef046ac76a723bf6cc274a4332992f6), uint256(0x2ec18e0850c59d724c0109b16f300004175545757c4b25846049266f940dc048)], [uint256(0x21f360a41f2c794c965545861954a3df5577b5fba070771059aef3566c10cbc6), uint256(0x1e0d627e3e5153c706e754043076da7e18b8baf41651b6c37844a7bc8597da82)]);
        vk.delta = Pairing.G2Point([uint256(0x1b08552c4dd3111fa3f001c513612ce5ef564c7d3789105a39ddbeb2760da148), uint256(0x27a451064414f8f2fb72a6889419421d1a86efc5ddaa7d0b69101a1a14104ff2)], [uint256(0x2ff5b61dc9db08e4d6f47f1f189f0955278f68af9bb8b44af262cb519e123db6), uint256(0x14954be07bee3098281095a5142a390082374c9292b4d7f044eebdea5f85860c)]);
        vk.gamma_abc = new Pairing.G1Point[](210);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0345d6ab26b2d814b0562bc81dbc1cd3c7ee67d91a7c211440d3f44add353591), uint256(0x20b4aa4e15eab8f57c1cfd26b5ef43a75ac96266294cfb1a0f2d28cef7c249c4));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0b932efd0b3e24b82ad4ba9dd461938de2a4271022aaff8b88bdd5ed4cb0f733), uint256(0x251d544f150a1663b4abbb3bf4e46953fddb2d08b11c140e7322839f8168da2e));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1e796307798bd7510c391efa0bedc59385446fb951d3b9082d42b7aabd5fca5e), uint256(0x2aacdefe788d68ed356558a3ed085cf3f80fb84044251aafb5915dc418cce4ae));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1cc115a3e3f7f38bb5ff8a933c44651890104ecb788b4264dc804fb651999f09), uint256(0x0f5e2ab3cd798498f410338519b2b416ac600e0c427fe7e1bd56f076ee2ab997));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0a970c830afee2e4c7b0b002105c572c0e6894a114bc553afd8d77a0909954b9), uint256(0x0934d7aec453807a2bab4ccd10d391a946d9b2c66611189d8f4c3f498e5f0669));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1584e9445405a4f76b9d137ab9434a8f06dada1719dab692551ced1a75298d6d), uint256(0x0fe7b4d7ba219512120ea1de1498ddadf37ba09f2083e2b6ef2306dd5f1cea8e));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x15fe45fbef8912446e7e336a387528b30bd10560ab3c2a7080a92047179e7ade), uint256(0x23ba8cc04df8833b0dfbf17c72f959e668bfb1bf9e420663b3e0c6f8704d39ce));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x286e9788907fb0b345dfbb3ea6328d15dec030f5f872d7449e410ce0b4680321), uint256(0x17cd26bf219ed889c8a5a651732857c62eb6f5f42eaf9550b9a3910fd66d55e6));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x20027fd2ea46fa215af63bd6706d1b3a8d4d62204e83bf8a03594f4b1ac7625f), uint256(0x2db053ffd80ea54db5e8428f5a138bafe8b955d5546b68899931c98df5d48585));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0ae0856a75e0059cbe5f8241d963295eb1bf01016123be230db84c7bc95db663), uint256(0x2d9707f0ef21873518696244bf157f0025bc27623440cbed19d2b65156eed76d));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x026a5b2a63d6a48e24b62b4cdd7550a7f594750c3b113c8331da9253ca6eeb10), uint256(0x1c9fdb6409097ddc4441f70f35f8360152ea19f95c38548d246c1fa67602df4b));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x295affd9001a797c87d843021c0fe9daa27d737ed6268a55581352a6b766fe72), uint256(0x07c08cb74c69eed03ee8e3aa53822aa063b04c4a19db6d06429d1c50b1a2b592));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0287048a3200342a0a2b129a14345863c1fd9ed657404b00080c89885790ac19), uint256(0x2b90d3e0e227b87a22cdbf84a0f02e8a3caf7a6fd8993151ca0213103d54a640));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1ce781913464163f57697cb7ad72a8d0a45396d39c9c9a27dceb4e5cf87a65e3), uint256(0x20c417bb72baf82b50e70c58247392bb3a4d8ffd68a447a51a5feb2b45c74e78));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1815a07118238b458cba3e9a12a0134679e7cd86f1dd4c057affde18637f204d), uint256(0x1cb1c76ebb4bfadb6f2fe34fb2df61cf1b1f0156bf9ed4d2fa0520880bc8d88d));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1a1e673d173b1f79c0b66bc5b044bdd6812755516bac6338fed5a604ecaad12b), uint256(0x2f16014369790d711807a2eb3c7ce7bbd19003068c7d4104f9b24fa29e1b12af));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x231580b7f5137ccbcd8b142701b2ca010da120695baa4b2c8c258497396afbf8), uint256(0x163112242eef71711a0a59ab32319464fd7e4c1b9598785415e666d90f880f3e));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2db3cbf8b821a6d1db047a0e7af27ccdb38a86a40f53139cbcebf4ff21d3a2a3), uint256(0x1405abf2627a0287c419319e050b6b8ff0ca4bf55d8841c07102a7f9f24acdb5));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2543dc6a3bcf5867a90c1796b9e653be94fe596e95cb39a37bdf286a4ed5a88a), uint256(0x0f7e89309af460b03d416622ba39975f92854823bcf51bd34560efa70b287418));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x28a126955407576154d8d3d663308c4ff6c948b9b3ceb51a331dcb661bbb4ae7), uint256(0x06c968741a68460cb8ca691eaf656ecbc051bcbfa846b2135e87a40724a553b5));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2abfc045b41b193fd6e7b6a77a5424e608ccbe0d00a863533c736aa470408f77), uint256(0x2a180c2ca5eb894082602c94e35d90e27ad95f87d9f6c8873ec24dcc986053a0));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2a0d5b1a1bddd9e6d2c4381db92c568521163a04f01dabdca465a6209522d832), uint256(0x0aa64d26213093e0d42d44edb04c2a5ac1166e128346b20065ea1999a3c2ed8d));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2e6da71fa0f5098e1d1ef2f4c01663411f4f9657bc31d647c9a92bf5b2118a60), uint256(0x0dc3e7d09a1390f0868fb32e2f930ba9ceacef79ec2cab0e0845dea4dc116273));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x24eb955058257e971d468a0461ce139f16c3bb72cf65c00a083b024cda1d81b3), uint256(0x143732718ad495858ec21c68e69ae344272b73e664c9927b136f0d3f6e6beb5a));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1a83f74e6a4f2a4370927b1f4b4a64e5affc483825c568793d80e06a9f2950dd), uint256(0x2b05386b4832abba196e0d014f8042e1787be32fe2b3fd1299d1c263a24b1815));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0f1b096a7e9f976b73f4d36de0888e6d82a930464e42c33063b788e42eb3be0e), uint256(0x14c2cd87f5ce82e421da7dbbd7fd43113eb3c99e89e1510da2ea447cd8e04a9e));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0b18beaf107f0d8c2e08597a9b1e88467184e877752e25305ea1b42936f3a853), uint256(0x14cb1e0f735387bf6fd2f02749b69f02368590d31d075b012db6ef1db8025c1a));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x21e2dc987781552b5eac819a9510277d825db6c515fc403f436c9d73cfe8ef95), uint256(0x298758393fe0c6144c4a7b656f2e68776343455a80e5268f7430614a551c6d52));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x2d2cd6ea4a40a78483b94f7bdfff9139ef95c6dc604793b68d547af105b7f227), uint256(0x148c714f243630e5c0e74ec1652607640f1133d3cd463ab72b5f6a6b37115bc8));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1a4e0fe872868b8e7cf01dda5f091082cee04e6ddc55360955e70751d2d01568), uint256(0x19f9d63aea83428172a626e64e0861538fdf78b431f52d0e3eeb018304c2027c));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x10a6f90c0d3b555319527842014d9013d022b0f307c9b69cbd2e8003c9875e23), uint256(0x1d545fc5e6c298a4abd8d315fe7eb98e99310b8cd55e6aa7dbe88563a2cab654));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x236341ced737264c7f478ebcfeb3db9dd0b57db7d6563d23af77bc0d31485135), uint256(0x0b8dc943b9a705b27c38e2201dbf096380a3867fbdfa0ef029cb3e16a9472d39));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x032556632e49dc5ca201929e793ead86f97ff7c29a5162c508c145eaa28df22f), uint256(0x1a6eb856b030bb8ecbf439567ec5c941d7cf725b268f06403b23663be5b58e59));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x0f8cee462276d8b29ac8f93adcd1509c761e9a225239762608a5e37aaf87e9cf), uint256(0x18c40ce79c31a59d69b7ed856c11da3139e3befd1ee1425d37214b545326bd7a));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x1f3aee08ffd73afad9e9b64298d0e26122a2042088361b5508a1b75e874ea247), uint256(0x0d97372cd7fbdb5af08a93f45fe4c4d8037f111234d80f629acc6ffc1c6757c0));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x26a7e608c65a26acba3a7b97615750c874a4f795d783a955875053fa1a1a874f), uint256(0x2d1c1ac8ead496f7891a75e3898858abf1cf462e1296e66f24e83a3982366b56));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x16e0e727be77b84e74a58def6ded069505669fa867de21438cf3ba1964e53c03), uint256(0x0606c910bf774236aed176aeb0fc519b79b108710c79b49659131e7b38e3bf57));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x04ae0810490e07662907320b865163f8ff0d5aa4bd03f482f30d3a3f6eb77b62), uint256(0x19c0f5ae2f850452e188d4612ed5b219066fe441b3f93d4c4fdcefddbd3d12d4));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x2a7bb1272070d16a4bdccd6f9472dc549494fc40315acbbc9fa6d934f4d08e3e), uint256(0x1052cc450efe67c04dc799736eb0fa2db45c692e03dac86ebcec4d07fdf4e7c4));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2a9655ba9ce0f88a24c6c1273847454dcc0fe843d0c6fda4122bf1e0bb944593), uint256(0x19791d887da7800c883a0fa6a8f04115d3d634ec34502fc6829e07f1a37a489d));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2bc7007ef4e4bea090fca1519848c7d9b5bc3e1118739d2f126e31fcb0fc7ff3), uint256(0x28757cc0bbeda950aa67ee1d029070eb11797c0ca63a367b18430bc76774383b));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2c8043614c6260484d3f44f371dd096c84be5b1cf6f368b50746f757d18dfd94), uint256(0x2c129078224d10472e9b5a5478f8b9105145fbf47990d61218aed5093a731276));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1bc3ac8de8ba51526e1d7d7e5bd3591dd2a5698b3d5f87297ce3e3a9d79215f0), uint256(0x286b369631b2e864b9017bb9a47e911d6cf524508d005708ed8bee7d51ec76d9));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0f8fbafb79b4ca6d83ccab270553061cd39e0c07ba645d65b2baba8525eef561), uint256(0x2c8cad84e98ff3744d311f2823fd184f0d272e78e7e75217a0399759b3aabac3));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x18547bf163d1b37aa2a6aa10929626b801ae3550fb10f7c701bb1462bfddc908), uint256(0x0830b73e810560ff996b566b0bcf80f45f88b0416c41b5581c768023f2f26a2b));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x09879a9e5876e2f4d93fb379effe39f476018d0369fb356a21399b2b84a6bb8e), uint256(0x045096a06a5124e0ab8146dd6976ade6afeeaeb0064c27fce855007b1b229b3c));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x22af7da5c23c72dbe005e873cdf0b320f2b6d6ddb412c908c34eee1e5d3976a2), uint256(0x26dc39563049831cf79b7a59dc6b87edc0003642e0db692ddecc755c4a30772a));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x080e452ba838fe6161f7982367c4818f4da618c5a6afc78c071f16d27697ca39), uint256(0x26edd0cb9b8c507d800cf6064f0b45fc99c0ee3413c5b3f3279dff6343b72dcf));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0384000f68497828dc663075b1ff348d81f4a108ebf27d666c295b0c2debc509), uint256(0x0bdb1ab5b93de623ca493d015f2a7f0986f075fc846ba06b0a3d59cc3b50f27a));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x09c0395ef073532c04399c97868cff4f820be28d91c816659211eda1efca4dc9), uint256(0x18416de4ce39933357bbc14aa3b72110f0eaf5a4c6c3470b0be55a78657da8ae));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x2ac23623ff15067da8d8e019e515dbf70a6560ff58ecae9bea170121c904c937), uint256(0x122c286bd37d8b4a899fdf844cd1532d7afe356e81f382af980ae9736033ba15));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x2b94444ad84ff49d7c9df38e1e4cc3558f2643fd6f8a196ea0602f72f2469a41), uint256(0x2b0eb6da8152268bf231a83a92396df13a8f689108c84c91965dbd5728f396a4));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x16dcc2ebb07a7e1e34d3a2b5831ddcf0a30a9f6f282ec6e9a65a8dc3f2983762), uint256(0x1f444fa26d7497f6f5efe93c373428b0a6dd2232882f44247959cde8ebd6519c));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1d5024018aceff426a63416a62f4be4bb2bcd75953f1b1ded74ffe8a3415ec2d), uint256(0x0432bc0c2b76c8ecd9d3033b20e09d1cd29373865314ab6503302ba87a063f85));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x0bf2b1ade45f749a43e63453b3ca32b43b96adc0ab0197b9b1b3ef34b59a6e00), uint256(0x17b09c712de915bad73835c6fcdd65adfd8a80eb408211f0ad6634bcfe3c586f));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x15dd11186f1020bb3ea1264f3334ead08f90adec35df87947f617e0b9adc7ea3), uint256(0x0d220586cd6715dc5e5c6074b48d12f93c6423fc9535aa8b51eb0cc5398e79aa));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x20970cb897166fdfeae7d3b8b60a7b679656d7989fb6c3be978fc903ddceb0e8), uint256(0x05365db4ea1b2f0a379030136cfee483b291fe7ebb73a1eb6a1c812b7765d693));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0fb60c2c3619745e5b7c7a0416b746b0ceabf3e5a26c992ef5d82b780e21f2a4), uint256(0x193be0fb42d7e36147bf1a970da4c250f964890888275daeb44dc0af1d444f32));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x24c2e5b6ce73d890021374a65063f49f343e0447c417b0e048d7777b784a0e13), uint256(0x10cdf77abfd2e75b50119b18a4294b5747629b3993329814b40e88e08431b24c));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2ac3b3253345934c3f547278df2a9707adc91ffa5ab757e482e5f2bbfa291c1c), uint256(0x1a6d251ceabffc898d993b9c34ea749bdabac41d688793261a6e2c109f26fab0));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x10974210e5ba371a05c67b849f103ae608c108234b2ac175ea94ce7a08953ce5), uint256(0x01775abc2261a0634ba7a64bb3db9cae59198a34b8e8dca016f962c4b409fd91));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x2abe449192459441248aa3d6bb2ee8bfd126793a7020b7579cafc39cb0b7f679), uint256(0x2b9d9c8c658376f9c78b8e84e85b4a5a8fd267075e02b9974f925758155f6c44));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x02934124b0b5df4e12171bf7b91bd56f9c250434899ea3a312ccefd049fac6b1), uint256(0x075e7ace72dc46600c30b53ff89111f3734f1f22c9e7cd69aaa85a770b6358e1));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x1a5e7de9302489d535ea59422c3dbeee2d9e23b8671be3d531bc4ba95855530f), uint256(0x1723bdb99c31e9b01910a8be79c7838bc22f996af8d8095f6f0760c800c40c9e));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x22f258e63ca388958fb7578da3c5d522a727917b118fb4b55826fc57edfa6aec), uint256(0x0c60f30f1404619485943554334937fecd705447a36ab1a23951a184d97c91b9));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x060113325ae050e0311a75b1547e500c879902a380fb2929b73b7dccea348880), uint256(0x08d74271d38e1032b2e19bc4fcf544cdd1fc846753a352cfccffa34cf8e02436));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x17cbc1d465140ba36cc75d9514fa0543a403367b2cdbd1d62d3bc280ec956979), uint256(0x1a447f74851688bf30ce1c9e54bb2f91ac2aa0fcd5cff278182de5115402e51b));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x064b850644cbbadc386346c144c6e80d5fa68686d6db1458a2b27f6db53ec7d7), uint256(0x0bed9b2b053594b48d12e8b8da6ecef6d3975648e4b3c692db3151509dfbf467));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x0c67c9cce32dbca777ac961f988214fad6c396051892281cadf0016870b0d396), uint256(0x16e40ad770bf08394ea08d46a48c2efe6da729de1fc62443c60d88301d865679));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1ec491d13e91be249b6b1ed94b409af7ee6dc7df1e153cd07c069f8b8a1d068c), uint256(0x1e59faefe0204477873240af3e0a1caa1f068159c14c3975e50050ad1e677592));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x219aefef5eb8c5a293a349bf930708a6df08510e57952b3ebbbec9e0122f443e), uint256(0x15008fd707a1adbb3332f556d9c2cbdddd4f33f352b7591d3a2729ba1a243eb5));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x13117734d2b17e2173fcafd907cc6e515e74c0eea256e32046545d09a73c09bc), uint256(0x1c2f7382b94c75f1d2d7ef5fadb63c7f6698d90bcd0053e5e4f87f4891259568));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0a47de93d497b8f60a5aff392744a58befa4db8bb70f66e6f6f47bd178ef5cc5), uint256(0x07d3f004e575d532cd400367a1ea1190a0381e4e207f90fd4e73ba85a90f9696));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0008f05831d076a35a243892aa7c85f65634d8ea1db1d1e1283570c3266893d2), uint256(0x261bafbaa8ac241f35a40c8c1859093b21b629d7882e102c9c511b21b7282fec));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x05fbe2eb5946623a49c4463360158c26b8068a73ef3ffae8d51c1c65e1b6ace1), uint256(0x3048607a61c588d173c13681614b80e69afcf24bbbaa3a5b392088878a1fb741));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x15eb97082f11dee880cceeed70cf0edc195af807dd0c7eaad83e0363ac264bdc), uint256(0x1e89af7999fba7d5188fc87723d25753515376bc2dcebdd4610f0111aa9be521));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2dcfb40dc5644f845b108f458611056381a0a335596ffc8367829d37697e3367), uint256(0x0cfaf7aba16395ff2d84065f58cf16fcda8d61e9d9c361b2b12a429c43db89ba));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x051389862422987c8f946cc89cb2e694a327b54959cea20bbac3cde25b72d770), uint256(0x1b963215ea96aeb5fbba6650298436237301977361007e077f649cf25b4902b4));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x1575332389baf367b354ef0d4ab3fc0021abae8c6ed01176caf6f9c6357715ca), uint256(0x1e4bee9a0fa334a3459a29db250b4ec908b47219fbb9e7a3829ab74af7e948aa));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0aee4f30d0d47c89d71d5393e228704dd044684105f7bccd0780464fead419f5), uint256(0x2da6b57719e7d45433084cc84039b41df0bac795860893d1a851bf4151ad06e4));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0e16c68191c8e38ad89698e9664777c1e1b9fcb5b48794fecbe802cf3c83a02e), uint256(0x03688af8c68d7b5a6a0f48f0ebcaa4b2420f3e91af8e89311f2ae46b74dabef6));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2add0e98ee4e3a7b5b0cfaee0862b84d1f32dcf7ee02bc856b5e4bd1e7804371), uint256(0x2fdda254412cc239bf244243f6d7b894a2e10fee15142f65fbdd8f4862e29102));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x1a1a17dad63df9766986f94eba6c6c7cdc24c800ee3aa29bf431f2c54e4e5dae), uint256(0x12c09a485c981fdf6d1703bf3872539ba80230287d57482b80e958152c17b6a3));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1ae534427ee0cb9239ad53e59df090ce59615054ab747648b4a6d6f449ca767d), uint256(0x135640924448460fb4d33d0adf577d6117618896f4d8bd645b3b9a1c13d5ba88));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x12daf5121eea83de662b34bfecb5f1b6d458e5ca7a9f16a2bdb3c3f67ad3d538), uint256(0x07ec940a0e597f39f47bff719c011c408d9aa69c1d1f54e008368fc029df1e04));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x2f4f5e4e7bb58929eb9f77f426a37a7a73ff64e550abd55a312037e9dcff578c), uint256(0x0ca2f00fe71e2521ff8928771bbfdc324132378515239093e5f9752619b2c004));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x070e40c504d75e6760f072ec3497906c9ff87177bafce870870b259b958524cc), uint256(0x000698b15baaa85fa054c94d47061d9774eb548d5cccd2cd13a4c162e61ac4ce));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0ed5b41ce9a6d9c4ac6e0872c9a22a0fe8c463c024f2d6d1f9f097e73bcb6a40), uint256(0x15c83e334cb120ae6871296a47a20e8408120f2b12b4bad97d3df09ec9a82125));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x0851ddc088ce23a417e81a7b199a9479520df8db8f696ef7fdde39280d0c5914), uint256(0x266c67f63826abfb626b4477d4e8d8d9ef37ac26dfbe24764e4cb43d3388c782));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x1965459a0c4faf42754ad249bd81ade70a036ec13ca71853900aba24ad1b0d93), uint256(0x1ef6c79a8d442d1344e9ec9727dc11ca80332c2729662015f486937984fe108a));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x136c073ccf7f724ec5eaf979cb6174c7177ad588733e223c6a83fa6bf42e004c), uint256(0x276ff8b535d30f18ac60706fdb9f0992ede69eb4d873b8fbacbaf0084ff5ef08));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x185f6a74c4dde619e435bd31305aa230cbefebda98f2d63f3779dac54786d08c), uint256(0x087fbea804d1906587f96260b9db5d7c6a47fcc9d7e9bde17aba6329017ed233));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x2d6dc5d938e871ff1ce45dc6186bf9d071fbab474be2bc30ca2f41c0c105762a), uint256(0x1bbd426507fccdb764b74c42b5a4f83ca76938aa0b394210ff6d8502e9e79045));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x08a95a8ad8b060f837e7a0918ff7d056c92709355e4d068e698377ec6fed751d), uint256(0x2ab2fa84f18d58983f6a9c3c479687e08f67c3f3057bd6d9da296689e2aa26ad));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x2e1614ca2d529a46fce6877d9875cf669841f4d4fb14697de66f10fb963f014a), uint256(0x235704c2b863772a92a1351c891cb3f2f2ebaf24f17e0f3d9e55f1f6e6c9ac60));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x2448085f4474f87906b41c8baa42597e685d0a9cd80f588b84d261543dc0b165), uint256(0x2cf785b042165d56de25ed503e5895ed27cf5cdead98b5b9702ec66cb581299e));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1e21bc758f4b45c451b33d4a7641919b6144219528793316461ef8e0f82b666b), uint256(0x183a40313f804e8ce3e0e3e5f256a3796debb0b9b64c7a08947d28db5992380f));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x0e749c7e21a46b91f46dc06a1cc6cb8e540240b300cb52971e1c8e465dd1835e), uint256(0x090bb362327d6e80f65a9f51564f20b26378d06a872ceb7637cfe80000665aa1));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x251bedbc09ee3e166c1b97a04526bb014e2e41d460baa012dd170296465bb3f4), uint256(0x2bc68e4fafbb284e09b70d5a9cf4d8fbe09c593ae0606f024d15785ce6cee7f4));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x21518f2743611208b45a4080d15e44c7da8d7a3b319b0c124884f04069bc2f3f), uint256(0x28db58ce89bc9b2108ccbd2999eb8b66a504aba37af9784e31affda98e78ac64));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x24617d8dc4e6b22117076412604d8bc067ae1727f4ca568ade35594b835eff9d), uint256(0x06c2e987536fb9d4d83ce0245dbfd5aef11646695865dc9956649bb80d06447c));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x051b671a3ae478f218311fe98e9b066458eaa42f2ba8902e67c87a683c1f6110), uint256(0x1babf876acf304d8d45de9c0044ca627b3397a6f8c79996888419ea601de6a44));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x24524406187dc5818aa8de909d412243157a4393c892275851d79571dc5d9dbc), uint256(0x0fcd6bb3c36c0700b408a11c791d9d13de8946a6c7c4786cf0b82f243ba41083));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x2dcc9ca10a9143e854ce93a1cb5066335282fe6c25b57a93b067686aeb89edb6), uint256(0x0df7bf333a1cc788ce37aed78ba62c04692bfda76a7a35d96979cc3e9b96c2b4));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x225bb48fce2cbf0a972ee3ef7030109facfae404adf924b2d9d728e668f4f0a3), uint256(0x049bad7670ccfee25f7defa1edd5d85ebbe453ac60ba287d2b8c693a25871698));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x1ca7dbc03b772a970ee438b68d7fb04e0ef088e40c5169980475faebb60f0236), uint256(0x039e182c9195156a94e9fd5f6bbc12bc7c8f9d372cae4f4c4d99ed01da6fd104));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x0c211c1da3ba53c36e52bff507255b6f37038a9ba2abc01230d08ee325461172), uint256(0x1f256ed74f92687e49b3feb8032be609742ee2a201861375aa521c4b7e4968a6));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x18130f72621ccb64ea4580ec3e3453460eb49f8c8562c66c50573ac4f29bd891), uint256(0x0df52987bb3c6b7b718aa1e4f3a68bed3d33c1a6b5c11db3928a2033a23819f4));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x1d53c678f825339c0281366192e977734d9f7b3cecb90f6f96c0a6776324c16e), uint256(0x00a56f5058a6fedf09a6aef4f9013398ff860ade80959665bed158f2663421a0));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x06da166b6cb0b6a83f3417510fc716dd61c59aa4250ac98c69bc27d52663cd98), uint256(0x2f40809984b01dcefeb88597b1c9554aaf38e9740f162b9ebc3a1a367c41fae4));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x13c76e956c2a159d9928507b0c5486fc8b02e67f75b809c713d9f16c4882ebb6), uint256(0x231586ceb3fa6cdc900e031537911b5ea66ca9348ffcc9668f20ccbf14b4921b));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x045df937df050c5328449e12ddcf6bb7b474fb924fea5491ca11c825dc18dbbb), uint256(0x19cc40d5fdcd76cbd82c02a1b0a1cf555803fe2edf060dc9841fc4590211187f));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x114eb69481f5d5e26ddd89b65dcd800bdca7d6df3b155bd414a3a55a55a96c96), uint256(0x1fea2ca1d48d4cc7e6abaed18dd830b38f3f6a79b5923ad9e1d405c8410c381f));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x06712908308df093a8df1d90a05f4aff4edf146b1f1cf88f940a3296ce3686ab), uint256(0x1ffc1a9312d9b68f2027183531c38cc590fb697643d61bff13b906ffb1d56b22));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2a2576a75bd22528d07af60a9d9deedbebc3d9fead0db1f48a0ed0fd2de17a36), uint256(0x2c78ca4a03c325bb82b36ef396591a10274a435401c238a89beee8558995e2d2));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x205d67edcf478102e7f7d3ac4675679f9ec101bd5d1bc49ec7e2a8955d317e1a), uint256(0x2f9334fd2b20eef1f935db9da4e7481e4436ec8adc3ba90b58c97d29cf15e1cc));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x0add1def501232ad6d312253699137a1c4dd08f2e30971c14fef4fcdfbc48389), uint256(0x0a03c038f8f644872c62adf03e5a8617518f123171cfbea184b91ff8de28c3f8));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x2d1cdbeb301c8886cb1d0464dac877b8a4cd015a1d19af158c3c59253c1fb97e), uint256(0x116e0064f7ad74556f4e5c03c626cd39cd2db5d9c012f7a7d7c7f335418e397b));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2eccc619225fafb31b317bcde5d1bcd6098a6a5b1b4ddc92ce49be54ab1ce8be), uint256(0x1521f8a92840975c2ddf441b7e93d7084a5118b1e8cf255c45471e3a2aedeb2a));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x1105df213250562d2510977107da1d654f4ff755034e67b4a65fc9b5d7fdae14), uint256(0x0519adf26976df6026b7c734178f4c37f8822dc8de70e99bb42c5700d937f42c));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x02fbe2d7cfd980d99b6454164eb70aaabea6aa25d9403860bbe9389353475a1f), uint256(0x073bf48a19e40127e17b4535d16c1a377c250ec40fcfe20ce4a87225fe2aeebc));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x063b7a1e7d810dd56c930033476f911ab890dacca609c2630ec645eaebe6e7ea), uint256(0x1789caffda230461b9fed6fc360faf817b5650be59c85fb68f715e21e402ffd5));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0f8bd2147c222947d8319a4d84f885b4f94f7781ff687742e67ac706c6edab0a), uint256(0x12ad5abdfa676c7d506829dc0a7a66292ace014e0f8c6606baaecf99546eada6));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x1bca25ee195d675d37dde3d08f6db8869fddc9a812fbfead595c1df70f2360de), uint256(0x104036e64ee3d686c25e5baa4a8185d70bb273c105a433b7bc68077b4c472d4f));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x093aff82cd89df039ae3cf0e0e6543065e4498e559bab2ea67238db0cbdb5184), uint256(0x1b16da76d1b34111509d1e2e801102b70af4f8a6424ad69738b13a7d8be3b065));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x2baa64b0b8095e623c855e86f9c0074639606544166c2de0df1a447cc5fb99d8), uint256(0x0c96e72a2ab880db5b0c9fa002470a4d2facd5c00f05ef1b71cccd55b0402102));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x24590328df17707c4cc694d7740bdebfc0bb6f282014f843a9e420c2e38cce9d), uint256(0x23825cc149cdf8c8ec794bcce1f8bb4354db5513c11e60f0fc4199ec38f41fab));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x1bc0df4ec7a260299f6f6faea447772ae13c3e1d40f9d1e6ac40c7a70b883987), uint256(0x0ff533174717f49eff561de4596748ecacffef6f8ec9f976e9ae911a2fa77a3d));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x20b06c8d0b6337925a78230147a4cc036c2122592ed8ba3bd93187454078c6c7), uint256(0x1687bcb475c16412a6aebfdc1f567d4c747096e1fd44c4aef710a04694b71510));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x13380b2b86d34028dd22534bee1ca2a37381d72bd3eb77b37f4c2587ec1cdeb1), uint256(0x16daa12c8755bfaca98f142f00670a963a4c2c78a93b5144341b5c7125cbd237));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x0a45aff052f0a5611252f2b1a63a4ad2c1fae6515d38e3864408c22de250c60d), uint256(0x2d63a228e5e534502875dcfa1386cc49c69ad8b2ad3e17891474ed3c973a57e3));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x1fb8f372386da3743aea46f41c36264a66178fcaaec803919773d897540949ae), uint256(0x128805bac9eb56aae97d62757f486e6bc98ee35a49e022e1cc6345f4e1209eea));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x044973730c0820dc377c8277b29382bae1e74fd2212d8cc00def615dbc312f4a), uint256(0x0750da19251b2e925c66107202fa33b23478db3f9d27aaa81a4dfc283777be45));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x037fe444ec75dd36cbcfd7d9e050ae1d3f8ad36ff89d1a8afba693d3e5d0b45c), uint256(0x0da4135b81f9104579524905c65b995b942ee69fd939c2df5c5cc3ac942ef1c4));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x018b5228962ffa88f0a4c45860bee4cc8e1714d1ab218adf58caebed30cab974), uint256(0x12a9bfd436dc308f286e2477bcf8c3574837e9a6a70342ef86e117ad115cb976));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x0e2fce30e40f7cd8beaabe7699c4d3a6d631e07bb4ee0efa2d071b2417335f37), uint256(0x0527fce9de6ed2dbcff178c256014ebeee58c26c497da678c83a7830422f4695));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x0df66636e0bf3e914fc176548d1100e38cc9118366c7257e0a881bc3fb419bfb), uint256(0x17f3b4df3007fd221f3a527d5a58e07ba6d57ddac0dddbce6aaed29656844b9a));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x03c155bf65e855bce3476da3ea705d7402e3274bf0a6a6ac42a05eb2288d8892), uint256(0x142495b844bb709eb16e9fe7f3dd1afb8dda2ce83e845c5637882d12e47b8e04));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x193b07d88b2d14e633bfa321e31e3879f4d1df62024d795512f6ab18ca3e5faf), uint256(0x2041c0888b489eda67d2e40ccaa66d3b163db328978e79156431035f028b9b95));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x2cf0196fd7edd9cd8e22d3f98c2edc6c5e2fef7f1b9a69488e1a190131967bca), uint256(0x204509750b0951a43beec17c5f2fac7a252abb86edb2057e5bbce5e4cb6d23a5));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x0e7fbd657be9d93142fb50176f95cdc73e983bd42445a6fd9c92412b9c4e6911), uint256(0x13984068cd4c912ac4dc046e59749d2b1e1d565dabdd6a5fd9f8d12bae8ba574));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x249167295cd4d7872c42e64aece98ceac0118579e211c1922ffae43bff1e2c67), uint256(0x0c78c3a56d090f37dbc12b0e728c3cc86c271daac23bd14b8725da6edc5a3632));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x1bbfacd81c918e8d6a75b029adeec320e7089d4c6f31034f573aca12d7f86db3), uint256(0x2093786622868bfe4cc761baa3cce72344fa895d41ff1a7afb4051f043433dca));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x3021f6ad2271b5264b2fad9bdff0b12c5cf4460b5cdd45a29bdad3d232361782), uint256(0x0a382646d237a06e2e8170738eda7b0120a21416b15645b52752d0485d8eb725));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x11472e7955b9a40898aeb9608fd4055c0e05e426c2b46572d5dcdc53fbec9f47), uint256(0x235d6907d198b1ca5c5a792cd0de9af6f016fcad7a81199c2f2f67aa0d1d5b08));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x2ec187c9fd6828a39bd59ed53d801631dbf422315d380b09d8fbc418489b2ff5), uint256(0x1d89bcfe39d95647550cd72fe73fe5e32e36b1866f634f237bb1ef8914e2f09e));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x246ac0c58b2a689715c418e1856d5e1dcd3b7104b3624fc9ade399146aca09c2), uint256(0x0dddae39c202d17669d19f6b13f025bd14727a63e0548367de466c364ea64b00));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x21589fdbd95cc761ed3cee4a41dc189a2f87f90b6e7ee48ef49785748e5edb8c), uint256(0x19894aec48e89c808926071dcfdbfc288f63e50cf1203ebbbcb8b54aa2446aaa));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x17f3f373297958063ad41f8ff388a55c28653b5885f15dd5bf3f47dba4e3a024), uint256(0x07ba85228b6a0660955376132bc7c57175d0c9f30417824751ee6ad057e370cd));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2edebca7ba507e8b38f32915f19bbbf6474a91c2d64ce158fb230836978ace8f), uint256(0x11aedc6ce1bafb376b3111e2f3f3ffc9608e2e8e5c978cf2b47721f220d815f7));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x070665d0e0105a0b2358384a20cc89011a160ed8feb232bd184949eb72c73463), uint256(0x26d9cebd2a5c3bb9ba51f76ce7fe8d4de5c284a20e288ee4add06c0497127c66));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x09b12c925e8a5f11559bf620cf4ab107e89179b8aa1a7c134c58cbf028529880), uint256(0x1a34ec60431826d7f3a3443a00ea1fcf9485f8c8c66f1c0463d03abda0a57a78));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x031523477423051eb0e47027fed6270b94149c7d3287abb77887060c4098d741), uint256(0x2e808ef30027a4df292c92bf895dedda42934f7b0d5af00c72402202a64590bd));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x12f01394c9e3e11e268196194e26180dbc5404a418da438601b526385de658bc), uint256(0x0d7e03a1ea9cc53291580cc889d8ca12df9dab7cfd88e00f69aa5f57f8bd24d3));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x1fa52848efc1f618724396f5bd1f6fd0c2fa9df22ec2066d23c8d8476c5d263d), uint256(0x05bed92a848c4cf6790f027d1d8cc58941bc4b62df4cda86b067c1dbda89567b));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x19f81010fd267ae808f0d19ac91679bea553587eef680136da6bc5e8b4aae180), uint256(0x14d56f91455d28cef58328749c59378b8269400aa957649564cafa02fa3e7e3b));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x171cc44184cfdac7b8cb8c3cc631afd965481f705c09e90d9adac6f920ed199e), uint256(0x01d3c65cf695cbd95c1b267f054914d9ed95669bda5a72c778adba9d4d4ddced));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x243360445717afc6604d36e75e9afeb3fa974dba39a94e0e9b9b39266fe4b215), uint256(0x025b7166a108a3b276bfed109ea67fb1874ccdfd7cb4447e23a3a31c6c9261b2));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x256f6b8254f1f2353f99c80fb7a0b57a94e23c27d879d7f7c795e7d4ec7973c1), uint256(0x1c3ae8559af4cd330abcad5b4346f41965014d7943dfa7995863b1b0e7ff2e2b));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x047f685c373386bde9ec77359920ca22db80f188f677c47e9a8eec9dea3901c4), uint256(0x08a0f7a151aa18c50204e7f58db39d277c79d4538c07c0564e5daa4ab196729e));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x21eab473ef8cbc69fa44d9d1d6120e068a580204e98d113d3a0ac2d16893a44d), uint256(0x2aabd6a9de2e1dfb5b1b00b2227cb0e7f5ae3fe2632c37ee23c24d9d6b3d2bda));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x117ca089b54b360fe4bbbc0d923d8f54335447722393dc24f896f9f6dc88d286), uint256(0x26d6c30b1aab5580769cd5efdfe964fafdfb20cd0941c3607f227a5db8b9f249));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x2eaf5a8547cb50c2b2913fabc38a8a51e418a5e36b03c17c1755eef15ec32809), uint256(0x0587d96f769106e28acbaef1b5bc85acaeb7041383a9a03855214099ddb88749));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x1e693a658f81df85bc3bae388badde2096a85e1849caed2882f069958540d9d1), uint256(0x066e4ea0fef9f13de9d39d26fad62e3881e445c1bdd8a6296f91ef8d3fbf96a4));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x23db237b3c5cba67dd15bc9606954c606536192eeeb57974d384afa3bfe88d94), uint256(0x06f7363885439142f03fb2f137f027b8772d4e424fb551fc9edce9de94cd3656));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x2006e8e188b195b45d3f40554b1b7a567d8b5fc4892140594b81c29c622d2ff2), uint256(0x21ce92e87e12957550d1ef9c7f823bd84748e6c50c53ffd2ba58096fde251799));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x08b97e77d33205d34cf18119e94bcb51a461a1f28dc7e460a16abe42aad0d320), uint256(0x09b6d1fa58e87c9574e78984b13ac78bd2a852e9c5bfff5e29cec6d4170d6cd0));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x0bd86cd22fb4e55a7247b1c060b68778a2970d64089ffbf424c0d47cf889e24c), uint256(0x24b70c9ee0890b2578c345f1f3b3b3b50c139ce3e4f9fddf6a5e73336c565ff2));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x16f679d1c93f48f07992dbc2aad802847e24625d97d9d1aa4afc52f1f7202101), uint256(0x0d8cfe7ae071bfe30e3722e3e2a12416cd851e6bc008ba26282eaac9d94ae7d1));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x1f0acc395848e56ee1c499c6ca039b1cad7198d11b11eb75810fae8a79fa8719), uint256(0x14fd1c173f1c4f1142ef229e52b4e3edec5d904cdb08a47e869ef185a3a80581));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x1b74d18cbfb3b746c77865a89f6f457dd72b738ca1418065a13be649b293b03e), uint256(0x000ccf908fb697b1dc73a18fefd6bd16d0804ec47dde4a8895c2a28a2b22a255));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x194d980c63d72dd998ee3c65e2e591a0f8825a6444458e10462cea4fdb542fe9), uint256(0x0cb3184431ab7d30f1a96f60a13292fef5ae81085813f3e874d1188b1cb53ddb));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x100db58ba8f73d9d95b5ed4d2eba7ab1b1ec91798b1b5c485135ef4fe7312687), uint256(0x28f460363036eab765e22609043aea79156f18cf806d691768e0446276d08fbb));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x1a17ecda87887ad01c6edbb7f4fee0318f4d3c14cc7531a4ee5f2124baf17702), uint256(0x1c59a60d2ecadf50c877b73181acd222216264add44f521ec4433476dcf3fd16));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x091bb22fb060503a603fedb0124ffd5522e7693c606a2a651a2bda90fe037b5a), uint256(0x0351df6ed79b7a02698a893f9362069b9caffdfb34d79ae8a3ef9c4bc939d687));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x18f62d45daf02c815b3bf259ee5aaf93af74dd3889196bb6e08f344c6f248c04), uint256(0x1b5743a1b2bb56f59541edc0bf86f79a23d040db051a08cc7acabe8d33be0efa));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x1ba49f8e13a39e029ca6c747c694c9d52403371ded4fb18f9f52bde690e9a08d), uint256(0x0e38f4aec9d13e43330d4b6fa39be9845890bdf6459b6c680cd1f28564f66cfd));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x157edf73d1fe5e86f882eac9d0cc4cf94aa6aaaac9593087100edf3a385af228), uint256(0x06a95ed99f85df8f0ea3bc166bb2886f10fe3f4165fa0f7bbf95a64bfc2467df));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x0b2b8b821b99d675e5362a2a4a3bb94a8c0a7d5e6cf9afe0ef22da65a96e8ccb), uint256(0x0b765f377909913ee18a911a781f7ada2b9e09371f104623d7dc424d82cc6e41));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x2bd684f1546c1f3264e461a3c22864845dd087e85c1eb2f5f55b4f1ced8287fa), uint256(0x0a7653d7ff8e2ff1748d60dfd6fc1ff91c7a2db9932bdd40327d801a6a21029a));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x2ae5964c569b53e12581ff495e3c66b155e4ce14fd6547ec8c00341fe3ac9917), uint256(0x27d06a343d4869d623ea09fbb2045db297718169f58e9cf2596a800b219b5705));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x083e190f663fac73751ee5ec5e201fa6302ee10cf7573fad6d99fe1c79f689db), uint256(0x212fc6828e75ae0884f171016fa7c6d265859bfa6fff7c82c4343be96b3c52c3));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x1d7e36952fe2377a216b188663a16bd45a8cacafdc44d276bd2a0b526fd45643), uint256(0x2d2829d35f38dfda70203c1ebdd0d8535093b68b4d4fea8da5e5c98cf7cbc090));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x1eb226d758923b99828a7cd5cece48324596c885035edd6a4f2700e5babb0b33), uint256(0x10c6ae56367c5801b9384ac17ea8ee7accdbe7a080e67d7ac4da2557cc2e6447));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x12fe30fc7caa197f1f9b39bf1dbf72c99e0b81f568c175a0022131f323162dd6), uint256(0x0f613ab86a396e9824dd027e7173956261a2fad317b3b3a73da3e509ac5fc8e2));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x1d2719d97bd7c04b473b23194ae50074f19bef66b409045e6cbd6974f6035eb1), uint256(0x14de1a2cc2eaf2259adc8743457a2925ca81c8091b0d92dab9178cada582f22d));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x017c2c64c6b3309353682e38768b642e7c47a1c56bdddcaff6377c846aa024cf), uint256(0x2d29dbba89966b7e7efc5ba7502af33d22b3d002bcb43a6c53c306ac21be1677));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x108f600d8d6b287de5beb5dd3038908b1ca7306fab69d2e810e8eb6772f74e9d), uint256(0x2b743b2dc82fea3e0d00caf5297a57c1857782aa13c68d98325a3c4cee84fca7));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x11983b4741a1419ad44c238f5a97459cef2296a0910aa59da28dc2d064f837da), uint256(0x28dbd4d1d279ee1963575c5e967bd43fd914aad1338bc8338f78aae0437f4f8a));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x2898defdf6ca518e98e97ba04f601a525a7faf3d2c737df5c7915d9d1eb5e308), uint256(0x1c1daab62a81b953c5d23095a64d881259316ae41edb8cee46c3e89b726aeda8));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x19b7e7e6b0241c718f60ef5e5cbf0f79a9aba10e54a8122e2738884bcf4bc947), uint256(0x0b7d74e1d86dd35c0d45433079707d1ec545663838352dab9eb5cba78df10b4a));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x1c11ea1b43f09b2ec92fa75de38d6d570a8f78f6419505b3bd257933294fdb56), uint256(0x03c015ff6eae3c028eaad5a08fce60462a1c38720f74b4ccd3b58ab8e36327b7));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x3023b8661ccb9ec4d92937cfd85a7595bc4ebb2cc3a87bd79ced9fc263e85601), uint256(0x050cad0e94b57b297ed13211c53c682a232fa6facd4eb40e0618c9e8b71163e9));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x1db4ad26ae0797823a69fa12023e23fe162bde8f71db28f93735f892f91d8514), uint256(0x18be28191144267b12cf3451595a806e3f7d5325189a05f4590d9c839bcbd11c));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x30548217d8f191fc0f6406597db2242959b430321225d84bed9ec7a4e67a12a4), uint256(0x24112ca4574c62576c50634d549ed7183eeb6b4eb39008603a85bd6f79a2042e));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x12102e16f9271ebfcbd2426bcf11b8af658bb53535f3ef261b7c350a47826765), uint256(0x2a886e554d23b7a5e6abf35d694fe2a2c638097d2155ea852abdc49a3ced8ead));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x1e53fe6fa02e83b4a72a157b957f1ff69db9f120554aa527dd7b7447e060f5fa), uint256(0x2ce77aefe26576023ecd25393a39e959934ca15164137ca9a64ff48fbf6079c7));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x08b6ba050fef5f2c49ef9b6ab60188afae9147eba17cdebba3b901aacef7c04b), uint256(0x0990e9540fd2ded3489b8c73ce6a4c89e44153f7e2e6cf086ebb268b3c6893a9));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x10cb501351ab19d24b92dc444c2530884b65edcad624eccff6cc90e11f309ec5), uint256(0x03974b0aa8a130b7fa4e3f23637174c11c976f08dda5deb0cda5bbe684f250ff));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x29019c62eea7711d55af97d19d1996b7c81d89139520366049e81e544679b1f9), uint256(0x10b4e9fb812d91864b3dab9985f71dec200fa12fdd2a518aab73dd6e33587182));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x296d2b3b2ab24dc4f938e3724bbab479c0ad70933171f6ecda343f4cc53250e8), uint256(0x1b47b2ac81f77d6f6ab10ec927e237857e23bfe606817309ece294ecbbda2278));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x034c62e045415fe78e7595bba2283c38504bba8a9eec9751cdfb90d76cdaca1f), uint256(0x29e429bcfb8875dc712c7160f21c638ea275b874d46aa300664cc77fe3badf5b));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x2da09a96f0f99c63e25583b238781ab13635f317634471ef0c355f1a5e719f17), uint256(0x21212c6908cde1ebdd9645a58d9b8c8fdf5b419310af0c9ae9aac9b7b8dc49e3));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x2190b3b800f540cbd7e96d92faa4c99012151ab3eed9b214858569cc2d2cd93f), uint256(0x23fc754a779c352ff100f0efb13431fb9e5c5e7a40639775d4c5ac0283383467));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x17b05d9ab94d386d8c9baae94445f4ca976e305c61845fa865336e1a36e9a686), uint256(0x0ba564be021e14ccc65aa8ccc4bb3ff9010e9078c0dbd272a7e3983f84d9f585));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x2858f3e36dee593fb3ef4b8ac96ff02ba915596842a58ace12ec57a680e5bbf8), uint256(0x1f3e2adeb0f2da5018cd8aa199b988df7f947beb78cbd012980b64242a1e3f09));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x2c5502c9e08f544d0cc2dd560097dc2cdb56d2eeac2ddc2d1f54063d52f48d0f), uint256(0x051fce6abc72ac0ded57e7f03ef405cf509b158730aa9690f92269777539b516));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x221073f1dece153a8d30c5cefe4939728da3e2a804fab86e0f14c6bb54506250), uint256(0x126fa5837681cb52e2f55b8325eb8ccc4cf7f8f1ec6eb4a6922f80c65d5feb34));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x29932b6010ee99840461733196997a8f41a02ac1216ad9c782ed91ee1ae0c874), uint256(0x056cb72b04b2394a5b03e1144d9380964b17ccdcdd61188cd1839cfb9c2b141e));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x27c8aab5b614729de7ac41094cc932d0fcfd824461a0de58f8dbe40013defbd6), uint256(0x1edf7acce25d027ce25fecf27a22b7d88fe60ce066df88a9b781fee21d4dcce5));
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
