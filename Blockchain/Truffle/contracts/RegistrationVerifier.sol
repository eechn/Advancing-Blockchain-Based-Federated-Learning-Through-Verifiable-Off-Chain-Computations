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

contract RegistrationVerifier {
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
        vk.alpha = Pairing.G1Point(uint256(0x1e8716e38cc828faee8aa6babddf21ced349f46e0117e968691b44e2688bb5a7), uint256(0x13800f39f962c578fe0a6ba583c48b3da20be431dde1a630e36652801f13634c));
        vk.beta = Pairing.G2Point([uint256(0x2c685952bad8182980cddb4afb61938ef7484b3e779722912c9d2306f7b473d5), uint256(0x18c8b88f1698e6c60df5569e1e53e120ce088cc3d92f146167bd0de5293bc286)], [uint256(0x0de90530ec3271560e629b7f44e180c14a5447800bc8d78f90066c8abab85216), uint256(0x2a75e120e1f2c69b4e1358b23fdf424d56cb4ef085c8f5bb150e0911c5e1f153)]);
        vk.gamma = Pairing.G2Point([uint256(0x0521fe05fc52bdf7dad0d8749a7c40ced1d5023ec11114db6919b5f8770673d2), uint256(0x1317e390aa510950920b69aeb7cabdd9a033d2dd9acdbf4562595bc8a900bd8f)], [uint256(0x02e28190b2d52e7dc15015bba3e151c1129f793032028ec0c8cdc13f99b9a414), uint256(0x1649093ff99e5c9e7bf0306c7ebd06e4e1d03c3255b2f9a3ceb6af8ec9e25eab)]);
        vk.delta = Pairing.G2Point([uint256(0x0754d557f4bb6c9a47db833655cdf82725210b06f9c0d7ed1488ca2f7831a01e), uint256(0x1a918d9db53d548df1ff37155787e1d4c8ab40bc80626cbf7be34b725a5853f2)], [uint256(0x1910bd3a9258acf624dde98c1a0dba158281461ceefa41599af1df7c4e30daa5), uint256(0x14fca1bf930abe4fbdbf1ba971004ae63ba90afb21e2e3ceb8b5dc8c38352833)]);
        vk.gamma_abc = new Pairing.G1Point[](27);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x16201e157c7c2a1aaecf4f9ed9322d578e5c5623286026aff072bb6e04a25322), uint256(0x0f9d3de752d2a3bdf651498e3fe5c5ebbfa2d22f6e5f75232775bd0f550d1ad3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x091f9b7d7988cdfba32ff669bce23a33e7eb289356095bb7519055809cfc7fa4), uint256(0x25b1734f21e806b6de1b545084f45e6009457ba453d184a9ba421aca0ed7f95b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0d9261285c07eb60ca074d93347eaaf6ee10a40c9ff1e3e909efc34e4e05eb52), uint256(0x1a8f4a8046251f555dd3ec417664d541251685c120081c957a51264d3340b357));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0b7b573ab14c64664acf348233a25dee7e7ca4c39b66f54484cca5d12dd83a59), uint256(0x0daaa34a1dc55bf2403e1bbf3250f0da978ee693b6be11873f4a960323fa3706));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x25da759304b502fa40e9a9b1321a60a18abd1cadd731ce5272f48106a3d0378d), uint256(0x2966037f22135facd547a7d25c1174e095bfd7746023c25674100e56924e9058));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1116cd3ceaa5e3361abc9f8635a571f59650c93d572556d2d1e3c8ddca796ed9), uint256(0x0f73ef8bcc06e1c1f52e493c24148d087495286868b68ab33b737de2071ec9cc));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x12e385116f62db1f7aee1d2e5555ba5bb91e86a648f21a07a8c94c4087c705ea), uint256(0x12812212b8e4b5d61083b5b794a664ac5fd760f5a78ad6ab381d9640cbaee4ef));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0679b2c5d1a52cea398670fb8808644eadf7b6afdb0354fc60c4c72bc01a4066), uint256(0x1a3d9a493f5f953baa0158fb0f466b7eb988dcc1483fa2973f05409832c7a5b9));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1ac264121de4e84e7449c2ec93c63a72ea53d31bf28c2aad5a9c24b8b03d37a4), uint256(0x101ce4e61bf4405d0b04420d18c9de43e6dc97d2622499d9197c602c8ceaadf0));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x04627444c114ac204424c2e4d12936ab5ca05a23374ea7e2da9c5e2e8f29697d), uint256(0x1adcaf0012f81d0c1f0bd0edb801bbd57b0598debba0512437c055569952d201));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2d0499c678794d4478effef41ca22e74b4da5d39e92b038bf76766b9f201d800), uint256(0x145dede30e09923ca35c34ad927ec424c88d83ad06335097b2368d82854cbcae));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1216d6b35543e46c3e15dd5d8284d10caf7d0adc1c762eb92d5ab80b7267bca0), uint256(0x1fb060418d8d13e1f5d0ff8807177d8e7d156b555df60ccdeb4123de31c86bec));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0fede26b0f5789e8b13ece5dc23434450c0d5e450f9f51882cbf19a701f7d0c0), uint256(0x04daa2f4744b60f9dab42ead74587b74bc18ea6428c8b0b66065f65fe83d595a));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x175ad2c29745f081af48edf14883b024c6f8b8a3b9e7638555b1d63ba853d64d), uint256(0x1e9c120385e672935463b4928d78571eb3038436547586ae117086c54e29e76a));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x13985c54185d234c433a226592dd84e728b414689080afa0c962636f78115bc6), uint256(0x241fd914c714e48b566d02e6edaedd9a07f619be5d408b10b9a7d1798bec93db));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x17c3146671300cc1b1d1555b9167ac207a752a28820c4b667cbc4c48407f6b9e), uint256(0x102221fe449577e0cae0cd61eaca44002c0ab10076d5100eb4393e8e0a01591c));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1c2c9228da84e0bb9d9c7663f859bd7f4b4d80ca0bf1768f564e745c678ba94e), uint256(0x22035836a5156c9e519342744834ea3766cd342fd5a2ee552cd899d507243e43));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0b356fc9d64759511e216da53ebb657d3ebf7572c3484bbc10979b9a96434e3f), uint256(0x20eef01e30724d698b17be167fea2a3ad947722638bca1872f4baede133caeb1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1469f843d32c5595a7aeeeaf2d5a27c8f7b738f3db95eac9a0fb70fd847db2c8), uint256(0x1f1374d3c7befdb1e2bca6d062b7704194476f4af000e44fc7166b8f6019a986));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x10e62bd34d21888295ce18e5d6a92b7c2dba71d18cece901a0abb8a19ebfa7ec), uint256(0x030f45169900d372556827441e11e7340f477e0c9b24513d29c692037bc448f6));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x11f0f9e7cf3020ed6f780f1f665c203b594e32b59df43c3730525c8e1aae1ce2), uint256(0x1ea3c592130a81d306d7c91c2afce9e5c44cdd908d2ca56e8d31936f4672ea37));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1eda2d47431ae6155c3e5cd371706a398f8b3634b68489773f384ecafbfbac5a), uint256(0x054303d42b3ae5a94f6de5b49a04bf0d819be91dd96a375c7cae4624a72096bf));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x249c4349b9fe2e138b5b406a00687d1d9880b7a25d6cec7dd21466cf8f210224), uint256(0x01864d6e89659540758e17a7e60ebc04213b34fe1a10b472ff82f86bfcfcc30d));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x17c0b89ed5447c62bd065a258ec1d603f7a74692d25ea7417069b7811545bf10), uint256(0x17590a0343f581e3e41fb264f59fa843c8d47cc98e4904ea6933a651b7d89fa0));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0ca4a256148c3023cbf940e9e7028fc8d5fc9157c1c90aacb876fae64e2f7554), uint256(0x0aff1c78ec00976d15a4938c426618c4662b567edd6117d195067f6c6ae1a2e9));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x20a362a501ecc22ea140758bf55039b608941f5c325ce5d22cc1b6053b081260), uint256(0x26cafd5304b1c7ec6c5e199dfe66bfe946d5a277dfd57f49dcc510ca7e8a00b0));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x07314fd5f73ae2d569327c0689c8aef52cd90dcf17bc07880a908e7d3dd8665b), uint256(0x093aa11e3ab06bf50aacbe6c3e023355b955772dd617d68ab4a4af0f4986ad4a));
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
            Proof memory proof, uint[26] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](26);
        
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
