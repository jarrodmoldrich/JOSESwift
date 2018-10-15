//
//  ECDecrypterTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 15.10.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import XCTest
@testable import JOSESwift

class ECDecrypterTests: ECCryptoTestCase {
    // produced using the openssl command line: `echo <text> | openssl enc -e -a -K <key>`
    let cipherTextBase64URL = "VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24uCg"

    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
    }

    func _testDecrypting(algorithm: AsymmetricKeyAlgorithm) {
        guard privateKey2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = ECDecrypter(algorithm: .RSA1_5, privateKey: privateKey2048!)
        let plainText = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextBase64URL)!)

        XCTAssertEqual(plainText, message.data(using: .utf8))
    }

    func testDecrypting() {
        guard privateKey2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = ECDecrypter(algorithm: .RSA1_5, privateKey: privateKey2048!)
        let plainText = try! decrypter.decrypt(Data(base64URLEncoded: cipherTextBase64URL)!)

        XCTAssertEqual(plainText, message.data(using: .utf8))
    }

    func testCipherTextLengthTooLong() {
        guard privateKey2048 != nil else {
            XCTFail()
            return
        }

        let decrypter = ECDecrypter(algorithm: .RSA1_5, privateKey: privateKey2048!)
        XCTAssertThrowsError(try decrypter.decrypt(Data(count: 300))) { (error: Error) in
            XCTAssertEqual(error as? ECError, ECError.cipherTextLenghtNotSatisfied)
        }
    }

}
