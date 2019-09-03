import XCTest

import SymmetricState
@testable import Noise

final class NoiseTests: XCTestCase {
    private let initiatorStatic = SecretKey()
    private let responderStatic = SecretKey()
    private let payload  = [UInt8](repeating: 0x12, count: Int.random(in: 0..<1024))
    private let prologue = [UInt8](repeating: 0x34, count: Int.random(in: 0..<32))
    
    func testN() {
        var initiator = Handshake<SymmetricState>(.N, .initiator, prologue: prologue, their: responderStatic.publicKey)
        var responder = Handshake<SymmetricState>(.N, .responder, prologue: prologue, my: responderStatic)
        
        let message = initiator.write(payload: payload)
        let newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testK() {
        var initiator = Handshake<SymmetricState>(.K, .initiator, prologue: prologue, my: initiatorStatic, their: responderStatic.publicKey)
        var responder = Handshake<SymmetricState>(.K, .responder, prologue: prologue, my: responderStatic, their: initiatorStatic.publicKey)
        
        let message = initiator.write(payload: payload)
        let newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testX() {
        var initiator = Handshake<SymmetricState>(.X, .initiator, prologue: prologue, my: initiatorStatic, their: responderStatic.publicKey)
        var responder = Handshake<SymmetricState>(.X, .responder, prologue: prologue, my: responderStatic)
        
        let message = initiator.write(payload: payload)
        let newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testNN() {
        var initiator = Handshake<SymmetricState>(.NN, .initiator, prologue: prologue)
        var responder = Handshake<SymmetricState>(.NN, .responder, prologue: prologue)
        
        var message = initiator.write()
        responder.read(message)
        
        message = responder.write(payload: payload)
        let newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testNK() {
        var initiator = Handshake<SymmetricState>(.NK, .initiator, prologue: prologue, their: responderStatic.publicKey)
        var responder = Handshake<SymmetricState>(.NK, .responder, prologue: prologue, my: responderStatic)
        
        var message = initiator.write(payload: payload)
        var newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        
        message = responder.write(payload: payload)
        newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testNX() {
        var initiator = Handshake<SymmetricState>(.NX, .initiator, prologue: prologue)
        var responder = Handshake<SymmetricState>(.NX, .responder, prologue: prologue, my: responderStatic)
        
        var message = initiator.write()
        responder.read(message)
        
        message = responder.write(payload: payload)
        let newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testKN() {
        var initiator = Handshake<SymmetricState>(.KN, .initiator, prologue: prologue, my: initiatorStatic)
        var responder = Handshake<SymmetricState>(.KN, .responder, prologue: prologue, their: initiatorStatic.publicKey)
        
        var message = initiator.write()
        responder.read(message)
        
        message = responder.write(payload: payload)
        let newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testKK() {
        var initiator = Handshake<SymmetricState>(.KK, .initiator, prologue: prologue, my: initiatorStatic, their: responderStatic.publicKey)
        var responder = Handshake<SymmetricState>(.KK, .responder, prologue: prologue, my: responderStatic, their: initiatorStatic.publicKey)
        
        var message = initiator.write(payload: payload)
        var newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        
        message = responder.write(payload: payload)
        newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testKX() {
        var initiator = Handshake<SymmetricState>(.KX, .initiator, prologue: prologue, my: initiatorStatic)
        var responder = Handshake<SymmetricState>(.KX, .responder, prologue: prologue, my: responderStatic, their: initiatorStatic.publicKey)
        
        var message = initiator.write()
        responder.read(message)
        
        message = responder.write(payload: payload)
        let newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testXN() {
        var initiator = Handshake<SymmetricState>(.XN, .initiator, prologue: prologue, my: initiatorStatic)
        var responder = Handshake<SymmetricState>(.XN, .responder, prologue: prologue)
        
        var message = initiator.write()
        responder.read(message)
        
        message = responder.write(payload: payload)
        var newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        
        message = initiator.write(payload: payload)
        newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testXK() {
        var initiator = Handshake<SymmetricState>(.XK, .initiator, prologue: prologue, my: initiatorStatic, their: responderStatic.publicKey)
        var responder = Handshake<SymmetricState>(.XK, .responder, prologue: prologue, my: responderStatic)
        
        var message = initiator.write(payload: payload)
        var newPayload = responder.read(message)
        message = responder.write(payload: payload)
        newPayload = initiator.read(message)
        message = initiator.write(payload: payload)
        newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testXX() {
        var initiator = Handshake<SymmetricState>(.XX, .initiator, prologue: prologue, my: initiatorStatic)
        var responder = Handshake<SymmetricState>(.XX, .responder, prologue: prologue, my: responderStatic)
        
        var message = initiator.write()
        responder.read(message)
        
        message = responder.write(payload: payload)
        var newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        
        message = initiator.write(payload: payload)
        newPayload = responder.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testIK() {
        var initiator = Handshake<SymmetricState>(.IK, .initiator, prologue: prologue, my: initiatorStatic, their: responderStatic.publicKey)
        var responder = Handshake<SymmetricState>(.IK, .responder, prologue: prologue, my: responderStatic)
        
        var message = initiator.write(payload: payload)
        var newPayload = responder.read(message)
        message = responder.write(payload: payload)
        newPayload = initiator.read(message)
        
        XCTAssertEqual(payload, newPayload)
        XCTAssertEqual(initiator.finalize(), responder.finalize())
    }
    
    func testKeyExchange() {
        let a = SecretKey()
        let b = SecretKey()
        XCTAssertEqual(a * b.publicKey, b * a.publicKey)
    }
    
    func testSignatures() {
        let secretKey = SecretKey()
        let publicKey = secretKey.publicKey
        
        var rng = SystemRandomNumberGenerator()
        let message: [UInt8] = (0..<Int.random(in: 0..<1024)).map { _ in rng.next() }
        
        let signature = secretKey.signature(for: message)
        
        XCTAssert(publicKey.isValidSignature(signature, for: message))
    }
    
    static var allTests = [
        ("testN", testN),
        ("testK", testK),
        ("testX", testX),
        
        ("testNN", testNN),
        ("testNK", testNK),
        ("testNX", testNX),
        
        ("testKN", testKN),
        ("testKK", testKK),
        ("testKX", testKX),
        
        ("testXN", testXN),
        ("testXK", testXK),
        ("testXX", testXX),
        
        ("testIK", testIK),
    ]
}
