import Foundation

import Ristretto255
import Xoodyak

public struct SecretKey {
    fileprivate let scalar: Scalar
    public let publicKey: PublicKey
    
    public init() {
        scalar = Scalar.random()
        publicKey = PublicKey(scalar)
    }
    
    public func signature<D, M>(for data: D, to output: inout M) where D : DataProtocol, M: MutableDataProtocol {
        let ephemeral = SecretKey()
        let c = Scalar(fromUniformBytes: hash(self.publicKey, ephemeral.publicKey, data))
        let t = ephemeral.scalar + c * self.scalar
        
        output.append(contentsOf: ephemeral.publicKey.rawRepresentation)
        t.encode(to: &output)
    }
    
    public func signature<D>(for data: D) -> [UInt8] where D : DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(64)
        signature(for: data, to: &output)
        return output
    }
}

public struct PublicKey {
    fileprivate let element: Element
    public let rawRepresentation: [UInt8]
    
    fileprivate init(_ secretKey: Scalar) {
        element = Element(generatorTimes: secretKey)
        rawRepresentation = element.encoded()
    }
    
    public init<D>(rawRepresentation data: D) where D: DataProtocol {
        precondition(data.count >= 32)
        let data = data.prefix(32)
        element = Element(from: data)
        rawRepresentation = [UInt8](data)
    }
    
    public func isValidSignature<S, D>(_ signature: S, for data: D) -> Bool where S: DataProtocol, D: DataProtocol {
        precondition(signature.count >= 64)
        let signature = signature.prefix(64)
        
        let ephemeralPublic = PublicKey(rawRepresentation: signature.prefix(32))
        let t = Scalar(from: signature.suffix(32))
        let c = Scalar(fromUniformBytes: hash(self, ephemeralPublic, data))
        
        let lhs = Element(generatorTimes: t)
        let rhs = c * self.element + ephemeralPublic.element
        
        return lhs == rhs
    }
}

public func * (lhs: SecretKey, rhs: PublicKey) -> [UInt8] {
    (lhs.scalar * rhs.element).encoded()
}

func * (lhs: SecretKey?, rhs: PublicKey?) -> [UInt8] {
    (lhs!.scalar * rhs!.element).encoded()
}

fileprivate func hash<D>(_ staticPublic: PublicKey, _ ephemeralPublic: PublicKey, _ data: D) -> [UInt8] where D: DataProtocol {
    var xoodyak = Xoodyak()
    xoodyak.absorb(staticPublic.rawRepresentation)
    xoodyak.absorb(ephemeralPublic.rawRepresentation)
    xoodyak.absorb(data)
    return xoodyak.squeeze(64)
}
