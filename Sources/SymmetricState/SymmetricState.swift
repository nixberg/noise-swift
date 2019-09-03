import Foundation

import Noise
import Xoodyak

public struct SymmetricState {
    public private(set) var isKeyed = false
    private var xoodyak: Xoodyak
}

extension SymmetricState: SymmetricStateProtocol {
    public init<D>(customization: D) where D: DataProtocol {
        xoodyak = Xoodyak(key: [], id: customization, counter: [])
    }
    
    public mutating func absorb<D>(_ input: D) where D: DataProtocol {
        xoodyak.absorb(input)
    }
    
    public mutating func absorbKey<D>(_ input: D) where D: DataProtocol {
        xoodyak.absorb(input)
        isKeyed = true
    }
    
    public mutating func squeeze<M>(_ count: Int, to output: inout M) where M: MutableDataProtocol {
        xoodyak.squeeze(count, to: &output)
    }
    
    public mutating func squeeze(_ count: Int) -> [UInt8] {
        xoodyak.squeeze(count)
    }
    
    public mutating func encrypt<D, M>(_ plaintext: D, to ciphertext: inout M) where D : DataProtocol, M : MutableDataProtocol {
        precondition(isKeyed)
        xoodyak.encrypt(plaintext, to: &ciphertext)
        xoodyak.squeeze(16, to: &ciphertext)
    }
    
    public mutating func encrypt<D>(_ plaintext: D) -> [UInt8] where D: DataProtocol {
        var ciphertext = [UInt8]()
        ciphertext.reserveCapacity(plaintext.count + 16)
        encrypt(plaintext, to: &ciphertext)
        return ciphertext
    }
    
    public mutating func decrypt<D, M>(_ ciphertext: D, to plaintext: inout M) where D : DataProtocol, M : MutableDataProtocol {
        precondition(isKeyed)
        precondition(ciphertext.count >= 16)
        
        let actualCiphertext = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)
        let indexBefore = plaintext.endIndex
        
        xoodyak.decrypt(actualCiphertext, to: &plaintext)
        let newTag = xoodyak.squeeze(16)
        
        guard zip(tag, newTag).map(^).reduce(0, |) == 0 else {
            plaintext.resetBytes(in: indexBefore...)
            fatalError()
        }
    }
    
    public mutating func decrypt<D>(_ ciphertext: D) -> [UInt8] where D: DataProtocol {
        var plaintext = [UInt8]()
        plaintext.reserveCapacity(ciphertext.count - 16)
        decrypt(ciphertext, to: &plaintext)
        return plaintext
    }
    
    public mutating func ratchet() {
        xoodyak.ratchet()
    }
}
