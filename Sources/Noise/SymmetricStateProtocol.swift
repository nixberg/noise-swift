import Foundation

public protocol SymmetricStateProtocol {
    static var name: String { get }
    
    var isKeyed: Bool { get }
    
    init<D>(customization: D) where D: DataProtocol
    
    mutating func absorb<D>(_ input: D) where D: DataProtocol
    
    mutating func absorbKey<D>(_ input: D) where D: DataProtocol
    
    mutating func squeeze<M>(_ count: Int, to output: inout M) where M: MutableDataProtocol
    
    mutating func squeeze(_ count: Int) -> [UInt8]
    
    mutating func encrypt<D, M>(_ plaintext: D, to ciphertext: inout M) where D: DataProtocol, M: MutableDataProtocol
    
    mutating func encrypt<D>(_ plaintext: D) -> [UInt8] where D: DataProtocol
    
    mutating func decrypt<D, M>(_ ciphertext: D, to plaintext: inout M) where D: DataProtocol, M: MutableDataProtocol
    
    mutating func decrypt<D>(_ ciphertext: D) -> [UInt8] where D: DataProtocol
    
    mutating func ratchet()
}
