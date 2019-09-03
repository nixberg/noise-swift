import Foundation

public enum Role {
    case initiator
    case responder
}

fileprivate enum Operation {
    case write
    case read
}

public struct Handshake<SymmetricState: SymmetricStateProtocol> {
    public let role: Role
    
    private var e: SecretKey? = nil
    private var s: SecretKey?
    private var re: PublicKey? = nil
    private var rs: PublicKey?
    
    public var myStaticKey: SecretKey? { s }
    public var theirStaticKey: PublicKey? { rs }
    
    private var symmetricState: SymmetricState
    
    private var nextOperation: Operation
    private var messagePatterns: [[Token]]
    
    private var finished = false
    
    public init<D>(_ pattern: Pattern, _ role: Role, prologue: D, my s: SecretKey? = nil, their rs: PublicKey? = nil) where D: DataProtocol {
        self.role = role
        
        self.s = s
        self.rs = rs
        
        let patternDefinition = patternDefinitions[pattern]!
        let protocolName = "Noise_\(patternDefinition.name)_ristretto255_\(SymmetricState.name)"
        
        symmetricState = SymmetricState(customization: protocolName.data(using: .ascii)!)
        symmetricState.absorb(prologue)

        messagePatterns = patternDefinition.messagePatterns
        
        switch role {
        case .initiator:
            switch patternDefinition.preMessagePatterns.initiator {
            case .e:
                symmetricState.absorb(e)
            case .s:
                symmetricState.absorb(s)
            case .none:
                break
            }
            switch patternDefinition.preMessagePatterns.responder {
            case .e:
                symmetricState.absorb(re)
            case .s:
                symmetricState.absorb(rs)
            case .none:
                break
            }
            
            nextOperation = .write
            
        case .responder:
            switch patternDefinition.preMessagePatterns.initiator {
            case .e:
                symmetricState.absorb(re)
            case .s:
                symmetricState.absorb(rs)
            case .none:
                break
            }
            switch patternDefinition.preMessagePatterns.responder {
            case .e:
                symmetricState.absorb(e)
            case .s:
                symmetricState.absorb(s)
            case .none:
                break
            }
            
            nextOperation = .read
        }
    }
    
    public func nextMessageOverhead() -> Int {
        precondition(!finished)
        fatalError("Not implemented!")
    }
    
    public func nextMaximumPayloadLength() -> Int {
        65536 - nextMessageOverhead() - 16
    }
    
    public mutating func write<D, M>(payload: D, to output: inout M) where D: DataProtocol, M: MutableDataProtocol {
        precondition(!finished)
        precondition(nextOperation == .write)
        
        for token in messagePatterns.removeFirst() {
            switch token {
            case .e:
                precondition(e == nil)
                e = SecretKey()
                output.append(e)
                symmetricState.absorb(e)
            case .s:
                symmetricState.encrypt(s, to: &output)
            case .ee:
                symmetricState.absorbKey(e * re)
            case .es:
                if role == .initiator {
                    symmetricState.absorbKey(e * rs)
                } else {
                    symmetricState.absorbKey(s * re)
                }
            case .se:
                if role == .initiator {
                    symmetricState.absorbKey(s * re)
                } else {
                    symmetricState.absorbKey(e * rs)
                }
            case .ss:
                symmetricState.absorbKey(s * rs)
            }
        }
        
        if !payload.isEmpty {
            symmetricState.encrypt(payload, to: &output)
        }
        
        nextOperation = .read
    }
    
    public mutating func read<D, M>(_ input: D, to payload: inout M) where D: DataProtocol, M: MutableDataProtocol {
        precondition(!finished)
        precondition(nextOperation == .read)
        
        var input = input.suffix(input.count)
        
        for token in messagePatterns.removeFirst() {
            switch token {
            case .e:
                precondition(re == nil)
                re = PublicKey(rawRepresentation: input)
                input = input.suffix(input.count - 32)
                symmetricState.absorb(re)
            case .s:
                precondition(rs == nil)
                rs = symmetricState.decrypt(input)
                input = input.suffix(input.count - 48)
            case .ee:
                symmetricState.absorbKey(e * re)
            case .es:
                if role == .initiator {
                    symmetricState.absorbKey(e * rs)
                } else {
                    symmetricState.absorbKey(s * re)
                }
            case .se:
                if role == .initiator {
                    symmetricState.absorbKey(s * re)
                } else {
                    symmetricState.absorbKey(e * rs)
                }
            case .ss:
                symmetricState.absorbKey(s * rs)
            }
        }
        
        if !input.isEmpty {
            symmetricState.decrypt(input, to: &payload)
        }
        
        nextOperation = .write
    }
    
    public mutating func finalize() -> [UInt8] {
        precondition(!finished)
        precondition(messagePatterns.isEmpty)
        
        finished = true
        let key = symmetricState.squeeze(32)
        symmetricState.ratchet()
        return key
    }
}

extension Handshake {
    public mutating func write<M>(to output: inout M) where M: MutableDataProtocol {
        write(payload: [], to: &output)
    }
    
    public mutating func write<D>(payload: D) -> [UInt8] where D: DataProtocol {
        var output = [UInt8]()
        write(payload: payload, to: &output)
        return output
    }
    
    public mutating func write() -> [UInt8] {
        var output = [UInt8]()
        write(payload: [], to: &output)
        return output
    }
    
    @discardableResult
    public mutating func read<D>(_ input: D) -> [UInt8] where D: DataProtocol {
        var payload = [UInt8]()
        read(input, to: &payload)
        return payload
    }
}

extension SymmetricStateProtocol {
    fileprivate mutating func absorb(_ input: SecretKey?) {
        absorb(input!.publicKey.rawRepresentation)
    }
    
    fileprivate mutating func absorb(_ input: PublicKey?) {
        absorb(input!.rawRepresentation)
    }
    
    fileprivate mutating func encrypt<M>(_ input: SecretKey?, to output: inout M) where M: MutableDataProtocol {
        encrypt(input!.publicKey.rawRepresentation, to: &output)
    }
    
    fileprivate mutating func decrypt<D>(_ input: D) -> PublicKey where D: DataProtocol {
        precondition(input.count >= 48)
        return PublicKey(rawRepresentation: decrypt(input.prefix(48)))
    }
}

extension MutableDataProtocol {
    fileprivate mutating func append(_ input: SecretKey?) {
        append(contentsOf: input!.publicKey.rawRepresentation)
    }
}
