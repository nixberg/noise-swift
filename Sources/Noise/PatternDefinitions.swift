enum PreMessageToken {
    case e
    case s
    case none
}

enum Token {
    case e
    case s
    case ee
    case es
    case se
    case ss
}

struct PatternDefinition {
    let name: String
    let preMessagePatterns: (
        initiator: PreMessageToken,
        responder: PreMessageToken
    )
    let messagePatterns: [[Token]]
    
    init(_ name: String, _ preMessagePatterns: (PreMessageToken, PreMessageToken), _ messagePatterns: [[Token]]) {
        self.name = name
        self.preMessagePatterns = preMessagePatterns
        self.messagePatterns = messagePatterns
    }
}

public enum Pattern {
    case N
    case K
    case X
    
    case NN
    case NK
    case NX
    
    case KN
    case KK
    case KX
    
    case XN
    case XK
    case XX
    
    case IK
}

let patternDefinitions: [Pattern: PatternDefinition] = [
    .N: PatternDefinition("N", (.none, .s), [
        [.e, .es],
    ]),
    
    .K: PatternDefinition("K", (.s, .s), [
        [.e, .es, .ss],
    ]),
    
    .X: PatternDefinition("X", (.none, .s), [
        [.e, .es, .s, .ss],
    ]),
    
    .NN: PatternDefinition("NN", (.none, .none), [
        [.e],
        [.e, .ee]
    ]),
    
    .NK: PatternDefinition("NK", (.none, .s), [
        [.e, .es],
        [.e, .ee]
    ]),
    
    .NX: PatternDefinition("NX", (.none, .none), [
        [.e],
        [.e, .ee, .s, .es]
    ]),
    
    .KN: PatternDefinition("KN", (.s, .none), [
        [.e],
        [.e, .ee, .se]
    ]),
    
    .KK: PatternDefinition("KK", (.s, .s), [
        [.e, .es, .ss],
        [.e, .ee, .se]
    ]),
    
    .KX: PatternDefinition("KX", (.s, .none), [
        [.e],
        [.e, .ee, .se, .s, .es]
    ]),
    
    .XN: PatternDefinition("XN", (.none, .none), [
        [.e],
        [.e, .ee],
        [.s, .se]
    ]),
    
    .XK: PatternDefinition("XK", (.none, .s), [
        [.e, .es],
        [.e, .ee],
        [.s, .se]
    ]),
    
    .XX: PatternDefinition("XX", (.none, .none), [
        [.e],
        [.e, .ee, .s, .es],
        [.s, .se]
    ]),
    
    .IK: PatternDefinition("IK", (.none, .s), [
        [.e, .es, .s, .ss],
        [.e, .ee, .se],
    ]),
]
