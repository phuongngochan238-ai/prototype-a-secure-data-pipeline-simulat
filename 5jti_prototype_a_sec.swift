//
//  5jti_prototype_a_sec.swift
//  Secure Data Pipeline Simulator
//

import Foundation
import CryptoKit

// MARK: - Data Pipeline Components

struct Source {
    let data: Data
    let encryptionKey: SymmetricKey
}

struct Processor {
    let encryptionKey: SymmetricKey
    let decryptionKey: SymmetricKey
    let integrityCheckKey: SymmetricKey
    
    func process(_ data: Data) -> Data? {
        // Encrypt data
        guard let encryptedData = encrypt(data) else { return nil }
        
        // Compute digital signature
        let signature = computeSignature(encryptedData)
        
        // Return encrypted data with digital signature
        return encryptedData + signature
    }
    
    private func encrypt(_ data: Data) -> Data? {
        // Use the encryption key to encrypt the data
        return try? ChaChaPoly.encrypt(data, using: encryptionKey)
    }
    
    private func computeSignature(_ data: Data) -> Data {
        // Compute the digital signature using the integrity check key
        return try! HMACSHA256.authenticate(data, using: integrityCheckKey)
    }
}

struct Sink {
    let decryptionKey: SymmetricKey
    let integrityCheckKey: SymmetricKey
    
    func receive(_ data: Data) -> Data? {
        // Separate encrypted data and digital signature
        guard let (encryptedData, signature) = separateDataAndSignature(data) else { return nil }
        
        // Verify digital signature
        guard verifySignature(encryptedData, signature) else { return nil }
        
        // Decrypt data
        return decrypt(encryptedData)
    }
    
    private func separateDataAndSignature(_ data: Data) -> (Data, Data)? {
        // Separate the encrypted data and digital signature
        let signatureSize = 32 // SHA256 signature size
        guard data.count > signatureSize else { return nil }
        let encryptedData = data.dropLast(signatureSize)
        let signature = data.suffix(signatureSize)
        return (Data(encryptedData), signature)
    }
    
    private func verifySignature(_ data: Data, _ signature: Data) -> Bool {
        // Verify the digital signature using the integrity check key
        return try! HMACSHA256.verify(data, using: integrityCheckKey, authenticator: signature)
    }
    
    private func decrypt(_ data: Data) -> Data? {
        // Use the decryption key to decrypt the data
        return try? ChaChaPoly.decrypt(data, using: decryptionKey)
    }
}

// MARK: - Simulator

class SecureDataPipelineSimulator {
    let source: Source
    let processor: Processor
    let sink: Sink
    
    init(source: Source, processor: Processor, sink: Sink) {
        self.source = source
        self.processor = processor
        self.sink = sink
    }
    
    func simulate() -> Data? {
        // Get data from source
        let data = source.data
        
        // Process data
        guard let processedData = processor.process(data) else { return nil }
        
        // Receive data at sink
        return sink.receive(processedData)
    }
}

// MARK: - Example Usage

let encryptionKey = SymmetricKey(size: .bits256)
let decryptionKey = encryptionKey
let integrityCheckKey = SymmetricKey(size: .bits256)

let source = Source(data: Data("Hello, World!".utf8), encryptionKey: encryptionKey)
let processor = Processor(encryptionKey: encryptionKey, decryptionKey: decryptionKey, integrityCheckKey: integrityCheckKey)
let sink = Sink(decryptionKey: decryptionKey, integrityCheckKey: integrityCheckKey)

let simulator = SecureDataPipelineSimulator(source: source, processor: processor, sink: sink)

if let result = simulator.simulate() {
    print("Secure data transmission successful: \(String(data: result, encoding: .utf8)!)")
} else {
    print("Secure data transmission failed")
}