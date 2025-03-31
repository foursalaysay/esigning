const crypto = require('crypto');

class SequentialSigning {
    constructor(signatureQueue) {
        if (!Array.isArray(signatureQueue) || signatureQueue.length === 0) {
            throw new Error('Signature queue must be a non-empty array');
        }
        this.signatureQueue = signatureQueue;
        this.signatures = new Map();
        this.currentIndex = 0;
        this.documentId = crypto.randomBytes(16).toString('hex');
    }

    // Add a signature for a specific section
    addSignature(section, content, signature, signerId) {
        // Validate if this is the next section in queue
        if (section !== this.signatureQueue[this.currentIndex]) {
            throw new Error(`Cannot sign section "${section}". Next required section is "${this.signatureQueue[this.currentIndex]}"`);
        }

        // Store the signature with metadata
        this.signatures.set(section, {
            signature,
            signerId,
            content,
            timestamp: new Date().toISOString(),
            documentId: this.documentId
        });

        // Move to next section
        this.currentIndex++;

        return {
            success: true,
            message: `Successfully signed section "${section}"`,
            nextSection: this.getNextSection()
        };
    }

    // Get the next section that needs to be signed
    getNextSection() {
        return this.currentIndex < this.signatureQueue.length 
            ? this.signatureQueue[this.currentIndex] 
            : null;
    }

    // Check if all sections have been signed
    isComplete() {
        return this.currentIndex >= this.signatureQueue.length;
    }

    // Get the current status of all signatures
    getStatus() {
        return {
            isComplete: this.isComplete(),
            currentIndex: this.currentIndex,
            totalSections: this.signatureQueue.length,
            signatures: Object.fromEntries(this.signatures),
            nextSection: this.getNextSection(),
            documentId: this.documentId
        };
    }

    // Verify a single signature
    verifySignature(section, content, signature, publicKey) {
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(content);
        return verify.verify(publicKey, signature, 'base64');
    }

    // Verify all signatures
    verifySignatures(publicKeys) {
        if (!this.isComplete()) {
            return {
                isValid: false,
                message: 'Not all sections have been signed yet'
            };
        }

        let allSignaturesValid = true;
        const verificationResults = [];

        // Verify each signature
        for (const [section, signatureData] of this.signatures) {
            const publicKey = publicKeys[signatureData.signerId];
            if (!publicKey) {
                allSignaturesValid = false;
                verificationResults.push({
                    section,
                    isValid: false,
                    message: `No public key found for signer ${signatureData.signerId}`
                });
                continue;
            }

            const isValid = this.verifySignature(
                section,
                signatureData.content,
                signatureData.signature,
                publicKey
            );

            verificationResults.push({
                section,
                isValid,
                signerId: signatureData.signerId,
                timestamp: signatureData.timestamp
            });

            if (!isValid) {
                allSignaturesValid = false;
            }
        }

        return {
            isValid: allSignaturesValid,
            message: allSignaturesValid 
                ? 'All signatures are cryptographically valid' 
                : 'Some signatures are invalid or have been tampered with',
            documentId: this.documentId,
            verificationResults
        };
    }
}

module.exports = SequentialSigning;
