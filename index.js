const crypto = require('crypto');

class SequentialSigning {
    constructor(signatureQueue) {
        if (!Array.isArray(signatureQueue) || signatureQueue.length === 0) {
            throw new Error('Signature queue must be a non-empty array');
        }
        this.signatureQueue = signatureQueue;
        this.signatures = new Map();
        this.currentIndex = 0;
    }

    // Add a signature for a specific section
    addSignature(section, signature, signer) {
        // Validate if this is the next section in queue
        if (section !== this.signatureQueue[this.currentIndex]) {
            throw new Error(`Cannot sign section "${section}". Next required section is "${this.signatureQueue[this.currentIndex]}"`);
        }

        // Validate signature format (you might want to add more validation)
        if (!signature || typeof signature !== 'string') {
            throw new Error('Invalid signature format');
        }

        // Store the signature
        this.signatures.set(section, {
            signature,
            signer,
            timestamp: new Date().toISOString()
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
            nextSection: this.getNextSection()
        };
    }

    // Verify all signatures (you might want to add more verification logic)
    verifySignatures() {
        if (!this.isComplete()) {
            return {
                isValid: false,
                message: 'Not all sections have been signed yet'
            };
        }

        // Here you would typically implement your signature verification logic
        // This is just a basic example
        const allSignaturesPresent = this.signatureQueue.every(section => 
            this.signatures.has(section)
        );

        return {
            isValid: allSignaturesPresent,
            message: allSignaturesPresent 
                ? 'All signatures are present and valid' 
                : 'Some signatures are missing or invalid'
        };
    }
}

module.exports = SequentialSigning;
