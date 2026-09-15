/**
 * AEGIS Node.js KAT (Known Answer Test) Validation
 *
 * Validates all WASM implementations against official NIST test vectors
 * to ensure cryptographic correctness.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AEGIS = require('../index.js');

class KATValidator {
    constructor() {
        this.aegis = new AEGIS();
        this.katResults = {
            passed: 0,
            failed: 0,
            total: 0
        };
        this.testVectors = this.loadTestVectors();
    }

    /**
     * Load test vectors from the pqkat directory
     */
    loadTestVectors() {
        const katDir = path.join(__dirname, '../../pqkat');
        const testVectors = {};

        if (!fs.existsSync(katDir)) {
            console.warn('KAT directory not found, using synthetic test vectors');
            return this.generateSyntheticTestVectors();
        }

        // Load actual KAT files
        const algorithms = ['ML-KEM', 'ML-DSA', 'FN-DSA', 'SLH-DSA', 'HQC-KEM'];
        const levels = {
            'ML-KEM': ['512', '768', '1024'],
            'ML-DSA': ['44', '65', '87'],
            'FN-DSA': ['512', '1024'],
            'SLH-DSA': ['128f', '128s', '192f', '192s', '256f', '256s'],
            'HQC-KEM': ['128', '192', '256']
        };

        for (const algorithm of algorithms) {
            for (const level of levels[algorithm] || []) {
                const katFile = this.findKatFile(katDir, algorithm, level);
                if (katFile && fs.existsSync(katFile)) {
                    testVectors[`${algorithm}-${level}`] = this.parseKatFile(katFile);
                }
            }
        }

        return testVectors;
    }

    /**
     * Find KAT file for a specific algorithm and level
     */
    findKatFile(katDir, algorithm, level) {
        const mappings = {
            'ML-KEM-512': 'mlkem512',
            'ML-KEM-768': 'mlkem768',
            'ML-KEM-1024': 'mlkem1024',
            'ML-DSA-44': 'dilithium2',
            'ML-DSA-65': 'dilithium3',
            'ML-DSA-87': 'dilithium5',
            'FN-DSA-512': 'falcon512',
            'FN-DSA-1024': 'falcon1024',
            'SLH-DSA-128f': 'sphincs-sha2-128f-simple',
            'SLH-DSA-128s': 'sphincs-sha2-128s-simple',
            'SLH-DSA-192f': 'sphincs-sha2-192f-simple',
            'SLH-DSA-192s': 'sphincs-sha2-192s-simple',
            'SLH-DSA-256f': 'sphincs-sha2-256f-simple',
            'SLH-DSA-256s': 'sphincs-sha2-256s-simple',
            'HQC-KEM-128': 'hqc-128',
            'HQC-KEM-192': 'hqc-192',
            'HQC-KEM-256': 'hqc-256'
        };

        const searchName = mappings[`${algorithm}-${level}`] || `${algorithm.toLowerCase()}${level}`;
        const searchPaths = [
            path.join(katDir, 'NIST-ml-kem', 'KAT'),
            path.join(katDir, 'NIST-ml-dsa', 'KAT'),
            path.join(katDir, 'NIST-falcon', 'KAT'),
            path.join(katDir, 'NIST-slhdsa', 'KAT'),
            path.join(katDir, 'NIST-hqc-kem', 'KATs', 'Optimized_Implementation'),
            path.join(katDir, 'NIST-hqc-kem', 'KATs', 'Reference_Implementation')
        ];

        for (const searchPath of searchPaths) {
            if (fs.existsSync(searchPath)) {
                const files = fs.readdirSync(searchPath);
                const matchingFiles = files.filter(f =>
                    f.toLowerCase().includes(searchName.toLowerCase()) &&
                    (f.endsWith('.req') || f.endsWith('.rsp'))
                );

                for (const file of matchingFiles) {
                    return path.join(searchPath, file);
                }
            }
        }

        return null;
    }

    /**
     * Parse KAT file into structured test vectors
     */
    parseKatFile(filePath) {
        if (!fs.existsSync(filePath)) {
            return [];
        }

        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n').map(line => line.trim()).filter(line => line);
        const testVectors = [];

        let currentVector = {};
        for (const line of lines) {
            if (line.startsWith('#')) continue;
            if (line.startsWith('count')) {
                if (Object.keys(currentVector).length > 0) {
                    testVectors.push(currentVector);
                }
                currentVector = { count: parseInt(line.split('=')[1].trim()) };
            } else if (line.includes('=')) {
                const [key, value] = line.split('=').map(s => s.trim());
                if (key && value) {
                    currentVector[key] = value;
                }
            }
        }

        if (Object.keys(currentVector).length > 0) {
            testVectors.push(currentVector);
        }

        return testVectors;
    }

    /**
     * Generate synthetic test vectors when KAT files are not available
     */
    generateSyntheticTestVectors() {
        const vectors = {};

        // Generate test vectors for each algorithm
        const algorithms = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024',
                           'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
                           'FN-DSA-512', 'FN-DSA-1024',
                           'SLH-DSA-128f', 'SLH-DSA-128s', 'SLH-DSA-192f', 'SLH-DSA-192s', 'SLH-DSA-256f', 'SLH-DSA-256s',
                           'HQC-KEM-128', 'HQC-KEM-192', 'HQC-KEM-256'];

        for (const algorithm of algorithms) {
            vectors[algorithm] = this.generateTestVectorsForAlgorithm(algorithm);
        }

        return vectors;
    }

    /**
     * Generate synthetic test vectors for a specific algorithm
     */
    generateTestVectorsForAlgorithm(algorithm) {
        const vectors = [];
        const numVectors = 10;

        for (let i = 0; i < numVectors; i++) {
            const vector = {
                count: i,
                seed: crypto.randomBytes(32).toString('hex'),
                message: crypto.randomBytes(32).toString('hex')
            };

            // Generate synthetic cryptographic outputs
            vector.pk = crypto.randomBytes(this.getKeySize(algorithm, 'public')).toString('hex');
            vector.sk = crypto.randomBytes(this.getKeySize(algorithm, 'secret')).toString('hex');

            if (algorithm.startsWith('ML-KEM') || algorithm.startsWith('HQC-KEM')) {
                vector.ct = crypto.randomBytes(this.getCiphertextSize(algorithm)).toString('hex');
                vector.ss = crypto.randomBytes(32).toString('hex');
            } else {
                vector.signature = crypto.randomBytes(this.getSignatureSize(algorithm)).toString('hex');
            }

            vectors.push(vector);
        }

        return vectors;
    }

    /**
     * Get public key size for algorithm
     */
    getKeySize(algorithm, keyType) {
        const sizes = {
            'ML-KEM-512': { public: 800, secret: 1632 },
            'ML-KEM-768': { public: 1184, secret: 2400 },
            'ML-KEM-1024': { public: 1568, secret: 3168 },
            'ML-DSA-44': { public: 1312, secret: 2560 },
            'ML-DSA-65': { public: 1952, secret: 4032 },
            'ML-DSA-87': { public: 2592, secret: 4896 },
            'FN-DSA-512': { public: 897, secret: 1281 },
            'FN-DSA-1024': { public: 1793, secret: 2305 },
            'SLH-DSA-128f': { public: 32, secret: 64 },
            'SLH-DSA-128s': { public: 32, secret: 64 },
            'SLH-DSA-192f': { public: 48, secret: 96 },
            'SLH-DSA-192s': { public: 48, secret: 96 },
            'SLH-DSA-256f': { public: 64, secret: 128 },
            'SLH-DSA-256s': { public: 64, secret: 128 },
            'HQC-KEM-128': { public: 2249, secret: 2305 },
            'HQC-KEM-192': { public: 4522, secret: 4586 },
            'HQC-KEM-256': { public: 7245, secret: 7317 }
        };

        return sizes[algorithm]?.[keyType] || 32;
    }

    /**
     * Get ciphertext size for KEM algorithms
     */
    getCiphertextSize(algorithm) {
        const sizes = {
            'ML-KEM-512': 768,
            'ML-KEM-768': 1088,
            'ML-KEM-1024': 1568,
            'HQC-KEM-128': 4433,
            'HQC-KEM-192': 8978,
            'HQC-KEM-256': 14421
        };

        return sizes[algorithm] || 768;
    }

    /**
     * Get signature size for signature algorithms
     */
    getSignatureSize(algorithm) {
        const sizes = {
            'ML-DSA-44': 2420,
            'ML-DSA-65': 3309,
            'ML-DSA-87': 4627,
            'FN-DSA-512': 752,
            'FN-DSA-1024': 1462,
            'SLH-DSA-128f': 17088,
            'SLH-DSA-128s': 7856,
            'SLH-DSA-192f': 35664,
            'SLH-DSA-192s': 16224,
            'SLH-DSA-256f': 49856,
            'SLH-DSA-256s': 29792
        };

        return sizes[algorithm] || 64;
    }

    /**
     * Run KAT tests for all algorithms
     */
    async runAllKatTests() {
        console.log('🔬 Running AEGIS Node.js KAT (Known Answer Test) Validation\n');

        const results = {
            passed: 0,
            failed: 0,
            total: 0,
            byAlgorithm: {}
        };

        for (const algorithm of Object.keys(this.testVectors)) {
            console.log(`Testing ${algorithm}...`);
            const algorithmResults = await this.runKatTestsForAlgorithm(algorithm);
            results.byAlgorithm[algorithm] = algorithmResults;

            results.passed += algorithmResults.passed;
            results.failed += algorithmResults.failed;
            results.total += algorithmResults.total;

            const successRate = algorithmResults.total > 0 ?
                (algorithmResults.passed / algorithmResults.total * 100).toFixed(1) : 0;
            console.log(`  ${algorithm}: ${algorithmResults.passed}/${algorithmResults.total} passed (${successRate}%)`);
        }

        this.katResults = results;
        return results;
    }

    /**
     * Run KAT tests for a specific algorithm
     */
    async runKatTestsForAlgorithm(algorithm) {
        const vectors = this.testVectors[algorithm];
        if (!vectors || vectors.length === 0) {
            return { passed: 0, failed: 0, total: 0 };
        }

        let passed = 0;
        let failed = 0;

        for (let i = 0; i < Math.min(vectors.length, 10); i++) { // Test first 10 vectors for speed
            const vector = vectors[i];

            try {
                if (algorithm.startsWith('ML-KEM') || algorithm.startsWith('HQC-KEM')) {
                    const result = await this.testKemAlgorithm(algorithm, vector);
                    if (result) passed++;
                    else failed++;
                } else {
                    const result = await this.testSignatureAlgorithm(algorithm, vector);
                    if (result) passed++;
                    else failed++;
                }
            } catch (error) {
                console.error(`  Error testing ${algorithm} vector ${i}:`, error.message);
                failed++;
            }
        }

        return { passed, failed, total: passed + failed };
    }

    /**
     * Test KEM algorithm against KAT vector
     */
    async testKemAlgorithm(algorithm, vector) {
        try {
            // Generate keypair
            const keypair = await this.aegis.mlkemKeypair(algorithm);
            const pk = Buffer.from(vector.pk, 'hex');
            const sk = Buffer.from(vector.sk, 'hex');

            // Test encapsulation
            const encapsResult = await this.aegis.mlkemEncapsulate(pk, algorithm);
            const expectedCt = Buffer.from(vector.ct, 'hex');
            const expectedSs = Buffer.from(vector.ss, 'hex');

            if (!encapsResult.ciphertext.equals(expectedCt) ||
                !encapsResult.sharedSecret.equals(expectedSs)) {
                return false;
            }

            // Test decapsulation
            const decapsResult = await this.aegis.mlkemDecapsulate(sk, expectedCt, algorithm);
            if (!decapsResult.equals(expectedSs)) {
                return false;
            }

            return true;
        } catch (error) {
            console.error(`KEM test failed for ${algorithm}:`, error.message);
            return false;
        }
    }

    /**
     * Test signature algorithm against KAT vector
     */
    async testSignatureAlgorithm(algorithm, vector) {
        try {
            // Generate keypair
            let keypair;
            if (algorithm.startsWith('ML-DSA')) {
                keypair = await this.aegis.mldsaKeypair(algorithm);
            } else if (algorithm.startsWith('FN-DSA')) {
                keypair = await this.aegis.fndsaKeypair(algorithm);
            } else if (algorithm.startsWith('SLH-DSA')) {
                keypair = await this.aegis.slhdsaKeypair(algorithm);
            } else {
                return false; // Unknown algorithm
            }

            const pk = Buffer.from(vector.pk, 'hex');
            const sk = Buffer.from(vector.sk, 'hex');
            const message = Buffer.from(vector.message, 'hex');
            const expectedSignature = Buffer.from(vector.signature, 'hex');

            // Test signing
            let signature;
            if (algorithm.startsWith('ML-DSA')) {
                signature = await this.aegis.mldsaSign(message, sk, algorithm);
            } else if (algorithm.startsWith('FN-DSA')) {
                signature = await this.aegis.fndsaSign(message, sk, algorithm);
            } else if (algorithm.startsWith('SLH-DSA')) {
                signature = await this.aegis.slhdsaSign(message, sk, algorithm);
            }

            if (!signature.equals(expectedSignature)) {
                return false;
            }

            // Test verification
            let isValid;
            if (algorithm.startsWith('ML-DSA')) {
                isValid = await this.aegis.mldsaVerify(signature, message, pk, algorithm);
            } else if (algorithm.startsWith('FN-DSA')) {
                isValid = await this.aegis.fndsaVerify(signature, message, pk, algorithm);
            } else if (algorithm.startsWith('SLH-DSA')) {
                isValid = await this.aegis.slhdsaVerify(signature, message, pk, algorithm);
            }

            if (!isValid) {
                return false;
            }

            return true;
        } catch (error) {
            console.error(`Signature test failed for ${algorithm}:`, error.message);
            return false;
        }
    }

    /**
     * Print KAT test results summary
     */
    printResults() {
        console.log('\n📊 KAT Test Results Summary');
        console.log('=' * 50);

        const totalTests = this.katResults.total;
        const passedTests = this.katResults.passed;
        const failedTests = this.katResults.failed;
        const successRate = totalTests > 0 ? (passedTests / totalTests * 100).toFixed(1) : 0;

        console.log(`Total KAT Tests: ${totalTests}`);
        console.log(`Passed: ${passedTests}`);
        console.log(`Failed: ${failedTests}`);
        console.log(`Success Rate: ${successRate}%`);

        console.log('\nResults by Algorithm:');
        console.log('-' * 30);

        for (const [algorithm, results] of Object.entries(this.katResults.byAlgorithm)) {
            if (results.total > 0) {
                const algSuccessRate = (results.passed / results.total * 100).toFixed(1);
                const status = results.passed === results.total ? '✅ PASSED' : '❌ FAILED';
                console.log(`${algorithm}: ${results.passed}/${results.total} passed (${algSuccessRate}%) ${status}`);
            }
        }

        console.log('\n' + '=' * 50);
        console.log(`Overall KAT Validation: ${passedTests === totalTests ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);
    }

    /**
     * Get final results
     */
    getResults() {
        return this.katResults;
    }
}

// Run KAT tests if this file is executed directly
if (require.main === module) {
    async function main() {
        const validator = new KATValidator();
        await validator.runAllKatTests();
        validator.printResults();

        const results = validator.getResults();
        process.exit(results.passed === results.total ? 0 : 1);
    }

    main().catch(error => {
        console.error('KAT validation failed:', error);
        process.exit(1);
    });
}

module.exports = KATValidator;
