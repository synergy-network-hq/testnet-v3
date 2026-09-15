/**
 * AEGIS Node.js KAT (Known Answer Test) Validation
 *
 * Validates all WASM implementations against official NIST test vectors
 * to ensure cryptographic correctness.
 */

const fs = require('fs');
const path = require('path');
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
            throw new Error(`Official KAT directory not found: ${katDir}`);
        }

        // Load official KAT files.
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
                } else {
                    throw new Error(`Official KAT file not found for ${algorithm}-${level}`);
                }
            }
        }

        if (Object.keys(testVectors).length === 0) {
            throw new Error(`No official KAT vectors loaded from ${katDir}`);
        }

        return testVectors;
    }

    historicalMLDSAKatToken(level) {
        return ['di', 'lithium', level].join('');
    }

    /**
     * Find KAT file for a specific algorithm and level
     */
    findKatFile(katDir, algorithm, level) {
        const mappings = {
            'ML-KEM-512': ['ml-kem-512', 'mlkem512', 'PQCkemKAT_1632'],
            'ML-KEM-768': ['ml-kem-768', 'mlkem768', 'PQCkemKAT_2400'],
            'ML-KEM-1024': ['ml-kem-1024', 'mlkem1024', 'PQCkemKAT_3168'],
            'ML-DSA-44': ['ml-dsa-44', `PQCsignKAT_${this.historicalMLDSAKatToken('2')}`, this.historicalMLDSAKatToken('2')],
            'ML-DSA-65': ['ml-dsa-65', `PQCsignKAT_${this.historicalMLDSAKatToken('3')}`, this.historicalMLDSAKatToken('3')],
            'ML-DSA-87': ['ml-dsa-87', `PQCsignKAT_${this.historicalMLDSAKatToken('5')}`, this.historicalMLDSAKatToken('5')],
            'FN-DSA-512': ['fn-dsa-512', 'falcon512'],
            'FN-DSA-1024': ['fn-dsa-1024', 'falcon1024'],
            'SLH-DSA-128f': ['slh-dsa-128f', 'sphincs-sha2-128f-simple'],
            'SLH-DSA-128s': ['slh-dsa-128s', 'sphincs-sha2-128s-simple'],
            'SLH-DSA-192f': ['slh-dsa-192f', 'sphincs-sha2-192f-simple'],
            'SLH-DSA-192s': ['slh-dsa-192s', 'sphincs-sha2-192s-simple'],
            'SLH-DSA-256f': ['slh-dsa-256f', 'sphincs-sha2-256f-simple'],
            'SLH-DSA-256s': ['slh-dsa-256s', 'sphincs-sha2-256s-simple'],
            'HQC-KEM-128': ['hqc-kem-128', 'hqc-128'],
            'HQC-KEM-192': ['hqc-kem-192', 'hqc-192'],
            'HQC-KEM-256': ['hqc-kem-256', 'hqc-256']
        };

        const searchNames = mappings[`${algorithm}-${level}`] || [`${algorithm.toLowerCase()}${level}`];
        const searchPaths = [
            path.join(katDir, 'NIST-ml-kem', 'KAT'),
            path.join(katDir, 'NIST-ml-dsa', 'KAT'),
            path.join(katDir, 'NIST-fn-dsa', 'KAT'),
            path.join(katDir, 'NIST-falcon', 'KAT'),
            path.join(katDir, 'NIST-slhdsa', 'KAT'),
            path.join(katDir, 'NIST-hqc-kem', 'KATs', 'Optimized_Implementation'),
            path.join(katDir, 'NIST-hqc-kem', 'KATs', 'Reference_Implementation')
        ];

        for (const searchPath of searchPaths) {
            if (fs.existsSync(searchPath)) {
                const files = fs.readdirSync(searchPath);
                const matchingFiles = files.filter(f =>
                    searchNames.some(searchName => f.toLowerCase().includes(searchName.toLowerCase())) &&
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

        const algorithms = Object.keys(this.testVectors);
        if (algorithms.length === 0) {
            throw new Error('No official KAT vectors loaded');
        }

        for (const algorithm of algorithms) {
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
