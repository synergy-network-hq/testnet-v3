/**
 * AEGIS Node.js Comprehensive Test Suite
 *
 * Tests all algorithms and implementations to ensure they work correctly
 */

const AEGIS = require('../index.js');

class ComprehensiveTestSuite {
    constructor() {
        this.aegis = new AEGIS();
        this.testResults = {
            passed: 0,
            failed: 0,
            total: 0,
            byAlgorithm: {}
        };
    }

    /**
     * Run all tests
     */
    async runAllTests() {
        console.log('🔬 Running AEGIS Node.js Comprehensive Test Suite\n');

        // Test ML-KEM algorithms
        await this.testMLKEM();

        // Test ML-DSA algorithms
        await this.testMLDSA();

        // Test FN-DSA algorithms
        await this.testFNDSA();

        // Test SLH-DSA algorithms
        await this.testSLHDSA();

        // Test HQC-KEM algorithms
        await this.testHQCKEM();

        this.printResults();
        return this.testResults;
    }

    /**
     * Test ML-KEM algorithms
     */
    async testMLKEM() {
        console.log('Testing ML-KEM algorithms...');

        const algorithms = ['MLKEM512', 'MLKEM768', 'MLKEM1024'];
        const results = { passed: 0, failed: 0, total: 0 };

        for (const algorithm of algorithms) {
            try {
                // Test keypair generation
                const keypair = await this.aegis.mlkemKeypair(algorithm);
                if (!keypair.publicKey || !keypair.secretKey) {
                    throw new Error('Invalid keypair');
                }

                // Test encapsulation
                const encapsResult = await this.aegis.mlkemEncapsulate(keypair.publicKey, algorithm);
                if (!encapsResult.ciphertext || !encapsResult.sharedSecret) {
                    throw new Error('Invalid encapsulation result');
                }

                // Test decapsulation
                const decapsResult = await this.aegis.mlkemDecapsulate(keypair.secretKey, encapsResult.ciphertext, algorithm);
                if (!decapsResult.equals(encapsResult.sharedSecret)) {
                    throw new Error('Shared secrets do not match');
                }

                console.log(`  ✅ ${algorithm}: All tests passed`);
                results.passed++;
            } catch (error) {
                console.log(`  ❌ ${algorithm}: ${error.message}`);
                results.failed++;
            }
            results.total++;
        }

        this.testResults.byAlgorithm['ML-KEM'] = results;
    }

    /**
     * Test ML-DSA (Dilithium) algorithms
     */
    async testMLDSA() {
        console.log('Testing ML-DSA algorithms...');

        const algorithms = ['MLDSA44', 'MLDSA65', 'MLDSA87'];
        const results = { passed: 0, failed: 0, total: 0 };

        for (const algorithm of algorithms) {
            try {
                // Test keypair generation
                const keypair = await this.aegis.mldsaKeypair(algorithm);
                if (!keypair.publicKey || !keypair.secretKey) {
                    throw new Error('Invalid keypair');
                }

                // Test signing
                const message = Buffer.from('Hello, AEGIS Node.js test!');
                const signature = await this.aegis.mldsaSign(message, keypair.secretKey, algorithm);
                if (!signature || signature.length === 0) {
                    throw new Error('Invalid signature');
                }

                // Test verification
                const isValid = await this.aegis.mldsaVerify(signature, message, keypair.publicKey, algorithm);
                if (!isValid) {
                    throw new Error('Signature verification failed');
                }

                // Test with wrong message (should fail)
                const wrongMessage = Buffer.from('Wrong message');
                const isInvalid = await this.aegis.mldsaVerify(signature, wrongMessage, keypair.publicKey, algorithm);
                if (isInvalid) {
                    throw new Error('Wrong message was accepted');
                }

                console.log(`  ✅ ${algorithm}: All tests passed`);
                results.passed++;
            } catch (error) {
                console.log(`  ❌ ${algorithm}: ${error.message}`);
                results.failed++;
            }
            results.total++;
        }

        this.testResults.byAlgorithm['ML-DSA'] = results;
    }

    /**
     * Test FN-DSA (Falcon) algorithms
     */
    async testFNDSA() {
        console.log('Testing FN-DSA algorithms...');

        const algorithms = ['FNDSA512', 'FNDSA1024'];
        const results = { passed: 0, failed: 0, total: 0 };

        for (const algorithm of algorithms) {
            try {
                // Test keypair generation
                const keypair = await this.aegis.fndsaKeypair(algorithm);
                if (!keypair.publicKey || !keypair.secretKey) {
                    throw new Error('Invalid keypair');
                }

                // Test signing
                const message = Buffer.from('Hello, AEGIS Node.js test!');
                const signature = await this.aegis.fndsaSign(message, keypair.secretKey, algorithm);
                if (!signature || signature.length === 0) {
                    throw new Error('Invalid signature');
                }

                // Test verification
                const isValid = await this.aegis.fndsaVerify(signature, message, keypair.publicKey, algorithm);
                if (!isValid) {
                    throw new Error('Signature verification failed');
                }

                // Test with wrong message (should fail)
                const wrongMessage = Buffer.from('Wrong message');
                const isInvalid = await this.aegis.fndsaVerify(signature, wrongMessage, keypair.publicKey, algorithm);
                if (isInvalid) {
                    throw new Error('Wrong message was accepted');
                }

                console.log(`  ✅ ${algorithm}: All tests passed`);
                results.passed++;
            } catch (error) {
                console.log(`  ❌ ${algorithm}: ${error.message}`);
                results.failed++;
            }
            results.total++;
        }

        this.testResults.byAlgorithm['FN-DSA'] = results;
    }

    /**
     * Test SLH-DSA (SPHINCS+) algorithms
     */
    async testSLHDSA() {
        console.log('Testing SLH-DSA algorithms...');

        const algorithms = [
            'SLHDSA_SHA2_128F_SIMPLE', 'SLHDSA_SHA2_128S_SIMPLE',
            'SLHDSA_SHA2_192F_SIMPLE', 'SLHDSA_SHA2_192S_SIMPLE',
            'SLHDSA_SHA2_256F_SIMPLE', 'SLHDSA_SHA2_256S_SIMPLE'
        ];
        const results = { passed: 0, failed: 0, total: 0 };

        for (const algorithm of algorithms) {
            try {
                // Test keypair generation
                const keypair = await this.aegis.slhdsaKeypair(algorithm);
                if (!keypair.publicKey || !keypair.secretKey) {
                    throw new Error('Invalid keypair');
                }

                // Test signing
                const message = Buffer.from('Hello, AEGIS Node.js test!');
                const signature = await this.aegis.slhdsaSign(message, keypair.secretKey, algorithm);
                if (!signature || signature.length === 0) {
                    throw new Error('Invalid signature');
                }

                // Test verification
                const isValid = await this.aegis.slhdsaVerify(signature, message, keypair.publicKey, algorithm);
                if (!isValid) {
                    throw new Error('Signature verification failed');
                }

                // Test with wrong message (should fail)
                const wrongMessage = Buffer.from('Wrong message');
                const isInvalid = await this.aegis.slhdsaVerify(signature, wrongMessage, keypair.publicKey, algorithm);
                if (isInvalid) {
                    throw new Error('Wrong message was accepted');
                }

                console.log(`  ✅ ${algorithm}: All tests passed`);
                results.passed++;
            } catch (error) {
                console.log(`  ❌ ${algorithm}: ${error.message}`);
                results.failed++;
            }
            results.total++;
        }

        this.testResults.byAlgorithm['SLH-DSA'] = results;
    }

    /**
     * Test HQC-KEM algorithms
     */
    async testHQCKEM() {
        console.log('Testing HQC-KEM algorithms...');

        const algorithms = ['HQCKEM128', 'HQCKEM192', 'HQCKEM256'];
        const results = { passed: 0, failed: 0, total: 0 };

        for (const algorithm of algorithms) {
            try {
                // Test keypair generation
                const keypair = await this.aegis.hqcKeypair(algorithm);
                if (!keypair.publicKey || !keypair.secretKey) {
                    throw new Error('Invalid keypair');
                }

                // Test encapsulation
                const encapsResult = await this.aegis.hqcEncapsulate(keypair.publicKey, algorithm);
                if (!encapsResult.ciphertext || !encapsResult.sharedSecret) {
                    throw new Error('Invalid encapsulation result');
                }

                // Test decapsulation
                const decapsResult = await this.aegis.hqcDecapsulate(keypair.secretKey, encapsResult.ciphertext, algorithm);
                if (!decapsResult.equals(encapsResult.sharedSecret)) {
                    throw new Error('Shared secrets do not match');
                }

                console.log(`  ✅ ${algorithm}: All tests passed`);
                results.passed++;
            } catch (error) {
                console.log(`  ❌ ${algorithm}: ${error.message}`);
                results.failed++;
            }
            results.total++;
        }

        this.testResults.byAlgorithm['HQC-KEM'] = results;
    }

    /**
     * Print test results summary
     */
    printResults() {
        console.log('\n📊 Test Results Summary');
        console.log('=' * 50);

        const totalTests = this.testResults.total;
        const passedTests = this.testResults.passed;
        const failedTests = this.testResults.failed;
        const successRate = totalTests > 0 ? (passedTests / totalTests * 100).toFixed(1) : 0;

        console.log(`Total Tests: ${totalTests}`);
        console.log(`Passed: ${passedTests}`);
        console.log(`Failed: ${failedTests}`);
        console.log(`Success Rate: ${successRate}%`);

        console.log('\nResults by Algorithm:');
        console.log('-' * 30);

        for (const [algorithm, results] of Object.entries(this.testResults.byAlgorithm)) {
            if (results.total > 0) {
                const algSuccessRate = (results.passed / results.total * 100).toFixed(1);
                const status = results.passed === results.total ? '✅ PASSED' : '❌ FAILED';
                console.log(`${algorithm}: ${results.passed}/${results.total} passed (${algSuccessRate}%) ${status}`);
            }
        }

        console.log('\n' + '=' * 50);
        console.log(`Overall Test Result: ${passedTests === totalTests ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);

        this.testResults.passed = passedTests;
        this.testResults.failed = failedTests;
        this.testResults.total = totalTests;
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    async function main() {
        const testSuite = new ComprehensiveTestSuite();
        const results = await testSuite.runAllTests();
        process.exit(results.passed === results.total ? 0 : 1);
    }

    main().catch(error => {
        console.error('Test suite failed:', error);
        process.exit(1);
    });
}

module.exports = ComprehensiveTestSuite;
