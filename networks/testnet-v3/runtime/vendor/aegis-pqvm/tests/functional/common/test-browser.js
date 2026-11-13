/**
 * AEGIS Browser WASM Comprehensive Test Suite
 *
 * Tests all algorithms and implementations in the browser environment
 */

class BrowserTestSuite {
    constructor() {
        this.aegis = null;
        this.testResults = {
            passed: 0,
            failed: 0,
            total: 0,
            byAlgorithm: {}
        };
        this.isRunning = false;
    }

    /**
     * Initialize the test suite
     */
    async initialize() {
        if (this.aegis) return;

        // Load the AEGIS browser script
        await this.loadScript('aegis-browser.js');
        this.aegis = new AEGIS();
        await this.aegis.initialize();
    }

    /**
     * Load a JavaScript file dynamically
     */
    loadScript(src) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            script.src = src;
            script.onload = resolve;
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    /**
     * Run all tests
     */
    async runAllTests() {
        if (this.isRunning) {
            throw new Error('Tests are already running');
        }

        this.isRunning = true;
        this.testResults = { passed: 0, failed: 0, total: 0, byAlgorithm: {} };

        console.log('🔬 Starting AEGIS Browser WASM Test Suite...');

        try {
            await this.initialize();

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
        } catch (error) {
            console.error('Test suite failed:', error);
            throw error;
        } finally {
            this.isRunning = false;
        }
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
                await this.testKEMAlgorithm(algorithm);
                results.passed++;
                this.testResults.passed++;
            } catch (error) {
                console.error(`${algorithm} failed:`, error);
                results.failed++;
                this.testResults.failed++;
            }
            results.total++;
            this.testResults.total++;
        }

        this.testResults.byAlgorithm['ML-KEM'] = results;
        console.log(`ML-KEM: ${results.passed}/${results.total} passed`);
    }

    /**
     * Test ML-DSA algorithms
     */
    async testMLDSA() {
        console.log('Testing ML-DSA algorithms...');

        const algorithms = ['MLDSA44', 'MLDSA65', 'MLDSA87'];
        const results = { passed: 0, failed: 0, total: 0 };

        for (const algorithm of algorithms) {
            try {
                await this.testSignatureAlgorithm(algorithm, 'mldsa');
                results.passed++;
                this.testResults.passed++;
            } catch (error) {
                console.error(`${algorithm} failed:`, error);
                results.failed++;
                this.testResults.failed++;
            }
            results.total++;
            this.testResults.total++;
        }

        this.testResults.byAlgorithm['ML-DSA'] = results;
        console.log(`ML-DSA: ${results.passed}/${results.total} passed`);
    }

    /**
     * Test FN-DSA algorithms
     */
    async testFNDSA() {
        console.log('Testing FN-DSA algorithms...');

        const algorithms = ['FNDSA512', 'FNDSA1024'];
        const results = { passed: 0, failed: 0, total: 0 };

        for (const algorithm of algorithms) {
            try {
                await this.testSignatureAlgorithm(algorithm, 'fndsa');
                results.passed++;
                this.testResults.passed++;
            } catch (error) {
                console.error(`${algorithm} failed:`, error);
                results.failed++;
                this.testResults.failed++;
            }
            results.total++;
            this.testResults.total++;
        }

        this.testResults.byAlgorithm['FN-DSA'] = results;
        console.log(`FN-DSA: ${results.passed}/${results.total} passed`);
    }

    /**
     * Test SLH-DSA algorithms
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
                await this.testSignatureAlgorithm(algorithm, 'slhdsa');
                results.passed++;
                this.testResults.passed++;
            } catch (error) {
                console.error(`${algorithm} failed:`, error);
                results.failed++;
                this.testResults.failed++;
            }
            results.total++;
            this.testResults.total++;
        }

        this.testResults.byAlgorithm['SLH-DSA'] = results;
        console.log(`SLH-DSA: ${results.passed}/${results.total} passed`);
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
                await this.testKEMAlgorithm(algorithm);
                results.passed++;
                this.testResults.passed++;
            } catch (error) {
                console.error(`${algorithm} failed:`, error);
                results.failed++;
                this.testResults.failed++;
            }
            results.total++;
            this.testResults.total++;
        }

        this.testResults.byAlgorithm['HQC-KEM'] = results;
        console.log(`HQC-KEM: ${results.passed}/${results.total} passed`);
    }

    /**
     * Test KEM algorithm
     */
    async testKEMAlgorithm(algorithm) {
        console.log(`  Testing ${algorithm}...`);

        // Generate keypair
        const keypair = await this.aegis.mlkemKeypair(algorithm);
        if (!keypair.publicKey || !keypair.secretKey) {
            throw new Error('Invalid keypair generated');
        }

        // Test encapsulation
        const encapsResult = await this.aegis.mlkemEncapsulate(keypair.publicKey, algorithm);
        if (!encapsResult.ciphertext || !encapsResult.sharedSecret) {
            throw new Error('Invalid encapsulation result');
        }

        // Test decapsulation
        const decapsSecret = await this.aegis.mlkemDecapsulate(keypair.secretKey, encapsResult.ciphertext, algorithm);
        if (!this.arraysEqual(decapsSecret, encapsResult.sharedSecret)) {
            throw new Error('Shared secrets do not match');
        }

        console.log(`    ✅ ${algorithm} passed`);
    }

    /**
     * Test signature algorithm
     */
    async testSignatureAlgorithm(algorithm, type) {
        console.log(`  Testing ${algorithm}...`);

        let keypair, signature, isValid;

        if (type === 'mldsa') {
            keypair = await this.aegis.mldsaKeypair(algorithm);
            signature = await this.aegis.mldsaSign(this.textEncoder.encode('Test message'), keypair.secretKey, algorithm);
            isValid = await this.aegis.mldsaVerify(signature, this.textEncoder.encode('Test message'), keypair.publicKey, algorithm);
        } else if (type === 'fndsa') {
            keypair = await this.aegis.fndsaKeypair(algorithm);
            signature = await this.aegis.fndsaSign(this.textEncoder.encode('Test message'), keypair.secretKey, algorithm);
            isValid = await this.aegis.fndsaVerify(signature, this.textEncoder.encode('Test message'), keypair.publicKey, algorithm);
        } else if (type === 'slhdsa') {
            keypair = await this.aegis.slhdsaKeypair(algorithm);
            signature = await this.aegis.slhdsaSign(this.textEncoder.encode('Test message'), keypair.secretKey, algorithm);
            isValid = await this.aegis.slhdsaVerify(signature, this.textEncoder.encode('Test message'), keypair.publicKey, algorithm);
        } else {
            throw new Error(`Unknown algorithm type: ${type}`);
        }

        if (!keypair.publicKey || !keypair.secretKey) {
            throw new Error('Invalid keypair generated');
        }

        if (!signature || signature.length === 0) {
            throw new Error('Invalid signature generated');
        }

        if (!isValid) {
            throw new Error('Signature verification failed');
        }

        console.log(`    ✅ ${algorithm} passed`);
    }

    /**
     * Print test results
     */
    printResults() {
        console.log('\n📊 AEGIS Browser WASM Test Results');
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
            const algSuccessRate = (results.passed / results.total * 100).toFixed(1);
            const status = results.passed === results.total ? '✅' : '❌';
            console.log(`${algorithm}: ${results.passed}/${results.total} passed (${algSuccessRate}%) ${status}`);
        }

        console.log('\n' + '=' * 50);
        console.log(`Overall Result: ${passedTests === totalTests ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);
    }

    /**
     * Utility method to compare arrays
     */
    arraysEqual(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    get textEncoder() {
        return this._textEncoder || (this._textEncoder = new TextEncoder());
    }
}

// Export for use in browser
if (typeof window !== 'undefined') {
    window.BrowserTestSuite = BrowserTestSuite;
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BrowserTestSuite;
}
