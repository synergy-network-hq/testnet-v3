/**
 * AEGIS Node.js Comprehensive Benchmark Suite
 *
 * Benchmarks all algorithms and implementations to measure performance
 */

const AEGIS = require('../index.js');

class BenchmarkSuite {
    constructor() {
        this.aegis = new AEGIS();
        this.benchmarkResults = {
            byAlgorithm: {},
            summary: {
                totalBenchmarks: 0,
                totalTime: 0,
                fastest: null,
                slowest: null
            }
        };
    }

    /**
     * Run all benchmarks
     */
    async runAllBenchmarks(iterations = 100) {
        console.log('🚀 Running AEGIS Node.js Performance Benchmarks\n');

        // Benchmark ML-KEM algorithms
        await this.benchmarkMLKEM(iterations);

        // Benchmark ML-DSA algorithms
        await this.benchmarkMLDSA(iterations);

        // Benchmark FN-DSA algorithms
        await this.benchmarkFNDSA(iterations);

        // Benchmark SLH-DSA algorithms
        await this.benchmarkSLHDSA(iterations);

        // Benchmark HQC-KEM algorithms
        await this.benchmarkHQCKEM(iterations);

        this.printResults();
        this.generateCSV();
        return this.benchmarkResults;
    }

    /**
     * Benchmark ML-KEM algorithms
     */
    async benchmarkMLKEM(iterations = 100) {
        console.log('Benchmarking ML-KEM algorithms...');

        const algorithms = ['MLKEM512', 'MLKEM768', 'MLKEM1024'];

        for (const algorithm of algorithms) {
            await this.benchmarkKEM(algorithm, 'ML-KEM', iterations);
        }
    }

    /**
     * Benchmark ML-DSA algorithms
     */
    async benchmarkMLDSA(iterations = 100) {
        console.log('Benchmarking ML-DSA algorithms...');

        const algorithms = ['MLDSA44', 'MLDSA65', 'MLDSA87'];

        for (const algorithm of algorithms) {
            await this.benchmarkSignature(algorithm, 'ML-DSA', iterations);
        }
    }

    /**
     * Benchmark FN-DSA algorithms
     */
    async benchmarkFNDSA(iterations = 100) {
        console.log('Benchmarking FN-DSA algorithms...');

        const algorithms = ['FNDSA512', 'FNDSA1024'];

        for (const algorithm of algorithms) {
            await this.benchmarkSignature(algorithm, 'FN-DSA', iterations);
        }
    }

    /**
     * Benchmark SLH-DSA algorithms
     */
    async benchmarkSLHDSA(iterations = 100) {
        console.log('Benchmarking SLH-DSA algorithms...');

        const algorithms = [
            'SLHDSA_SHA2_128F_SIMPLE', 'SLHDSA_SHA2_128S_SIMPLE',
            'SLHDSA_SHA2_192F_SIMPLE', 'SLHDSA_SHA2_192S_SIMPLE',
            'SLHDSA_SHA2_256F_SIMPLE', 'SLHDSA_SHA2_256S_SIMPLE'
        ];

        for (const algorithm of algorithms) {
            await this.benchmarkSignature(algorithm, 'SLH-DSA', iterations);
        }
    }

    /**
     * Benchmark HQC-KEM algorithms
     */
    async benchmarkHQCKEM(iterations = 100) {
        console.log('Benchmarking HQC-KEM algorithms...');

        const algorithms = ['HQCKEM128', 'HQCKEM192', 'HQCKEM256'];

        for (const algorithm of algorithms) {
            await this.benchmarkKEM(algorithm, 'HQC-KEM', iterations);
        }
    }

    /**
     * Benchmark KEM algorithm
     */
    async benchmarkKEM(algorithm, algorithmType, iterations) {
        const results = {
            keygen: { times: [], average: 0, min: Infinity, max: 0 },
            encapsulate: { times: [], average: 0, min: Infinity, max: 0 },
            decapsulate: { times: [], average: 0, min: Infinity, max: 0 }
        };

        try {
            // Warm up
            await this.aegis.mlkemKeypair(algorithm);
            await this.aegis.mlkemKeypair(algorithm);
            await this.aegis.mlkemKeypair(algorithm);

            // Benchmark key generation
            for (let i = 0; i < iterations; i++) {
                const start = performance.now();
                await this.aegis.mlkemKeypair(algorithm);
                const end = performance.now();
                const time = end - start;
                results.keygen.times.push(time);
                results.keygen.min = Math.min(results.keygen.min, time);
                results.keygen.max = Math.max(results.keygen.max, time);
            }

            // Get a keypair for encapsulation/decapsulation
            const keypair = await this.aegis.mlkemKeypair(algorithm);

            // Benchmark encapsulation
            for (let i = 0; i < iterations; i++) {
                const start = performance.now();
                await this.aegis.mlkemEncapsulate(keypair.publicKey, algorithm);
                const end = performance.now();
                const time = end - start;
                results.encapsulate.times.push(time);
                results.encapsulate.min = Math.min(results.encapsulate.min, time);
                results.encapsulate.max = Math.max(results.encapsulate.max, time);
            }

            // Get ciphertext for decapsulation
            const encapsResult = await this.aegis.mlkemEncapsulate(keypair.publicKey, algorithm);

            // Benchmark decapsulation
            for (let i = 0; i < iterations; i++) {
                const start = performance.now();
                await this.aegis.mlkemDecapsulate(keypair.secretKey, encapsResult.ciphertext, algorithm);
                const end = performance.now();
                const time = end - start;
                results.decapsulate.times.push(time);
                results.decapsulate.min = Math.min(results.decapsulate.min, time);
                results.decapsulate.max = Math.max(results.decapsulate.max, time);
            }

            // Calculate averages
            results.keygen.average = results.keygen.times.reduce((a, b) => a + b, 0) / results.keygen.times.length;
            results.encapsulate.average = results.encapsulate.times.reduce((a, b) => a + b, 0) / results.encapsulate.times.length;
            results.decapsulate.average = results.decapsulate.times.reduce((a, b) => a + b, 0) / results.decapsulate.times.length;

            this.benchmarkResults.byAlgorithm[algorithm] = results;
            this.updateSummary(results, algorithm, algorithmType);

            console.log(`  ✅ ${algorithm}: KeyGen ${(results.keygen.average).toFixed(2)}ms, Encaps ${(results.encapsulate.average).toFixed(2)}ms, Decaps ${(results.decapsulate.average).toFixed(2)}ms`);
        } catch (error) {
            console.log(`  ❌ ${algorithm}: Error - ${error.message}`);
            this.benchmarkResults.byAlgorithm[algorithm] = { error: error.message };
        }
    }

    /**
     * Benchmark signature algorithm
     */
    async benchmarkSignature(algorithm, algorithmType, iterations) {
        const results = {
            keygen: { times: [], average: 0, min: Infinity, max: 0 },
            sign: { times: [], average: 0, min: Infinity, max: 0 },
            verify: { times: [], average: 0, min: Infinity, max: 0 }
        };

        try {
            // Determine which algorithm type to use
            const isMLDSA = algorithm.startsWith('MLDSA');
            const isFNDSA = algorithm.startsWith('FNDSA');
            const isSLHDSA = algorithm.startsWith('SLHDSA');

            // Warm up
            let keypair;
            if (isMLDSA) {
                keypair = await this.aegis.mldsaKeypair(algorithm);
            } else if (isFNDSA) {
                keypair = await this.aegis.fndsaKeypair(algorithm);
            } else if (isSLHDSA) {
                keypair = await this.aegis.slhdsaKeypair(algorithm);
            }

            // Benchmark key generation
            for (let i = 0; i < iterations; i++) {
                const start = performance.now();
                if (isMLDSA) {
                    await this.aegis.mldsaKeypair(algorithm);
                } else if (isFNDSA) {
                    await this.aegis.fndsaKeypair(algorithm);
                } else if (isSLHDSA) {
                    await this.aegis.slhdsaKeypair(algorithm);
                }
                const end = performance.now();
                const time = end - start;
                results.keygen.times.push(time);
                results.keygen.min = Math.min(results.keygen.min, time);
                results.keygen.max = Math.max(results.keygen.max, time);
            }

            // Benchmark signing
            const message = Buffer.from('Hello, AEGIS benchmark test message for performance measurement!');
            for (let i = 0; i < iterations; i++) {
                const start = performance.now();
                if (isMLDSA) {
                    await this.aegis.mldsaSign(message, keypair.secretKey, algorithm);
                } else if (isFNDSA) {
                    await this.aegis.fndsaSign(message, keypair.secretKey, algorithm);
                } else if (isSLHDSA) {
                    await this.aegis.slhdsaSign(message, keypair.secretKey, algorithm);
                }
                const end = performance.now();
                const time = end - start;
                results.sign.times.push(time);
                results.sign.min = Math.min(results.sign.min, time);
                results.sign.max = Math.max(results.sign.max, time);
            }

            // Get a signature for verification
            let signature;
            if (isMLDSA) {
                signature = await this.aegis.mldsaSign(message, keypair.secretKey, algorithm);
            } else if (isFNDSA) {
                signature = await this.aegis.fndsaSign(message, keypair.secretKey, algorithm);
            } else if (isSLHDSA) {
                signature = await this.aegis.slhdsaSign(message, keypair.secretKey, algorithm);
            }

            // Benchmark verification
            for (let i = 0; i < iterations; i++) {
                const start = performance.now();
                if (isMLDSA) {
                    await this.aegis.mldsaVerify(signature, message, keypair.publicKey, algorithm);
                } else if (isFNDSA) {
                    await this.aegis.fndsaVerify(signature, message, keypair.publicKey, algorithm);
                } else if (isSLHDSA) {
                    await this.aegis.slhdsaVerify(signature, message, keypair.publicKey, algorithm);
                }
                const end = performance.now();
                const time = end - start;
                results.verify.times.push(time);
                results.verify.min = Math.min(results.verify.min, time);
                results.verify.max = Math.max(results.verify.max, time);
            }

            // Calculate averages
            results.keygen.average = results.keygen.times.reduce((a, b) => a + b, 0) / results.keygen.times.length;
            results.sign.average = results.sign.times.reduce((a, b) => a + b, 0) / results.sign.times.length;
            results.verify.average = results.verify.times.reduce((a, b) => a + b, 0) / results.verify.times.length;

            this.benchmarkResults.byAlgorithm[algorithm] = results;
            this.updateSummary(results, algorithm, algorithmType);

            console.log(`  ✅ ${algorithm}: KeyGen ${(results.keygen.average).toFixed(2)}ms, Sign ${(results.sign.average).toFixed(2)}ms, Verify ${(results.verify.average).toFixed(2)}ms`);
        } catch (error) {
            console.log(`  ❌ ${algorithm}: Error - ${error.message}`);
            this.benchmarkResults.byAlgorithm[algorithm] = { error: error.message };
        }
    }

    /**
     * Update benchmark summary
     */
    updateSummary(results, algorithm, algorithmType) {
        this.benchmarkResults.summary.totalBenchmarks++;

        // Update fastest/slowest
        const keygenTime = results.keygen.average;
        const signTime = results.sign ? results.sign.average : 0;
        const encapsTime = results.encapsulate ? results.encapsulate.average : 0;

        if (!this.benchmarkResults.summary.fastest || keygenTime < this.benchmarkResults.summary.fastest.time) {
            this.benchmarkResults.summary.fastest = { algorithm, operation: 'keygen', time: keygenTime };
        }

        if (!this.benchmarkResults.summary.slowest || keygenTime > this.benchmarkResults.summary.slowest.time) {
            this.benchmarkResults.summary.slowest = { algorithm, operation: 'keygen', time: keygenTime };
        }

        this.benchmarkResults.summary.totalTime += keygenTime;
        if (results.sign) this.benchmarkResults.summary.totalTime += results.sign.average;
        if (results.encapsulate) this.benchmarkResults.summary.totalTime += results.encapsulate.average;
    }

    /**
     * Print benchmark results
     */
    printResults() {
        console.log('\n📊 Benchmark Results Summary');
        console.log('=' * 60);

        const totalBenchmarks = this.benchmarkResults.summary.totalBenchmarks;
        const averageTime = this.benchmarkResults.summary.totalTime / totalBenchmarks;

        console.log(`Total Benchmarks: ${totalBenchmarks}`);
        console.log(`Average Time: ${averageTime.toFixed(2)}ms`);
        console.log(`Fastest Operation: ${this.benchmarkResults.summary.fastest.algorithm} ${this.benchmarkResults.summary.fastest.operation} (${this.benchmarkResults.summary.fastest.time.toFixed(2)}ms)`);
        console.log(`Slowest Operation: ${this.benchmarkResults.summary.slowest.algorithm} ${this.benchmarkResults.summary.slowest.operation} (${this.benchmarkResults.summary.slowest.time.toFixed(2)}ms)`);

        console.log('\nDetailed Results:');
        console.log('-' * 40);

        for (const [algorithm, results] of Object.entries(this.benchmarkResults.byAlgorithm)) {
            if (results.keygen) {
                console.log(`${algorithm}:`);
                console.log(`  KeyGen: ${results.keygen.average.toFixed(2)}ms (min: ${results.keygen.min.toFixed(2)}ms, max: ${results.keygen.max.toFixed(2)}ms)`);

                if (results.sign) {
                    console.log(`  Sign:   ${results.sign.average.toFixed(2)}ms (min: ${results.sign.min.toFixed(2)}ms, max: ${results.sign.max.toFixed(2)}ms)`);
                }

                if (results.verify) {
                    console.log(`  Verify: ${results.verify.average.toFixed(2)}ms (min: ${results.verify.min.toFixed(2)}ms, max: ${results.verify.max.toFixed(2)}ms)`);
                }

                if (results.encapsulate) {
                    console.log(`  Encaps: ${results.encapsulate.average.toFixed(2)}ms (min: ${results.encapsulate.min.toFixed(2)}ms, max: ${results.encapsulate.max.toFixed(2)}ms)`);
                }

                if (results.decapsulate) {
                    console.log(`  Decaps: ${results.decapsulate.average.toFixed(2)}ms (min: ${results.decapsulate.min.toFixed(2)}ms, max: ${results.decapsulate.max.toFixed(2)}ms)`);
                }

                console.log('');
            }
        }

        console.log('=' * 60);
        console.log('✅ Benchmarking completed successfully!');
    }

    /**
     * Generate CSV output for performance analysis
     */
    generateCSV() {
        const fs = require('fs');
        const path = require('path');
        const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];

        const csvPath = path.join(__dirname, `../performance_results/aegis_nodejs_benchmarks_${timestamp}.csv`);
        const csvData = [
            ['Algorithm', 'Operation', 'Average Time (ms)', 'Min Time (ms)', 'Max Time (ms)', 'Iterations']
        ];

        for (const [algorithm, results] of Object.entries(this.benchmarkResults.byAlgorithm)) {
            if (results.keygen) {
                csvData.push([
                    algorithm,
                    'keygen',
                    results.keygen.average.toFixed(3),
                    results.keygen.min.toFixed(3),
                    results.keygen.max.toFixed(3),
                    results.keygen.times.length
                ]);

                if (results.sign) {
                    csvData.push([
                        algorithm,
                        'sign',
                        results.sign.average.toFixed(3),
                        results.sign.min.toFixed(3),
                        results.sign.max.toFixed(3),
                        results.sign.times.length
                    ]);
                }

                if (results.verify) {
                    csvData.push([
                        algorithm,
                        'verify',
                        results.verify.average.toFixed(3),
                        results.verify.min.toFixed(3),
                        results.verify.max.toFixed(3),
                        results.verify.times.length
                    ]);
                }

                if (results.encapsulate) {
                    csvData.push([
                        algorithm,
                        'encapsulate',
                        results.encapsulate.average.toFixed(3),
                        results.encapsulate.min.toFixed(3),
                        results.encapsulate.max.toFixed(3),
                        results.encapsulate.times.length
                    ]);
                }

                if (results.decapsulate) {
                    csvData.push([
                        algorithm,
                        'decapsulate',
                        results.decapsulate.average.toFixed(3),
                        results.decapsulate.min.toFixed(3),
                        results.decapsulate.max.toFixed(3),
                        results.decapsulate.times.length
                    ]);
                }
            }
        }

        // Write CSV file
        const csvContent = csvData.map(row => row.join(',')).join('\n');
        fs.writeFileSync(csvPath, csvContent);

        console.log(`📊 Benchmark results exported to: ${csvPath}`);
    }
}

// Run benchmarks if this file is executed directly
if (require.main === module) {
    async function main() {
        const benchmarkSuite = new BenchmarkSuite();
        const results = await benchmarkSuite.runAllBenchmarks(50); // Reduced iterations for faster testing
        process.exit(0);
    }

    main().catch(error => {
        console.error('Benchmark suite failed:', error);
        process.exit(1);
    });
}

module.exports = BenchmarkSuite;
