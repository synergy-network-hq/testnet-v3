#!/usr/bin/env python3
"""
Test script for pqpython - NIST PQC algorithms
"""

import pqpython
import time
import os
from pathlib import Path


def test_kem_algorithm(alg, name):
    """Test a KEM algorithm"""
    print(f"Testing {name}...")
    try:
        # Generate keypair
        pk, sk = alg.keypair()
        assert len(pk) == alg.public_key_bytes
        assert len(sk) == alg.secret_key_bytes
        print(f"  ✓ Keypair: pk={len(pk)} bytes, sk={len(sk)} bytes")

        # Test encapsulation/decapsulation
        ct, ss_enc = alg.enc(pk)
        assert len(ct) == alg.ciphertext_bytes
        assert len(ss_enc) == alg.shared_secret_bytes
        print(f"  ✓ Encapsulation: ct={len(ct)} bytes, ss={len(ss_enc)} bytes")

        ss_dec = alg.dec(ct, sk)
        assert len(ss_dec) == alg.shared_secret_bytes
        assert ss_enc == ss_dec
        print(f"  ✓ Decapsulation: shared secrets match")

        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False


def test_signature_algorithm(alg, name):
    """Test a signature algorithm"""
    print(f"Testing {name}...")
    try:
        # Generate keypair
        pk, sk = alg.keypair()
        assert len(pk) == alg.public_key_bytes
        assert len(sk) == alg.secret_key_bytes
        print(f"  ✓ Keypair: pk={len(pk)} bytes, sk={len(sk)} bytes")

        # Test signing/verification
        message = b"Hello, post-quantum world! This is a test message for signature verification."
        sig = alg.sign(message, sk)
        # For FN-DSA, signatures are variable length, so we check they're within bounds
        if name.startswith("FN-DSA"):
            assert 0 < len(sig) <= alg.signature_bytes
        else:
            assert len(sig) == alg.signature_bytes
        print(f"  ✓ Signature: {len(sig)} bytes")

        valid = alg.verify(sig, message, pk)
        assert valid
        print(f"  ✓ Verification: valid")

        # Test with wrong message
        wrong_message = b"This is a different message"
        invalid = alg.verify(sig, wrong_message, pk)
        assert not invalid
        print(f"  ✓ Wrong message rejection: correctly invalid")

        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False


def benchmark_algorithm(alg, name, operation, iterations=100):
    """Benchmark an algorithm operation"""
    # Reduce iterations for slower Classic McEliece algorithms
    if "Classic-McEliece" in name:
        iterations = 5  # Much fewer iterations for slow algorithms
    elif "HQC" in name:
        iterations = 10  # Fewer iterations for HQC

    print(f"Benchmarking {name} - {operation}...")

    times = []
    for _ in range(iterations):
        start_time = time.time()

        if operation == "keypair":
            alg.keypair()
        elif operation == "enc" and hasattr(alg, 'enc'):
            pk, _ = alg.keypair()
            alg.enc(pk)
        elif operation == "sign" and hasattr(alg, 'sign'):
            pk, sk = alg.keypair()
            message = b"Benchmark message"
            alg.sign(message, sk)
        elif operation == "verify" and hasattr(alg, 'verify'):
            pk, sk = alg.keypair()
            message = b"Benchmark message"
            sig = alg.sign(message, sk)
            alg.verify(sig, message, pk)

        end_time = time.time()
        times.append(end_time - start_time)

    avg_time = sum(times) / len(times) * 1000  # Convert to milliseconds
    print(f"  {name} {operation}: {avg_time:.2f} ms")
    return avg_time


def validate_kat_algorithms():
    """Validate algorithms against NIST KAT vectors"""
    print("\nNIST KAT Validation:")
    print("=" * 25)

    # Find KAT directory
    kat_dir = None
    current_dir = Path(__file__).parent
    module_root = current_dir.parents[2]
    possible_dirs = []
    kat_override = os.environ.get("AEGIS_PQKAT_DIR")
    if kat_override:
        possible_dirs.append(Path(kat_override))
    possible_dirs.extend(
        [
            module_root / "tests" / "kats",
            module_root.parent / "5-nist-kat-vectors",
        ]
    )

    for dir_path in possible_dirs:
        if dir_path.exists():
            kat_dir = str(dir_path)
            break

    if not kat_dir:
        print("  ✗ KAT directory not found")
        return False

    print(f"  Using KAT directory: {kat_dir}")

    validator = pqpython.KATValidator(kat_dir)

    # KEM algorithms to validate
    kem_algorithms = [
        ("ml-kem-512", pqpython.MLKEM512),
        ("ml-kem-768", pqpython.MLKEM768),
        ("ml-kem-1024", pqpython.MLKEM1024),
        ("hqc-kem-128", pqpython.HQCKEM128),
        ("hqc-kem-192", pqpython.HQCKEM192),
        ("hqc-kem-256", pqpython.HQCKEM256),
    ]

    # Signature algorithms to validate
    sig_algorithms = [
        ("ml-dsa-44", pqpython.MLDSA44),
        ("ml-dsa-65", pqpython.MLDSA65),
        ("ml-dsa-87", pqpython.MLDSA87),
    ]

    all_passed = True

    # Validate KEM algorithms
    print("\nKEM Algorithm KAT Validation:")
    print("-" * 30)
    for alg_name, alg_impl in kem_algorithms:
        result = validator.validate_kem_algorithm(alg_name, alg_impl)
        if result['total'] > 0:
            passed_rate = result['passed'] / result['total'] * 100
            print(f"  {alg_name}: {result['passed']}/{result['total']} passed ({passed_rate:.1f}%)")
            if result['failed'] > 0:
                all_passed = False
        else:
            print(f"  {alg_name}: No KAT tests available")
            all_passed = False

    # Validate signature algorithms
    print("\nSignature Algorithm KAT Validation:")
    print("-" * 35)
    for alg_name, alg_impl in sig_algorithms:
        result = validator.validate_signature_algorithm(alg_name, alg_impl)
        if result['total'] > 0:
            passed_rate = result['passed'] / result['total'] * 100
            print(f"  {alg_name}: {result['passed']}/{result['total']} passed ({passed_rate:.1f}%)")
            if result['failed'] > 0:
                all_passed = False
        else:
            print(f"  {alg_name}: No KAT tests available")
            all_passed = False

    return all_passed


def main():
    """Main test function"""
    print("pqpython Test Suite")
    print("=" * 50)

    # Test KEM algorithms
    print("\nTesting KEM Algorithms:")
    print("-" * 25)
    kem_results = []
    kem_results.append(test_kem_algorithm(pqpython.MLKEM512, "ML-KEM-512"))
    kem_results.append(test_kem_algorithm(pqpython.MLKEM768, "ML-KEM-768"))
    kem_results.append(test_kem_algorithm(pqpython.MLKEM1024, "ML-KEM-1024"))
    kem_results.append(test_kem_algorithm(pqpython.HQCKEM128, "HQC-KEM-128"))
    kem_results.append(test_kem_algorithm(pqpython.HQCKEM192, "HQC-KEM-192"))
    kem_results.append(test_kem_algorithm(pqpython.HQCKEM256, "HQC-KEM-256"))
    kem_results.append(test_kem_algorithm(pqpython.ClassicMcEliece348864, "Classic-McEliece-348864"))
    kem_results.append(test_kem_algorithm(pqpython.ClassicMcEliece460896, "Classic-McEliece-460896"))
    kem_results.append(test_kem_algorithm(pqpython.ClassicMcEliece6688128, "Classic-McEliece-6688128"))
    kem_results.append(test_kem_algorithm(pqpython.ClassicMcEliece6960119, "Classic-McEliece-6960119"))
    kem_results.append(test_kem_algorithm(pqpython.ClassicMcEliece8192128, "Classic-McEliece-8192128"))

    # Test signature algorithms
    print("\nTesting Signature Algorithms:")
    print("-" * 30)
    sig_results = []
    sig_results.append(test_signature_algorithm(pqpython.MLDSA44, "ML-DSA-44"))
    sig_results.append(test_signature_algorithm(pqpython.MLDSA65, "ML-DSA-65"))
    sig_results.append(test_signature_algorithm(pqpython.MLDSA87, "ML-DSA-87"))
    sig_results.append(test_signature_algorithm(pqpython.FNDSA512, "FN-DSA-512"))
    sig_results.append(test_signature_algorithm(pqpython.FNDSA1024, "FN-DSA-1024"))
    sig_results.append(test_signature_algorithm(pqpython.SLHDSA_SHA2_128F_SIMPLE, "SLH-DSA-SHA2-128f-simple"))
    sig_results.append(test_signature_algorithm(pqpython.SLHDSA_SHA2_128S_SIMPLE, "SLH-DSA-SHA2-128s-simple"))
    sig_results.append(test_signature_algorithm(pqpython.SLHDSA_SHAKE_256F_SIMPLE, "SLH-DSA-SHAKE-256f-simple"))

    # Summary
    print("\nTest Summary:")
    print("-" * 15)
    total_tests = len(kem_results) + len(sig_results)
    passed_tests = sum(kem_results + sig_results)
    print(f"KEM tests passed: {sum(kem_results)}/{len(kem_results)}")
    print(f"Signature tests passed: {sum(sig_results)}/{len(sig_results)}")
    print(f"Total: {passed_tests}/{total_tests} tests passed")

    basic_tests_passed = passed_tests == total_tests

    # KAT Validation
    kat_passed = validate_kat_algorithms()

    if basic_tests_passed and kat_passed:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed!")
        return False

    # Benchmarks
    print("\nBenchmarks (average time per operation):")
    print("-" * 45)

    # KEM benchmarks
    benchmark_algorithm(pqpython.MLKEM512, "ML-KEM-512", "keypair")
    benchmark_algorithm(pqpython.MLKEM512, "ML-KEM-512", "enc")
    benchmark_algorithm(pqpython.MLKEM768, "ML-KEM-768", "keypair")
    benchmark_algorithm(pqpython.MLKEM768, "ML-KEM-768", "enc")
    benchmark_algorithm(pqpython.MLKEM1024, "ML-KEM-1024", "keypair")
    benchmark_algorithm(pqpython.MLKEM1024, "ML-KEM-1024", "enc")
    benchmark_algorithm(pqpython.HQCKEM128, "HQC-KEM-128", "keypair")
    benchmark_algorithm(pqpython.HQCKEM128, "HQC-KEM-128", "enc")
    benchmark_algorithm(pqpython.HQCKEM192, "HQC-KEM-192", "keypair")
    benchmark_algorithm(pqpython.HQCKEM192, "HQC-KEM-192", "enc")
    benchmark_algorithm(pqpython.HQCKEM256, "HQC-KEM-256", "keypair")
    benchmark_algorithm(pqpython.HQCKEM256, "HQC-KEM-256", "enc")
    benchmark_algorithm(pqpython.ClassicMcEliece348864, "Classic-McEliece-348864", "keypair")
    benchmark_algorithm(pqpython.ClassicMcEliece348864, "Classic-McEliece-348864", "enc")
    benchmark_algorithm(pqpython.ClassicMcEliece460896, "Classic-McEliece-460896", "keypair")
    benchmark_algorithm(pqpython.ClassicMcEliece460896, "Classic-McEliece-460896", "enc")
    benchmark_algorithm(pqpython.ClassicMcEliece6688128, "Classic-McEliece-6688128", "keypair")
    benchmark_algorithm(pqpython.ClassicMcEliece6688128, "Classic-McEliece-6688128", "enc")
    benchmark_algorithm(pqpython.ClassicMcEliece6960119, "Classic-McEliece-6960119", "keypair")
    benchmark_algorithm(pqpython.ClassicMcEliece6960119, "Classic-McEliece-6960119", "enc")
    benchmark_algorithm(pqpython.ClassicMcEliece8192128, "Classic-McEliece-8192128", "keypair")
    benchmark_algorithm(pqpython.ClassicMcEliece8192128, "Classic-McEliece-8192128", "enc")

    # Signature benchmarks
    benchmark_algorithm(pqpython.MLDSA44, "ML-DSA-44", "keypair")
    benchmark_algorithm(pqpython.MLDSA44, "ML-DSA-44", "sign")
    benchmark_algorithm(pqpython.MLDSA44, "ML-DSA-44", "verify")
    benchmark_algorithm(pqpython.MLDSA65, "ML-DSA-65", "keypair")
    benchmark_algorithm(pqpython.MLDSA65, "ML-DSA-65", "sign")
    benchmark_algorithm(pqpython.MLDSA65, "ML-DSA-65", "verify")
    benchmark_algorithm(pqpython.MLDSA87, "ML-DSA-87", "keypair")
    benchmark_algorithm(pqpython.MLDSA87, "ML-DSA-87", "sign")
    benchmark_algorithm(pqpython.MLDSA87, "ML-DSA-87", "verify")
    benchmark_algorithm(pqpython.FNDSA512, "FN-DSA-512", "keypair")
    benchmark_algorithm(pqpython.FNDSA512, "FN-DSA-512", "sign")
    benchmark_algorithm(pqpython.FNDSA512, "FN-DSA-512", "verify")
    benchmark_algorithm(pqpython.FNDSA1024, "FN-DSA-1024", "keypair")
    benchmark_algorithm(pqpython.FNDSA1024, "FN-DSA-1024", "sign")
    benchmark_algorithm(pqpython.FNDSA1024, "FN-DSA-1024", "verify")
    benchmark_algorithm(pqpython.SLHDSA_SHA2_128F_SIMPLE, "SLH-DSA-SHA2-128f-simple", "keypair")
    benchmark_algorithm(pqpython.SLHDSA_SHA2_128F_SIMPLE, "SLH-DSA-SHA2-128f-simple", "sign")
    benchmark_algorithm(pqpython.SLHDSA_SHA2_128F_SIMPLE, "SLH-DSA-SHA2-128f-simple", "verify")

    return True


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
