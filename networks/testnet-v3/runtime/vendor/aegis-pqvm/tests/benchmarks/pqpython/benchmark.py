import timeit
import csv
from aegis_crypto_core import *  # pyo3 module

def measure_time(func, iterations=1000):
    times = timeit.repeat(func, number=1, repeat=iterations)
    mean = sum(times) / len(times) * 1e9  # ns
    variance = sum((t - mean/1e9)**2 for t in times) / len(times)
    std_dev = (variance * 1e18)**0.5  # ns
    return mean, std_dev

results = []
iterations = 1000

# ML-KEM 512 keygen
def ml_kem_512_keygen():
    MLKem512.keypair()

mean, std = measure_time(ml_kem_512_keygen, iterations)
results.append(("pqpython", "ml_kem", "512", "keygen", mean, std, iterations))

# ... encapsulate/decapsulate (setup pk/sk once)
pk512 = MLKem512.keypair()[0]
def ml_kem_512_encaps():
    MLKem512.encapsulate(pk512)

mean, std = measure_time(ml_kem_512_encaps, iterations)
results.append(("pqpython", "ml_kem", "512", "encapsulate", mean, std, iterations))

# Similar for decaps, all levels (768/1024), all algos (ML-DSA 44/65/87 sign/verify with msg=b"test", SLH-DSA all variants, FN-DSA 512/1024, HQC 128/192/256)

msg = b"test message"
# Example ML-DSA 44 sign
sk44 = MLDsa44.keypair()[1]
def ml_dsa_44_sign():
    MLDsa44.sign(sk44, msg)

mean, std = measure_time(ml_dsa_44_sign, iterations)
results.append(("pqpython", "ml_dsa", "44", "sign", mean, std, iterations))

# ... all ops/levels

# Write CSV
import os
os.makedirs("../../performance_results", exist_ok=True)
with open("../../performance_results/pqpython_benchmarks.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["impl", "algorithm", "variant", "operation", "mean_time_ns", "std_dev_ns", "iterations"])
    writer.writerows(results)

print("Generated pqpython_benchmarks.csv")
