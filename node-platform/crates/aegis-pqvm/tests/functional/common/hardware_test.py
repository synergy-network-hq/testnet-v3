#!/usr/bin/env python3
"""
AEGIS PQC Hardware Testing Framework

Comprehensive testing framework for hardware-accelerated PQC implementations
across FPGA, ASIC, GPU, and HSM platforms.
"""

import argparse
import json
import time
import sys
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../..'))

try:
    from aegi_pqc_hardware import AEGISHardware
except ImportError as exc:
    AEGISHardware = None
    HARDWARE_IMPORT_ERROR = exc
else:
    HARDWARE_IMPORT_ERROR = None

class TestPlatform(Enum):
    """Supported hardware test platforms"""
    FPGA = "fpga"
    ASIC = "asic"
    GPU = "gpu"
    HSM = "hsm"
    SOFTWARE = "software"

class TestType(Enum):
    """Types of hardware tests"""
    FUNCTIONAL = "functional"
    PERFORMANCE = "performance"
    STRESS = "stress"
    SECURITY = "security"
    INTEGRATION = "integration"

@dataclass
class TestResult:
    """Test execution result"""
    test_name: str
    platform: str
    algorithm: str
    test_type: str
    passed: bool
    duration: float
    metrics: Dict[str, Any]
    error_message: Optional[str] = None

@dataclass
class HardwareTestConfig:
    """Hardware test configuration"""
    platform: TestPlatform
    algorithms: List[str]
    test_types: List[TestType]
    iterations: int
    timeout: float
    verbose: bool

class HardwareTester:
    """Main hardware testing framework"""

    def __init__(self, config: HardwareTestConfig):
        self.config = config
        self.results: List[TestResult] = []
        self.hardware = None

        if AEGISHardware is None:
            raise RuntimeError(
                f"AEGIS hardware library is required for hardware tests: {HARDWARE_IMPORT_ERROR}"
            )

        try:
            self.hardware = AEGISHardware()
            self.hardware.initialize()
        except Exception as e:
            raise RuntimeError(f"Hardware initialization failed: {e}") from e

    def _invoke_hardware(self, method_names: List[str], algorithm: str) -> Any:
        """Call a real hardware adapter method or fail closed."""
        if self.hardware is None:
            raise RuntimeError("Hardware adapter is not initialized")

        attempted = []
        for method_name in method_names:
            method = getattr(self.hardware, method_name, None)
            if not callable(method):
                attempted.append(method_name)
                continue

            try:
                return method(algorithm, self.config.iterations)
            except TypeError:
                return method(algorithm)

        raise RuntimeError(
            "Hardware adapter does not expose any required method: "
            + ", ".join(attempted or method_names)
        )

    @staticmethod
    def _result_passed(raw_result: Any) -> bool:
        if isinstance(raw_result, bool):
            return raw_result
        if isinstance(raw_result, dict) and "passed" in raw_result:
            return bool(raw_result["passed"])
        passed = getattr(raw_result, "passed", None)
        if passed is not None:
            return bool(passed)
        return True

    @staticmethod
    def _result_metrics(raw_result: Any) -> Dict[str, Any]:
        if raw_result is None:
            return {}
        if isinstance(raw_result, dict):
            return {k: v for k, v in raw_result.items() if k != "passed"}

        metrics = getattr(raw_result, "metrics", None)
        if isinstance(metrics, dict):
            return metrics

        extracted = {}
        for attr in ("throughput", "latency", "iterations", "error_rate"):
            if hasattr(raw_result, attr):
                extracted[attr] = getattr(raw_result, attr)
        if extracted:
            return extracted

        return {"hardware_result": str(raw_result)}

    def _build_result(
        self,
        algorithm: str,
        test_type: str,
        start_time: float,
        raw_result: Any,
    ) -> TestResult:
        return TestResult(
            test_name=f"{algorithm}_{test_type}",
            platform=self.config.platform.value,
            algorithm=algorithm,
            test_type=test_type,
            passed=self._result_passed(raw_result),
            duration=time.time() - start_time,
            metrics=self._result_metrics(raw_result),
        )

    def run_all_tests(self) -> List[TestResult]:
        """Run all configured tests"""
        print(f"🧪 Starting hardware tests for platform: {self.config.platform.value}")

        for algorithm in self.config.algorithms:
            for test_type in self.config.test_types:
                try:
                    result = self.run_single_test(algorithm, test_type)
                    self.results.append(result)

                    if self.config.verbose:
                        print(f"  ✅ {algorithm} {test_type.value}: {result.duration:.3f}s")

                except Exception as e:
                    error_result = TestResult(
                        test_name=f"{algorithm}_{test_type.value}",
                        platform=self.config.platform.value,
                        algorithm=algorithm,
                        test_type=test_type.value,
                        passed=False,
                        duration=0.0,
                        metrics={},
                        error_message=str(e)
                    )
                    self.results.append(error_result)

                    if self.config.verbose:
                        print(f"  ❌ {algorithm} {test_type.value}: {e}")

        return self.results

    def run_single_test(self, algorithm: str, test_type: TestType) -> TestResult:
        """Run a single test case"""
        start_time = time.time()

        try:
            if test_type == TestType.FUNCTIONAL:
                return self.run_functional_test(algorithm)
            elif test_type == TestType.PERFORMANCE:
                return self.run_performance_test(algorithm)
            elif test_type == TestType.STRESS:
                return self.run_stress_test(algorithm)
            elif test_type == TestType.SECURITY:
                return self.run_security_test(algorithm)
            elif test_type == TestType.INTEGRATION:
                return self.run_integration_test(algorithm)
            else:
                raise ValueError(f"Unknown test type: {test_type}")

        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_name=f"{algorithm}_{test_type.value}",
                platform=self.config.platform.value,
                algorithm=algorithm,
                test_type=test_type.value,
                passed=False,
                duration=duration,
                metrics={},
                error_message=str(e)
            )

    def run_functional_test(self, algorithm: str) -> TestResult:
        """Run functional correctness tests"""
        start_time = time.time()

        raw_result = self._invoke_hardware(
            ["run_functional_test", "functional_test", "test_functional"],
            algorithm,
        )
        return self._build_result(algorithm, "functional", start_time, raw_result)

    def run_performance_test(self, algorithm: str) -> TestResult:
        """Run performance benchmark tests"""
        start_time = time.time()

        raw_result = self._invoke_hardware(
            ["benchmark", "run_performance_test", "performance_test"],
            algorithm,
        )
        return self._build_result(algorithm, "performance", start_time, raw_result)

    def run_stress_test(self, algorithm: str) -> TestResult:
        """Run stress and reliability tests"""
        start_time = time.time()

        raw_result = self._invoke_hardware(
            ["run_stress_test", "stress_test"],
            algorithm,
        )
        return self._build_result(algorithm, "stress", start_time, raw_result)

    def run_security_test(self, algorithm: str) -> TestResult:
        """Run security validation tests"""
        start_time = time.time()

        raw_result = self._invoke_hardware(
            ["run_security_test", "security_test", "validate_security"],
            algorithm,
        )
        return self._build_result(algorithm, "security", start_time, raw_result)

    def run_integration_test(self, algorithm: str) -> TestResult:
        """Run system integration tests"""
        start_time = time.time()

        raw_result = self._invoke_hardware(
            ["run_integration_test", "integration_test"],
            algorithm,
        )
        return self._build_result(algorithm, "integration", start_time, raw_result)

    def generate_report(self, output_file: str = "hardware_test_report.json") -> None:
        """Generate test report in JSON format"""
        report = {
            "test_config": {
                "platform": self.config.platform.value,
                "algorithms": self.config.algorithms,
                "test_types": [t.value for t in self.config.test_types],
                "iterations": self.config.iterations,
                "timeout": self.config.timeout
            },
            "summary": self.get_summary(),
            "results": [
                {
                    "test_name": r.test_name,
                    "platform": r.platform,
                    "algorithm": r.algorithm,
                    "test_type": r.test_type,
                    "passed": r.passed,
                    "duration": r.duration,
                    "metrics": r.metrics,
                    "error_message": r.error_message
                }
                for r in self.results
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📊 Test report saved to: {output_file}")

    def get_summary(self) -> Dict[str, Any]:
        """Get test execution summary"""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = total_tests - passed_tests
        total_duration = sum(r.duration for r in self.results)

        return {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "success_rate": passed_tests / total_tests if total_tests > 0 else 0,
            "total_duration": total_duration,
            "average_duration": total_duration / total_tests if total_tests > 0 else 0
        }

    def print_summary(self) -> None:
        """Print test summary to console"""
        summary = self.get_summary()

        print("\n📊 Hardware Test Summary")
        print("=" * 50)
        print(f"Platform: {self.config.platform.value}")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed_tests']}")
        print(f"Failed: {summary['failed_tests']}")
        print(f"Success Rate: {summary['success_rate']:.1%}")
        print(f"Total Duration: {summary['total_duration']:.2f}s")
        print(f"Average Duration: {summary['average_duration']:.3f}s")

        if summary['failed_tests'] > 0:
            print("\n❌ Failed Tests:")
            for result in self.results:
                if not result.passed:
                    print(f"  - {result.test_name}: {result.error_message or 'Unknown error'}")

def main():
    """Main test execution function"""
    parser = argparse.ArgumentParser(description="AEGIS PQC Hardware Testing Framework")
    parser.add_argument("--platform", type=str, required=True,
                       choices=["fpga", "asic", "gpu", "hsm", "software"],
                       help="Hardware platform to test")
    parser.add_argument("--algorithms", nargs="+", required=True,
                       help="PQC algorithms to test")
    parser.add_argument("--test-types", nargs="+", default=["functional", "performance"],
                       choices=["functional", "performance", "stress", "security", "integration"],
                       help="Types of tests to run")
    parser.add_argument("--iterations", type=int, default=100,
                       help="Number of test iterations")
    parser.add_argument("--timeout", type=float, default=30.0,
                       help="Test timeout in seconds")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--output", type=str, default="hardware_test_report.json",
                       help="Output report file")

    args = parser.parse_args()

    # Convert string arguments to enums
    platform = TestPlatform(args.platform)
    test_types = [TestType(t) for t in args.test_types]

    # Create test configuration
    config = HardwareTestConfig(
        platform=platform,
        algorithms=args.algorithms,
        test_types=test_types,
        iterations=args.iterations,
        timeout=args.timeout,
        verbose=args.verbose
    )

    # Run tests
    tester = HardwareTester(config)
    results = tester.run_all_tests()

    # Generate report
    tester.generate_report(args.output)
    tester.print_summary()

    # Exit with appropriate code
    summary = tester.get_summary()
    exit(0 if summary['failed_tests'] == 0 else 1)

if __name__ == "__main__":
    main()
