#!/usr/bin/env python3
"""Checks that bandwidth-demo validation rejects misleading success reports."""
from pathlib import Path
import runpy
import unittest

analyze = runpy.run_path(str(Path(__file__).with_name('multipath_bw_demo')))['analyze']


class BandwidthReportTests(unittest.TestCase):
    def fixture(self):
        rates = (0.8, 1.6, 3.2, 6.4)
        output = ''.join(f'path {i}: rate={rate * 1e6 / 8:.0f} B/s share={rate / 12 * 100:.1f}%\n'
                         for i, rate in enumerate(rates))
        output += ('window_offered: 1500\nwindow_admitted: 1500\nwindow_received: 1500\n'
                   'window_goodput_mbps: 11.9\nwindow_p99_latency_ms: 50\n')
        samples = [{'time': 4.5 + i * 0.25,
                    'queues': {f'1:{n}2': {'bytes': int(rate * i * 0.25 * 1e6 / 8),
                                           'packets': i, 'drops': 0,
                                           'backlog': (2 ** (n - 1)) * 2500}
                               for n, rate in enumerate(rates, 1)}}
                   for i in range(29)]
        return output, samples

    def test_healthy_aggregation(self):
        output, samples = self.fixture()
        self.assertTrue(analyze(output, samples, 0)['passed'])

    def test_missing_measurements_cannot_pass(self):
        output, samples = self.fixture()
        self.assertFalse(analyze('', samples, 0)['passed'])
        self.assertFalse(analyze(output, [], 0)['passed'])
        del samples[10]['queues']['1:12']
        self.assertFalse(analyze(output, samples, 0)['checks']['measurement_available'])

    def test_backpressure_is_delivery_failure(self):
        output, samples = self.fixture()
        output = output.replace('window_admitted: 1500', 'window_admitted: 1000')
        output = output.replace('window_received: 1500', 'window_received: 1000')
        self.assertFalse(analyze(output, samples, 0)['checks']['delivery_at_least_99pct'])

    def test_growing_queue_and_drops_fail(self):
        output, samples = self.fixture()
        for i, sample in enumerate(samples):
            sample['queues']['1:12']['backlog'] += i * 2500
            sample['queues']['1:12']['drops'] = i
        checks = analyze(output, samples, 0)['checks']
        self.assertFalse(checks['queues_bounded'])
        self.assertFalse(checks['no_steady_queue_drops'])

    def test_broken_cap_or_preference_fails(self):
        output, samples = self.fixture()
        for sample in samples:
            sample['queues']['1:12']['bytes'] *= 10
        checks = analyze(output, samples, 0)['checks']
        self.assertFalse(checks['caps_respected'])
        self.assertFalse(checks['faster_links_carry_more'])

    def test_failed_benchmark_cannot_pass(self):
        output, samples = self.fixture()
        self.assertFalse(analyze(output, samples, 1)['passed'])


if __name__ == '__main__':
    unittest.main()
