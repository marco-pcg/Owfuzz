#!/usr/bin/env python3
import unittest
from extension_metrics import report
class MetricsTests(unittest.TestCase):
    def observation(self, variant, seconds, trial=1):
        return dict(participant='p1',task='frame',trial=trial,variant=variant,seconds=seconds,core_files_changed=0)
    def test_pairs_and_unmatched(self):
        result=report([self.observation('baseline',120),self.observation('refactored',30),self.observation('baseline',90,2)])
        self.assertEqual(result['paired_comparisons'][0]['time_reduction_percent'],75)
        self.assertEqual(result['unpaired_observations'],1)
        self.assertEqual(result['groups']['baseline']['median_seconds'],105)
    def test_duplicate_trial_rejected(self):
        with self.assertRaises(ValueError): report([self.observation('baseline',120),self.observation('baseline',100)])
    def test_empty_report_does_not_invent_results(self):
        self.assertEqual(report([])['paired_comparisons'],[])
if __name__=='__main__': unittest.main()
