import re
import unittest
import audit_chain_selection as audit


class ChainSelectionTests(unittest.TestCase):
    def test_child_fixtures_are_guarded_by_test_only_parents(self):
        services = audit.ROOT/'bin/synergy-node/src/services'
        self.assertRegex((services/'mod.rs').read_text(), r'#\[cfg\(test\)\]\s*mod socket_qualification;')
        self.assertRegex((services/'posy.rs').read_text(), r'#\[cfg\(test\)\]\s*#\[path = "posy_qualification.rs"\]\s*pub\(super\) mod qualification;')
        for parent, child in (('posy_qualification.rs','posy_storage_qualification.rs'), ('socket_qualification.rs','socket_qualification_tps.rs')):
            self.assertIn('#[path = "'+child+'"]', (services/parent).read_text())
            path = 'bin/synergy-node/src/services/'+child
            self.assertIn(path, audit.TEST_MODULES)
            self.assertEqual(audit.classify(path,0,'chain_id: 1266',[])[0], 'network_test_fixture')

    def test_production_chain_literal_remains_prohibited(self):
        source = 'let chain_id: u64 = 1266;'
        self.assertIsNotNone(audit.RESTRICTION.search(source))
        self.assertEqual(audit.classify('crates/synergy-config/src/lib.rs',0,source,[])[0], 'review_required')
        self.assertNotIn('crates/synergy-config/src/lib.rs',audit.TEST_MODULES)


if __name__ == '__main__':
    unittest.main()
