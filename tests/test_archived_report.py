import csv
import unittest
from decimal import Decimal
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / 'data' / 'monthly_summary.csv'

class ArchivedAuditReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with DATA.open('r', newline='', encoding='utf-8-sig') as f:
            cls.by_month = {(r['chain'], r['month']): r for r in csv.DictReader(f)}

    def test_september_base_count(self):
        r = self.by_month['Base', '2026-09']
        self.assertEqual(int(r['claims']), 4263)
        self.assertEqual(int(r['transactions']), 127)
        self.assertEqual(Decimal(r['reward_token']), Decimal('0.002847348004126521'))

    def test_september_cost_reconciliation(self):
        r = self.by_month['Base', '2026-09']
        rewards = Decimal(r['reward_usd_est'])
        gas = Decimal(r['gas_usd_est'])
        net = Decimal(r['system_net_usd_est'])
        self.assertLess(abs(rewards-gas-net), Decimal('0.00000001'))
        self.assertFalse(r['recipient_net_usd_est'])
        self.assertEqual(r['all_recipients_pay_gas'], 'False')

    def test_october_sample_is_not_full_month(self):
        r = self.by_month['Base','2026-10']
        self.assertEqual(int(r['claims']), 0)
        self.assertEqual(int(r['transactions']), 0)

if __name__ == '__main__':
    unittest.main()
