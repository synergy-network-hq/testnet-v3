# Team & Support Allocation Reconciliation — 526,000,000 SNRG

Updated: 2026-08-23. Source: fresh PoSy v3 Genesis `address_assignment_register`,
`vesting[0]`, `allocation_sum_check` (specification `SN-TNV3-GEN-TOK-001`
v1.3). Governance moved 14,000,000 SNRG from TEM-A02 to SAL-A01 without
changing the fixed supply.

## Complete accounting (no overlap, no remainder)

| Record | Address | Amount | Disposition |
|---|---|---|---|
| TEM-A01 — Shared Team & Support Vesting Contract | Pending fresh deterministic deployment | **340,000,000 SNRG** (3.4e17 nwei) | Funds the shared vesting contract directly at genesis. Fully scheduled across 9 beneficiaries: 5 team × 60,000,000 + 4 support × 10,000,000; 20% initial, 1-year cliff, 80% over 36 monthly events; team initial tranche restricted 2 years (genesis `vesting[0]`, beneficiary sums verified). |
| TEM-A02 — Unassigned Team & Support Reserve | Pending fresh custody identity | **186,000,000 SNRG** (1.86e17 nwei) | Explicitly assigned reserve wallet for future team/support allocations (future hires, advisors, support programs). Not part of the current 9-beneficiary schedule by design; custody per the register's control reference. |
| **Category total** | | **526,000,000 SNRG** | Matches the Team & Support tokenomics category exactly. |

Cross-checks: the 340M beneficiary schedule sums exactly to TEM-A01's funded
amount (contract-funding reconciliation for `TeamVesting` ✓). The full
register (DAO 720M, ECO 1,560M, LIQ 1,440M, MKT 1,260M, PAR 894M, SAL 2,240M,
TEM 526M, TRE 720M, VNS 2,640M, SYS 0) sums to the 12,000,000,000 SNRG supply
cap; `allocation_sum_check.matches_supply_cap = true` independently verified.

Conclusion: the remaining 186,000,000 SNRG is neither unassigned nor
double-assigned — it is the deliberate TEM-A02 reserve. The transferred
14,000,000 SNRG is included in SAL-A01. No further allocation action is required;
any future disbursement from TEM-A02 is a governance/custody action, not a
genesis defect.
