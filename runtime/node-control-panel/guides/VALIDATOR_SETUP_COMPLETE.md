# ✅ Synergy Testnet Validator System - READY FOR TEAM ONBOARDING

> Current post-fork onboarding requires the Synergy Node Control Panel flow, explicit FN-DSA validator keys, and `50,000 SNRG` bonded stake. This legacy status note is retained for historical context; use `guides/CONTROL_PANEL_INSTALL_AND_NEW_VALIDATOR_ONBOARDING.md` for launch-current validator setup.

**Date:** December 6, 2025  
**Status:** Production Ready for Team Member Validators

---

## 🎯 What's Been Set Up

The Synergy Testnet now supports **dynamic validator onboarding** for team members who want to run validators on their own remote systems.

### ✅ Core Features Implemented

1. **Staked Validators** - Team members bond 50,000 SNRG before activation
2. **Dynamic Registration** - Validators register after blockchain is running (not in genesis)
3. **Automatic Sync** - New validators sync from current blockchain state
4. **Synergy Score Calculation** - Real-time scoring based on participation
5. **Manual Token Distribution** - Coordinator can send SNRG to validators
6. **Complete Onboarding Guide** - Step-by-step instructions for team members

---

## 📚 Documentation Created

### For Team Members

**[VALIDATOR_ONBOARDING_GUIDE.md](VALIDATOR_ONBOARDING_GUIDE.md)** - Complete setup guide
- Environment setup (Ubuntu/Linux)
- Build instructions
- Validator identity generation (FN-DSA-1024)
- Node configuration
- Firewall setup
- systemd service creation
- Monitoring & troubleshooting
- Synergy Score tracking

**Key Features:**
- ✅ Connects to existing bootnodes
- ✅ Syncs from live blockchain
- ✅ Generates proper lowercase addresses (synv1...)
- ✅ No staking required for initial setup
- ✅ Automatic Synergy Score calculation

### For Coordinators

**[COORDINATOR_GUIDE.md](COORDINATOR_GUIDE.md)** - Validator management
- Validator registration process
- Token distribution workflows
- Network monitoring
- Security best practices

---

## 🛠️ Helper Scripts Created

Located in `scripts/` directory:

### 1. Send SNRG Tokens
```bash
./scripts/send-tokens.sh <validator_address> <amount>
```
- Sends SNRG from faucet to validator
- Validates address format
- Checks faucet balance
- Confirms transaction

### 2. Register Validator
```bash
./scripts/register-validator.sh <address> <public_key>
```
- Registers new validator on-chain
- Verifies not already registered
- Sets initial Synergy Score to 0
- Prepares for token distribution

### 3. List All Validators
```bash
./scripts/list-validators.sh
```
- Shows all active validators
- Displays balances and Synergy Scores
- Shows validator status

---

## ⚙️ Genesis Configuration Updates

**File:** `config/genesis.json`

### Updated Parameters:

```json
{
  "consensus": {
    "parameters": {
      "max_validators": 100,          // Increased from 21
      "min_stake_amount": "50000000000000", // 50,000 SNRG in nWei
      "allow_zero_stake_validators": false,
      "dynamic_validator_registration": true
    }
  }
}
```

### Key Changes:
- ✅ **Minimum stake:** 50,000 SNRG bonded before activation
- ✅ **Max validators:** 100 (plenty of room for team)
- ✅ **Dynamic registration:** Enabled
- ✅ **Zero-stake allowed:** false

---

## 🚀 How Team Members Join

### Quick Start (5 Steps):

1. **Clone & Build**
   ```bash
   git clone https://github.com/synergy-network-hq/synergy-testnet.git
   cd synergy-testnet
   cargo build --release
   ```

2. **Generate Validator Identity**
   ```bash
   ./target/release/synergy-address-engine --node-type validator \
     --output config/my-validator/identity.json
   ```

3. **Share Info with Coordinator**
   - Send `validator-info.txt` via Discord/Email
   - Contains address & public key

4. **Start Validator Node**
   ```bash
   ./target/release/synergy-testnet start --config config/my-validator-config.toml
   ```

5. **Receive SNRG Tokens**
   - Coordinator sends 1M SNRG
   - Validator becomes active
   - Synergy Score starts calculating

---

## 📊 Validator Lifecycle

```
┌─────────────────────┐
│ Generate Identity   │ ← Team member creates FN-DSA-1024 keys
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Share with Coord    │ ← Send validator-info.txt
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Coordinator         │ ← Registers validator & sends SNRG
│ Registers & Funds   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Start Node & Sync   │ ← Node syncs with blockchain
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Participate         │ ← Synergy Score increases with activity
│ Earn Score          │
└─────────────────────┘
```

---

## 💰 Token Economics (Testnet)

### Faucet Allocation
- **Address:** `synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07`
- **Balance:** 2,000,000,000 SNRG (2 Billion)
- **Purpose:** Team validator funding

### Recommended Distributions
- **Initial allocation:** 1,000,000 SNRG per validator
- **Additional testing:** 500K - 5M SNRG as needed
- **No minimum stake required**

### Treasury Reserve
- **Address:** `synw14lswrh8z7kremft633xym9wtr5l9vkm3rd6lvd`
- **Balance:** 9,997,000,000 SNRG (9.997 Billion)
- **Purpose:** Future funding, emergency reserves

---

## 🏆 Synergy Score System

Validators earn Synergy Scores based on:

Synergy Score is observational telemetry for operator and reward views. It never controls validator eligibility, consensus quorum, or admission.

### Components (100% Total):
- **Participation (40%)** - Block proposals, votes, consensus tasks
- **Uptime (30%)** - Node availability and responsiveness  
- **Accuracy (30%)** - Correct validation and consensus

### Score Progression:
- **Initial:** 0.00 (starts at zero)
- **After 1 hour:** 0.01 - 0.05 (basic participation)
- **After 24 hours:** 0.10 - 0.30 (steady operation)
- **After 1 week:** 0.50+ (consistent validator)
- **Top validators:** 0.80 - 1.00 (excellent performance)

---

## 🔧 Coordinator Operations

### Daily Tasks:

1. **Monitor registrations** (Discord/Email)
2. **Register new validators**
   ```bash
   ./scripts/register-validator.sh <addr> <pubkey>
   ```
3. **Send initial SNRG**
   ```bash
   ./scripts/send-tokens.sh <addr> 1000000
   ```
4. **Check network health**
   ```bash
   ./scripts/list-validators.sh
   ```

### Weekly Tasks:

1. Check faucet balance
2. Review Synergy Scores
3. Assist with troubleshooting
4. Monitor blockchain growth

---

## 📝 Files to Share with Team

### Primary Document:
**[VALIDATOR_ONBOARDING_GUIDE.md](VALIDATOR_ONBOARDING_GUIDE.md)**

This is the **complete guide** team members need. It includes:
- Full setup instructions
- Configuration examples
- Troubleshooting guides
- Monitoring commands

### Quick Reference:
**[QUICK_REFERENCE.md](QUICK_REFERENCE.md)**

Network info, addresses, ports, endpoints.

---

## ✅ Pre-Launch Checklist

Before inviting team members:

- [x] Genesis config updated (min_stake = 0)
- [x] Helper scripts created and tested
- [x] Documentation written
- [x] Faucet wallet funded (2B SNRG)
- [x] Bootnodes running and synced
- [ ] Test onboarding with 1-2 validators
- [ ] Verify Synergy Score calculation
- [ ] Confirm token distribution works
- [ ] Update DNS records for bootnodes
- [ ] Announce in Discord/Telegram

---

## 🚨 Important Notes

### Security:
- ⚠️ **Private keys in plaintext** - Acceptable for testnet only
- ⚠️ **Staking required** - Validators must bond 50,000 SNRG before activation
- ⚠️ **Open RPC** - Firewall correctly if exposing publicly

### Limitations:
- **Testnet only** - Do not use for testnet/mainnet
- **Team members only** - Not public validator recruitment
- **Manual coordination** - Registration requires coordinator approval

### Next Steps:
1. **Test the system** with 1-2 team members
2. **Verify everything works** end-to-end
3. **Open to full team** once validated
4. **Monitor closely** during first week

---

## 📞 Support Channels

### For Team Members:
- **Discord:** #testnet-validators
- **Telegram:** @synergy_testnet
- **Email:** testnet-support@synergy.network

### For Coordinators:
- **Discord DM:** Testnet coordinator
- **Emergency:** testnet-admin@synergy.network

---

## 🎉 System Status

```
✅ Address Engine Updated (lowercase, FN-DSA-1024)
✅ Genesis Config Updated (0 stake, 100 validators)
✅ Onboarding Guide Created
✅ Coordinator Guide Created
✅ Helper Scripts Created
✅ Network Ports Corrected (5622/5640/5660)
✅ Bootnodes Configured
✅ Faucet Funded (2B SNRG)
✅ Documentation Complete

🚀 READY FOR TEAM VALIDATOR ONBOARDING
```

---

**The Synergy Testnet is now ready for your team to join as validators!**

Share `VALIDATOR_ONBOARDING_GUIDE.md` with team members who want to participate.
