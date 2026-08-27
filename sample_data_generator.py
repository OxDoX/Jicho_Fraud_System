"""
Generates synthetic transaction data with deliberately planted fraud
patterns matching the East/Central African typologies the engine detects.
This lets you demo/validate the engine without needing real bank data
(which you obviously can't use for a portfolio demo anyway).
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

random.seed(42)
np.random.seed(42)

rows = []
base_time = datetime(2026, 8, 20, 6, 0, 0)


def add(account_id, ttype, amount, ts, channel="mobile_money", counterparty_id=None,
        agent_id=None, initiated_by_staff=False, event_type="transaction"):
    rows.append({
        "transaction_id": f"TXN{len(rows)+1:06d}",
        "account_id": account_id,
        "transaction_type": ttype,
        "amount": amount,
        "timestamp": ts,
        "channel": channel,
        "counterparty_id": counterparty_id,
        "agent_id": agent_id,
        "initiated_by_staff": initiated_by_staff,
        "event_type": event_type,
    })


# --- Normal background traffic (noise) ---
for i in range(150):
    acct = f"ACC{random.randint(1000, 1050)}"
    ts = base_time + timedelta(hours=random.uniform(0, 96))
    add(acct, random.choice(["deposit", "withdrawal", "transfer_out", "cash_in"]),
        round(random.uniform(5_000, 300_000), -3), ts,
        channel=random.choice(["mobile_money", "bank_transfer"]))

# --- Pattern 1: SIM-swap cash-out (ACC2001) ---
t0 = base_time + timedelta(hours=10)
add("ACC2001", "sim_swap", 0, t0, event_type="sim_swap")
add("ACC2001", "withdrawal", 1_800_000, t0 + timedelta(hours=2))

# --- Pattern 2: Velocity spike (ACC2002) ---
t0 = base_time + timedelta(hours=20)
for i in range(5):
    add("ACC2002", "withdrawal", 150_000, t0 + timedelta(minutes=i * 5))

# --- Pattern 3: Structuring (ACC2003) — deposits just under 10M threshold ---
t0 = base_time + timedelta(hours=30)
for i in range(4):
    add("ACC2003", "deposit", 9_200_000 - i * 100_000, t0 + timedelta(hours=i * 3))

# --- Pattern 4: Mule fan-in / sweep-out (ACC2004) ---
t0 = base_time + timedelta(hours=40)
for i in range(6):
    add("ACC2004", "transfer_in", 400_000, t0 + timedelta(minutes=i * 20),
        counterparty_id=f"SENDER{i}")
add("ACC2004", "transfer_out", 2_200_000, t0 + timedelta(hours=3), counterparty_id="MULE_NEXT")

# --- Pattern 5: Agent till anomaly (AGENT500) ---
t0 = base_time + timedelta(hours=15)
add("ACC3001", "cash_in", 100_000, t0, channel="agent", agent_id="AGENT500")
add("ACC3002", "cash_out", 800_000, t0 + timedelta(minutes=10), channel="agent", agent_id="AGENT500")
add("ACC3003", "cash_out", 600_000, t0 + timedelta(minutes=20), channel="agent", agent_id="AGENT500")

# --- Pattern 6: Off-hours insider transaction (ACC2005) ---
t0 = base_time.replace(hour=23, minute=30) + timedelta(hours=50)
add("ACC2005", "transfer_out", 3_500_000, t0, initiated_by_staff=True)

# --- Pattern 7: Rapid cross-account layering (ACC2006 -> 2007 -> 2008 -> 2009) ---
t0 = base_time + timedelta(hours=60)
add("ACC2006", "transfer_out", 5_000_000, t0, counterparty_id="ACC2007")
add("ACC2007", "transfer_out", 4_900_000, t0 + timedelta(minutes=10), counterparty_id="ACC2008")
add("ACC2008", "transfer_out", 4_800_000, t0 + timedelta(minutes=25), counterparty_id="ACC2009")

# --- Pattern 8: Dormant mule account sudden inflow + sweep (Southern Africa EFT rail) ---
t0 = base_time + timedelta(hours=70)
add("ACC4001", "transfer_in", 3_200_000, t0, channel="bank_transfer", counterparty_id="VICTIM01")
add("ACC4001", "transfer_out", 3_000_000, t0 + timedelta(hours=1), channel="bank_transfer", counterparty_id="ACC4002")

# --- Pattern 9: Synchronized multi-account withdrawal spike (scheme collapse) ---
t0 = base_time + timedelta(hours=80)
for i in range(9):
    add(f"ACC50{i:02d}", "withdrawal", 250_000, t0 + timedelta(minutes=i * 2))

# --- Pattern 10: Fraudulent loan-app disbursement rapid cash-out ---
t0 = base_time + timedelta(hours=85)
add("ACC6001", "loan_disbursement", 900_000, t0, channel="mobile_money")
add("ACC6001", "cash_out", 880_000, t0 + timedelta(minutes=45), channel="agent")

# --- Pattern 11: EMV fallback abuse (high magstripe ratio at one merchant) ---
t0 = base_time + timedelta(hours=90)
for i in range(8):
    entry = "swipe" if i < 6 else "chip"  # 6/8 = 75% fallback rate, way above Visa's 1.5% threshold
    rows.append({
        "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": f"ACC70{i:02d}",
        "transaction_type": "pos_purchase", "amount": 45_000,
        "timestamp": t0 + timedelta(minutes=i * 5), "channel": "pos",
        "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
        "event_type": "transaction", "entry_mode": entry, "merchant_id": "MERCH900",
        "card_id": f"CARD70{i:02d}", "terminal_country": "TZ",
    })

# --- Pattern 12: Card testing (many small POS transactions on one card) ---
t0 = base_time + timedelta(hours=95)
for i in range(4):
    rows.append({
        "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC8001",
        "transaction_type": "pos_purchase", "amount": 5_000,
        "timestamp": t0 + timedelta(minutes=i * 3), "channel": "pos",
        "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
        "event_type": "transaction", "entry_mode": "card_not_present",
        "merchant_id": f"MERCH{i:03d}", "card_id": "CARD8001", "terminal_country": "TZ",
    })

# --- Pattern 13: Cross-border card velocity (impossible travel) ---
t0 = base_time + timedelta(hours=100)
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC9001",
    "transaction_type": "pos_purchase", "amount": 300_000,
    "timestamp": t0, "channel": "pos", "counterparty_id": None, "agent_id": None,
    "initiated_by_staff": False, "event_type": "transaction", "entry_mode": "chip",
    "merchant_id": "MERCH500", "card_id": "CARD9001", "terminal_country": "TZ",
})
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC9002",
    "transaction_type": "pos_purchase", "amount": 280_000,
    "timestamp": t0 + timedelta(hours=1), "channel": "pos", "counterparty_id": None,
    "agent_id": None, "initiated_by_staff": False, "event_type": "transaction",
    "entry_mode": "chip", "merchant_id": "MERCH501", "card_id": "CARD9001", "terminal_country": "KE",
})

# --- Pattern 14: Merchant refund anomaly (return fraud / collusion) ---
t0 = base_time + timedelta(hours=105)
for i in range(3):
    rows.append({
        "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": f"ACC110{i}",
        "transaction_type": "pos_purchase", "amount": 200_000,
        "timestamp": t0 + timedelta(minutes=i * 10), "channel": "pos",
        "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
        "event_type": "transaction", "entry_mode": "chip", "merchant_id": "MERCH700",
        "card_id": f"CARD110{i}", "terminal_country": "TZ",
    })
for i in range(2):
    rows.append({
        "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": f"ACC110{i}",
        "transaction_type": "refund", "amount": 190_000,
        "timestamp": t0 + timedelta(hours=1, minutes=i * 5), "channel": "pos",
        "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
        "event_type": "transaction", "entry_mode": "chip", "merchant_id": "MERCH700",
        "card_id": f"CARD110{i}", "terminal_country": "TZ",
    })



# --- Pattern 15: Offline authorization abuse (repeated offline-mode POS approvals) ---
t0 = base_time + timedelta(hours=110)
for i in range(4):
    rows.append({
        "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC1201",
        "transaction_type": "pos_purchase", "amount": 450_000,
        "timestamp": t0 + timedelta(minutes=i * 30), "channel": "pos",
        "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
        "event_type": "transaction", "auth_mode": "offline", "merchant_id": "MERCH800",
        "card_id": "CARD1201", "terminal_country": "TZ",
    })

# --- Pattern 16: BEC-pattern payment redirection ---
t0 = base_time + timedelta(hours=115)
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC1301",
    "transaction_type": "withdrawal", "amount": 0, "timestamp": t0, "channel": "bank_transfer",
    "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
    "event_type": "beneficiary_change",
})
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC1301",
    "transaction_type": "transfer_out", "amount": 4_500_000,
    "timestamp": t0 + timedelta(hours=2), "channel": "bank_transfer",
    "counterparty_id": "NEWBENEFICIARY", "agent_id": None, "initiated_by_staff": False,
    "event_type": "transaction",
})

# --- Pattern 17: Credential-phishing account takeover ---
t0 = base_time + timedelta(hours=120)
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC1401",
    "transaction_type": "withdrawal", "amount": 0, "timestamp": t0, "channel": "mobile_money",
    "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
    "event_type": "suspicious_login",
})
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC1401",
    "transaction_type": "transfer_out", "amount": 900_000,
    "timestamp": t0 + timedelta(minutes=15), "channel": "mobile_money",
    "counterparty_id": "ATTACKER_ACCT", "agent_id": None, "initiated_by_staff": False,
    "event_type": "transaction",
})

# --- Pattern 18: Rapid multi-terminal ATM withdrawal ---
t0 = base_time + timedelta(hours=125)
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC1501",
    "transaction_type": "withdrawal", "amount": 300_000, "timestamp": t0,
    "channel": "atm", "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
    "event_type": "transaction", "terminal_id": "ATM_CITY_A",
})
rows.append({
    "transaction_id": f"TXN{len(rows)+1:06d}", "account_id": "ACC1501",
    "transaction_type": "withdrawal", "amount": 280_000,
    "timestamp": t0 + timedelta(minutes=8), "channel": "atm",
    "counterparty_id": None, "agent_id": None, "initiated_by_staff": False,
    "event_type": "transaction", "terminal_id": "ATM_CITY_B",
})

df = pd.DataFrame(rows)
df.to_csv("data/sample_transactions.csv", index=False)
print(f"Generated {len(df)} transactions -> data/sample_transactions.csv")
