"""
Cross-institution layering: technical readiness, not a solved problem.

Be precise about what this module is and is NOT. The underlying limitation
documented for R7 is genuinely structural, not technical: detecting a
layering chain that hops from Institution A to Institution B to Institution
C requires those institutions to compare notes, and that requires either a
bilateral/multilateral data-sharing agreement or a regulator-operated shared
utility — neither of which a codebase can create. No amount of engineering
here signs that agreement or stands up that utility.

What CAN be built now, so the system is technically ready the day such an
agreement exists, is the privacy-preserving matching primitive: a way for
two institutions to discover that they each saw a leg of the SAME layering
chain WITHOUT either one revealing raw account numbers to the other (or to
a third party) in the process. This module is that primitive, plus a
reference matching function proving it actually works. It is deliberately
NOT a network client, NOT a live integration with any regulator system, and
NOT something that should be pointed at another institution's data without
that institution's explicit, contractual agreement to participate — running
this against real data without such an agreement would just be a different
way of leaking account information, not a solution to the leak.
"""

import hashlib
from dataclasses import dataclass, field

import pandas as pd


def hash_account_id(account_id: str, salt: str) -> str:
    """Deterministically hashes an account identifier with a shared salt.

    The salt must be distributed only by a trusted party both institutions
    already agree to trust (e.g. the regulator operating the shared utility)
    and never by either institution to the other directly — if institution A
    chose the salt, institution B revealing a hash to A would let A brute-
    force-check specific account numbers it suspects, which defeats the
    privacy property. This function only implements the hashing step; salt
    distribution and rotation policy is an operational/legal decision for
    whoever operates the shared utility, not something this code can decide.
    """
    return hashlib.sha256(f"{salt}:{account_id}".encode()).hexdigest()


@dataclass
class LayeringFingerprint:
    """One exportable, privacy-preserving record of a single hop in a
    detected (or suspected) layering chain — safe to share with a regulator-
    operated matching utility because it contains no raw account identifiers,
    only salted hashes, an amount, and a timestamp.
    """
    hashed_account: str
    hashed_counterparty: str
    amount: float
    timestamp: str
    institution_id: str  # the exporting institution's own public identifier, not a secret

    def to_dict(self) -> dict:
        return {
            "hashed_account": self.hashed_account,
            "hashed_counterparty": self.hashed_counterparty,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "institution_id": self.institution_id,
        }


def export_layering_fingerprints(
    df: pd.DataFrame, salt: str, institution_id: str, amount_threshold: float = 0
) -> list[LayeringFingerprint]:
    """Builds the exportable fingerprint set for this institution's own
    transfer_out transactions above a threshold. This is what would be
    submitted to a regulator-run matching utility — never raw transaction
    data, only salted hashes plus amount/timestamp, which by design cannot
    be reversed to a raw account number without the salt.
    """
    transfers = df[(df["transaction_type"] == "transfer_out") & (df["amount"] >= amount_threshold)]
    fingerprints = []
    for _, row in transfers.iterrows():
        counterparty = row.get("counterparty_id")
        if pd.isna(counterparty) or counterparty is None:
            continue
        fingerprints.append(LayeringFingerprint(
            hashed_account=hash_account_id(row["account_id"], salt),
            hashed_counterparty=hash_account_id(counterparty, salt),
            amount=float(row["amount"]),
            timestamp=str(row["timestamp"]),
            institution_id=institution_id,
        ))
    return fingerprints


@dataclass
class CrossInstitutionMatch:
    hashed_account: str
    institutions_involved: list[str] = field(default_factory=list)
    hop_count: int = 0
    total_amount: float = 0.0

    def to_dict(self) -> dict:
        return {
            "hashed_account": self.hashed_account,
            "institutions_involved": self.institutions_involved,
            "hop_count": self.hop_count,
            "total_amount": self.total_amount,
        }


def match_cross_institution_chains(
    fingerprint_sets: list[list[LayeringFingerprint]], window_minutes: float = 45
) -> list[CrossInstitutionMatch]:
    """Reference implementation of what a regulator-operated matching utility
    would run: given fingerprint sets from MULTIPLE institutions (each
    containing only salted hashes, never raw identifiers), finds accounts
    that appear as a hop destination in one institution's data and a hop
    origin in another's within a short window — the cross-institution
    layering signature R7 cannot see on its own.

    This function is a proof that the matching works technically GIVEN that
    fingerprints from multiple institutions are already available to compare
    — it does not address how those fingerprints get to a common place
    safely, which is the actual unsolved part (a regulator-run utility, or a
    secure multi-party computation service, would own that role in
    production; this reference implementation assumes fingerprints are
    already in one trusted process, which is only true once that
    institutional/regulatory arrangement exists).
    """
    all_prints = [(fp, idx) for idx, fps in enumerate(fingerprint_sets) for fp in fps]
    matches: dict[str, CrossInstitutionMatch] = {}

    for fp, set_idx in all_prints:
        t0 = pd.Timestamp(fp.timestamp)
        for other_fp, other_idx in all_prints:
            if other_idx == set_idx:
                continue  # only cross-institution matches are interesting here
            if fp.hashed_counterparty != other_fp.hashed_account:
                continue
            t1 = pd.Timestamp(other_fp.timestamp)
            gap = t1 - t0
            if pd.Timedelta(0) <= gap <= pd.Timedelta(minutes=window_minutes):
                key = fp.hashed_counterparty
                if key not in matches:
                    matches[key] = CrossInstitutionMatch(hashed_account=key)
                m = matches[key]
                if fp.institution_id not in m.institutions_involved:
                    m.institutions_involved.append(fp.institution_id)
                if other_fp.institution_id not in m.institutions_involved:
                    m.institutions_involved.append(other_fp.institution_id)
                m.hop_count += 1
                m.total_amount += other_fp.amount

    return [m for m in matches.values() if len(m.institutions_involved) >= 2]
