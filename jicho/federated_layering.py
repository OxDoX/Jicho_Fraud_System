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

# Real account identifiers (sequential account numbers, or a mobile-money
# ID keyed to a phone number) are LOW-ENTROPY — often just a 9-11 digit
# space. A single pass of a fast hash like SHA-256 does not protect a
# low-entropy secret: this is the exact same reasoning password-storage
# standards use to mandate a slow KDF instead of raw SHA-256, and it
# applies here for the same reason. Confirmed directly during this
# module's own development: plain salted SHA-256 brute-forces a 10-digit
# account-number space at ~660,000 candidates/sec on a single CPU core in
# pure Python — seconds on commodity hardware, faster still on a GPU —
# once the salt is known to (or guessed by) whoever holds a fingerprint.
# That directly defeats the property hash_account_id's own docstring
# describes wanting ("so an institution can't brute-force-check specific
# account numbers it suspects").
#
# PBKDF2-HMAC-SHA256 (stdlib, no new dependency) makes each guess this
# much slower to compute — a real, if partial, mitigation, not a complete
# fix: it doesn't make a genuinely small ID space (say, under a million
# possibilities) infeasible to brute-force, and Argon2id would resist a
# GPU/ASIC attacker considerably better than PBKDF2 can. OWASP currently
# recommends 600,000 iterations for PBKDF2-HMAC-SHA256 in the password-
# storage context (a login checked once per session); this reference
# implementation may hash many account IDs per export call, so
# PBKDF2_ITERATIONS is set lower for practicality, and export_layering_fingerprints()
# caches each account_id's hash within one export rather than recomputing
# it per transaction row. Whoever actually operates a production matching
# utility should tune this iteration count against their own transaction
# volume and threat model — this default is a reference starting point,
# not a claim that it's sufficient for every deployment's account-ID
# entropy.
PBKDF2_ITERATIONS = 100_000


def hash_account_id(account_id: str, salt: str) -> str:
    """Hashes an account identifier with a shared salt via PBKDF2-HMAC-SHA256
    (see PBKDF2_ITERATIONS above for why a single fast hash isn't enough).

    The salt must be distributed only by a trusted party both institutions
    already agree to trust (e.g. the regulator operating the shared utility)
    and never by either institution to the other directly — if institution A
    chose the salt, institution B revealing a hash to A would let A brute-
    force-check specific account numbers it suspects, which defeats the
    privacy property. This function only implements the hashing step; salt
    distribution and rotation policy is an operational/legal decision for
    whoever operates the shared utility, not something this code can decide.
    """
    return hashlib.pbkdf2_hmac("sha256", account_id.encode(), salt.encode(), PBKDF2_ITERATIONS, dklen=32).hex()


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
    # PBKDF2 is deliberately slow (see PBKDF2_ITERATIONS); an institution's
    # own account IDs repeat across many transactions, so hash each distinct
    # ID once per export call rather than once per row.
    hash_cache: dict[str, str] = {}

    def _cached_hash(account_id: str) -> str:
        if account_id not in hash_cache:
            hash_cache[account_id] = hash_account_id(account_id, salt)
        return hash_cache[account_id]

    for _, row in transfers.iterrows():
        counterparty = row.get("counterparty_id")
        if pd.isna(counterparty) or counterparty is None:
            continue
        fingerprints.append(LayeringFingerprint(
            hashed_account=_cached_hash(row["account_id"]),
            hashed_counterparty=_cached_hash(counterparty),
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
