"""
Défi — Détection de fraude financière.
Lomé Business School — Édition 2026
"""

import csv
from datetime import datetime, timezone
import math


# ---------------------------------------------------------------------------
# Fourni par l'organisateur — ne pas modifier
# ---------------------------------------------------------------------------

def load_transactions(path):
    """Lit un fichier CSV de transactions et renvoie une liste de dicts."""
    transactions = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            transactions.append(_clean_row(row))
    return transactions


def _clean_row(row):
    def get(key):
        v = row.get(key)
        return v.strip() if isinstance(v, str) and v.strip() != "" else None

    amount_raw = get("amount")
    try:
        amount = float(amount_raw) if amount_raw is not None else None
    except ValueError:
        amount = None

    card_raw = get("card_present")
    if card_raw is None:
        card_present = None
    else:
        card_present = card_raw.lower() in ("true", "1", "yes", "oui")

    return {
        "transaction_id": get("transaction_id"),
        "timestamp":      get("timestamp"),
        "user_id":        get("user_id"),
        "amount":         amount,
        "currency":       get("currency"),
        "merchant":       get("merchant"),
        "country":        get("country"),
        "card_present":   card_present,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts_str):
    """Retourne un datetime UTC ou None si invalide/absent."""
    if not ts_str:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


COUNTRY_COORDS = {
    "FR": (46.2, 2.2),   "DE": (51.2, 10.5),  "GB": (55.4, -3.4),
    "ES": (40.5, -3.7),  "IT": (42.8, 12.8),  "US": (37.1, -95.7),
    "CN": (35.9, 104.2), "JP": (36.2, 138.3),  "BR": (-14.2, -51.9),
    "NG": (9.1, 8.7),    "ZA": (-30.6, 22.9),  "AU": (-25.3, 133.8),
    "RU": (61.5, 105.3), "IN": (20.6, 78.9),   "MX": (23.6, -102.6),
    "TG": (8.6, 0.8),    "GH": (7.9, -1.0),    "SN": (14.5, -14.5),
    "CI": (7.5, -5.5),   "CM": (3.9, 11.5),    "BE": (50.5, 4.5),
    "NL": (52.1, 5.3),   "CH": (46.8, 8.2),    "CA": (56.1, -106.3),
    "AR": (-38.4, -63.6),"KE": (-0.0, 37.9),   "MA": (31.8, -7.1),
}


def _haversine(c1, c2):
    """Distance en km entre deux (lat, lon)."""
    lat1, lon1 = math.radians(c1[0]), math.radians(c1[1])
    lat2, lon2 = math.radians(c2[0]), math.radians(c2[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
    return 6371 * 2 * math.asin(math.sqrt(a))


def _country_distance_km(c1, c2):
    if c1 and c2 and c1 != c2 and c1 in COUNTRY_COORDS and c2 in COUNTRY_COORDS:
        return _haversine(COUNTRY_COORDS[c1], COUNTRY_COORDS[c2])
    return 0.0


# ---------------------------------------------------------------------------
# Moteur de détection
# ---------------------------------------------------------------------------

def detect_fraud(transactions):
    """Analyse une liste de transactions et retourne un verdict par transaction."""
    if not transactions:
        return []

    # Étape 1 : Indexation pour préserver l'ordre original requis par pytest
    for i, tx in enumerate(transactions):
        tx["_original_index"] = i

    # Étape 2 : Tri chronologique strict pour l'analyse spatiotemporelle
    def get_tx_time(t):
        ts = _parse_ts(t.get("timestamp"))
        return ts if ts else datetime.min.replace(tzinfo=timezone.utc)

    sorted_transactions = sorted(transactions, key=get_tx_time)

    # Structures de suivi dynamiques (fil de l'eau)
    user_history_amounts = {}  # Seulement les montants sains validés
    user_history_txs = {}      # Toutes les transactions chronologiques passées
    seen_ids = set()
    sorted_results = []

    # Étape 3 : Analyse séquentielle
    for tx in sorted_transactions:
        tid = tx.get("transaction_id") or "UNKNOWN"
        uid = tx.get("user_id")
        amount = tx.get("amount")
        ts_str = tx.get("timestamp")
        country = tx.get("country")
        card_pres = tx.get("card_present")
        ts = _parse_ts(ts_str)

        score = 0.0
        reasons = []

        # ── NIVEAU 1 : Fondamentaux ──────────────────────────────────────
        
        # Champs critiques manquants
        missing = [f for f in ("transaction_id", "user_id", "amount", "currency")
                   if not tx.get(f) and tx.get(f) != 0]
        
        if missing:
            score = 1.0
            reasons.append(f"Champ(s) manquant(s) : {', '.join(missing)}")

        # Montant invalide ou absent
        if amount is None:
            score = 1.0
            reasons.append("Montant absent ou non lisible")
        elif amount <= 0:
            score = 1.0
            reasons.append(f"Montant invalide ({amount})")

        # Doublon d'identifiant
        if tid != "UNKNOWN" and tid in seen_ids:
            score = 1.0
            reasons.append("Identifiant de transaction dupliqué")
        if tid != "UNKNOWN":
            seen_ids.add(tid)

        # Si anomalie critique de Niveau 1, on arrête l'analyse ici
        if score >= 1.0:
            sorted_results.append({
                "_original_index": tx["_original_index"],
                "transaction_id": tid,
                "fraud_score": round(score, 2),
                "is_suspicious": True,
                "reason": " | ".join(reasons)
            })
            continue

        # Convertir de manière sûre après les vérifications de niveau 1
        current_amount = float(amount)

        # ── NIVEAU 2 : Logique métier ────────────────────────────────────
        if uid:
            # 1. Analyse de l'écart par rapport à l'historique strict PASSÉ
            previous_amounts = user_history_amounts.get(uid, [])
            if previous_amounts:
                mean = sum(previous_amounts) / len(previous_amounts)
                variance = sum((a - mean) ** 2 for a in previous_amounts) / len(previous_amounts)
                std = math.sqrt(variance)

                threshold = max(mean * 4, mean + 3 * std)
                if current_amount > threshold:
                    ratio = current_amount / mean
                    added = min(0.60, 0.15 * math.log(ratio))
                    score += added
                    reasons.append(f"Montant {ratio:.1f}× supérieur à la moyenne du client ({mean:.2f})")

            # 2. Analyse de fréquence et de vélocité spatiotemporelle
            past_txs = user_history_txs.get(uid, [])
            window_count = 0

            for other in reversed(past_txs):  # Parcourir du plus récent au plus ancien
                other_ts = _parse_ts(other.get("timestamp"))
                other_ctry = other.get("country")

                if other_ts and ts:
                    diff_sec = (ts - other_ts).total_seconds()
                    
                    if diff_sec >= 0:
                        # Fréquence (fenêtre de 5 min)
                        if diff_sec <= 300:
                            window_count += 1
                        
                        # Incohérence géographique
                        if other_ctry and country and other_ctry != country:
                            dist_km = _country_distance_km(country, other_ctry)
                            diff_h = diff_sec / 3600.0
                            
                            if dist_km > 500 and diff_h < 2:
                                score += 0.70
                                reasons.append(f"Géolocalisation impossible : {country} ↔ {other_ctry} ({dist_km:.0f} km) en {diff_h:.1f} h")
                                break
                            elif dist_km > 2000 and diff_h < 6:
                                score += 0.50
                                reasons.append(f"Déplacement suspect : {country} ↔ {other_ctry} ({dist_km:.0f} km) en {diff_h:.1f} h")
                                break

            if window_count >= 4:
                score += min(0.50, 0.10 * window_count)
                reasons.append(f"{window_count} autres transactions du même client en moins de 5 min")
            elif window_count >= 2:
                score += 0.25
                reasons.append(f"{window_count} autres transactions du même client en moins de 5 min")

        # Carte absente (CNP) pour un montant élevé
        if card_pres is False and current_amount > 500:
            score += 0.20
            reasons.append(f"Transaction sans carte physique pour un montant élevé ({current_amount:.2f})")

        # ── NIVEAU 3 : Finesse — réduction des faux positifs ────────────
        if uid and previous_amounts:
            mean = sum(previous_amounts) / len(previous_amounts)
            variance = sum((a - mean) ** 2 for a in previous_amounts) / len(previous_amounts)
            std = math.sqrt(variance)
            
            if mean > 0 and std > mean * 1.5 and score < 0.8:
                score *= 0.65
                reasons.append("(client aux dépenses très variables : score atténué)")

        # ── Normalisation finale ──────────────────────────────────────────
        score = min(max(score, 0.0), 1.0)
        is_suspicious = score >= 0.50

        if not reasons:
            reason_str = "Transaction légitime"
        else:
            reason_str = " | ".join(reasons)

        # On n'ajoute à l'historique des montants de référence QUE si elle n'est pas suspecte
        if not is_suspicious and uid:
            if uid not in user_history_amounts:
                user_history_amounts[uid] = []
            user_history_amounts[uid].append(current_amount)

        # On enregistre TOUTES les transactions dans l'historique spatiotemporel
        if uid:
            if uid not in user_history_txs:
                user_history_txs[uid] = []
            user_history_txs[uid].append(tx)

        sorted_results.append({
            "_original_index": tx["_original_index"],
            "transaction_id": tid,
            "fraud_score": round(score, 2),
            "is_suspicious": is_suspicious,
            "reason": reason_str,
        })

    # Remise en ordre d'origine pour valider pytest
    final_results = sorted(sorted_results, key=lambda r: r["_original_index"])
    
    # Nettoyage de la clé d'indexation
    for r in final_results:
        r.pop("_original_index", None)

    return final_results