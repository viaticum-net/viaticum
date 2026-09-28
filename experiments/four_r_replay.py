#!/usr/bin/env python3
"""Independent replay of the 4R shadow records (В-0, intent 4r-i45).

Reads a daemon log, takes every `four_r: record rec=<JSON>` line (DEBUG of the
`viaticum::four_r` target) and re-computes the shadow's decision from the RAW inputs the
record carries, by the formulas of the В-0 spec (private/beta-planning/tasks/v0_shadow.md,
В0-9 и) — NOT by translating the Rust code. Any difference is a mismatch.

    python3 experiments/four_r_replay.py [--dials CONFIG.toml] <daemon.log>

Output: one summary line
    four_r replay: records=N pressure=P offer=O notified_records=K phase_true=T
                   measure_invalid=I runs=R latch_pairs=L latch_pairs_true=LT
                   params_checked=C mismatches=M
plus one line per mismatch (record index, kind, field, want, got).
Exit code: 0 = every record replayed and N > 0; 1 = mismatches; 2 = no records.

What is re-derived from the RAW inputs, not taken from the record's aggregates (4r-i67):
  - the quota sums H / H_notified / H_mfd of a pressure record, from its holdings list;
  - the presence of our placements by master (R2 classes), by joining the raw placements
    (device, status, count) with the stored device -> master map, skipping the placeholder
    master and devices without a peer record;
  - the latch: the rule on the forecast phi, FROZEN (phase = phase_prev) on a tick whose
    measure is invalid (disk_free = 0, 4r-i66); and its CONTINUITY: within one run of the
    holder task (a run starts at the log line `holder_cleanup: started`, printed once per
    start of the task that alone writes the latch), a pressure record's phase_prev equals the
    previous pressure record's phase; an offer record (its shadow reads the latch concurrently
    with the tick) must carry the phase of the last pressure record or the one before it.
    `latch_pairs` counts the continuity checks made, `latch_pairs_true` those whose previous
    phase was `true` (a continuity check only ever made on `false` proves nothing about the
    persisted ON latch);
  - the aggregates of an offer record against its owner rows: H_notified equals the sum of
    the owners' notified bytes EXACTLY (both count every record with a notice, our own
    master's included), and H >= sum(parked + notified) + H_mfd (the difference is our own
    master's live bytes, which are neither parked nor notified);
  - with --dials: every record's params equal the [four_r] dials in CONFIG.toml (the file the
    scenario wrote; a dial absent from the file is reported, not assumed).

Comparison rules: lists and decisions exactly; kappa, phi, V_ret with relative tolerance
1e-9 (|a - b| <= 1e-9 * max(1, |a|)). The owner order is checked in two halves: every
kappa the record prints matches the formula (within the tolerance), and the printed order is
sorted by (printed kappa, observed_tau, master hex) — so a floating-point near-tie cannot
flip the verdict, while a wrong seat or a wrong tie rule still does.
"""

import json
import re
import sys

GB = float(1 << 30)
LAMBDA = 1.0 / 60.0  # the ledger's fast leak; the record also carries params.lambda
ZERO_KAPPA_EPS = 1e-6
VERSION = 2  # the record format this replay reads (v2: raw inputs of the presence join)
TOL = 1e-9
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def close(a, b):
    if a is None or b is None:
        return a is b
    return abs(a - b) <= TOL * max(1.0, abs(a))


class Checker:
    def __init__(self):
        self.mismatches = []

    def eq(self, idx, kind, field, want, got):
        if want != got:
            self.mismatches.append((idx, kind, field, want, got))

    def near(self, idx, kind, field, want, got):
        if not close(want, got):
            self.mismatches.append((idx, kind, field, want, got))


def quota(rec, h=None, hn=None):
    """Q and phi; H / H_notified from the arguments (re-summed) or from the record."""
    q = rec["quota"]
    h = q["h_all_bytes"] if h is None else h
    hn = q["h_notified_bytes"] if hn is None else hn
    base = h + q["disk_free_bytes"] - q["disk_reserve_bytes"]
    soft = q["soft_quota_bytes"]
    big_q = base if soft == 0 else min(soft, base)
    if big_q <= 0:
        return big_q, -1.0, -1.0, True
    return big_q, (big_q - h) / big_q, (big_q - (h - hn)) / big_q, False


def kappa_of(row, prm):
    """kappa = g_they + w_d * min(depth / d_ref, 1) * g*, d_ref = tau_ref * v_dem,
    g* = v_dem / lambda; d_ref <= 0 saturates the floor; no row -> 0."""
    if row is None:
        return 0.0
    v_dem = row["v_dem"]
    d_ref = prm["tau_ref_days"] * v_dem
    g_star = max(0.0, v_dem / (1.0 / 60.0)) if prm["lambda"] > 0 else 0.0
    depth = max(0.0, row["depth"])
    sat = min(depth / d_ref, 1.0) if d_ref > 0 else 1.0
    return row["g_they"] + max(0.0, prm["w_d"]) * sat * g_star


def quota_sums(rec):
    """H, H_notified, H_mfd from every holding of the pressure record (own master included):
    notified = drop notice sent; mfd = MarkedForDelete WITHOUT a notice."""
    h = hn = hm = 0
    for o in rec["owners"]:
        for x in o["holdings"]:
            h += x["bytes"]
            if x["notified"]:
                hn += x["bytes"]
            elif x["status"] == "MarkedForDelete":
                hm += x["bytes"]
    return h, hn, hm


PLACEHOLDER = "0" * 64
HELD = ("Alive", "Uncertain")


def presence_join(rec):
    """Presence by master from the raw placements and the stored device -> master map."""
    master_of = {x["device"]: x["master"] for x in rec["peer_masters"]}
    out = {}
    for pl in rec["placements"]:
        m = master_of.get(pl["device"])
        if m is None or m == PLACEHOLDER or pl["count"] <= 0:
            continue
        e = out.setdefault(m, {"master": m, "any": False, "held": False})
        e["any"] = True
        if pl["status"] in HELD:
            e["held"] = True
    return out


def zk_class(presence, master):
    p = presence.get(master)
    if p is not None and p["held"]:
        return "ServingUnconfirmed"
    if p is not None and p["any"]:
        return "Asked"
    return "NeverAsked"


def kendall(old, new):
    common_new = [m for m in new if m in set(old)]
    rank = {m: i for i, m in enumerate(common_new)}
    seq = [rank[m] for m in old if m in rank]
    n = len(seq)
    if n < 2:
        return None
    s = 0
    for i in range(n):
        for j in range(i + 1, n):
            s += 1 if seq[i] < seq[j] else -1
    return s / (n * (n - 1) / 2)


def replay_pressure(idx, rec, c):
    prm = rec["params"]
    out = rec["out"]
    own = rec["own_master"]
    k = "pressure"

    # 1. quota and phi, over H / H_notified / H_mfd re-summed from the holdings
    h_all, h_not, h_mfd = quota_sums(rec)
    c.eq(idx, k, "quota.h_all_bytes (re-summed)", h_all, rec["quota"]["h_all_bytes"])
    c.eq(idx, k, "quota.h_notified_bytes (re-summed)", h_not, rec["quota"]["h_notified_bytes"])
    c.eq(idx, k, "quota.h_mfd_bytes (re-summed)", h_mfd, rec["quota"]["h_mfd_bytes"])
    big_q, phi_a, phi_f, nonpos = quota(rec, h_all, h_not)
    c.eq(idx, k, "q_bytes", big_q, out["q_bytes"])
    c.eq(idx, k, "q_nonpositive", nonpos, out["q_nonpositive"])
    c.near(idx, k, "phi_actual", phi_a, out["phi_actual"])
    c.near(idx, k, "phi_forecast", phi_f, out["phi_forecast"])
    valid = rec["quota"]["disk_free_bytes"] != 0
    c.eq(idx, k, "measure_valid", valid, out["measure_valid"])

    # 2. the view: owners except our own master; holdings neither notified nor
    #    MarkedForDelete; symbols by (importance, block hex)
    view = {}
    mfd = []
    parked = {}
    tau = {}
    rows = {}
    for o in rec["owners"]:
        m = o["master"]
        if m == own:
            continue
        rows[m] = o["row"]
        tau[m] = o["row"]["observed_tau"] if o["row"] else 0.0
        syms = [h for h in o["holdings"] if not h["notified"] and h["status"] != "MarkedForDelete"]
        mfd += [(h["block"], m, h["bytes"]) for h in o["holdings"]
                if not h["notified"] and h["status"] == "MarkedForDelete"]
        if syms:
            view[m] = sorted(syms, key=lambda h: (h["importance"], h["block"]))
            parked[m] = sum(h["bytes"] for h in syms)
        c.eq(idx, k, "owners.parked_bytes " + m[:16], parked.get(m, 0), o["parked_bytes"])
    c.eq(idx, k, "parked_bytes", sorted(parked.items()),
         sorted((m, b) for m, b in out["parked_bytes"]))

    # 3. kappa
    kap_out = dict(out["kappa"])
    kap = {}
    for m in view:
        want = kappa_of(rows.get(m), prm)
        got = kap_out.get(m)
        c.near(idx, k, "kappa " + m[:16], want, got)
        # Downstream arithmetic uses the printed value when it agrees with the formula, so a
        # last-ulp difference cannot flip a V_ret boundary.
        kap[m] = got if (got is not None and close(want, got)) else want
    c.eq(idx, k, "kappa owners", sorted(view), sorted(kap_out))

    # 4. latch on the FORECAST phi — frozen when the node did not read its disk (4r-i66);
    #    accept only above s_soft and not evicting
    phase = rec["phase_prev"]
    if not valid:
        pass
    elif phi_f < prm["s_hard"]:
        phase = True
    elif phi_f >= prm["s_target"]:
        phase = False
    c.eq(idx, k, "phase", phase, out["phase"])
    c.eq(idx, k, "accept_ok", phi_f > prm["s_soft"] and not phase, out["accept_ok"])

    # 5. owner order: ascending (kappa, observed_tau, master hex)
    order = sorted(view, key=lambda m: (kap[m], tau[m], m))
    got_order = out["owner_order_new"]
    c.eq(idx, k, "owner_order set", sorted(order), sorted(got_order))
    for a, b in zip(got_order, got_order[1:]):
        ka, kb = kap_out.get(a, 0.0), kap_out.get(b, 0.0)
        ok = ka < kb or (ka == kb and (tau.get(a, 0.0), a) <= (tau.get(b, 0.0), b))
        if not ok:
            c.mismatches.append((idx, k, "owner_order pair", (a[:16], ka), (b[:16], kb)))
    order = [m for m in got_order if m in view] if sorted(order) == sorted(got_order) else order
    c.eq(idx, k, "first_owner_new", order[0] if order else None, out["first_owner_new"])

    # 6. the cap (latched and c_recip > 0): V_ret = V_free + kappa / c_recip, drop the lowest
    #    symbols of each owner while parked > V_ret; drop_order = the rest in the same order
    cap, drop_order = [], []
    if phase:
        for m in order:
            # V_parked summed in block order (the view's slot order), like the kernel.
            # (a plain left-to-right loop: Python >= 3.12 `sum` of floats is compensated).
            vol = 0.0
            for h in sorted(view[m], key=lambda h: h["block"]):
                vol += h["bytes"] / GB
            rest = []
            if prm["c_recip_days"] > 0:
                v_ret = prm["v_free_gb"] + kap[m] / prm["c_recip_days"]
                for h in view[m]:
                    if vol > v_ret:
                        cap.append((h["block"], m, h["bytes"]))
                        vol -= h["bytes"] / GB
                    else:
                        rest.append(h)
            else:
                rest = list(view[m])
            drop_order += [(h["block"], m, h["bytes"]) for h in rest]

    # 7. the plan: cap whole (floor only), then pressure down to s_target, MarkedForDelete
    #    (block hex) first; the hard_quota floor bounds both
    hard = rec["quota"]["hard_quota_bytes"]
    h_live = h_all - h_not
    planned = 0
    skipped = 0
    plan_cap, plan_mfd, plan_pr = [], [], []

    def phi_after(pl):
        return -1.0 if nonpos else (big_q - (h_live - pl)) / big_q

    if phase:
        for b, m, n in cap:
            if hard > 0 and h_live - planned - n < hard:
                skipped += n
                continue
            planned += n
            plan_cap.append([b, m])
        cands = [(b, m, n, "mfd") for b, m, n in sorted(mfd)] + \
                [(b, m, n, "pr") for b, m, n in drop_order]
        for b, m, n, why in cands:
            if not phi_after(planned) < prm["s_target"]:
                break
            if hard > 0 and h_live - planned - n < hard:
                skipped += n
                continue
            planned += n
            (plan_mfd if why == "mfd" else plan_pr).append([b, m])
    c.eq(idx, k, "cap", plan_cap, [list(x) for x in out["cap"]])
    c.eq(idx, k, "mfd", plan_mfd, [list(x) for x in out["mfd"]])
    c.eq(idx, k, "pressure", plan_pr, [list(x) for x in out["pressure"]])
    c.eq(idx, k, "floor_skipped_bytes", skipped, out["floor_skipped_bytes"])
    c.near(idx, k, "phi_forecast_after", phi_after(planned) if phase else phi_f,
           out["phi_forecast_after"])

    # 8. divergence from the old order; the old path's first immediate eviction (N-2).
    #    The old order itself cannot be re-derived here (the record does not carry the old
    #    path's trust and received_at); `first_owner_old` is checked against the old path's
    #    OWN plan (N-2) below, not against `old_owner_order[0]` — both come from one vector.
    old = rec["old_owner_order"]
    c.eq(idx, k, "top10_overlap", len(set(old[:10]) & set(got_order[:10])), out["top10_overlap"])
    c.near(idx, k, "kendall_tau", kendall(old, got_order), out["kendall_tau"])
    op = rec.get("old_plan") or {}
    if op.get("pressure") == "Hard" and op.get("immediate"):
        c.eq(idx, k, "first_owner_old vs old_plan.immediate[0]", op["immediate"][0][1],
             out["first_owner_old"])

    # zero-kappa classes (R2) from the presence of our placements — the replay's OWN join of
    # the raw placements with the device -> master map; the shadow's join must agree
    presence = presence_join(rec)
    c.eq(idx, k, "presence (join)", sorted((m, p["any"], p["held"]) for m, p in presence.items()),
         sorted((p["master"], p["any"], p["held"]) for p in rec["presence"]))
    zk = {"total": 0, "never_asked": 0, "asked": 0, "serving_unconfirmed": 0}
    classes = []
    col = {"NeverAsked": "never_asked", "Asked": "asked", "ServingUnconfirmed": "serving_unconfirmed"}
    for m in sorted(view):
        if kap[m] < ZERO_KAPPA_EPS:
            cl = zk_class(presence, m)
            zk["total"] += parked[m]
            zk[col[cl]] += parked[m]
            classes.append([m, cl])
    c.eq(idx, k, "zk", zk, out["zk"])
    c.eq(idx, k, "zk_class", classes, [list(x) for x in out["zk_class"]])
    return phase


RUN_START = "holder_cleanup: started"
DIALS = ("v_free_gb", "c_recip_days", "w_d", "tau_ref_days", "theta_p", "v_min_gb",
         "s_hard", "s_target", "s_soft")


def read_dials(path):
    """The [four_r] section of a node's config.toml: `key = number` lines (the scenario writes
    plain numbers; no inline tables, no strings)."""
    dials, section = {}, None
    with open(path) as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("["):
                section = line.strip("[] ")
                continue
            if section == "four_r" and "=" in line:
                key, val = (x.strip() for x in line.split("=", 1))
                if key in DIALS:
                    dials[key] = float(val)
    return dials


def check_params(idx, rec, dials, c):
    prm = rec["params"]
    for key in DIALS:
        if key not in dials:
            c.mismatches.append((idx, rec["kind"], "params." + key, "absent from --dials file",
                                 prm.get(key)))
        else:
            c.eq(idx, rec["kind"], "params." + key + " vs config", dials[key], prm.get(key))
    c.near(idx, rec["kind"], "params.lambda", LAMBDA, prm.get("lambda"))


def read_log(path):
    """[(run, record)] in log order; `run` counts RUN_START lines seen so far."""
    out, run = [], 0
    with open(path, errors="replace") as f:
        for line in f:
            line = ANSI.sub("", line)
            if RUN_START in line:
                run += 1
                continue
            if "four_r: record" not in line or "rec=" not in line:
                continue
            out.append((run, json.loads(line.split("rec=", 1)[1].strip())))
    return out


def main():
    args = sys.argv[1:]
    dials = None
    if len(args) == 3 and args[0] == "--dials":
        dials = read_dials(args[1])
        args = args[2:]
    if len(args) != 1:
        print(__doc__)
        return 2
    records = read_log(args[0])
    c = Checker()
    n_pressure = n_offer = n_notified = n_phase = n_invalid = 0
    n_params = n_latch = n_latch_true = 0
    runs = set()
    last = {}  # run -> (phase_prev, phase) of the last pressure record of that run
    for idx, (run, rec) in enumerate(records):
        runs.add(run)
        if rec.get("v") != VERSION:
            c.mismatches.append((idx, rec.get("kind"), "version", VERSION, rec.get("v")))
            continue
        if dials is not None:
            check_params(idx, rec, dials, c)
            n_params += 1
        if rec["kind"] == "pressure":
            n_pressure += 1
            if rec["quota"]["h_notified_bytes"] > 0:
                n_notified += 1
            if rec["quota"]["disk_free_bytes"] == 0:
                n_invalid += 1
            phase = replay_pressure(idx, rec, c)
            if phase:
                n_phase += 1
            if run in last:
                c.eq(idx, "pressure", "latch continuity (phase_prev = previous phase)",
                     last[run][1], rec["phase_prev"])
                n_latch += 1
                if last[run][1]:
                    n_latch_true += 1
            last[run] = (rec["phase_prev"], rec["out"]["phase"])
        elif rec["kind"] == "offer":
            n_offer += 1
            replay_offer(idx, rec, c)
            if run in last and rec["phase_prev"] not in last[run]:
                c.mismatches.append((idx, "offer", "latch (phase of the last two ticks)",
                                     last[run], rec["phase_prev"]))
        else:
            c.mismatches.append((idx, rec["kind"], "kind", "pressure|offer", rec["kind"]))
    print(f"four_r replay: records={len(records)} pressure={n_pressure} offer={n_offer} "
          f"notified_records={n_notified} phase_true={n_phase} measure_invalid={n_invalid} "
          f"runs={len(runs)} latch_pairs={n_latch} latch_pairs_true={n_latch_true} "
          f"params_checked={n_params} "
          f"mismatches={len(c.mismatches)}")
    for idx, kind, field, want, got in c.mismatches[:50]:
        print(f"  MISMATCH record={idx} kind={kind} field={field} want={want} got={got}")
    if not records:
        return 2
    return 1 if c.mismatches else 0


def replay_offer(idx, rec, c):
    """Offer records: the holder layer (Q <= 0, a notified block, Р-17 on the free path) and
    the kernel's nine steps over the owner AGGREGATES (В0-9 б/и p.9)."""
    prm = rec["params"]
    out = rec["out"]
    adm = out["admit"]
    off = rec["offer"]
    own = rec["own_master"]
    k = "offer"
    big_q, phi_a, phi_f, nonpos = quota(rec)
    c.eq(idx, k, "q_bytes", big_q, out["q_bytes"])
    c.near(idx, k, "phi_actual", phi_a, out["phi_actual"])
    free_now = max(0, big_q - rec["quota"]["h_all_bytes"]) / GB
    v_offer = off["offer_bytes"] / GB

    # cheap aggregate checks: the quota sums against the owner rows of the same holdings read
    # (raw_owners counts notified bytes for EVERY master, our own included; parked excludes
    # our own master, notified and MarkedForDelete records).
    qa = rec["quota"]
    sum_notified = sum(o["notified_bytes"] for o in rec["owners"])
    sum_parked = sum(o["parked_bytes"] for o in rec["owners"])
    c.eq(idx, k, "quota.h_notified_bytes = sum(owners.notified_bytes)", sum_notified,
         qa["h_notified_bytes"])
    if qa["h_all_bytes"] < sum_parked + sum_notified + qa["h_mfd_bytes"]:
        c.mismatches.append((idx, k, "quota.h_all_bytes >= sum(parked + notified) + h_mfd",
                             f">= {sum_parked + sum_notified + qa['h_mfd_bytes']}",
                             qa["h_all_bytes"]))

    # the view from the aggregates: owners (not our master) with in-view bytes
    rows = {o["master"]: o["row"] for o in rec["owners"]}
    parked = {o["master"]: o["parked_bytes"] for o in rec["owners"]
              if o["master"] != own and o["parked_bytes"] > 0}
    notified = {o["master"]: o["notified_bytes"] for o in rec["owners"]}
    kap_out = dict(out["kappa"])
    kap = {}
    for m in parked:
        want = kappa_of(rows.get(m), prm)
        got = kap_out.get(m)
        c.near(idx, k, "kappa " + m[:16], want, got)
        kap[m] = got if (got is not None and close(want, got)) else want
    k_off = kappa_of(off["offerer_row"], prm)
    c.near(idx, k, "offerer_kappa", k_off, adm["offerer_kappa"])
    k_off = adm["offerer_kappa"] if close(k_off, adm["offerer_kappa"]) else k_off
    v_parked = parked.get(off["owner"], 0) / GB
    c.eq(idx, k, "offerer_parked_bytes", parked.get(off["owner"], 0), adm["offerer_parked_bytes"])
    c.eq(idx, k, "offerer_notified_bytes", notified.get(off["owner"], 0), adm["offerer_notified_bytes"])
    c.eq(idx, k, "parked_bytes", sorted(parked.items()),
         sorted((m, b) for m, b in out["parked_bytes"] if b > 0))
    cap_on = prm["c_recip_days"] > 0
    v_ret = (prm["v_free_gb"] + k_off / prm["c_recip_days"]) if cap_on else None
    c.near(idx, k, "v_ret_offerer_gb", v_ret, adm["v_ret_offerer_gb"])
    lam = 1.0 / 60.0
    margin = prm["theta_p"] * (max(v_offer, prm["v_min_gb"]) / lam if lam > 0 else 0.0)
    c.near(idx, k, "margin", margin, adm["margin"])
    # the candidate victim: argmin kappa over the view, not the offerer; ties -> master hex
    cand = None
    for m in sorted(parked):
        if m == off["owner"]:
            continue
        if cand is None or kap[m] < kap[cand]:
            cand = m
    c.eq(idx, k, "candidate", cand, adm["candidate"])
    c.near(idx, k, "victim_kappa", kap[cand] if cand else None, adm["victim_kappa"])

    phase = rec["phase_prev"]
    tag, reason, victims = None, None, []
    if nonpos:
        tag, reason = "Reject", "QuotaNonPositive"
    elif off["offer_block_notified"]:
        tag, reason = "Reject", "NotifiedBlock"
    elif phi_a > prm["s_soft"] and not phase and free_now >= v_offer:           # 1
        tag = "Free"
        if notified.get(off["owner"], 0) > 0 and cap_on and v_parked + v_offer > v_ret:
            tag, reason = "Reject", "GuardWhileNotified"                        # Р-17
    elif not (prm["theta_p"] == prm["theta_p"] and abs(prm["theta_p"]) != float("inf")
              and prm["theta_p"] >= 0):                                           # 2
        tag, reason = "Reject", "PreemptDisabled"
    elif cap_on and v_parked + v_offer > v_ret:                                   # 4
        tag, reason = "Reject", "Guard"
    elif cand is None:                                                            # 5
        tag, reason = "Reject", "NoVictim"
    elif k_off <= kap[cand] + margin:                                             # 6
        tag, reason = "Reject", "Margin"
    else:
        vh = sorted(rec["victim_holdings"] or [], key=lambda h: (h["importance"], h["block"]))
        acc = 0.0
        for h in vh:                                                              # 7
            if acc >= v_offer:
                break
            acc += h["bytes"] / GB
            victims.append([h["block"], cand])
        if acc < v_offer:
            tag, reason, victims = "Reject", "VictimTooSmall", []
        elif free_now < v_offer:                                                  # 8
            tag, reason, victims = "Reject", "NoRoomNow", []
        else:
            tag = "Preempt"                                                       # 9
    c.eq(idx, k, "tag", tag, adm["tag"])
    c.eq(idx, k, "reason", reason, adm["reason"])
    c.eq(idx, k, "victim", cand if tag == "Preempt" else None, adm["victim"])
    c.eq(idx, k, "victims", victims, [list(x) for x in adm["victims"]])


if __name__ == "__main__":
    sys.exit(main())
