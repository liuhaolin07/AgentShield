"""Unapplied finite-sample interval candidates, conditional on declared design.

Weighted Hoeffding supports arbitrary within-cluster dependence and unequal,
fixed family counts. Independence of clusters and outcome-independent weights/
eligibility are mathematical assumptions, not facts established by cluster IDs.
Clopper-Pearson is a separate iid binary-count diagnostic, not a replacement
for family/seed averages or paired contrasts.
"""

from functools import lru_cache
import math

import numpy as np

from paired_inference import ALPHA, MIN_CLUSTERS, STAT_IDS
from validate_intake import require

ASSUMPTIONS = {
    "independent_clusters": True,
    "cluster_membership_fixed_before_outcomes": True,
    "family_weights_fixed_before_outcomes": True,
    "eligibility_fixed_before_outcomes": True,
    "estimand": "conditional_expectation_given_frozen_design",
}


def weighted_hoeffding(lower, upper, clusters, *, assumptions):
    require(assumptions == ASSUMPTIONS, "explicit_design_assumptions_required")
    lower, upper = np.asarray(lower, dtype=float), np.asarray(upper, dtype=float)
    require(lower.shape == upper.shape == (len(clusters), 17) and len(clusters) > 0, "seventeen_family_components")
    require(all(isinstance(c, str) and c for c in clusters), "explicit_cluster_labels")
    present = np.isfinite(lower)
    require(np.array_equal(present, np.isfinite(upper)) and not np.isinf(lower).any()
            and not np.isinf(upper).any(), "paired_finite_or_absent")
    require(not np.isnan(lower[:, [j for j in range(17) if j != 3]]).any(), "only_h3_may_be_absent")
    require(np.all(lower[present] <= upper[present]), "ordered_identification_bounds")
    labels = sorted(set(clusters))
    statistics = {}
    for j, name in enumerate(STAT_IDS):
        domain = (0., 1.) if name.startswith("H5.TCR_conservative_") else (-1., 1.)
        mask = present[:, j]
        require(np.all(lower[mask, j] >= domain[0] - 1e-12)
                and np.all(upper[mask, j] <= domain[1] + 1e-12), "prespecified_parameter_domain")
        n = int(mask.sum())
        counts = np.array([np.count_nonzero(mask & (np.array(clusters) == c)) for c in labels])
        count_map = {c: int(k) for c, k in zip(labels, counts) if k}
        c = len(count_map)
        if not n:
            statistics[name] = {"families": 0, "clusters": 0, "domain": list(domain),
                "identification_bounds": None, "interval": None, "radius": None,
                "effective_clusters": None, "cluster_family_counts": {}, "flags": ["empty_h3_cohort"]}
            continue
        weights = counts / n
        sum_squares = float(np.sum(weights ** 2))
        radius = (domain[1] - domain[0]) * math.sqrt(math.log(2 * len(STAT_IDS) / ALPHA) * sum_squares / 2)
        empirical = [float(np.mean(lower[mask, j])), float(np.mean(upper[mask, j]))]
        statistics[name] = {"families": n, "clusters": c, "domain": list(domain),
            "identification_bounds": empirical,
            "interval": [max(domain[0], empirical[0] - radius), min(domain[1], empirical[1] + radius)],
            "radius": radius, "effective_clusters": 1 / sum_squares,
            "cluster_family_counts": count_map,
            "flags": ["fewer_than_30_eligible_clusters"] if c < MIN_CLUSTERS else []}
    return {"method": "weighted_cluster_Hoeffding_Bonferroni_candidate_v1", "statistics": statistics,
            "multiplicity": 17, "familywise_alpha": ALPHA,
            "coverage_guarantee": "at_least_0.95_conditional_on_declared_design_assumptions",
            "assumptions": assumptions.copy(), "assumptions_independently_verified": False,
            "real_data_coverage_validated": False, "power_validated": False,
            "applied_to_protocol": False, "confirmatory_success": False,
            "H5_superiority_claim_allowed": False, "experiment_authorized": False}


def binomial_tail(n, k, p, *, upper):
    """P(X >= k) if upper, otherwise P(X <= k), with direct log-PMF sum."""
    require(type(n) is int and 1 <= n <= 10000 and type(k) is int and 0 <= k <= n, "binomial_count")
    require(math.isfinite(p) and 0 <= p <= 1, "binomial_probability")
    if p == 0:
        return float(k == 0) if upper else 1.
    if p == 1:
        return 1. if upper else float(k == n)
    indices = range(k, n + 1) if upper else range(k + 1)
    result = math.fsum(math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                                + i * math.log(p) + (n - i) * math.log1p(-p)) for i in indices)
    return min(1., max(0., result))


@lru_cache(maxsize=256, typed=True)
def clopper_pearson(k, n):
    """Numerical inversion of exact binomial tails, alpha=.05/17.

    A 1e-12 outward pad covers inversion tolerance; this is floating-point
    numerical evaluation, not an interval-arithmetic proof of roundoff.
    """
    require(type(n) is int and 1 <= n <= 10000 and type(k) is int and 0 <= k <= n, "binomial_count")
    tail = ALPHA / (2 * len(STAT_IDS))
    if k == 0:
        lower = 0.
    elif k == n:
        lower = tail ** (1 / n)
    else:
        left, right = 0., 1.
        for _ in range(70):
            middle = (left + right) / 2
            if binomial_tail(n, k, middle, upper=True) < tail:
                left = middle
            else:
                right = middle
        lower = left
    if k == n:
        upper = 1.
    elif k == 0:
        upper = 1 - tail ** (1 / n)
    else:
        left, right = 0., 1.
        for _ in range(70):
            middle = (left + right) / 2
            if binomial_tail(n, k, middle, upper=False) > tail:
                left = middle
            else:
                right = middle
        upper = right
    return max(0., lower - 1e-12), min(1., upper + 1e-12)


def exact_binomial_coverage(n, p):
    require(type(n) is int and 1 <= n <= 1000, "enumeration_budget")
    require(math.isfinite(p) and 0 <= p <= 1, "binomial_probability")
    if p in (0, 1):
        return 1.
    return math.fsum(math.comb(n, k) * p ** k * (1 - p) ** (n - k)
                     for k in range(n + 1) if clopper_pearson(k, n)[0] <= p <= clopper_pearson(k, n)[1])
