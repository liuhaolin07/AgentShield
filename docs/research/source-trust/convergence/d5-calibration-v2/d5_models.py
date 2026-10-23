"""D5 engineering generators; mathematical components are not task executions."""
from functools import lru_cache
from numbers import Real

import numpy as np

from paired_inference import ALPHA, STAT_IDS, SEEDS, cluster_draw_counts, recipes, reduce_families, required_keys
from validate_intake import require
from validate_statistics import synthetic_components


def _endpoint_marginals(name):
    panel, rate, _, policy, metric = name.split("|")
    p = float(rate)
    if metric == "ASR":
        return (.04 + (.4*p if panel == "SP" else 0) + (.04 if panel == "targeted" else 0)
                if policy == "precision" else .01 + (.1*p if panel == "SP" else 0))
    tcr = (.94 - (.2*p if panel == "PS" else .12*p if panel == "SP" else 0)
           if policy == "precision" else .90 - (.18*p if panel == "SP" else 0))
    return tcr if metric == "TCR" else .5 * (1-tcr)


def _conditional_probability(name, marginal, scale, q):
    panel, rate, _, _, metric = name.split("|")
    shock = scale*float(rate)*(q-.2) if panel != "E0" else 0.
    return marginal + shock*(1 if metric == "ASR" else -1 if metric == "TCR" else .5)


def _binary_dataset(scenario, rng, include_families):
    _, _, labels, _ = synthetic_components({**scenario, "generator": "constant_components"}, rng)
    names = sorted(required_keys())
    marginals = {name: _endpoint_marginals(name) for name in names}
    groups = sorted({(name.rsplit("|", 1)[0], "attack" if name.endswith("|ASR") else "benign")
                     for name in names})
    group_index = {group: j for j, group in enumerate(groups)}
    labels_unique = sorted(set(labels))
    cluster_index = {label: c for c, label in enumerate(labels_unique)}
    # Fix membership before any endpoint, cluster error or missingness draw.
    eligible_labels = set(labels_unique[:scenario.get("h3_eligible_clusters", len(labels_unique))])
    q = rng.binomial(1, .2, len(labels_unique))
    cluster_u = rng.random((len(labels_unique), 2))
    family_u = rng.random((len(labels), 2))
    selectors = rng.random((len(labels), len(groups)))
    independent_u = rng.random((len(labels), len(groups)))
    wc = scenario.get("shared_cluster_uniform_weight", 0.)
    wf = scenario.get("shared_family_uniform_weight", 0.)
    shock_scale = scenario.get("error_shock_scale", 0.)
    families = []
    for i, label in enumerate(labels):
        c, values = cluster_index[label], {}
        for name in names:
            condition, metric = name.rsplit("|", 1)
            task_kind = "attack" if metric == "ASR" else "benign"
            j, t = group_index[(condition, task_kind)], int(task_kind == "benign")
            u = (cluster_u[c, t] if selectors[i, j] < wc else
                 family_u[i, t] if selectors[i, j] < wc+wf else independent_u[i, j])
            probability = _conditional_probability(name, marginals[name], shock_scale, q[c])
            value = int(u >= 1-probability) if metric == "FPR" else int(u < probability)
            values[name] = {"value": value, "observed": True}
        families.append({"family_id": f"f{i:09d}", "template_cluster_id": label,
                         "H3_eligible_by_seed": {str(s): label in eligible_labels for s in SEEDS}, "values": values})
    if scenario.get("missingness", "none") == "outcome_dependent":
        missing_u = rng.random((len(labels), len(groups)))
        for i, family in enumerate(families):
            task_missing = {}
            for j, (condition, kind) in enumerate(groups):
                metric = "ASR" if kind == "attack" else "TCR"
                success = family["values"][condition + "|" + metric]["value"]
                adverse = success == (1 if kind == "attack" else 0)
                task_missing[(condition, kind)] = missing_u[i, j] < (.25 if adverse else .02)
            for name in names:
                condition, metric = name.rsplit("|", 1)
                kind = "attack" if metric == "ASR" else "benign"
                if task_missing[(condition, kind)]:
                    family["values"][name].update(value=None, observed=False)
    missing_count = sum(not value["observed"] for f in families for value in f["values"].values())
    reduced = reduce_families(families)
    truth = np.array([sum(c*marginals[name] for name, c in terms.items()) for terms in recipes().values()])
    if not eligible_labels:
        truth[3] = np.nan
    result = {k: reduced[k] for k in ("lower", "upper", "clusters")}
    result.update(truth=truth, metadata={
        "family_count": len(labels), "cluster_count": len(set(labels)),
        "endpoint_count": len(labels)*len(names), "missing_endpoint_count": missing_count,
        "analytic_truth_scope": "unconditional endpoint marginals; equal families; fixed preexecution H3 cohort"})
    if include_families:
        result["families"] = families
    return result


@lru_cache(maxsize=1)
def _endpoint_design():
    """Cache the fixed endpoint grid and the old recipe's exact addition order."""
    names = tuple(sorted(required_keys()))
    columns = {name: j for j, name in enumerate(names)}
    parsed = [name.split("|") for name in names]
    group_keys = [(name.rsplit("|", 1)[0], "attack" if row[4] == "ASR" else "benign")
                  for name, row in zip(names, parsed)]
    groups = sorted(set(group_keys))
    group_columns = {group: j for j, group in enumerate(groups)}
    coefficients = np.zeros((17, len(names)))
    orders, truth = [], []
    marginals = np.array([_endpoint_marginals(name) for name in names])
    for j, terms in enumerate(recipes().values()):
        order = np.array([columns[name] for name in terms], dtype=int)
        orders.append(order)
        coefficients[j, order] = list(terms.values())
        truth.append(sum(c*float(marginals[columns[name]]) for name, c in terms.items()))
    design = {"names": names, "marginals": marginals, "coefficients": coefficients,
              "orders": tuple(orders), "truth": np.array(truth),
              "rates": np.array([float(row[1]) for row in parsed]),
              "effect_sign": np.array([1. if row[4] == "ASR" else -1. if row[4] == "TCR" else .5 for row in parsed]),
              "is_fpr": np.array([row[4] == "FPR" for row in parsed]),
              "is_attack": np.array([row[4] == "ASR" for row in parsed]),
              "group_index": np.array([group_columns[group] for group in group_keys]),
              "group_success_column": np.array([columns[condition + ("|ASR" if kind == "attack" else "|TCR")]
                                                 for condition, kind in groups]),
              "group_kind": np.array([int(group[1] == "benign") for group in groups])}
    for value in (*design.values(), *orders):
        if isinstance(value, np.ndarray):
            value.setflags(write=False)
    return design


@lru_cache(maxsize=32)
def _binary_layout(cluster_count, size_name):
    cycle = {"one": [1], "two": [2], "cycle_1_2_3": [1, 2, 3], "sixty": [60]}[size_name]
    labels = tuple(f"c{i:03d}" for i in range(cluster_count) for _ in range(cycle[i % len(cycle)]))
    rank = {label: j for j, label in enumerate(sorted(set(labels)))}
    index = np.array([rank[label] for label in labels])
    index.setflags(write=False)
    return tuple("template:" + label for label in labels), index


@lru_cache(maxsize=32)
def _check_binary_probability_support(scale):
    design = _endpoint_design()
    columns = {name: j for j, name in enumerate(design["names"])}
    for q in (0, 1):
        shock = scale*design["rates"]*(q-.2)
        probability = design["marginals"] + shock*design["effect_sign"]
        require(np.isfinite(probability).all() and ((0 <= probability) & (probability <= 1)).all(),
                "endpoint_probability_out_of_bounds")
        for name in design["names"]:
            if name.endswith("|FPR"):
                require(probability[columns[name]] + probability[columns[name[:-3]+"TCR"]] <= 1,
                        "benign_tcr_fpr_exclusivity_probability")


def _binary_array_dataset(scenario, rng):
    """Same draws as the inspectable family oracle, with no endpoint objects."""
    design = _endpoint_design()
    clusters, index = _binary_layout(scenario["clusters"], scenario["sizes"])
    n, c, g = len(clusters), scenario["clusters"], len(design["group_kind"])
    # Keep shapes and call order identical to _binary_dataset, including q=0.
    q = rng.binomial(1, .2, c)
    cluster_u = rng.random((c, 2))
    family_u = rng.random((n, 2))
    selectors = rng.random((n, g))
    independent_u = rng.random((n, g))
    wc, wf = scenario.get("shared_cluster_uniform_weight", 0.), scenario.get("shared_family_uniform_weight", 0.)
    # Categorical source selection, not a weighted sum of uniforms.
    uniforms = np.where(selectors < wc, cluster_u[index[:, None], design["group_kind"]],
                        np.where(selectors < wc+wf, family_u[:, design["group_kind"]], independent_u))
    endpoint_u = uniforms[:, design["group_index"]]
    shock = scenario.get("error_shock_scale", 0.)*design["rates"]*(q[index, None]-.2)
    probability = design["marginals"] + shock*design["effect_sign"]
    values = np.where(design["is_fpr"], endpoint_u >= 1-probability, endpoint_u < probability)
    missing = np.zeros(values.shape, dtype=bool)
    if scenario.get("missingness", "none") == "outcome_dependent":
        missing_u = rng.random((n, g))
        adverse = values[:, design["group_success_column"]] == (design["group_kind"] == 0)
        task_missing = missing_u < np.where(adverse, .25, .02)
        missing = task_missing[:, design["group_index"]]
    endpoint_lo, endpoint_hi = np.where(missing, 0., values), np.where(missing, 1., values)
    lower, upper = np.zeros((n, 17)), np.zeros((n, 17))
    for j, order in enumerate(design["orders"]):
        coefficients = design["coefficients"][j, order]
        lo_terms = coefficients*np.where(coefficients >= 0, endpoint_lo[:, order], endpoint_hi[:, order])
        hi_terms = coefficients*np.where(coefficients >= 0, endpoint_hi[:, order], endpoint_lo[:, order])
        # Sequential cumsum preserves the OLD recipe's floating-point sum order;
        # a BLAS dot product is faster but need not be bit-for-bit identical.
        lower[:, j] = np.cumsum(np.column_stack((np.zeros(n), lo_terms)), axis=1)[:, -1]
        upper[:, j] = np.cumsum(np.column_stack((np.zeros(n), hi_terms)), axis=1)[:, -1]
    k = scenario.get("h3_eligible_clusters", c)
    lower[index >= k, 3] = upper[index >= k, 3] = np.nan
    truth = design["truth"].copy()
    if not k:
        truth[3] = np.nan
    return {"lower": lower, "upper": upper, "truth": truth, "clusters": list(clusters),
            "metadata": {"family_count": n, "cluster_count": c, "endpoint_count": values.size,
                         "missing_endpoint_count": int(missing.sum()),
                         "analytic_truth_scope": "unconditional endpoint marginals; equal families; fixed preexecution H3 cohort"}}


_LEGACY_GENERATORS = frozenset(("bounded_correlated_components", "cluster_bernoulli",
                                "constant_components"))


def _validate_scenario(scenario, include_families):
    require(isinstance(scenario, dict), "scenario_mapping")
    require(isinstance(scenario.get("id"), str) and bool(scenario["id"]), "scenario_id")
    kind, clusters = scenario.get("generator"), scenario.get("clusters")
    require(isinstance(kind, str) and kind in _LEGACY_GENERATORS | {"zero_components", "binary_endpoint_process"},
            "known_simulation_generator")
    require(type(clusters) is int and clusters > 0, "positive_integer_clusters")
    require(scenario.get("sizes") in ("one", "two", "cycle_1_2_3", "sixty"), "known_cluster_sizes")
    require(scenario.get("missingness", "none") in ("none", "outcome_dependent"), "known_missingness")
    require(not include_families or kind == "binary_endpoint_process", "families_require_binary_endpoint_process")
    k = scenario.get("h3_eligible_clusters", clusters)
    require(type(k) is int and 0 <= k <= clusters, "fixed_h3_cohort_cluster_count")
    parameters = {}
    for name in ("shared_cluster_uniform_weight", "shared_family_uniform_weight", "error_shock_scale"):
        value = scenario.get(name, 0.)
        require(isinstance(value, Real) and not isinstance(value, (bool, np.bool_))
                and np.isfinite(value) and value >= 0, "finite_nonnegative_" + name)
        parameters[name] = value
    require(parameters["shared_cluster_uniform_weight"] + parameters["shared_family_uniform_weight"] <= 1,
            "unconditional_mixture_weights_sum_at_most_one")
    if kind == "cluster_bernoulli":
        p = scenario.get("event_probability")
        require(isinstance(p, Real) and not isinstance(p, (bool, np.bool_)) and np.isfinite(p) and 0 <= p <= 1,
                "event_probability_in_unit_interval")
    if kind == "binary_endpoint_process":
        # Check the entire q support, not only realized clusters; never clip.
        _check_binary_probability_support(parameters["error_shock_scale"])


def generate_dataset(scenario, rng, include_families=False):
    """Generate one engineering dataset, retaining all family-level components.

    Only the binary process admits inspectable ``families``. Legacy components
    are mathematical vectors, so asking for invented binary families is rejected.
    """
    _validate_scenario(scenario, include_families)
    if scenario["generator"] == "binary_endpoint_process":
        return _binary_dataset(scenario, rng, True) if include_families else _binary_array_dataset(scenario, rng)
    if scenario["generator"] == "zero_components":
        # Reuse only the old deterministic cluster layout, never its centers.
        centers, _, clusters, _ = synthetic_components(
            {**scenario, "generator": "constant_components"}, rng)
        values, truth, icc = np.zeros_like(centers), np.zeros(17), None
    else:
        values, truth, clusters, icc = synthetic_components(scenario, rng)
    return {"lower": values, "upper": values.copy(), "truth": truth,
            "clusters": clusters,
            "metadata": {"family_count": len(clusters), "cluster_count": len(set(clusters)),
                         "endpoint_count": 0, "missing_endpoint_count": 0,
                         "analytic_truth_scope": "legacy mathematical component expectation",
                         "analytic_component_ICC": icc}}


def _aggregate_dataset(dataset):
    lower, upper = np.asarray(dataset["lower"], dtype=float), np.asarray(dataset["upper"], dtype=float)
    labels_input = dataset["clusters"]
    require(lower.shape == upper.shape == (len(labels_input), 17) and len(labels_input) > 0,
            "seventeen_family_components")
    require(all(isinstance(c, str) and c for c in labels_input), "explicit_cluster_labels")
    present = np.isfinite(lower)
    require(np.array_equal(present, np.isfinite(upper)) and not np.isinf(lower).any()
            and not np.isinf(upper).any(), "paired_finite_or_absent")
    require(not np.isnan(lower[:, [i for i in range(17) if i != 3]]).any(), "only_h3_cohort_may_be_absent")
    require(np.all(lower[present] <= upper[present]) and np.all(lower[present] >= -1-1e-12)
            and np.all(upper[present] <= 1+1e-12), "ordered_bounded_components")
    clusters = np.asarray(labels_input)
    labels = sorted(set(labels_input))
    sums_lo, sums_hi, counts = [], [], []
    for label in labels:
        mask = clusters == label
        sums_lo.append(np.nansum(lower[mask], axis=0))
        sums_hi.append(np.nansum(upper[mask], axis=0))
        counts.append(np.isfinite(lower[mask]).sum(axis=0))
    return np.array(sums_lo), np.array(sums_hi), np.array(counts)


def _evaluate_group(aggregates):
    # Columns pack dataset x statistic, sharing only the legacy cluster draws.
    count = aggregates[0][0].shape[0]
    sums_lo, sums_hi, counts = (np.stack([a[k] for a in aggregates], axis=1) for k in range(3))
    shape = (len(aggregates), len(STAT_IDS))
    draws = cluster_draw_counts(count)
    denominators = (draws @ counts.reshape(count, -1)).reshape((-1, *shape))
    with np.errstate(divide="ignore", invalid="ignore"):
        boot_lo = (draws @ sums_lo.reshape(count, -1)).reshape((-1, *shape)) / denominators
        boot_hi = (draws @ sums_hi.reshape(count, -1)).reshape((-1, *shape)) / denominators
        identification = np.stack((sums_lo.sum(axis=0)/counts.sum(axis=0),
                                   sums_hi.sum(axis=0)/counts.sum(axis=0)), axis=-1)
    eligible = (counts > 0).sum(axis=0)
    undefined = (denominators == 0).sum(axis=0)
    degenerate = (undefined == 0) & (np.ptp(boot_lo, axis=0) < 1e-12) & (np.ptp(boot_hi, axis=0) < 1e-12)
    tail = ALPHA/(2*len(STAT_IDS))
    intervals = np.stack((np.quantile(boot_lo, tail, axis=0, method="linear"),
                          np.quantile(boot_hi, 1-tail, axis=0, method="linear")), axis=-1)
    intervals[(eligible < 2) | (undefined > 0)] = np.nan
    return {"intervals": intervals, "eligible_clusters": eligible, "degenerate": degenerate,
            "undefined": undefined, "identification": identification}


def evaluate_batch(datasets):
    """Vectorized current bootstrap; no draw, tail, quantile or seed changes.

    Result fields are ``intervals`` and ``identification`` (D,17,2),
    ``eligible_clusters``, ``degenerate`` and ``undefined`` (D,17).
    Undefined is the integer number of invalid draws, not a filtered-draw mask.
    BLAS thread limits should be set by the caller before NumPy is imported.
    """
    aggregates = [_aggregate_dataset(data) for data in datasets]
    groups = {}
    for i, aggregate in enumerate(aggregates):
        groups.setdefault(aggregate[0].shape[0], []).append(i)
    d = len(aggregates)
    result = {"intervals": np.full((d, 17, 2), np.nan), "identification": np.full((d, 17, 2), np.nan),
              "eligible_clusters": np.zeros((d, 17), dtype=int), "degenerate": np.zeros((d, 17), dtype=bool),
              "undefined": np.zeros((d, 17), dtype=int)}
    for indices in groups.values():
        # Bound temporary memory even if a caller submits a large batch.
        for start in range(0, len(indices), 8):
            chunk = indices[start:start+8]
            evaluated = _evaluate_group([aggregates[i] for i in chunk])
            for field, values in evaluated.items():
                result[field][chunk] = values
    return result
