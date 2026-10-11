"""Opt-in research policy; the frozen V1.10 runtime is unchanged.

Only unclassified values of a MIXED source get a sensitive fallback. An explicit
PUBLIC field/container or whole PUBLIC declaration is still trusted and may be
wrong. This policy is not a classifier or an implicit-flow defense.
"""
from __future__ import annotations
from dataclasses import replace
from typing import Literal
from security.precision_runtime import PrecisionRuntime
from security.source_classification import SourceRegistry

Strategy = Literal['coarse', 'precision', 'conservative']
STRATEGIES: tuple[Strategy, ...] = ('coarse', 'precision', 'conservative')


def effective_registry(registry: SourceRegistry, strategy: Strategy) -> SourceRegistry:
    if not isinstance(registry, SourceRegistry) or strategy not in STRATEGIES:
        raise ValueError('invalid_source_trust_configuration')
    if strategy != 'conservative':
        return registry
    plans = tuple((category, reference,
                   replace(plan, layout=replace(plan.layout, default_sensitive=True))
                   if plan.status == 'MIXED' else plan)
                  for category, reference, plan in registry.plans)
    return SourceRegistry(plans, registry.unknown_policy)


class SourceTrustRuntime(PrecisionRuntime):
    """Trusted loopback-only comparison, not a tool callable by an agent."""
    def __init__(self, *, strategy: Strategy, registry: SourceRegistry,
                 measurement: bool = False, **kwargs):
        if strategy not in STRATEGIES or type(measurement) is not bool or kwargs.get('local_target') is None:
            raise ValueError('source_trust_study_requires_pinned_loopback')
        flags = {'field_precision': strategy != 'coarse', 'scan_content': not measurement,
                 'defense_mode': 'no_defense' if measurement else 'scanner_taint',
                 'release_enabled': False, 'propagate': True, 'source_labels': True,
                 'source_policy_enabled': True, 'enforce_content': True}
        if set(flags).intersection(kwargs):
            raise ValueError('conflicting_source_trust_flags')
        self.strategy = strategy
        self.declared_registry = registry
        compiled = effective_registry(registry, strategy)
        super().__init__(registry=compiled, **flags, **kwargs)
        self.observe('source_trust_policy', strategy=strategy,
                     mixed_unlisted_sensitive=strategy == 'conservative',
                     explicit_public_overrides=True, measurement_enforcement_off=measurement)
