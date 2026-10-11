"""Trusted local-only defense switches. Never exposed through AgentPort."""
from security.precision_runtime import PrecisionRuntime

ARMS=('no_defense','static_rule','scanner','coarse','precision','full','no_source','no_propagation','no_fields','no_release','detect_only')
ABLATIONS={'without_source_policy':'no_source','without_propagation':'no_propagation','without_field_precision':'no_fields','without_declassification':'no_release','without_scanner':'precision','detection_only':'detect_only'}

def configuration(arm):
    if arm not in ARMS: raise ValueError('unknown_research_arm')
    return {'defense_mode':arm if arm in ('no_defense','static_rule','scanner') else 'scanner_taint',
        'scan_content':arm not in ('coarse','precision'), 'field_precision':arm not in ('coarse','no_fields'),
        'release_enabled':arm not in ('coarse','no_release'),'propagate':arm!='no_propagation',
        'source_policy_enabled':arm!='no_source','source_labels':arm!='no_source','enforce_content':arm!='detect_only'}

class ResearchPrecisionRuntime(PrecisionRuntime):
    def __init__(self,*,arm,**kwargs):
        if kwargs.get('local_target') is None: raise ValueError('research_switches_require_pinned_loopback')
        if set(configuration(arm)).intersection(kwargs): raise ValueError('conflicting_research_switches')
        super().__init__(**configuration(arm),**kwargs)
