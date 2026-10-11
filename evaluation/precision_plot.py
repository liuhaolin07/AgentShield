"""Exports only computed observations; matplotlib is optional."""
import csv,json
from pathlib import Path
BASELINES=('no_defense','static_rule','scanner','coarse','precision','full')

def export_metrics(report,output):
    output=Path(output); output.mkdir(parents=True,exist_ok=True)
    with (output/'metrics.csv').open('w',newline='') as f:
        w=csv.writer(f); w.writerow(['arm','metric','numerator','denominator','value','unique_task_numerator','unique_task_denominator','unique_task_wilson_95'])
        for arm,m in report['metrics'].items():
            for key in ('ASR','ABR','TCR','FPR','precision','recall'):
                r=m[key]; cluster=m['task_cluster_estimates'].get(key,{})
                w.writerow([arm,key,r['numerator'],r['denominator'],r['value'],cluster.get('numerator'),cluster.get('denominator'),json.dumps(cluster.get('wilson_95'))])
    with (output/'ablations.csv').open('w',newline='') as f:
        w=csv.writer(f); w.writerow(['ablation','arm','ASR','TCR','FPR','failures'])
        for name,arm in report['ablations'].items():
            m=report['metrics'][arm]; w.writerow([name,arm,*[json.dumps(m[k]) for k in ('ASR','TCR','FPR')],m['summary']['FAILED']])
    with (output/'failures.csv').open('w',newline='') as f:
        w=csv.writer(f); w.writerow(['run','arm','case_id','category','status','reason'])
        for r in report['results']:
            if r['status']!='HELD': w.writerow([r['run'],r['arm'],r['case_id'],r['category'],r['status'],r['actual'].get('unrun_reason') or r['actual'].get('block_reason') or '; '.join(r['differences'])])

def export_charts(report,output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,3,figsize=(15,5))
    for ax,key in zip(axes,('ASR','TCR','FPR')):
        points=[report['metrics'][a]['task_cluster_estimates'][key] for a in BASELINES]
        values=[p['value'] or 0 for p in points]; lo=[v-(p['wilson_95'][0] if p['wilson_95'] else v) for p,v in zip(points,values)]; hi=[(p['wilson_95'][1] if p['wilson_95'] else v)-v for p,v in zip(points,values)]
        ax.bar(range(6),values,yerr=[lo,hi],capsize=3); ax.set_xticks(range(6),BASELINES,rotation=45,ha='right'); ax.set_ylim(0,1.1); ax.set_title(key+' (unique tasks)')
        for i,p in enumerate(points): ax.text(i,values[i]+.025,f"{p['numerator']}/{p['denominator']}",ha='center',fontsize=9)
    fig.suptitle('V1.10 '+report['split']+': authored explicit-flow study; Wilson intervals, not population proof')
    fig.tight_layout(); fig.savefig(Path(output)/'security-utility.svg'); plt.close(fig)
