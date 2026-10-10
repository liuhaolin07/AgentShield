"""Export actual V1.9 fractions, costs and ablation comparisons; no token guesses."""

import argparse
import csv
import json
from pathlib import Path
from typing import Any


LABELS={'no_defense':'No Defense','static_rule':'Static Rule','scanner':'Scanner','taint':'Taint',
        'full':'Full','source_only':'Source only','detect_only':'Detect only'}


def export_metrics_csv(report: dict[str,Any], output: Path) -> None:
    output.mkdir(parents=True,exist_ok=True)
    fields=['arm','metric','numerator','denominator','value','pairs','status','exclusions']
    with (output/'metrics.csv').open('w',encoding='utf-8',newline='') as file:
        writer=csv.DictWriter(file,fieldnames=fields); writer.writeheader()
        for arm,stats in report['metrics'].items():
            excluded=json.dumps(stats['excluded'],sort_keys=True)
            for name in ('ASR','attack_blocking_rate','TCR','task_success_rate','FPR','precision','recall'):
                value=stats[name]
                writer.writerow({'arm':arm,'metric':name,**value,'status':'OBSERVED' if value['denominator'] else 'UNKNOWN','exclusions':excluded})
            for name in ('latency_ms','python_peak_delta_bytes'):
                cost=stats['paired_cost'][name]
                writer.writerow({'arm':arm,'metric':name,'value':cost['mean'],'pairs':cost['pairs'],
                                 'status':'OBSERVED' if cost['pairs'] else 'UNRUN','exclusions':excluded})
            writer.writerow({'arm':arm,'metric':'token_overhead','status':'UNRUN','exclusions':excluded})
    with (output/'ablations.csv').open('w',encoding='utf-8',newline='') as file:
        writer=csv.DictWriter(file,fieldnames=['ablation','arm','matched_assessments','additional_full_attack_blocks','additional_full_benign_blocks'])
        writer.writeheader()
        for name,value in report['ablations'].items(): writer.writerow({'ablation':name,**value})


def export_charts(report: dict[str,Any], output: Path) -> None:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    export_metrics_csv(report,output)
    arms=list(report['metrics']); labels=[LABELS[a] for a in arms]
    colors=['#aab3bc','#d88a52','#689bcc','#9d8bc2','#46947b','#c4aa62','#cb8499']
    figure,axes=plt.subplots(1,3,figsize=(16,4.6),constrained_layout=True)
    for axis,name in zip(axes,('ASR','TCR','FPR')):
        values=[report['metrics'][a][name] for a in arms]
        axis.bar(range(len(arms)),[v['value'] or 0 for v in values],color=colors)
        axis.set_xticks(range(len(arms)),labels,rotation=35,ha='right'); axis.set_ylim(0,1.15)
        axis.set_title(name); axis.set_ylabel('Observed proportion')
        for i,v in enumerate(values):
            axis.text(i,(v['value'] or 0)+0.03,f"{v['numerator']}/{v['denominator']}" if v['denominator'] else 'UNRUN',ha='center',fontsize=8)
    figure.suptitle(f"V1.9 exploratory synthetic {report['split']} · seed {report['seed']} · repeats {report['repeat']}\n"
                   'Unsupported / missing observations excluded; misclassification and utility failures retained',fontsize=11)
    for suffix in ('svg','png'): figure.savefig(output/f'outcomes.{suffix}',dpi=160)
    plt.close(figure)
    figure,axes=plt.subplots(1,2,figsize=(12,4.6),constrained_layout=True)
    for axis,name,scale,title in ((axes[0],'latency_ms',1,'Paired end-to-end difference (ms)'),
                                  (axes[1],'python_peak_delta_bytes',1024,'Paired Python peak difference (KiB)')):
        values=[report['metrics'][a]['paired_cost'][name] for a in arms]
        heights=[(v['mean'] or 0)/scale for v in values]
        axis.bar(range(len(arms)),heights,color=colors); axis.axhline(0,color='black',linewidth=.6)
        axis.set_xticks(range(len(arms)),labels,rotation=35,ha='right'); axis.set_title(title)
        for i,v in enumerate(values):
            axis.annotate(f"n={v['pairs']}" if v['pairs'] else 'UNRUN',(i,heights[i]),xytext=(0,5),textcoords='offset points',ha='center',fontsize=8)
    figure.suptitle('Matched completed benign flows only; tracemalloc instrumented, Python allocations are not RSS\n'
                   'Common issuance cost shared; token overhead UNRUN (no live inference)',fontsize=10)
    for suffix in ('svg','png'): figure.savefig(output/f'cost.{suffix}',dpi=160)
    plt.close(figure)
    figure,axis=plt.subplots(figsize=(8,4),constrained_layout=True)
    entries=list(report['ablations'].items()); x=list(range(len(entries)))
    axis.bar([i-.18 for i in x],[v['additional_full_attack_blocks'] for _,v in entries],width=.35,label='Additional Full attack blocks',color='#46947b')
    axis.bar([i+.18 for i in x],[v['additional_full_benign_blocks'] for _,v in entries],width=.35,label='Additional Full benign blocks',color='#d88a52')
    axis.set_xticks(x,[name+' '+LABELS[v['arm']] for name,v in entries],rotation=15,ha='right')
    axis.set_ylabel('Paired observed assessment count'); axis.legend()
    axis.set_title('Conditional component comparison; repeats share authored cases\nSecurity benefit and utility loss are both shown')
    for suffix in ('svg','png'): figure.savefig(output/f'ablations.{suffix}',dpi=160)
    plt.close(figure)


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('report',type=Path)
    parser.add_argument('--output-dir',type=Path); args=parser.parse_args()
    export_charts(json.loads(args.report.read_text()),args.output_dir or args.report.parent)
    return 0


if __name__=='__main__': raise SystemExit(main())
