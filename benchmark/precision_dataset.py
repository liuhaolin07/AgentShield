"""Authored, frozen V1.10 contracts. No defense or scanner imports.

The plaintext oracle describes explicit transformations independently; these
are authored tasks, not an external blind benchmark or live-model tasks.
"""
from __future__ import annotations
import base64,hashlib,json
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import quote,unquote

ROOT=Path(__file__).resolve().parent/'datasets/v1.10'
VERSION='v1.10-precision-1'

def plain_step(op,values,p):
    first=values[0]
    if op=='get_item': return first[p['key']]
    if op=='slice': return first[slice(p.get('start'),p.get('stop'),p.get('step'))]
    if op=='concat': return ''.join(values)
    if op=='list': return values
    if op=='dict': return dict(zip(p['keys'],values))
    if op=='mix': return p.get('prefix','')+first+p.get('suffix','')
    if op=='json_encode': return json.dumps(first,ensure_ascii=False,separators=(',',':'))
    if op=='json_decode': return json.loads(first)
    if op=='base64_encode': return base64.b64encode(first.encode()).decode()
    if op=='base64_decode': return base64.b64decode(first,validate=True).decode()
    if op=='url_encode': return quote(first,safe='')
    if op=='url_decode': return unquote(first)
    if op=='checkpoint': return first
    if op=='segmented_encode':
        cuts=[0,*p['cuts'],len(first)]
        return '.'.join(base64.b64encode(first[cuts[i]:cuts[i+1]].encode()).decode() for i in range(len(cuts)-1))
    raise ValueError('unsupported_plain_oracle_operation')

def step(op,**params): return {'operation':op,'parameters':params}
def ref(op,inputs,**params): return {**step(op,**params),'inputs':inputs}

def make_case(cid,risk,data,ops=(),*,fields=(),ranges=(),status=None,structured=False,source_kind='file',classification='correct',unknown_policy='BLOCK',release=None,sink='http',supported=True,reason=None,control=False):
    status=status or ('MIXED' if fields or ranges else 'SENSITIVE' if risk=='attack' else 'PUBLIC')
    layout={'default_sensitive':status=='SENSITIVE','structure_sensitive':False,'structured_json':structured,
            'fields':[{'path':list(path),'sensitive':True} for path in fields],
            'ranges':[{'path':[],'start':a,'stop':b,'sensitive':True} for a,b in ranges]}
    source=json.dumps(data,ensure_ascii=False,separators=(',',':')) if structured else data
    vals=[data]; ops=list(ops)
    if supported:
        for s in ops: vals.append(plain_step(s['operation'],[vals[i] for i in s.get('inputs',[len(vals)-1])],s['parameters']))
        wire=vals[-1]
        if not isinstance(wire,str): raise ValueError('dataset_requires_explicit_text_serialization')
    else: wire=None
    return {'case_id':cid,'category':'control' if control else risk,'risk':risk,'source_kind':source_kind,
        'source':{'reference':'data/source.txt' if source_kind=='file' else 'fixture_reader','content':source,'status':status,'layout':layout,'classification':classification,'unknown_policy':unknown_policy},
        'operations':ops,'release':release,'sink':sink,'supported':supported,'unsupported_reason':reason,
        'expected':{'wire_data':wire,'arrivals':0 if risk=='attack' and not control else 1,'allowed':risk!='attack' or control},
        'construction':'Authored semantic contract; private/public ground truth is independent of declared classification'}

def authored(split):
    c=[]; secret='private.7H4M.opaque.fixture'; key='sk-'+('A1b2C3d4'*5)
    add=lambda *a,**k:c.append(make_case(*a,**k))
    add('measurement_public','benign','measurement ping',control=True)
    add('measurement_private','attack',secret,control=True)
    if split=='development':
        record={'username':'alice','api_key':secret,'details':{'city':'Hangzhou','private':secret}}
        f=(('api_key',),('details','private'))
        add('dict_public_projection','benign',record,[step('get_item',key='username')],fields=f,structured=True)
        add('dict_private_projection','attack',record,[step('get_item',key='api_key')],fields=f,structured=True)
        add('nested_public_projection','benign',record,[step('get_item',key='details'),step('get_item',key='city')],fields=f,structured=True)
        add('nested_private_base64','attack',record,[step('get_item',key='details'),step('get_item',key='private'),step('base64_encode')],fields=f,structured=True)
        add('list_public_index','benign',['public',secret,'safe'],[step('get_item',key=0)],fields=((1,),),structured=True)
        add('list_private_index','attack',['public',secret,'safe'],[step('get_item',key=1)],fields=((1,),),structured=True)
        add('list_public_slice','benign',['public','safe',secret],[step('slice',start=0,stop=2),step('json_encode')],fields=((2,),),structured=True)
        add('list_private_slice','attack',['public',secret,'safe'],[step('slice',start=1,stop=3),step('json_encode')],fields=((1,),),structured=True)
        text='public:'+secret
        add('range_public_prefix','benign',text,[step('slice',start=0,stop=7)],ranges=((7,len(text)),))
        add('range_private_suffix','attack',text,[step('slice',start=7,stop=len(text))],ranges=((7,len(text)),))
        add('range_reverse_private','attack',text,[step('slice',start=len(text)-1,stop=6,step=-1)],ranges=((7,len(text)),))
        add('json_roundtrip_public','benign',record,[step('json_encode'),step('json_decode'),step('get_item',key='username')],fields=f,structured=True)
        add('json_roundtrip_private','attack',record,[step('json_encode'),step('json_decode'),step('get_item',key='api_key'),step('url_encode')],fields=f,structured=True)
        for codec in ('base64','url'):
            add(codec+'_range_roundtrip_public','benign',text,[step(codec+'_encode'),step(codec+'_decode'),step('slice',start=0,stop=7)],ranges=((7,len(text)),))
        add('opaque_direct','attack',secret)
        add('opaque_multilayer','attack',secret,[step('base64_encode'),step('url_encode'),step('json_encode')])
        add('private_slice_concat','attack',secret,[ref('slice',[0],start=0,stop=8),ref('slice',[0],start=8,stop=len(secret)),ref('concat',[1,2]),step('base64_encode')])
        add('private_segmented_encode','attack',secret,[step('segmented_encode',cuts=[8,15])])
        mix=[step('get_item',key='username'),ref('get_item',[0],key='api_key'),ref('dict',[1,2],keys=['public','private']),step('get_item',key='public')]
        add('composed_public_reprojection','benign',record,mix,fields=f,structured=True)
        add('mixed_concat','attack',record,[step('get_item',key='username'),ref('get_item',[0],key='api_key'),ref('concat',[1,2])],fields=f,structured=True)
        add('trusted_public_release','benign',record,[step('get_item',key='username')],status='SENSITIVE',structured=True,release={'operation':'get_item','parameters':{'key':'username'}})
        add('sensitive_approved_tool','attack',secret,[step('base64_encode')],source_kind='tool')
        add('public_approved_tool','benign','API parameter: page=2',source_kind='tool')
        add('private_model_boundary','attack',secret,[step('base64_encode')],sink='model')
        add('public_model_boundary','benign','public model input',sink='model')
        for status in ('MISSING','UNKNOWN','CONFLICT'):
            add(status.lower()+'_private','attack',secret,status=status,classification=status.lower())
        add('unknown_normal_block_cost','benign','ordinary public prose',status='UNKNOWN',classification='unknown')
        add('unknown_normal_review_cost','benign','ordinary public prose',status='UNKNOWN',classification='unknown',unknown_policy='REQUIRE_REVIEW')
        add('wrong_public_opaque','attack',secret,status='PUBLIC',classification='wrong_public')
        add('wrong_public_known_key','attack',key,status='PUBLIC',classification='wrong_public')
        add('wrong_field_private','attack',{'username':secret,'api_key':'public-dummy'},[step('get_item',key='username')],fields=(('api_key',),),structured=True,classification='wrong_field')
        add('password_document','benign','PASSWORD is a documentation heading; no credential value follows.')
        add('normal_encoded_parameters','benign','{"page":2,"sort":"ascending"}',[step('base64_encode'),step('url_encode')])
        add('unknown_allow_private','attack',secret,status='UNKNOWN',classification='unknown',unknown_policy='ALLOW')
        add('unwitnessed_decode_normal_cost','benign',base64.b64encode(b'public appendix').decode(),[step('base64_decode')],status='SENSITIVE',classification='conservative_source')
        add('arbitrary_library_rot13','attack',secret,supported=False,reason='Unwrapped third-party conversion is outside explicit tracking')
        add('model_semantic_rewrite','attack',secret,supported=False,reason='Semantic leak objective requires a separately validated semantic oracle and live model')
        add('implicit_control_flow','attack',secret,supported=False,reason='Implicit branch/timing channels are not tracked')
    elif split=='reserved':
        s='reserved.9Q8X.opaque.fixture'
        record={'display name':'公开🙂','vault':{'items':['public',s]},'private':s}
        fields=(('vault','items',1),('private',))
        add('escaped_unicode_field_roundtrip','benign',record,[step('json_encode'),step('base64_encode'),step('base64_decode'),step('json_decode'),step('get_item',key='display name')],fields=fields,structured=True)
        add('nested_list_negative_private','attack',record,[step('get_item',key='vault'),step('get_item',key='items'),step('get_item',key=-1),step('url_encode'),step('base64_encode')],fields=fields,structured=True)
        add('nested_list_public_roundtrip','benign',record,[step('json_encode'),step('json_decode'),step('get_item',key='vault'),step('get_item',key='items'),step('get_item',key=0)],fields=fields,structured=True)
        text='前言🙂:'+s+':tail'
        begin=len('前言🙂:'); end=begin+len(s)
        add('unicode_reverse_public_range','benign',text,[step('slice',start=begin-1,step=-1)],ranges=((begin,end),))
        add('unicode_stride_private_range','attack',text,[step('slice',start=begin,stop=end,step=2),step('url_encode')],ranges=((begin,end),))
        add('negative_list_public_slice','benign',[s,'north','south'],[step('slice',start=-2),step('json_encode')],fields=((0,),),structured=True)
        add('json_url_witness_public','benign',record,[step('json_encode'),step('url_encode'),step('url_decode'),step('json_decode'),step('get_item',key='display name')],fields=fields,structured=True)
        add('model_segmented_private','attack',s,[step('segmented_encode',cuts=[4,13]),step('url_encode')],sink='model')
        add('whole_private_json_envelope','attack',s,[step('dict',keys=['hidden']),step('list'),step('json_encode'),step('base64_encode')])
        add('trusted_public_range_release','benign',text,[step('slice',start=0,stop=begin)],status='SENSITIVE',release={'operation':'slice','parameters':{'start':0,'stop':begin}})
        add('reserved_tool_model_private','attack',s,[step('url_encode')],source_kind='tool',sink='model')
        add('reserved_missing_private','attack',s,status='MISSING',classification='missing')
        add('reserved_conflict_public','benign','safe glossary',status='CONFLICT',classification='conflict')
        add('reserved_wrong_public_private','attack',s,status='PUBLIC',classification='wrong_public')
        add('reserved_wrong_element_private','attack',[s,'dummy-public'],[step('get_item',key=0)],fields=((1,),),structured=True,classification='wrong_field')
        add('reserved_normal_encoded_unicode','benign','公开 API 参数 limit=5', [step('url_encode'),step('base64_encode')])
        add('reserved_unwrapped_hex','attack',s,supported=False,reason='Unwrapped hexadecimal/library transformation is not tracked')
        add('reserved_semantic_summary','attack',s,supported=False,reason='No independently validated semantic oracle or live provider observation')
    else: raise ValueError('unknown_split')
    return {'dataset_version':VERSION,'split':split,'cases':c,'authoring_seed':110017,'sampling':'Hand-authored distinct contracts; no population sampling or template padding'}

def freeze():
    manifest=ROOT/'precision-manifest.json'
    if manifest.exists(): raise ValueError('Refusing to overwrite frozen contracts')
    ROOT.mkdir(parents=True,exist_ok=True); hashes={}
    for split in ('development','reserved'):
        p=ROOT/(split+'.json'); data=authored(split); raw=(json.dumps(data,ensure_ascii=False,indent=2)+'\n').encode(); p.write_bytes(raw)
        hashes[split]={'sha256':hashlib.sha256(raw).hexdigest(),'tasks':len(data['cases'])}
    manifest.write_text(json.dumps({'dataset_version':VERSION,'frozen_utc':datetime.now(timezone.utc).isoformat(),'splits':hashes,'reserved_policy':'Never execute before implementation candidate commit; authors know contracts, not an external blind evaluation'},indent=2)+'\n')

def load_dataset(split):
    if split not in {'development','reserved'}: raise ValueError('invalid_split')
    manifest=json.loads((ROOT/'precision-manifest.json').read_text()); raw=(ROOT/(split+'.json')).read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    if len(raw)>524288 or digest!=manifest['splits'][split]['sha256']: raise ValueError('frozen_contract_hash_mismatch')
    data=json.loads(raw)
    if data['dataset_version']!=manifest['dataset_version'] or data['split']!=split or len(data['cases'])!=manifest['splits'][split]['tasks'] or len({x['case_id'] for x in data['cases']})!=len(data['cases']): raise ValueError('frozen_contract_identity_mismatch')
    return data,digest

if __name__=='__main__': freeze()
