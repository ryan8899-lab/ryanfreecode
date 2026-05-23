#!/usr/bin/env python3
from __future__ import annotations
import json, sys, time, base64
from pathlib import Path

ROOT=Path('/root/Gpt-Agreement-Payment')
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'webui'))
sys.path.insert(0,str(ROOT/'CTF-pay'))
from webui.backend.db import get_db
from fresh_checkout import _create_chatgpt_http_session, _chatgpt_auth_headers, _compose_cookie_header, _fetch_auth_session_with_cookie, _extract_plan_type_from_access_token, _extract_email_from_access_token

def jwt_payload(tok):
    if not tok or tok.count('.')<2: return {}
    try:
        p=tok.split('.')[1]; p += '='*((4-len(p)%4)%4)
        return json.loads(base64.urlsafe_b64decode(p).decode())
    except Exception: return {}

def summarize_accounts_check(obj):
    out={}
    def walk(x,path=''):
        if isinstance(x,dict):
            for k,v in x.items():
                lk=k.lower()
                if any(s in lk for s in ['plan','subscription','entitlement','account','billing','paid','plus']):
                    if isinstance(v,(str,int,float,bool)) or v is None:
                        out[path+'.'+k if path else k]=v
                walk(v, path+'.'+k if path else k)
        elif isinstance(x,list):
            for i,v in enumerate(x[:5]): walk(v, f'{path}[{i}]')
    walk(obj)
    return out

def check(acc):
    cfg={}
    http,transport=_create_chatgpt_http_session(cfg, user_agent='', proxy_cfg_override={})
    cookie=_compose_cookie_header(acc.get('cookie_header') or '', acc.get('session_token') or '', acc.get('device_id') or '')
    access=acc.get('access_token') or ''
    auth_status='not_tried'; auth_data={}
    try:
        auth_data=_fetch_auth_session_with_cookie(http, cookie_header=cookie, user_agent='', accept_language='en-US,en;q=0.9')
        auth_status='ok'
        access=(auth_data.get('accessToken') or access or '').strip()
    except Exception as e:
        auth_status=f'err:{type(e).__name__}:{str(e)[:120]}'
    plan=(auth_data.get('account') or {}).get('planType') or _extract_plan_type_from_access_token(access) or ''
    email=(auth_data.get('user') or {}).get('email') or _extract_email_from_access_token(access) or acc.get('email')
    result={'id':acc.get('id'),'email':acc.get('email'),'auth_session':auth_status,'resolved_email':email,'jwt_plan_type':plan or '', 'transport':transport}
    headers=_chatgpt_auth_headers(access_token=access,cookie_header=cookie,user_agent='',accept_language='en-US,en;q=0.9',oai_device_id=acc.get('device_id') or '',accept='application/json',include_origin=True)
    endpoints={
        'me':'https://chatgpt.com/backend-api/me',
        'accounts_check':'https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=-480',
        'models':'https://chatgpt.com/backend-api/models',
    }
    for name,url in endpoints.items():
        try:
            r=http.get(url, headers=headers, timeout=25)
            item={'status':getattr(r,'status_code',None)}
            txt=(getattr(r,'text','') or '')
            if getattr(r,'status_code',None)==200:
                try:
                    obj=r.json(); item['keys']=list(obj.keys())[:30] if isinstance(obj,dict) else type(obj).__name__
                    if name=='accounts_check': item['plan_fields']=summarize_accounts_check(obj)
                    if name=='models':
                        s=json.dumps(obj)[:5000].lower()
                        item['mentions']={k:(k in s) for k in ['gpt-4','gpt-4o','plus','paid','free']}
                except Exception:
                    item['body']=txt[:300]
            else:
                item['body']=txt[:180]
            result[name]=item
        except Exception as e:
            result[name]={'error':f'{type(e).__name__}:{str(e)[:160]}'}
    # classify conservatively
    result['classification']='unknown'
    hay=json.dumps(result,ensure_ascii=False).lower()
    if 'plus' in (plan or '').lower() or 'paid' in hay or 'plus' in hay:
        result['classification']='possibly_plus_or_paid_signal'
    if (plan or '').lower() in ('free','freeuser','free_user'):
        result['classification']='free_by_auth_session_jwt'
    return result

def main():
    emails=sys.argv[1:] or ['santinojaycee3185@outlook.com','lorischristian7550@outlook.com','rafialivia1392@outlook.com']
    db=get_db(); outs=[]
    with db._conn() as c:
        for email in emails:
            row=c.execute('SELECT id,email,session_token,access_token,refresh_token,cookie_header,device_id,last_check_status,last_check_message FROM registered_accounts WHERE lower(email)=lower(?) ORDER BY id DESC LIMIT 1',(email,)).fetchone()
            if not row:
                outs.append({'email':email,'error':'not found'}); continue
            outs.append(check(dict(row)))
    print(json.dumps(outs,ensure_ascii=False,indent=2))
if __name__=='__main__': main()
