#!/usr/bin/env python3
from __future__ import annotations
import asyncio, json, sys, base64, time, re
from pathlib import Path
ROOT=Path('/root/Gpt-Agreement-Payment')
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'webui'))
from webui.backend.db import get_db
from playwright.async_api import async_playwright

EMAILS=sys.argv[1:] or ['santinojaycee3185@outlook.com','lorischristian7550@outlook.com','rafialivia1392@outlook.com']

def jwt_payload(tok):
    if not tok or tok.count('.')<2: return {}
    try:
        p=tok.split('.')[1]; p += '='*((4-len(p)%4)%4)
        return json.loads(base64.urlsafe_b64decode(p).decode())
    except Exception: return {}

def extract_plan_from_jwt(tok):
    p=jwt_payload(tok)
    a=p.get('https://api.openai.com/auth') or {}
    return a.get('chatgpt_plan_type') if isinstance(a,dict) else ''

def compact_plan_fields(obj):
    out={}
    def walk(x,path=''):
        if isinstance(x,dict):
            for k,v in x.items():
                lk=k.lower()
                np=f'{path}.{k}' if path else k
                if any(s in lk for s in ['plan','subscription','entitlement','account','billing','paid','plus','team']):
                    if isinstance(v,(str,int,float,bool)) or v is None:
                        out[np]=v
                walk(v,np)
        elif isinstance(x,list):
            for i,v in enumerate(x[:8]): walk(v,f'{path}[{i}]')
    walk(obj)
    return out

def classify(data):
    # positive paid signals first
    hay=json.dumps(data,ensure_ascii=False).lower()
    if re.search(r'"(planType|plan_type|chatgpt_plan_type)"\s*:\s*"(plus|team|enterprise|pro)"', json.dumps(data,ensure_ascii=False), re.I):
        return 'paid'
    for word in ['plus_user','chatgptplusplan','paid_subscription','has_paid_subscription','subscription_active']:
        if word in hay: return 'paid_signal'
    # explicit free from fresh auth/session/jwt
    plans=[]
    def collect(x):
        if isinstance(x,dict):
            for k,v in x.items():
                if k.lower() in ('plantype','plan_type','chatgpt_plan_type') and isinstance(v,str): plans.append(v.lower())
                collect(v)
        elif isinstance(x,list):
            for v in x: collect(v)
    collect(data)
    if plans and all(p in ('free','freeuser','free_user') for p in plans if p): return 'free'
    return 'unknown'

async def check_one(pw, acc):
    email=acc['email']
    browser=await pw.chromium.launch(headless=True, executable_path='/usr/bin/google-chrome', args=['--disable-blink-features=AutomationControlled','--no-sandbox'])
    context=await browser.new_context(user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')
    # seed cookies
    cookies=[]
    def add_cookie(name,value,domain='.chatgpt.com'):
        if value:
            cookies.append({'name':name,'value':value,'domain':domain,'path':'/','httpOnly':False,'secure':True,'sameSite':'Lax'})
    st=acc.get('session_token') or ''
    did=acc.get('device_id') or ''
    add_cookie('__Secure-next-auth.session-token', st)
    add_cookie('oai-did', did)
    for part in (acc.get('cookie_header') or '').split(';'):
        if '=' in part:
            n,v=part.strip().split('=',1)
            if n and v and n not in ['__Secure-next-auth.session-token','oai-did']:
                add_cookie(n,v)
    if cookies:
        try: await context.add_cookies(cookies)
        except Exception: pass
    page=await context.new_page()
    results={'id':acc.get('id'),'email':email,'jwt_plan_type':extract_plan_from_jwt(acc.get('access_token') or ''),'endpoints':{}}
    # Load homepage first to let CF/cookies settle
    try:
        resp=await page.goto('https://chatgpt.com/', wait_until='domcontentloaded', timeout=45000)
        results['home_status']=resp.status if resp else None
        results['home_url']=page.url
        await page.wait_for_timeout(5000)
    except Exception as e:
        results['home_error']=f'{type(e).__name__}:{str(e)[:160]}'
    endpoints=[
        ('auth_session','https://chatgpt.com/api/auth/session',None),
        ('me','https://chatgpt.com/backend-api/me',None),
        ('accounts_check','https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=-480',None),
        ('models','https://chatgpt.com/backend-api/models',None),
        ('realtime_status','https://chatgpt.com/realtime/status',{'conversation_id':None,'requested_voice_mode':'advanced','gizmo_id':None,'voice':'cove','requested_default_model':'auto','timezone_offset_min':-480,'nonce':did or str(time.time()),'voice_status_request_id':str(int(time.time()*1000))}),
    ]
    access=acc.get('access_token') or ''
    for name,url,payload in endpoints:
        try:
            if payload is None:
                res=await page.evaluate("""async ({url, access}) => {
                    const h={accept:'application/json'}; if(access) h.authorization='Bearer '+access;
                    const r=await fetch(url,{headers:h,credentials:'include'}); const t=await r.text();
                    return {status:r.status, text:t.slice(0,20000)};
                }""", {'url':url,'access':access})
            else:
                res=await page.evaluate("""async ({url, payload, access}) => {
                    const h={accept:'application/json','content-type':'application/json'}; if(access) h.authorization='Bearer '+access;
                    const r=await fetch(url,{method:'POST',headers:h,credentials:'include',body:JSON.stringify(payload)}); const t=await r.text();
                    return {status:r.status, text:t.slice(0,20000)};
                }""", {'url':url,'payload':payload,'access':access})
            item={'status':res.get('status')}
            txt=res.get('text') or ''
            try:
                obj=json.loads(txt)
                item['json_keys']=list(obj.keys())[:40] if isinstance(obj,dict) else type(obj).__name__
                item['plan_fields']=compact_plan_fields(obj)
                if name=='auth_session':
                    at=(obj.get('accessToken') or '') if isinstance(obj,dict) else ''
                    if at:
                        item['fresh_jwt_plan_type']=extract_plan_from_jwt(at)
                        access=at
                if name=='models':
                    s=json.dumps(obj)[:10000].lower(); item['mentions']={k:(k in s) for k in ['plus','paid','gpt-4','gpt-4o','free']}
            except Exception:
                item['text_snip']=txt[:300]
            results['endpoints'][name]=item
        except Exception as e:
            results['endpoints'][name]={'error':f'{type(e).__name__}:{str(e)[:160]}'}
    results['classification']=classify(results)
    await browser.close()
    return results

async def main():
    db=get_db(); accs=[]
    with db._conn() as c:
        for email in EMAILS:
            r=c.execute('SELECT * FROM registered_accounts WHERE lower(email)=lower(?) ORDER BY id DESC LIMIT 1',(email,)).fetchone()
            if r: accs.append(dict(r))
            else: print(json.dumps({'email':email,'error':'not found'},ensure_ascii=False))
    async with async_playwright() as pw:
        outs=[]
        for acc in accs:
            outs.append(await check_one(pw,acc))
        print(json.dumps(outs,ensure_ascii=False,indent=2))
if __name__=='__main__': asyncio.run(main())
