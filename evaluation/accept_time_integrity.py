"""Local-only HTTP acceptance for refusing the known contradictory saved AI run."""
import os,json,hashlib,shutil,threading,urllib.request,urllib.error,http.cookiejar
from pathlib import Path
from dataclasses import replace
ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT/'data/final-http-acceptance';WORK.mkdir(exist_ok=True)
os.environ['SOC_TRIAGE_DB_PATH']=str(WORK/'audit.db')
from services import api,auth
from services.config import load_settings
from services.triage import TriageService
from services.data_store import Dataset
from services.unified_audit import verify
settings=load_settings(); production=[settings.state_path,ROOT/'data/audit.db',ROOT/'data/auth/account.json']
def hashes():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None for p in production}
before=hashes();shutil.copyfile(settings.state_path,WORK/'state.json')
auth.AUTH_FILE=WORK/'account.json'
auth.USERNAME='AcceptanceTester'
if not auth.AUTH_FILE.exists():auth._write_account({'username':auth.USERNAME,'password_hash':auth._hash_password('Local-QA-only-2026!'),'password_version':1})
api._ai_service=TriageService(replace(settings,state_path=WORK/'state.json',audit_path=WORK/'audit.jsonl'),Dataset.load(settings.alerts_path,settings.timelines_path))
server=api.ThreadingHTTPServer(('127.0.0.1',0),api.Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
base='http://127.0.0.1:'+str(server.server_port);csrf=''
def request(path,payload=None,login=False):
 headers={'Content-Type':'application/json','X-SOC-Desk-Auth':'1','X-CSRF-Token':csrf}
 r=urllib.request.Request(base+path,data=json.dumps(payload).encode() if payload is not None else None,headers=headers)
 try:
  with opener.open(r) as response:return response.status,json.load(response)
 except urllib.error.HTTPError as e:return e.code,json.load(e)
try:
 code,r=request('/api/auth/login',{'username':auth.USERNAME,'password':'Local-QA-only-2026!'});assert code==200;csrf=r['csrf_token']
 case='INC-A787E11F2A22';prefix='/api/cases/'+case+'/'
 code,result=request(prefix+'ai-assessment');assert code==200 and result['status']=='unavailable' and result['assessment'] is None
 assert result['error']['code']=='EVIDENCE_INTEGRITY_FAILED'
 code,checks=request(prefix+'recommendations');assert code==200 and not any(item['ai_suggested'] for item in checks['checks'])
 code,_=request(prefix+'ai-decision',{'analyst':auth.USERNAME,'decision':'confirmed'});assert code==400
 code,_=request(prefix+'approval',{'analyst':auth.USERNAME,'decisions':{checks['checks'][0]['id']:'approved'}});assert code==400
 code,record=request(prefix+'record',{'analyst':auth.USERNAME});assert code==200 and record['record']['ai_summary'] is None
 code,audit=request('/api/audit/verify');assert code==200 and audit['ok']
 assert before==hashes()
 summary={'kind':'isolated-local-http-integrity-acceptance','case':case,'invalid_ai_hidden':True,'ai_suggestions_withheld':True,'assessment_confirmation_blocked':True,'recommendation_approval_blocked':True,'saved_record_excludes_invalid_conclusion':True,'audit_verified':True,'production_unchanged':True,'external_model_calls':0}
 (ROOT/'evaluation/final-http-integrity-20261024.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
finally:server.shutdown();server.server_close()
