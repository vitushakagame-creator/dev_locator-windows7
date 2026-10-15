import os, json, secrets, hashlib, re, uuid, mimetypes, base64
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlencode
import requests
from flask import Flask, request, jsonify, session, redirect, send_file, send_from_directory, make_response
import bcrypt
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('DATA_DIR', ROOT / 'data'))
UPLOAD_DIR = Path(os.environ.get('UPLOAD_DIR', ROOT / 'uploads'))
USERS_DIR = DATA_DIR / 'users'
DB_FILE = DATA_DIR / 'db.json'
SESSION_SECRET_FILE = DATA_DIR / 'session-secret.txt'
for folder in (DATA_DIR, UPLOAD_DIR, USERS_DIR): folder.mkdir(parents=True, exist_ok=True)

def now_iso(): return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def load_secret():
    value = os.environ.get('SESSION_SECRET', '').strip()
    if value: return value
    try:
        value = SESSION_SECRET_FILE.read_text(encoding='utf-8').strip()
        if len(value) >= 32: return value
    except OSError: pass
    value = secrets.token_hex(48)
    SESSION_SECRET_FILE.write_text(value, encoding='utf-8')
    try: SESSION_SECRET_FILE.chmod(0o600)
    except OSError: pass
    return value

def load_db():
    try:
        data = json.loads(DB_FILE.read_text(encoding='utf-8'))
        if isinstance(data.get('users'), list) and isinstance(data.get('projects'), list): return data
    except (OSError, ValueError, AttributeError): pass
    data = {'users': [], 'projects': []}; DB_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8'); return data

db = load_db()
def persist():
    temp = DB_FILE.with_suffix('.json.tmp')
    temp.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(DB_FILE)
    index=[]
    for user in db['users']:
        filename=hashlib.sha256(user['name'].lower().encode()).hexdigest()+'.json'
        projects=[]
        for p in db['projects']:
            if p.get('author') == user['name']:
                projects.append({'id':p.get('id'),'title':p.get('title'),'language':p.get('language'),'category':p.get('category'),'description':p.get('description'),'created':p.get('created'),'files':[{'id':f.get('id'),'name':f.get('name'),'size':f.get('size')} for f in p.get('files',[])]})
        record={'name':user['name'],'bio':user.get('bio',''),'createdAt':user.get('createdAt'),'lastAccountDownload':user.get('lastAccountDownload'),'accountDownloads':user.get('accountDownloads',[]),'projects':projects}
        (USERS_DIR/filename).write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
        index.append({'name':user['name'],'file':filename})
    (USERS_DIR/'index.json').write_text(json.dumps(index,ensure_ascii=False,indent=2),encoding='utf-8')

app=Flask(__name__)
app.secret_key=load_secret()
app.config.update(MAX_CONTENT_LENGTH=30*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=os.environ.get('NODE_ENV')=='production' or os.environ.get('FLASK_ENV')=='production', SESSION_COOKIE_SAMESITE='None' if os.environ.get('NODE_ENV')=='production' or os.environ.get('FLASK_ENV')=='production' else 'Lax', PERMANENT_SESSION_LIFETIME=604800)
SITE_ORIGIN=os.environ.get('SITE_ORIGIN','').rstrip('/')
SITE_URL=os.environ.get('SITE_URL',SITE_ORIGIN).rstrip('/')
API_PUBLIC_URL=os.environ.get('API_PUBLIC_URL','').rstrip('/')
GITHUB_CLIENT_ID=os.environ.get('GITHUB_CLIENT_ID','')
GITHUB_CLIENT_SECRET=os.environ.get('GITHUB_CLIENT_SECRET','')
GITHUB_CALLBACK_URL=os.environ.get('GITHUB_CALLBACK_URL', (API_PUBLIC_URL+'/auth/github/callback') if API_PUBLIC_URL else '')

@app.before_request
def cors_preflight():
    origin=request.headers.get('Origin')
    if request.method=='OPTIONS':
        resp=make_response('',204)
        if origin and SITE_ORIGIN and origin==SITE_ORIGIN:
            resp.headers['Access-Control-Allow-Origin']=origin; resp.headers['Access-Control-Allow-Credentials']='true'; resp.headers['Access-Control-Allow-Headers']='Content-Type'; resp.headers['Access-Control-Allow-Methods']='GET,POST,PATCH,DELETE,OPTIONS'; resp.headers['Vary']='Origin'
        return resp

@app.after_request
def cors_headers(resp):
    origin=request.headers.get('Origin')
    if origin and SITE_ORIGIN and origin==SITE_ORIGIN:
        resp.headers['Access-Control-Allow-Origin']=origin; resp.headers['Access-Control-Allow-Credentials']='true'; resp.headers['Access-Control-Allow-Headers']='Content-Type'; resp.headers['Access-Control-Allow-Methods']='GET,POST,PATCH,DELETE,OPTIONS'; resp.headers['Vary']='Origin'
    return resp

def safe_user(u): return {'name':u.get('name',''), 'bio':u.get('bio','') or ''}
def safe_project(p, viewer=None):
    result=dict(p); result['liked']=bool(viewer and viewer in (p.get('likedBy') or [])); result['imageUrl']='/uploads/'+p['imageFile']['storedName'] if p.get('imageFile') and p['imageFile'].get('storedName') else ''
    return result

def current_user(): return session.get('user')
def auth_required():
    if not current_user(): return jsonify(error='Сначала войди в аккаунт.'),401
    return None
def get_user(name): return next((u for u in db['users'] if u.get('name','').lower()==str(name or '').lower()),None)
def clean_name(v): return str(v or '').strip()
def json_body(): return request.get_json(silent=True) or {}
def remove_uploaded(groups):
    for group in (groups or {}).values():
        for item in group:
            try: Path(item['path']).unlink(missing_ok=True)
            except OSError: pass

def save_upload(file):
    original=Path(file.filename or 'file').name
    suffix=''.join(Path(original).suffixes)[-12:]
    suffix=re.sub(r'[^.a-zA-Z0-9]','',suffix)
    stored=uuid.uuid4().hex+suffix
    target=UPLOAD_DIR/stored
    file.save(target)
    return {'id':stored,'name':original[:180] or 'file','size':target.stat().st_size,'storedName':stored,'mime':file.mimetype or mimetypes.guess_type(original)[0] or 'application/octet-stream'}

@app.get('/healthz')
def health(): return jsonify(ok=True)
@app.get('/')
@app.get('/index.html')
def home(): return send_from_directory(ROOT,'index.html')
@app.get('/uploads/<path:filename>')
def uploaded_file(filename):
    if filename.startswith('.'): return 'Not found',404
    return send_from_directory(UPLOAD_DIR,filename,as_attachment=False)

@app.get('/auth/github')
def github_login():
    if not GITHUB_CLIENT_ID or not GITHUB_CALLBACK_URL: return 'GitHub login is not configured. Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and GITHUB_CALLBACK_URL.',503
    state=secrets.token_hex(24); session['githubOAuthState']=state
    params={'client_id':GITHUB_CLIENT_ID,'redirect_uri':GITHUB_CALLBACK_URL,'scope':'read:user user:email','state':state}
    return redirect('https://github.com/login/oauth/authorize?'+urlencode(params))

@app.get('/auth/github/callback')
def github_callback():
    def fail(msg): return redirect((SITE_URL+'/' if SITE_URL else '/')+'?github_login_error='+requests.utils.quote(msg,safe=''))
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET or not GITHUB_CALLBACK_URL: return 'GitHub OAuth is not configured.',503
    code=request.args.get('code'); state=request.args.get('state')
    if not code or not state or state != session.get('githubOAuthState'):
        session.pop('githubOAuthState',None); return fail('Проверка GitHub-входа не прошла. Попробуй ещё раз.')
    session.pop('githubOAuthState',None)
    try:
        token_response=requests.post('https://github.com/login/oauth/access_token',headers={'Accept':'application/json','User-Agent':'DevSpace'},json={'client_id':GITHUB_CLIENT_ID,'client_secret':GITHUB_CLIENT_SECRET,'code':code,'redirect_uri':GITHUB_CALLBACK_URL},timeout=20)
        token_data=token_response.json(); token=token_data.get('access_token')
        if not token_response.ok or not token: return fail('GitHub не подтвердил вход. Проверь настройки OAuth.')
        profile_response=requests.get('https://api.github.com/user',headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','User-Agent':'DevSpace'},timeout=20)
        profile=profile_response.json()
        if not profile_response.ok or not profile.get('id') or not profile.get('login'): return fail('Не удалось получить профиль GitHub.')
        u=next((x for x in db['users'] if str(x.get('githubId',''))==str(profile['id'])),None)
        if not u:
            base=re.sub(r'[^\w.-]','',str(profile['login']),flags=re.UNICODE)[:24] or 'github-user'; name=base; suffix=2
            while any(x['name'].lower()==name.lower() for x in db['users']):
                tail='-'+str(suffix); suffix+=1; name=base[:24-len(tail)]+tail
            u={'name':name,'githubId':str(profile['id']),'githubLogin':str(profile['login']),'bio':'','createdAt':now_iso(),'accountDownloads':[]}; db['users'].append(u)
        else: u['githubLogin']=str(profile['login'])
        session['user']=u['name']; session.permanent=True; persist()
        return redirect((SITE_URL+'/' if SITE_URL else '/')+'?github_login=success')
    except Exception as exc:
        app.logger.exception('GitHub OAuth error: %s',exc); return fail('Не удалось войти через GitHub. Попробуй ещё раз.')

@app.get('/api/state')
def state(): return jsonify(users=[safe_user(u) for u in db['users']],projects=[safe_project(p,current_user()) for p in db['projects']],currentUser=current_user() or '')

@app.post('/api/register')
def register():
    body=json_body(); name=clean_name(body.get('name')); password=str(body.get('password') or '')
    if not re.fullmatch(r'[\w .-]{2,24}',name,re.UNICODE): return jsonify(error='Имя: 2–24 символа, буквы, цифры, пробел, точка, дефис или подчёркивание.'),400
    if len(password)<8 or len(password)>100: return jsonify(error='Пароль должен содержать от 8 до 100 символов.'),400
    if get_user(name): return jsonify(error='Это имя уже занято.'),409
    u={'name':name,'passwordHash':bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8'),'bio':'','createdAt':now_iso(),'accountDownloads':[]}; db['users'].append(u); session['user']=name; session.permanent=True; persist()
    return jsonify(user=safe_user(u)),201

@app.post('/api/login')
def login():
    body=json_body(); name=clean_name(body.get('name')); password=str(body.get('password') or ''); u=get_user(name)
    if not u or not u.get('passwordHash'): return jsonify(error='Неверное имя пользователя или пароль.'),401
    try:
        stored=u['passwordHash'].encode('utf-8')
        valid=bcrypt.checkpw(password.encode('utf-8'),stored) if stored.startswith((b'$2a$',b'$2b$',b'$2y$')) else False
    except (ValueError, TypeError): valid=False
    if not valid: return jsonify(error='Неверное имя пользователя или пароль.'),401
    session['user']=u['name']; session.permanent=True; return jsonify(user=safe_user(u))

@app.post('/api/logout')
def logout(): session.clear(); resp=jsonify(ok=True); resp.delete_cookie('session'); return resp

def account_export_response():
    u=get_user(current_user())
    if not u: return jsonify(error='Пользователь не найден.'),404
    token=secrets.token_hex(32); downloaded=now_iso(); u['accountTokenHash']=hashlib.sha256(token.encode()).hexdigest(); u['createdAt']=u.get('createdAt') or downloaded
    u['lastAccountDownload']=downloaded; u['accountDownloads']=u.get('accountDownloads',[]); u['accountDownloads'].append(downloaded); u['accountDownloads']=u['accountDownloads'][-100:]; persist()
    owned=[p for p in db['projects'] if p.get('author')==u['name']]; projects=[]
    for p in owned:
        files=[]
        for f in p.get('files',[]):
            target=UPLOAD_DIR/Path(f.get('storedName','')).name if f.get('storedName') else None; data=''
            if target and target.is_file(): data='data:'+(f.get('mime') or 'application/octet-stream')+';base64,'+base64.b64encode(target.read_bytes()).decode()
            files.append({'id':f.get('id'),'name':f.get('name'),'size':f.get('size'),'mime':f.get('mime') or 'application/octet-stream','data':data})
        q={k:p.get(k) for k in ('id','title','language','category','description','author','likes','likedBy','created','symbol','theme')}; q['files']=files; projects.append(q)
    resp=jsonify(type='devspace-account',version=2,name=u['name'],token=token,bio=u.get('bio',''),createdAt=u.get('createdAt'),downloadedAt=downloaded,lastDownloadAt=downloaded,downloadHistory=u['accountDownloads'],stats={'projects':len(owned),'likesReceived':sum(int(p.get('likes') or 0) for p in owned),'likesGiven':sum(1 for p in db['projects'] if u['name'] in (p.get('likedBy') or [])),'totalProjectFiles':sum(len(p.get('files',[])) for p in owned)},projects=projects)
    resp.headers['Cache-Control']='no-store'; return resp

@app.get('/api/account/export')
@app.post('/api/account/export')
def export_account():
    denied=auth_required()
    if denied: return denied
    return account_export_response()

@app.post('/api/account/import')
def import_account():
    body=json_body(); name=clean_name(body.get('name')); token=str(body.get('token') or '')
    if body.get('type')!='devspace-account' or not name or not re.fullmatch(r'[a-f0-9]{64}',token,re.I): return jsonify(error='Файл аккаунта повреждён или имеет неверный формат.'),400
    u=get_user(name); token_hash=hashlib.sha256(token.encode()).hexdigest()
    if not u or not u.get('accountTokenHash') or not secrets.compare_digest(token_hash,u['accountTokenHash']): return jsonify(error='Файл аккаунта недействителен. Войди по паролю и скачай новый файл.'),401
    session['user']=u['name']; session.permanent=True; return jsonify(user=safe_user(u))

@app.patch('/api/profile')
def update_profile():
    denied=auth_required()
    if denied: return denied
    u=get_user(current_user())
    if not u: return jsonify(error='Пользователь не найден.'),404
    u['bio']=str(json_body().get('bio') or '')[:240]; persist(); return jsonify(user=safe_user(u))

@app.post('/api/projects')
def create_project():
    denied=auth_required()
    if denied: return denied
    title=str(request.form.get('title') or '').strip()
    if not title or len(title)>80: return jsonify(error='Название проекта обязательно (до 80 символов).'),400
    incoming=request.files.getlist('files'); images=request.files.getlist('image')
    if len(incoming)>10 or len(images)>1: return jsonify(error='Слишком много файлов или полей.'),400
    saved={}
    try:
        files=[]
        for file in incoming:
            if not file.filename: continue
            item=save_upload(file); files.append(item); saved[item['storedName']]=True
        img=None
        for image in images:
            if image and image.filename:
                if not (image.mimetype or '').startswith('image/'): raise ValueError('Картинка должна быть изображением.')
                img=save_upload(image); saved[img['storedName']]=True; break
        p={'id':str(uuid.uuid4()),'title':title,'language':str(request.form.get('language') or 'Другой')[:40],'category':str(request.form.get('category') or 'Другое')[:40],'description':str(request.form.get('description') or '')[:1200],'author':current_user(),'likes':0,'likedBy':[],'symbol':['</>','{ }','▦','✦','◈'][secrets.randbelow(5)],'theme':['mint','blue','orange'][len(db['projects'])%3],'files':files,'imageFile':{'storedName':img['storedName'],'name':img['name']} if img else None,'created':int(datetime.now(timezone.utc).timestamp()*1000)}
        db['projects'].insert(0,p); persist(); return jsonify(safe_project(p,current_user())),201
    except (ValueError, OSError) as exc:
        for stored in saved: (UPLOAD_DIR/stored).unlink(missing_ok=True)
        return jsonify(error=str(exc) or 'Не удалось сохранить файлы.'),400

@app.post('/api/projects/<project_id>/like')
def like_project(project_id):
    denied=auth_required()
    if denied: return denied
    p=next((x for x in db['projects'] if x.get('id')==project_id),None)
    if not p: return jsonify(error='Проект не найден.'),404
    p.setdefault('likedBy',[])
    if current_user() in p['likedBy']: p['likedBy'].remove(current_user()); p['likes']=max(0,int(p.get('likes') or 0)-1)
    else: p['likedBy'].append(current_user()); p['likes']=int(p.get('likes') or 0)+1
    persist(); return jsonify(safe_project(p,current_user()))

@app.delete('/api/projects/<project_id>')
def delete_project(project_id):
    denied=auth_required()
    if denied: return denied
    p=next((x for x in db['projects'] if x.get('id')==project_id),None)
    if not p: return jsonify(error='Проект не найден.'),404
    if p.get('author')!=current_user(): return jsonify(error='Удалять можно только свои проекты.'),403
    db['projects'].remove(p)
    for f in list(p.get('files',[]))+([p['imageFile']] if p.get('imageFile') else []):
        if f.get('storedName'):
            try: (UPLOAD_DIR/Path(f['storedName']).name).unlink(missing_ok=True)
            except OSError: pass
    persist(); return jsonify(ok=True)

@app.get('/api/projects/<project_id>/files/<file_id>')
def download_project_file(project_id,file_id):
    p=next((x for x in db['projects'] if x.get('id')==project_id),None)
    f=next((x for x in (p or {}).get('files',[]) if x.get('id')==file_id),None)
    if not f: return 'Файл не найден',404
    if not f.get('storedName'): return 'У этого проекта нет серверного файла',404
    target=UPLOAD_DIR/Path(f['storedName']).name
    if not target.is_file(): return 'Файл отсутствует на сервере',404
    resp=send_file(target,as_attachment=True,download_name=f.get('name') or 'project-file',conditional=True); resp.headers['Cache-Control']='no-store'; return resp

@app.errorhandler(413)
def too_large(_): return jsonify(error='Загружаемые файлы слишком большие.'),413
@app.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, HTTPException): return jsonify(error=exc.description), exc.code
    if isinstance(exc, (KeyboardInterrupt,SystemExit)): raise exc
    app.logger.exception('Unhandled request error')
    return jsonify(error='Ошибка сервера. Проверь настройки и журналы запуска.'),500

if __name__=='__main__':
    persist()
    port=int(os.environ.get('PORT','8080'))
    app.run(host='0.0.0.0',port=port)
