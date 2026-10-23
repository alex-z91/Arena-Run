"""Arena Brain admin authentication in an isolated Neon database.
No public signup. Initial setup requires an out-of-band provisioning secret.
"""
import os, time, hmac, hashlib, base64, struct, secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
import psycopg
from cryptography.fernet import Fernet
from psycopg.rows import dict_row
from flask import request, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import OperationalError

def register_brain(app, main_db=None, User=None):
    db_url=os.getenv("BRAIN_DATABASE_URL","")
    app_secret=os.getenv("BRAIN_SESSION_SECRET","")
    enrollment_key=os.getenv("BRAIN_ENROLLMENT_KEY","")
    enrollment_deadline=float(os.getenv("BRAIN_ENROLLMENT_DEADLINE","0"))
    fernet_key=os.getenv("BRAIN_FERNET_KEY","")
    if not db_url or not app_secret:
        app.logger.warning("Arena Brain API disabled: BRAIN_DATABASE_URL or BRAIN_SESSION_SECRET unset")
        return
    cipher=Fernet(fernet_key.encode()) if fernet_key else None
    signer=URLSafeTimedSerializer(app_secret,salt="arena-brain-admin-v1")
    def query(sql,params=(),one=False):
        with psycopg.connect(db_url,autocommit=False,row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql,params)
                result=cur.fetchone() if one else cur.fetchall() if cur.description else None
                conn.commit()
                return result
    def otp_step(key,code):
        if not isinstance(code,str) or len(code)!=6 or not code.isascii() or not code.isdigit(): return None
        try:
            raw=base64.b32decode(key,casefold=True)
            now=int(time.time()//30)
            for i in (now-1,now,now+1):
                d=hmac.new(raw,struct.pack(">Q",i),hashlib.sha1).digest()
                off=d[-1]&15
                num=(struct.unpack(">I",d[off:off+4])[0]&0x7fffffff)%1000000
                if hmac.compare_digest(f"{num:06d}",code):return i
        except (ValueError,TypeError):pass
        return None
    def admin_required(fn):
        @wraps(fn)
        def wrapped(*args,**kwargs):
            token=request.headers.get("Authorization","")
            if not token.startswith("Bearer "):return jsonify(error="Autenticação obrigatória"),401
            try: data=signer.loads(token[7:],max_age=1800)
            except (BadSignature,SignatureExpired):return jsonify(error="Sessão expirada"),401
            u=query("SELECT id,email,status,mfa_enabled,session_epoch FROM admin_accounts WHERE id=%s",(data.get("uid"),),one=True)
            if not u or u["status"]!="active" or not u["mfa_enabled"] or data.get("epoch")!=u["session_epoch"]:
                return jsonify(error="Acesso negado"),403
            return fn(u,*args,**kwargs)
        return wrapped
    @app.post("/api/brain/login")
    def brain_login():
        d=request.get_json(silent=True) or {}
        email=str(d.get("email","")).strip().lower()
        row=query("SELECT id,email,password_hash,mfa_secret_encrypted,mfa_enabled,status,failed_attempts,locked_until,session_epoch,last_totp_step FROM admin_accounts WHERE email=%s",(email,),one=True)
        if not row:return jsonify(error="Credenciais inválidas"),401
        if row["locked_until"] and row["locked_until"].replace(tzinfo=timezone.utc)>datetime.now(timezone.utc):return jsonify(error="Acesso temporariamente bloqueado"),429
        valid=row["status"]=="active" and row["mfa_enabled"] and row["password_hash"] and check_password_hash(row["password_hash"],str(d.get("password","")))
        step=otp_step(cipher.decrypt(row["mfa_secret_encrypted"].encode()).decode(),str(d.get("otp",""))) if valid and cipher else None
        if step is None or (row["last_totp_step"] is not None and step<=row["last_totp_step"]):
            query("UPDATE admin_accounts SET failed_attempts=CASE WHEN failed_attempts>=4 THEN 0 ELSE failed_attempts+1 END,locked_until=CASE WHEN failed_attempts>=4 THEN NOW()+INTERVAL '15 minutes' ELSE locked_until END WHERE id=%s",(row["id"],))
            return jsonify(error="Credenciais ou código inválidos"),401
        query("UPDATE admin_accounts SET failed_attempts=0,locked_until=NULL,last_totp_step=%s WHERE id=%s",(step,row["id"]))
        return jsonify(token=signer.dumps({"uid":row["id"],"epoch":row["session_epoch"]}),user={"email":row["email"],"role":"master"})
    @app.get("/api/brain/me")
    @admin_required
    def brain_me(admin):
        return {"email":admin["email"],"role":"master"}
    @app.post("/api/brain/logout")
    @admin_required
    def brain_logout(admin):
        query("UPDATE admin_accounts SET session_epoch=session_epoch+1 WHERE id=%s",(admin["id"],))
        return {"ok":True}
    @app.post("/api/brain/organizers")
    @admin_required
    def brain_create_organizer(admin):
        if main_db is None or User is None:return jsonify(error="Serviço indisponível"),503
        d=request.get_json(silent=True) or {}
        name=str(d.get("name","")).strip()
        email=str(d.get("email","")).strip().lower()
        password=str(d.get("temporary_password",""))
        if not 3<=len(name)<=100 or len(email)>180 or "@" not in email or not 12<=len(password)<=128:
            return jsonify(error="Informe nome, e-mail e senha provisória de pelo menos 12 caracteres"),400
        if User.query.filter_by(email=email).first():
            return jsonify(error="E-mail já cadastrado"),409
        organizer=User(name=name,email=email,password_hash=generate_password_hash(password),role="organizer",approved=True,must_change_password=True,auth_version=0)
        try:
            main_db.session.add(organizer)
            main_db.session.flush()
            query("INSERT INTO brain_audit_events (admin_id,action,target_type,target_id) VALUES (%s,%s,%s,%s)",(admin["id"],"organizer.create","organizer",organizer.id))
            main_db.session.commit()
        except Exception:
            main_db.session.rollback()
            app.logger.exception("Organizer provisioning failed")
            return jsonify(error="Não foi possível criar o organizador"),500
        return jsonify(id=organizer.id,name=name,email=email,must_change_password=True),201
    @app.get("/api/brain/organizers")
    @admin_required
    def brain_organizers(admin):
        if main_db is None or User is None: return jsonify(error="Serviço de organizadores indisponível"),503
        try:
            users=User.query.filter_by(role="organizer").order_by(User.id.desc()).limit(250).all()
        except OperationalError:
            main_db.session.rollback()
            main_db.engine.dispose()
            try:
                users=User.query.filter_by(role="organizer").order_by(User.id.desc()).limit(250).all()
            except OperationalError:
                main_db.session.rollback()
                return jsonify(error="Banco temporariamente indisponível. Tente novamente."),503
        return {"organizers":[{"id":u.id,"name":u.name,"email":u.email,"approved":u.approved,"must_change_password":u.must_change_password} for u in users]}
    @app.post("/api/brain/organizers/<int:organizer_id>/approve")
    @admin_required
    def brain_organizer_approve(admin,organizer_id):
        if main_db is None or User is None: return jsonify(error="Serviço indisponível"),503
        u=main_db.session.get(User,organizer_id)
        if not u or u.role!="organizer":return jsonify(error="Organizador não encontrado"),404
        if u.approved:return {"ok":True}
        try:
            u.approved=True
            main_db.session.commit()
            query("INSERT INTO brain_audit_events (admin_id,action,target_type,target_id) VALUES (%s,%s,%s,%s)",
                  (admin["id"],"organizer.approve","organizer",organizer_id))
            return {"ok":True}
        except Exception:
            main_db.session.rollback()
            app.logger.exception("Failed to approve organizer or write audit")
            return jsonify(error="Falha de aprovação; consulte auditoria"),500
    @app.get("/api/brain/overview")
    @admin_required
    def brain_overview(admin):
        # Separate database: organizer management requires a server-side API bridge; never expose main DB credentials to browser.
        return {"status":"ready","organizers_integration":"pending"}
