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

def register_brain(app, main_db=None, User=None):
    db_url=os.getenv("BRAIN_DATABASE_URL","")
    app_secret=os.getenv("BRAIN_SESSION_SECRET","")
    enrollment_key=os.getenv("BRAIN_ENROLLMENT_KEY","")
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
    @app.post("/api/brain/setup")
    def brain_setup():
        # Only initial enrollment; an authenticated email is NOT enough.
        d=request.get_json(silent=True) or {}
        supplied=str(d.get("enrollment_key",""))
        if not enrollment_key or not cipher or not hmac.compare_digest(supplied,enrollment_key):
            return jsonify(error="Credencial de ativação inválida"),403
        email=str(d.get("email","")).strip().lower()
        password=str(d.get("password",""))
        if len(password)<14 or len(password)>128:return jsonify(error="Senha deve ter entre 14 e 128 caracteres"),400
        row=query("SELECT id,status FROM admin_accounts WHERE email=%s",(email,),one=True)
        if not row or row["status"]!="pending_setup":return jsonify(error="Conta indisponível para ativação"),409
        secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        query("UPDATE admin_accounts SET password_hash=%s,mfa_pending_secret=%s WHERE id=%s AND status='pending_setup'",(generate_password_hash(password),cipher.encrypt(secret.encode()).decode(),row["id"]))
        return jsonify(secret=secret,otpauth_uri=f"otpauth://totp/Arena%20Brain:{email}?secret={secret}&issuer=Arena%20Brain")
    @app.post("/api/brain/setup/confirm")
    def brain_setup_confirm():
        d=request.get_json(silent=True) or {}
        if not enrollment_key or not cipher or not hmac.compare_digest(str(d.get("enrollment_key","")),enrollment_key):
            return jsonify(error="Credencial de ativação inválida"),403
        email=str(d.get("email","")).strip().lower()
        row=query("SELECT id,status,mfa_pending_secret FROM admin_accounts WHERE email=%s",(email,),one=True)
        if not row or row["status"]!="pending_setup" or not row["mfa_pending_secret"]:return jsonify(error="Ativação não iniciada"),409
        if otp_step(cipher.decrypt(row["mfa_pending_secret"].encode()).decode(),str(d.get("otp",""))) is None:return jsonify(error="Código inválido"),401
        query("UPDATE admin_accounts SET mfa_secret_encrypted=%s,mfa_pending_secret=NULL,mfa_enabled=TRUE,status='active',activated_at=NOW(),session_epoch=session_epoch+1 WHERE id=%s AND status='pending_setup'",(row["mfa_pending_secret"],row["id"]))
        return jsonify(ok=True)
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
    @app.get("/api/brain/organizers")
    @admin_required
    def brain_organizers(admin):
        if main_db is None or User is None: return jsonify(error="Serviço de organizadores indisponível"),503
        users=User.query.filter_by(role="organizer").order_by(User.id.desc()).limit(250).all()
        return {"organizers":[{"id":u.id,"name":u.name,"email":u.email,"approved":u.approved} for u in users]}
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
