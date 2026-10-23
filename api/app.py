import os
import secrets
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(180), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    birth_date = db.Column(db.String(10), nullable=True)
    city = db.Column(db.String(120), nullable=True)
    cpf = db.Column(db.String(11), nullable=True, unique=True)
    rg = db.Column(db.String(30), nullable=True)
    contact = db.Column(db.String(30), nullable=True)
    gender = db.Column(db.String(30), nullable=True)
    team = db.Column(db.String(120), nullable=True)
    shirt_size = db.Column(db.String(3), nullable=True)
    role = db.Column(db.String(24), nullable=False, default="runner")
    approved = db.Column(db.Boolean, nullable=False, default=False)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    auth_version = db.Column(db.Integer, nullable=False, default=0)

class Race(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organizer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(140), nullable=False)
    city = db.Column(db.String(120), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    published = db.Column(db.Boolean, nullable=False, default=False)
    publication_status = db.Column(db.String(24), nullable=True)
    local_city = db.Column(db.String(120), nullable=True)
    regulation_text = db.Column(db.Text, nullable=True)

class Distance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    race_id = db.Column(db.Integer, db.ForeignKey("race.id"), nullable=False, index=True)
    label = db.Column(db.String(30), nullable=False)
    price_cents = db.Column(db.Integer, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    runner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    distance_id = db.Column(db.Integer, db.ForeignKey("distance.id"), nullable=False, index=True)
    shirt_size = db.Column(db.String(3), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="awaiting_payment")
    category_snapshot = db.Column(db.String(60), nullable=True)
    locality_snapshot = db.Column(db.String(20), nullable=True)
    team_snapshot = db.Column(db.String(120), nullable=True)
    regulation_accepted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    paid_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

def create_app():
    app = Flask(__name__, static_folder="../", static_url_path="/arena-run")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///arena_run_dev.db").replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_recycle": 120, "pool_size": 3, "max_overflow": 2, "pool_timeout": 15}
    secret = os.environ.get("SECRET_KEY")
    if not secret and os.environ.get("APP_ENV") != "development":
        raise RuntimeError("Configure SECRET_KEY e APP_ENV antes de iniciar")
    app.config["SECRET_KEY"] = secret or secrets.token_hex(32)
    db.init_app(app)
    allowed_origins = {u.strip().rstrip("/") for u in (os.environ.get("FRONTEND_ORIGIN", "") + ",https://brain.alexcoder.space,https://coach.alexcoder.space").split(",") if u.strip()}
    @app.after_request
    def cors_headers(response):
        if request.headers.get("Origin") in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response
    @app.before_request
    def cors_preflight():
        if request.method == "OPTIONS" and request.path.startswith("/api/"):
            return app.make_default_options_response()

    signer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="arena-run-auth")
    def error(message, status=400):
        return jsonify({"error": message}), status
    def payload():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    def auth(*roles):
        def decorate(fn):
            @wraps(fn)
            def inner(*args, **kwargs):
                header = request.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    return error("Autenticação obrigatória", 401)
                try:
                    user_id = signer.loads(header[7:], max_age=60*60*12)
                except (BadSignature, SignatureExpired):
                    return error("Sessão inválida ou expirada", 401)
                session_data=user_id
                user_id=session_data.get("uid") if isinstance(session_data,dict) else session_data
                user = db.session.get(User, user_id)
                if user and user.role=="organizer":
                    if not isinstance(session_data,dict) or session_data.get("version")!=user.auth_version:
                        return error("Sessão expirada",401)
                    if user.must_change_password:
                        return error("Troque sua senha provisória antes de continuar",403)
                if not user or (roles and user.role not in roles):
                    return error("Sem permissão", 403)
                if user.role == "organizer" and not user.approved:
                    return error("Organizador aguardando aprovação", 403)
                return fn(user, *args, **kwargs)
            return inner
        return decorate
    def age_on(birth, date):
        b=datetime.strptime(birth, "%Y-%m-%d").date()
        d=datetime.strptime(date, "%Y-%m-%d").date()
        return d.year-b.year-((d.month,d.day)<(b.month,b.day))
    def user_data(u):
        return {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "approved": u.approved, "birth_date":u.birth_date,"city":u.city,"contact":u.contact,"gender":u.gender,"team":u.team,"shirt_size":u.shirt_size}
    def race_data(r):
        return {"id": r.id, "title": r.title, "city": r.city, "date": r.date, "local_city":r.local_city, "publication_status":r.publication_status or ("published" if r.published else "draft"), "regulation_text":r.regulation_text, "distances": [{"id": d.id, "label": d.label, "price_cents": d.price_cents, "capacity": d.capacity} for d in Distance.query.filter_by(race_id=r.id).order_by(Distance.id)]}
    @app.get("/api/health")
    def health():
        return {"status": "ok", "payment_integration": "not_configured"}
    @app.post("/api/auth/register")
    def register():
        data = payload()
        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        role = data.get("role", "runner")
        city = str(data.get("city","")).strip()
        birth = str(data.get("birth_date","")).strip()
        cpf = "".join(c for c in str(data.get("cpf","")) if c.isdigit())
        rg = str(data.get("rg","")).strip()
        contact = str(data.get("contact","")).strip()
        gender = str(data.get("gender","")).strip()
        team = str(data.get("team","")).strip()
        shirt = str(data.get("shirt_size","")).strip()
        if role!="runner": return error("O cadastro de organizadores é exclusivo do administrador",403)
        if role=="runner":
            try:
                parsed=datetime.strptime(birth,"%Y-%m-%d").date()
                if parsed.isoformat()!=birth or parsed>=datetime.now(timezone.utc).date() or parsed.year<1900: raise ValueError()
            except ValueError: return error("Data de nascimento inválida")
            if not 2<=len(city)<=120: return error("Informe a cidade do atleta")
            if len(cpf)!=11 or len(set(cpf))==1 or sum(int(cpf[i])*(10-i) for i in range(9))*10%11%10!=int(cpf[9]) or sum(int(cpf[i])*(11-i) for i in range(10))*10%11%10!=int(cpf[10]):
                return error("CPF inválido")
            if User.query.filter_by(cpf=cpf).first(): return error("CPF já cadastrado",409)
            if not 3<=len(rg)<=30 or not 8<=len(contact)<=30 or gender not in ("feminino","masculino","outro","nao_informar") or len(team)>120 or shirt not in ("PP","P","M","G","GG","XG"):
                return error("Confira RG, contato, gênero e tamanho da camiseta")
        if role not in ("runner", "organizer") or len(name) < 3 or len(name) > 100 or "@" not in email or len(email) > 180 or len(password) < 8 or len(password) > 128:
            return error("Preencha nome, e-mail e senha (mínimo 8 caracteres)")
        if User.query.filter_by(email=email).first():
            return error("E-mail já cadastrado", 409)
        u = User(name=name, email=email, password_hash=generate_password_hash(password), role=role, approved=role=="runner",birth_date=birth if role=="runner" else None,city=city if role=="runner" else None,cpf=cpf if role=="runner" else None,rg=rg if role=="runner" else None,contact=contact if role=="runner" else None,gender=gender if role=="runner" else None,team=team if role=="runner" else None,shirt_size=shirt if role=="runner" else None)
        db.session.add(u); db.session.commit()
        return jsonify({"user": user_data(u), "token": signer.dumps(u.id)}), 201
    @app.post("/api/auth/login")
    def login():
        data=payload()
        u=User.query.filter_by(email=str(data.get("email", "")).strip().lower()).first()
        if not u or not check_password_hash(u.password_hash, str(data.get("password", ""))):
            return error("Credenciais inválidas", 401)
        return {"user": user_data(u), "token": signer.dumps({"uid":u.id,"version":u.auth_version}) if u.role=="organizer" else signer.dumps(u.id),"must_change_password":bool(u.must_change_password)}
    @app.post("/api/auth/change-temporary-password")
    def organizer_change_password():
        header=request.headers.get("Authorization","")
        if not header.startswith("Bearer "): return error("Autenticação obrigatória",401)
        try:
            data=signer.loads(header[7:],max_age=60*60)
        except (BadSignature,SignatureExpired):
            return error("Sessão expirada",401)
        if not isinstance(data,dict): return error("Sessão inválida",401)
        u=db.session.get(User,data.get("uid"))
        if not u or u.role!="organizer" or data.get("version")!=u.auth_version or not u.must_change_password:
            return error("Troca de senha indisponível",403)
        body=payload()
        current=str(body.get("current_password",""))
        new=str(body.get("new_password",""))
        if not check_password_hash(u.password_hash,current):return error("Senha provisória inválida",401)
        if not (8<=len(new)<=128 and re.search(r"[A-Za-z]",new) and re.search(r"[0-9]",new) and re.search(r"[^A-Za-z0-9]",new)) or new==current:return error("A nova senha deve ter ao menos 8 caracteres, incluindo letra, número e caractere especial",400)
        u.password_hash=generate_password_hash(new)
        u.must_change_password=False
        u.auth_version+=1
        db.session.commit()
        return {"ok":True,"token":signer.dumps({"uid":u.id,"version":u.auth_version})}
    @app.get("/api/me")
    @auth()
    def me(user):
        return user_data(user)
    @app.get("/api/events")
    def events():
        q=Race.query.filter_by(published=True)
        term=str(request.args.get("q","")).strip()
        day=str(request.args.get("date","")).strip()
        if term: q=q.filter(db.or_(Race.title.ilike("%"+term[:100]+"%"),Race.city.ilike("%"+term[:100]+"%")))
        if day: q=q.filter_by(date=day)
        return {"events": [race_data(r) for r in q.order_by(Race.date).all()]}
    @app.post("/api/events")
    @auth("organizer", "master")
    def create_event(user):
        data=payload()
        title=str(data.get("title", "")).strip(); city=str(data.get("city", "")).strip(); date=str(data.get("date",""))
        distances=data.get("distances", [])
        try: datetime.strptime(date, "%Y-%m-%d")
        except ValueError: return error("Data inválida")
        if not (3<=len(title)<=140 and 2<=len(city)<=120 and isinstance(distances,list) and 1<=len(distances)<=10):
            return error("Dados do evento incompletos")
        validated=[]
        for d in distances:
            try:
                label=str(d["label"]).strip()
                cents=int(d["price_cents"]); capacity=int(d["capacity"])
                if not (1<=len(label)<=30 and 0<=cents<=10000000 and 1<=capacity<=100000): raise ValueError()
                validated.append((label,cents,capacity))
            except (KeyError, TypeError, ValueError): return error("Distância, preço ou vagas inválidos")
        r=Race(organizer_id=user.id,title=title,city=city,date=date,published=False,publication_status="draft",regulation_text=str(data.get("regulation_text") or "").strip()[:20000],local_city=str(data.get("local_city") or city).strip()[:120])
        db.session.add(r); db.session.flush()
        for label,cents,capacity in validated: db.session.add(Distance(race_id=r.id,label=label,price_cents=cents,capacity=capacity))
        db.session.commit()
        return jsonify(race_data(r)), 201
    @app.get("/api/organizer/events")
    @auth("organizer")
    def organizer_events(user):
        races=Race.query.filter_by(organizer_id=user.id).order_by(Race.id.desc()).all()
        return {"events":[race_data(r) for r in races]}
    @app.get("/api/organizer/overview")
    @auth("organizer")
    def organizer_overview(user):
        races=Race.query.filter_by(organizer_id=user.id).all()
        ids=[r.id for r in races]
        counts={"total_events":len(races),"drafts":sum((r.publication_status or "draft")=="draft" for r in races),"pending_review":sum(r.publication_status=="submitted" for r in races),"published":sum(r.published for r in races),"registrations":0}
        if ids:
            counts["registrations"]=db.session.query(Registration.id).join(Distance,Registration.distance_id==Distance.id).filter(Distance.race_id.in_(ids)).count()
        return counts
    @app.post("/api/organizer/events/<int:race_id>/submit")
    @auth("organizer")
    def organizer_submit(user,race_id):
        r=db.session.get(Race,race_id)
        if not r or r.organizer_id!=user.id:return error("Corrida não encontrada",404)
        if r.publication_status not in ("draft","rejected"):return error("Estado não permite envio",409)
        if not r.regulation_text or not Distance.query.filter_by(race_id=r.id).first():return error("Configure distâncias e regulamento antes do envio",400)
        r.publication_status="submitted"
        r.published=False
        db.session.commit()
        return race_data(r)
    @app.post("/api/registrations")
    @auth("runner", "organizer", "master")
    def create_registration(user):
        data=payload()
        try: distance_id=int(data.get("distance_id", 0))
        except (ValueError, TypeError): return error("Distância inválida")
        size=data.get("shirt_size")
        if data.get("regulation_accepted") is not True:
            return error("Leia e aceite o regulamento desta corrida")
        if size not in ("PP","P","M","G","GG","XG"):
            return error("Tamanho de camiseta inválido")
        d=db.session.get(Distance,distance_id)
        if not d or not db.session.get(Race,d.race_id).published:
            return error("Distância indisponível",404)
        existing=Registration.query.filter_by(runner_id=user.id,distance_id=distance_id).filter(Registration.status!="canceled").first()
        if existing: return error("Já existe uma inscrição para essa distância",409)
        # Vagas reais requerem transação serializável/lock na publicação.
        occupied=Registration.query.filter_by(distance_id=d.id).filter(Registration.status!="canceled").count()
        if occupied>=d.capacity: return error("Vagas esgotadas",409)
        if not user.birth_date or not user.city: return error("Complete data de nascimento e cidade do atleta antes da inscrição")
        race=db.session.get(Race,d.race_id)
        if not race.regulation_text: return error("Regulamento ainda não disponível para esta corrida",409)
        age=age_on(user.birth_date,race.date)
        if age<0: return error("Data de nascimento incompatível com a corrida")
        # Categoria etária definitiva depende de regulamento versionado por evento.
        locality="local" if user.city.strip().casefold()==(race.local_city or race.city).strip().casefold() else "general"
        reg=Registration(runner_id=user.id,distance_id=d.id,shirt_size=size,category_snapshot=f"Idade na prova: {age}",locality_snapshot=locality,team_snapshot=user.team,regulation_accepted_at=datetime.now(timezone.utc))
        db.session.add(reg); db.session.commit()
        return jsonify({"id":reg.id,"status":reg.status,"payment_mode":"pending_integration","price_cents":d.price_cents}),201
    @app.get("/api/registrations/me")
    @auth()
    def my_registrations(user):
        rows=Registration.query.filter_by(runner_id=user.id).order_by(Registration.id.desc()).all()
        result=[]
        for x in rows:
            dist=db.session.get(Distance,x.distance_id)
            race=db.session.get(Race,dist.race_id)
            result.append({"id":x.id,"race_id":race.id,"race":race.title,"city":race.city,"date":race.date,"distance":dist.label,"price_cents":dist.price_cents,"shirt_size":x.shirt_size,"status":x.status,"category":x.category_snapshot,"locality":x.locality_snapshot,"team":x.team_snapshot,"created_at":x.created_at.isoformat() if x.created_at else None,"paid_at":x.paid_at.isoformat() if x.paid_at else None,"regulation_accepted_at":x.regulation_accepted_at.isoformat() if x.regulation_accepted_at else None})
        return {"registrations":result}
    @app.get("/api/organizer/registrations")
    @auth("organizer","master")
    def organizer_registrations(user):
        q=db.session.query(Registration,Distance,Race,User).join(Distance,Registration.distance_id==Distance.id).join(Race,Distance.race_id==Race.id).join(User,Registration.runner_id==User.id)
        if user.role!="master": q=q.filter(Race.organizer_id==user.id)
        return {"registrations":[{"id":reg.id,"runner":runner.name,"event":race.title,"distance":dist.label,"status":reg.status,"locality":reg.locality_snapshot} for reg,dist,race,runner in q.order_by(Registration.id.desc()).all()]}
    @app.get("/api/master/organizers")
    @auth("master")
    def organizers(user):
        return {"organizers":[user_data(u) for u in User.query.filter_by(role="organizer").all()]}
    @app.post("/api/master/organizers/<int:user_id>/approve")
    @auth("master")
    def approve(user, user_id):
        target=db.session.get(User,user_id)
        if not target or target.role!="organizer": return error("Organizador não encontrado",404)
        target.approved=True; db.session.commit()
        return {"user":user_data(target)}
    with app.app_context():
        db.create_all()
    from brain_auth import register_brain
    register_brain(app, db, User)
    return app

if __name__=="__main__":
    app=create_app()
    app.run(host="127.0.0.1",port=int(os.environ.get("PORT","5001")),debug=False)
