import os
import secrets
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

class Race(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organizer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(140), nullable=False)
    city = db.Column(db.String(120), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    published = db.Column(db.Boolean, nullable=False, default=False)
    local_city = db.Column(db.String(120), nullable=True)

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
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

def create_app():
    app = Flask(__name__, static_folder="../", static_url_path="/arena-run")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///arena_run_dev.db").replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    secret = os.environ.get("SECRET_KEY")
    if not secret and os.environ.get("APP_ENV") != "development":
        raise RuntimeError("Configure SECRET_KEY e APP_ENV antes de iniciar")
    app.config["SECRET_KEY"] = secret or secrets.token_hex(32)
    db.init_app(app)
    allowed_origin = os.environ.get("FRONTEND_ORIGIN", "").rstrip("/")
    @app.after_request
    def cors_headers(response):
        if allowed_origin and request.headers.get("Origin") == allowed_origin:
            response.headers["Access-Control-Allow-Origin"] = allowed_origin
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
                user = db.session.get(User, user_id)
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
        return {"id": r.id, "title": r.title, "city": r.city, "date": r.date, "local_city":r.local_city, "distances": [{"id": d.id, "label": d.label, "price_cents": d.price_cents, "capacity": d.capacity} for d in Distance.query.filter_by(race_id=r.id).order_by(Distance.id)]}
    @app.get("/api/health")
    def health():
        return {"status": "ok", "payment_mode": "simulated"}
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
        return {"user": user_data(u), "token": signer.dumps(u.id)}
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
        r=Race(organizer_id=user.id,title=title,city=city,date=date,published=True,local_city=str(data.get("local_city") or city).strip()[:120])
        db.session.add(r); db.session.flush()
        for label,cents,capacity in validated: db.session.add(Distance(race_id=r.id,label=label,price_cents=cents,capacity=capacity))
        db.session.commit()
        return jsonify(race_data(r)), 201
    @app.post("/api/registrations")
    @auth("runner", "organizer", "master")
    def create_registration(user):
        data=payload()
        try: distance_id=int(data.get("distance_id", 0))
        except (ValueError, TypeError): return error("Distância inválida")
        size=data.get("shirt_size") or user.shirt_size
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
        age=age_on(user.birth_date,race.date)
        if age<0: return error("Data de nascimento incompatível com a corrida")
        # Categoria etária definitiva depende de regulamento versionado por evento.
        locality="local" if user.city.strip().casefold()==(race.local_city or race.city).strip().casefold() else "general"
        reg=Registration(runner_id=user.id,distance_id=d.id,shirt_size=size,category_snapshot=f"Idade na prova: {age}",locality_snapshot=locality,team_snapshot=user.team)
        db.session.add(reg); db.session.commit()
        return jsonify({"id":reg.id,"status":reg.status,"payment_mode":"simulated","price_cents":d.price_cents}),201
    @app.get("/api/registrations/me")
    @auth()
    def my_registrations(user):
        rows=Registration.query.filter_by(runner_id=user.id).order_by(Registration.id.desc()).all()
        return {"registrations":[{"id":x.id,"race":db.session.get(Race,db.session.get(Distance,x.distance_id).race_id).title,"distance":db.session.get(Distance,x.distance_id).label,"shirt_size":x.shirt_size,"status":x.status,"category":x.category_snapshot,"locality":x.locality_snapshot,"date":db.session.get(Race,db.session.get(Distance,x.distance_id).race_id).date} for x in rows]}
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
    # Simula aprovação por uma conta master autenticada. NÃO recebe notificações reais.
    @app.post("/api/demo/registrations/<int:reg_id>/confirm")
    @auth("master")
    def simulate_paid(user,reg_id):
        if os.environ.get("ENABLE_DEMO_PAYMENT")!="1": return error("Simulação desabilitada",403)
        r=db.session.get(Registration,reg_id)
        if not r: return error("Inscrição não encontrada",404)
        if r.status!="awaiting_payment": return error("Transição de status não permitida",409)
        r.status="paid_simulated";db.session.commit()
        return {"id":r.id,"status":r.status}
    with app.app_context():
        db.create_all()
        bootstrap_email=os.environ.get("BOOTSTRAP_MASTER_EMAIL", "").strip().lower()
        bootstrap_password=os.environ.get("BOOTSTRAP_MASTER_PASSWORD", "")
        if bootstrap_email and bootstrap_password and len(bootstrap_password)>=12:
            if not User.query.filter_by(email=bootstrap_email).first():
                db.session.add(User(name="Master Arena Run",email=bootstrap_email,password_hash=generate_password_hash(bootstrap_password),role="master",approved=True))
                db.session.commit()
    return app

if __name__=="__main__":
    app=create_app()
    app.run(host="127.0.0.1",port=int(os.environ.get("PORT","5001")),debug=False)
