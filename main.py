import os
import json
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, String, Integer, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

# --- VERİTABANI YAPILANDIRMASI ---
# SQLite kullanarak verileri users.db dosyasında saklıyoruz
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    credential_id = Column(LargeBinary)
    public_key = Column(LargeBinary)
    sign_count = Column(Integer, default=0)

# Tabloları oluştur
Base.metadata.create_all(bind=engine)

# --- UYGULAMA AYARLARI ---
app = FastAPI()
RP_ID = "localhost"
RP_NAME = "Yubikey Passkey Demo"
ORIGIN = "http://localhost:8000"
challenges = {} # Geçici challenge deposu

# --- SAYFALAR ---

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(username: str = "Misafir"):
    # Admin Paneli ve Kullanıcı Listesi artık sadece bu sayfada (Giriş sonrası)
    return f"""
    <html>
    <head>
        <title>Profil - {username}</title>
        <style>
            body {{ font-family: sans-serif; background: #f0f2f5; display: flex; flex-direction: column; align-items: center; padding: 40px; }}
            .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 500px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border-bottom: 1px solid #eee; text-align: left; }}
            .btn-delete {{ background: #ef4444; color: white; padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; }}
            .btn-logout {{ background: #6b7280; color: white; text-decoration: none; padding: 10px 20px; display: inline-block; margin-top: 20px; border-radius: 6px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Hoş geldin, {username}! 🛡️</h1>
            <p>Bu alan sadece başarılı <b>Passkey</b> doğrulaması sonrası görünür.</p>
            
            <h3>👥 Kayıtlı Tüm Kullanıcılar</h3>
            <table id="userTable">
                <thead><tr><th>Kullanıcı</th><th>Sayaç</th><th>İşlem</th></tr></thead>
                <tbody id="userList"></tbody>
            </table>
            
            <a href="/" class="btn-logout">Güvenli Çıkış Yap</a>
        </div>

        <script>
            async function loadUsers() {{
                const res = await fetch('/admin/users');
                const users = await res.json();
                const tbody = document.getElementById('userList');
                tbody.innerHTML = users.map(u => `
                    <tr>
                        <td>${{u.username}}</td>
                        <td>${{u.sign_count}}</td>
                        <td><button class="btn-delete" onclick="deleteUser('${{u.username}}')">Sil</button></td>
                    </tr>
                `).join('');
            }}

            async function deleteUser(user) {{
                if(confirm(user + ' kullanıcısını silmek istediğine emin misin?')) {{
                    const res = await fetch('/admin/users/' + user, {{ method: 'DELETE' }});
                    if(res.ok) loadUsers();
                }}
            }}
            
            window.onload = loadUsers;
        </script>
    </body>
    </html>
    """

# --- KAYIT (REGISTRATION) ---

@app.get("/registration/options")
async def get_reg_options(username: str):
    user_id = os.urandom(16)
    auth_selection = AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
        resident_key=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.PREFERRED
    )
    options = webauthn.generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME, user_id=user_id, user_name=username,
        authenticator_selection=auth_selection,
    )
    challenges[username] = options.challenge
    return json.loads(webauthn.options_to_json(options))

@app.post("/registration/verify")
async def verify_reg(request: Request, username: str):
    response_data = await request.json()
    db = SessionLocal()
    try:
        verification = webauthn.verify_registration_response(
            credential=response_data, expected_challenge=challenges[username],
            expected_origin=ORIGIN, expected_rp_id=RP_ID,
        )
        user = db.query(User).filter(User.username == username).first()
        if not user: user = User(username=username)
        user.credential_id = verification.credential_id
        user.public_key = verification.credential_public_key
        user.sign_count = verification.sign_count
        db.add(user); db.commit()
        return {"status": "ok"}
    except Exception as e:
        db.rollback(); raise HTTPException(status_code=400, detail=str(e))
    finally: db.close()

# --- GİRİŞ (AUTHENTICATION) ---

@app.get("/login/options")
async def get_login_options(username: str):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    db.close()
    if not user: raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    
    options = webauthn.generate_authentication_options(
        rp_id=RP_ID, 
        allow_credentials=[webauthn.helpers.structs.PublicKeyCredentialDescriptor(id=user.credential_id)],
        user_verification=UserVerificationRequirement.PREFERRED
    )
    challenges[username] = options.challenge
    return json.loads(webauthn.options_to_json(options))

@app.post("/login/verify")
async def verify_login(request: Request, username: str):
    response_data = await request.json()
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user: raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    
    try:
        verification = webauthn.verify_authentication_response(
            credential=response_data, expected_challenge=challenges[username],
            expected_origin=ORIGIN, expected_rp_id=RP_ID,
            credential_public_key=user.public_key, credential_current_sign_count=user.sign_count,
        )
        user.sign_count = verification.new_sign_count
        db.commit()
        return {"status": "ok", "redirect": f"/profile?username={username}"}
    except Exception:
        raise HTTPException(status_code=400, detail="Doğrulama hatası")
    finally: db.close()

# --- YÖNETİM (ADMIN API) ---

@app.get("/admin/users")
async def list_users():
    db = SessionLocal()
    users = db.query(User).all()
    db.close()
    return [{"username": u.username, "sign_count": u.sign_count} for u in users]

@app.delete("/admin/users/{username}")
async def delete_user(username: str):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if user:
        db.delete(user); db.commit()
    db.close()
    return {"status": "ok"}
