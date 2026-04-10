import os
import json
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

app = FastAPI()

# --- AYARLAR ---
RP_ID = "localhost"
RP_NAME = "Yubikey Passkey Demo"
ORIGIN = "http://localhost:8000"

# Bellek içi veritabanı
users_db = {}
challenges = {}

# --- SAYFALAR ---

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(username: str = "Misafir"):
    return f"""
    <html>
        <body style="font-family:sans-serif; display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh;">
            <h1>Hoş geldin, {username}! 🛡️</h1>
            <p>Bu sayfayı sadece fiziksel Yubikey'i olanlar görebilir.</p>
            <a href="/"><button style="padding:10px; cursor:pointer;">Çıkış Yap</button></a>
        </body>
    </html>
    """

# --- KAYIT (REGISTRATION) ---

@app.get("/registration/options")
async def get_reg_options(username: str):
    if not username:
        raise HTTPException(status_code=400, detail="Kullanıcı adı boş olamaz")

    user_id = os.urandom(16)
    
    # KRİTİK AYAR: Anahtarı Yubikey'in içine (Cross-Platform) yazmaya zorla
    auth_selection = AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
        resident_key=ResidentKeyRequirement.REQUIRED, # ykman listesinde görünmesini sağlar
        user_verification=UserVerificationRequirement.PREFERRED
    )

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
        authenticator_selection=auth_selection,
    )
    
    challenges[username] = options.challenge
    return json.loads(webauthn.options_to_json(options))

@app.post("/registration/verify")
async def verify_reg(request: Request, username: str):
    response_data = await request.json()
    
    try:
        verification = webauthn.verify_registration_response(
            credential=response_data,
            expected_challenge=challenges[username],
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
        
        users_db[username] = {
            "credential_id": verification.credential_id,
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count
        }
        return {"status": "ok"}
    except Exception as e:
        print(f"Hata: {e}")
        raise HTTPException(status_code=400, detail=str(e))

# --- GİRİŞ (AUTHENTICATION) ---

@app.get("/login/options")
async def get_login_options(username: str):
    if username not in users_db:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

    user_data = users_db[username]
    
    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            webauthn.helpers.structs.PublicKeyCredentialDescriptor(
                id=user_data["credential_id"]
            )
        ],
        user_verification=UserVerificationRequirement.PREFERRED
    )
    
    challenges[username] = options.challenge
    return json.loads(webauthn.options_to_json(options))

@app.post("/login/verify")
async def verify_login(request: Request, username: str):
    response_data = await request.json()
    user_data = users_db.get(username)
    
    try:
        verification = webauthn.verify_authentication_response(
            credential=response_data,
            expected_challenge=challenges[username],
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=user_data["public_key"],
            credential_current_sign_count=user_data["sign_count"],
        )
        
        users_db[username]["sign_count"] = verification.new_sign_count
        return {"status": "ok", "redirect": f"/profile?username={username}"}
    except Exception as e:
        print(f"Hata: {e}")
        raise HTTPException(status_code=400, detail="Giriş doğrulanamadı")
