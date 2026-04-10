from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import py_webauthn as webauthn

app = FastAPI()

# Sahte bir veritabanı (Gerçek projede DB kullanmalısın)
DB = {
    "user_id": "user_123",
    "username": "esatonbasi",
    "credentials": [] # Yubikey kayıtları buraya gelecek
}

RP_ID = "localhost"
RP_NAME = "Yubikey FastAPI Demo"
ORIGIN = f"http://{RP_ID}:8000"

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("index.html", "r") as f:
        return f.read()

# 1. ADIM: Kayıt için Challenge oluştur
@app.get("/generate-registration-options")
async def registration_options():
    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=DB["user_id"],
        user_name=DB["username"],
    )
    # Challenge'ı geçici olarak saklamalıyız (Session/Cache)
    return options

# 2. ADIM: Yubikey'den gelen yanıtı doğrula
@app.post("/verify-registration")
async def verify_registration(request: Request):
    registration_response = await request.json()
    # Burada webauthn.verify_registration_response ile doğrulama yapılır
    return {"status": "success", "message": "Yubikey başarıyla kaydedildi!"}
