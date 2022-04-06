import base64
import hashlib
import hmac
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()
SECRET_KEY = "9ce4af324e66b355159fe42d24dbf57f9211306e1895c9d0d07b0c64b1ae21e7"
PASSWORD_SALT = "8692ce766f3d866daa9159034d8004d3d0beae712547136222fee2c1c6ba74c3"
users = {
    "alexey.com": {
        "name": "Alexey",
        "password": "f85b720e24b8225333d006fd07035353ce554b7e2b41b5cca3f5a33976a8e516",
        "balance": 10000,
    }

}


def sign_data(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_passwod_hash = users[username]['password'].lower()
    return password_hash == stored_passwod_hash



@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(
        f'Привет {users[valid_username]["name"]}', media_type='text/html')


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
               "success": False,
                "message": "Unknown user"

            }),
            media_type="application/json")
    responce = Response(json.dumps({
        "success": True,
        "message": f'Привет {username},<br /> пароль {password}'

    }), media_type='application/json')
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    responce.set_cookie(key='username', value=username_signed)
    return responce
