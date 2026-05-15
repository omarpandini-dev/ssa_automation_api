import hashlib
import os
import secrets

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from aut_site import acessar_secure_page

load_dotenv()

security = HTTPBasic()
API_USER = os.getenv("API_USER", "")
API_PASSWORD = os.getenv("API_PASSWORD", "")


def authenticate(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    valid_user = secrets.compare_digest(credentials.username, API_USER)

    is_sha256 = len(API_PASSWORD) == 64 and all(c in "0123456789abcdef" for c in API_PASSWORD.lower())
    if is_sha256:
        provided_hash = hashlib.sha256(credentials.password.encode("utf-8")).hexdigest()
        valid_password = secrets.compare_digest(provided_hash, API_PASSWORD.lower()) or secrets.compare_digest(
            credentials.password, API_PASSWORD
        )
    else:
        valid_password = secrets.compare_digest(credentials.password, API_PASSWORD)

    if not (valid_user and valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais invalidas",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


app = FastAPI(title="Hello Word API", dependencies=[Depends(authenticate)])


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Hello Word"}


@app.get("/imprimeNome")
def imprime_nome(p_nome: str) -> dict[str, str]:
    return {"message": f"O nome e: {p_nome}"}


@app.get("/autSite")
def aut_site() -> dict[str, str]:
    return {"message": acessar_secure_page()}
