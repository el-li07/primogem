# demo-resource-server/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from primogem.key_manager import KeyManager
from primogem.verifier import TokenVerifier

app = FastAPI(title="Primogem — Корпоративный портал")
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

current_dir = os.path.dirname(os.path.abspath(__file__))

@app.get("/logo.png")
async def get_logo():
    file_path = os.path.join(current_dir, "logo.png")
    return FileResponse(file_path)

@app.get("/favicon.ico")
async def get_favicon():
    file_path = os.path.join(current_dir, "logo.png")
    return FileResponse(file_path)

# ==================== ДОКУМЕНТЫ ====================
documents = [
    {"id": 1, "name": "Стратегический план 2026.pdf",      "owner": "user-arthur",  "category": "all",          "content": "Секретный документ главы компании"},
    {"id": 2, "name": "Финансовый отчёт Q1 2026.xlsx",    "owner": "user-leticia", "category": "finance",     "content": "Баланс и отчётность"},
    {"id": 3, "name": "Техническая спецификация v2.1.pdf","owner": "user-quincy",  "category": "engineering", "content": "Описание нового модуля"},
    {"id": 4, "name": "Код модуля auth.py",               "owner": "user-amir",    "category": "engineering", "content": "Реализация аутентификации"},
    {"id": 5, "name": "Отчёт по безопасности.docx",       "owner": "user-aoi",     "category": "all",          "content": "Отчёт администратора системы"},
]

def get_current_payload(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    km = KeyManager()
    verifier = TokenVerifier()
    verifier.key_manager = km
    return verifier.verify(token)


def can_read(payload: dict, doc: dict) -> bool:
    roles = payload.get("roles", [])
    sub = payload.get("sub")

    if "head" in roles:
        return True
    if "admin" in roles:
        return sub == doc["owner"]
    if doc["category"] == "finance" and "accountant" in roles:
        return True
    if doc["category"] == "engineering" and "engineer" in roles:
        return True
    return sub == doc["owner"]


def can_edit(payload: dict, doc: dict) -> bool:
    roles = payload.get("roles", [])
    sub = payload.get("sub")

    # Куинси (dept_head) редактирует ВЕСЬ инженерный отдел
    if "dept_head" in roles and "engineer" in roles and doc["category"] == "engineering":
        return True

    if sub == doc["owner"]:
        return True

    return False


@app.get("/documents")
async def list_documents(payload: dict = Depends(get_current_payload)):
    visible = []
    for doc in documents:
        if can_read(payload, doc):
            doc_copy = doc.copy()
            doc_copy["can_edit"] = can_edit(payload, doc)
            doc_copy["full_name"] = payload.get("full_name", payload.get("sub", "Пользователь"))
            visible.append(doc_copy)
    return {"documents": visible}


@app.get("/documents/{doc_id}")
async def read_document(doc_id: int, payload: dict = Depends(get_current_payload)):
    doc = next((d for d in documents if d["id"] == doc_id), None)
    if not doc or not can_read(payload, doc):
        raise HTTPException(403, "Доступ к документу запрещён")
    return {"document": doc}


@app.put("/documents/{doc_id}")
async def edit_document(doc_id: int, payload: dict = Depends(get_current_payload)):
    doc = next((d for d in documents if d["id"] == doc_id), None)
    if not doc or not can_edit(payload, doc):
        raise HTTPException(403, "Редактирование запрещено")
    return {"message": f"Документ '{doc['name']}' успешно отредактирован", "by": payload.get("full_name", payload["sub"])}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)