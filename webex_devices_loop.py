import json
import os
import threading
import time
import webbrowser
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests
from flask import Flask, request

# =========================
# CONFIG (ENV VARS)
# =========================

CLIENT_ID = "C0ccc8f0d3de4dfad6dfc7771454769fc8a0eb85805bf2eb33dd844ef4aa4fb4c"#os.getenv("WEBEX_CLIENT_ID", "").strip()
CLIENT_SECRET = "b2def8f74f40948f6b8ac7d5d7e769c5b6b3d94a1890a41f5de6bcda47a8a394"

# Debe coincidir EXACTAMENTE con el Redirect URI en la Integration
#REDIRECT_URI = os.getenv("WEBEX_REDIRECT_URI", "http://localhost:8080/callback").strip()
REDIRECT_URI = "http://localhost:8080/callback"
# Scope típico para listar devices del tenant
#SCOPES = os.getenv("WEBEX_SCOPES", "spark-admin:devices_read").strip()
SCOPES = "spark-admin:devices_read"
#TOKENS_FILE = os.getenv("WEBEX_TOKENS_FILE", "tokens.json").strip()
TOKENS_FILE = "tokens.json"

AUTHORIZE_URL = "https://webexapis.com/v1/authorize"
TOKEN_URL = "https://webexapis.com/v1/access_token"
DEVICES_URL = "https://webexapis.com/v1/devices"

REFRESH_EVERY_SECONDS = 120  # 2 MINUTOS

app = Flask(__name__)
tokens_lock = threading.Lock()


# =========================
# UI ALERT (Popup)
# =========================
def popup_alert(title: str, message: str) -> None:
    """
    Muestra un popup en pantalla. Si no hay GUI disponible, cae a consola.
    """
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        messagebox.showinfo(title, message)
        root.destroy()
    except Exception:
        print(f"[ALERTA] {title}: {message}")


# =========================
# TOKEN STORAGE
# =========================
def load_tokens() -> Optional[Dict[str, Any]]:
    if not os.path.exists(TOKENS_FILE):
        return None
    with open(TOKENS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_tokens(data: Dict[str, Any]) -> None:
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# =========================
# OAUTH FLOW
# =========================
def build_authorize_url() -> str:
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    r = requests.post(TOKEN_URL, data=data, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Token exchange failed {r.status_code}: {r.text}")
    t = r.json()
    t["obtained_at"] = int(time.time())
    return t


def refresh_tokens(refresh_token: str) -> Dict[str, Any]:
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
    }
    r = requests.post(TOKEN_URL, data=data, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Token refresh failed {r.status_code}: {r.text}")
    t = r.json()
    t["obtained_at"] = int(time.time())
    return t


# =========================
# WEBEX API HELPERS
# =========================
def extract_next_link(link_header: Optional[str]) -> Optional[str]:
    """
    Webex pagina con header Link (rel="next").
    """
    if not link_header:
        return None
    parts = [p.strip() for p in link_header.split(",")]
    for part in parts:
        if 'rel="next"' in part:
            start = part.find("<") + 1
            end = part.find(">")
            if start > 0 and end > start:
                return part[start:end]
    return None


def webex_get(url: str, access_token: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    return requests.get(url, headers=headers, params=params, timeout=30)


def ensure_access_token() -> str:
    """
    Devuelve el access_token actual. Si no hay tokens, obliga a autorizar.
    """
    with tokens_lock:
        t = load_tokens()

    if not t or "access_token" not in t:
        raise RuntimeError("No hay tokens. Tenés que autorizar primero (se abre el navegador al iniciar).")

    return t["access_token"]


def refresh_now(reason: str = "") -> None:
    """
    Refresca token inmediatamente (usa refresh_token), guarda en disco y alerta.
    """
    with tokens_lock:
        current = load_tokens()

    if not current or "refresh_token" not in current:
        raise RuntimeError("No hay refresh_token guardado. Volvé a autorizar.")

    new_t = refresh_tokens(current["refresh_token"])

    with tokens_lock:
        save_tokens(new_t)

    msg = "Token actualizado correctamente."
    if reason:
        msg += f"\nMotivo: {reason}"
    popup_alert("Webex OAuth", msg)
    print("[OK] Token actualizado." + (f" Motivo: {reason}" if reason else ""))


def list_all_devices() -> List[Dict[str, Any]]:
    """
    Lista TODOS los devices siguiendo paginación.
    Si Webex devuelve 401, refresca y reintenta 1 vez.
    """
    access_token = ensure_access_token()

    devices: List[Dict[str, Any]] = []
    url = DEVICES_URL
    params = {"max": 100}

    def fetch_page(u: str, p: Optional[Dict[str, Any]], token: str) -> requests.Response:
        return webex_get(u, token, params=p)

    r = fetch_page(url, params, access_token)

    # Si está expirado/inválido, refrescamos y reintentamos 1 vez
    if r.status_code == 401:
        refresh_now(reason="401 al listar devices (token expirado o inválido)")
        access_token = ensure_access_token()
        r = fetch_page(url, params, access_token)

    if r.status_code != 200:
        try:
            payload = r.json()
        except Exception:
            payload = {"raw": r.text}
        raise RuntimeError(f"Error listando devices {r.status_code}: {payload}")

    while True:
        payload = r.json()
        items = payload.get("items", [])
        devices.extend(items)

        next_url = extract_next_link(r.headers.get("Link"))
        if not next_url:
            break

        url = next_url
        params = None  # IMPORTANTE: la URL next ya trae sus params
        r = fetch_page(url, params, access_token)

        if r.status_code == 401:
            refresh_now(reason="401 durante paginación de devices")
            access_token = ensure_access_token()
            r = fetch_page(url, params, access_token)

        if r.status_code != 200:
            try:
                payload2 = r.json()
            except Exception:
                payload2 = {"raw": r.text}
            raise RuntimeError(f"Error listando devices {r.status_code}: {payload2}")

    return devices


# =========================
# FLASK CALLBACK
# =========================
@app.route("/callback")
def callback():
    code = request.args.get("code")
    err = request.args.get("error")
    if err:
        return f"Error OAuth: {err}", 400
    if not code:
        return "No llegó 'code' en el callback.", 400

    try:
        new_tokens = exchange_code_for_tokens(code)
        with tokens_lock:
            save_tokens(new_tokens)
        popup_alert("Webex OAuth", "Autenticación completada.\nTokens guardados en tokens.json")
        print("[OK] Autenticación completada. Tokens guardados.")
    except Exception as e:
        return f"Error intercambiando code por tokens: {e}", 500

    return "OK. Autenticación Webex completada. Podés cerrar esta pestaña."


# =========================
# BACKGROUND REFRESH LOOP
# =========================
def refresh_loop():
    while True:
        time.sleep(REFRESH_EVERY_SECONDS)
        try:
            refresh_now(reason="Refresco programado (cada 1 hora)")
        except Exception as e:
            print(f"[WARN] No se pudo refrescar el token (programado): {e}")


# =========================
# CLI LOOP
# =========================
def cli_loop():
    print("\nEscribí LISTA y presioná Enter para listar devices del tenant.")
    print("Escribí SALIR para terminar.\n")

    while True:
        cmd = input("> ").strip().upper()

        if cmd == "SALIR":
            print("Saliendo.")
            return

        if cmd != "LISTA":
            print("Comando no reconocido. Usá LISTA o SALIR.")
            continue

        try:
            devices = list_all_devices()
            print(f"\nTotal devices: {len(devices)}\n")
            for d in devices:
                print(
                    f"- {d.get('displayName','(sin nombre)')} | "
                    f"type={d.get('type','')} | "
                    f"product={d.get('product','')} | "
                    f"model={d.get('model','')} | "
                    f"status={d.get('connectionStatus','')} | "
                    f"id={d.get('id','')}"
                )
            print("")  # línea en blanco
        except Exception as e:
            print(f"[ERROR] {e}")


# =========================
# MAIN
# =========================
def main():
    if not CLIENT_ID or not CLIENT_SECRET:
        raise SystemExit("Faltan WEBEX_CLIENT_ID / WEBEX_CLIENT_SECRET en variables de entorno.")

    # Si no hay tokens, abrimos el navegador para autorizar
    if not load_tokens():
        url = build_authorize_url()
        print("No hay tokens aún. Se abrirá el navegador para autorizar la Integration:")
        print(url)
        webbrowser.open(url)

    # Hilo refresh cada 1 hora
    threading.Thread(target=refresh_loop, daemon=True).start()

    # Hilo Flask para callback
    # REDIRECT_URI default: http://localhost:8080/callback
    threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=8080, debug=False, use_reloader=False),
        daemon=True,
    ).start()

    # Loop interactivo
    cli_loop()


if __name__ == "__main__":
    main()
