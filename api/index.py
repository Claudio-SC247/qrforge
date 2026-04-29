"""
Qrea-fy — API backend v2.2
Fix crítico: flask-limiter eliminado — era incompatible con Upstash REST URL (https://)
causando crash en startup (exit code 1 en Render).
Reemplazado por rate limiter propio usando upstash-redis directamente.
"""

import os, io, re, json, hmac, time, hashlib, base64, logging
import ipaddress, socket, urllib.parse, urllib.request, uuid, warnings

import qrcode
import requests
from PIL import Image, UnidentifiedImageError
from flask import Flask, request, jsonify, send_from_directory, Response, g

# ── PIL safety ────────────────────────────────────────────────────────────────
Image.MAX_IMAGE_PIXELS = 50_000_000

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("qreafy")

# ── Upstash Redis — KV + Rate limiting ───────────────────────────────────────
try:
    from upstash_redis import Redis
    _kv = Redis.from_env()
    _kv.ping()
    KV_AVAILABLE = True
    logger.info("Upstash Redis: conectado correctamente.")
except Exception as exc:
    _kv = None
    KV_AVAILABLE = False
    logger.warning("Upstash Redis no disponible: %s", exc)

KV_KEY       = "qreafy:url_history"
KV_MAX_ITEMS = 100

# ── Rutas absolutas ───────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path="")

app.config["SECRET_KEY"] = (
    os.environ.get("FLASK_SECRET_KEY")
    or __import__("secrets").token_hex(32)
)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB

# ── Constantes ────────────────────────────────────────────────────────────────
MAX_DATA_LEN   = 2000
MAX_LOGO_BYTES = 3 * 1024 * 1024
MAX_JSON_BYTES = 10_000
MAGIC_BYTES    = {b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF"}
BLOCKED_HOSTS  = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

_REQ_HEADERS = {
    "User-Agent": "qreafy/2.2 (+https://github.com/Claudio-SC247/qrea-fy)",
    "Accept":     "text/html,application/xhtml+xml,*/*",
}

_SHORTENER_DOMAINS = {
    "goo.gl", "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
    "ift.tt", "dlvr.it", "fb.me", "youtu.be", "amzn.to", "short.link",
    "rb.gy", "cutt.ly", "tiny.cc", "shorturl.at", "is.gd", "v.gd",
    "lnkd.in", "wp.me", "bc.vc",
}

HISTORY_TOKEN = os.environ.get("HISTORY_TOKEN", "")
if not HISTORY_TOKEN:
    warnings.warn(
        "HISTORY_TOKEN no configurado — DELETE /api/history siempre rechazará.",
        RuntimeWarning, stacklevel=1,
    )

# ── Rate limiting (sin flask-limiter — usa upstash-redis directamente) ────────
# flask-limiter crasheaba porque esperaba redis:// pero Upstash usa https://
RATE_LIMITS = {
    "generate-qr": {"per_min": 20, "per_hour": 100},
    "shorten-url": {"per_min": 10, "per_hour": 50},
    "history-get": {"per_min": 30, "per_hour": 300},
    "history-del": {"per_min": 5,  "per_hour": 10},
}

def _get_ip() -> str:
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("CF-Connecting-IP", "")
        or request.remote_addr
        or "unknown"
    )

def _is_rate_limited(endpoint: str) -> bool:
    """Sliding window con Upstash Redis. Fail-open si Redis no disponible."""
    if not KV_AVAILABLE:
        return False
    limits = RATE_LIMITS.get(endpoint, {"per_min": 60, "per_hour": 600})
    ip  = _get_ip()
    now = int(time.time())
    try:
        for key, limit, ttl in [
            (f"rl:{endpoint}:{ip}:{now // 60}",    limits["per_min"],  120),
            (f"rl:{endpoint}:{ip}:{now // 3600}h", limits["per_hour"], 7200),
        ]:
            count = _kv.incr(key)
            if count == 1:
                _kv.expire(key, ttl)
            if count > limit:
                logger.warning("RATE_LIMIT | %s | ip=%s | count=%d", endpoint, ip[:12], count)
                return True
    except Exception as exc:
        logger.warning("Rate limiter error: %s", exc)
    return False

def _rate_resp():
    resp = jsonify({"error": "Demasiadas solicitudes. Espera un momento."})
    resp.status_code = 429
    resp.headers["Retry-After"] = "60"
    return resp


# ── Request-ID middleware ─────────────────────────────────────────────────────

@app.before_request
def _set_request_id():
    g.request_id = str(uuid.uuid4())[:8]

def _log(level: str, msg: str, *args):
    rid = getattr(g, "request_id", "-")
    getattr(logger, level)(f"[{rid}] {msg}", *args)


# ── Helpers de seguridad ──────────────────────────────────────────────────────

def _is_safe_url(url: str) -> tuple:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "URL mal formada."
    if parsed.scheme not in ("http", "https"):
        return False, "Solo se permiten URLs http o https."
    host = parsed.hostname or ""
    if not host:
        return False, "URL sin host válido."
    if host.lower() in BLOCKED_HOSTS:
        return False, "Host no permitido."
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return False, "Host no permitido."
    except ValueError:
        pass
    return True, ""

def _is_host_safe_after_resolution(url: str) -> bool:
    """Anti DNS-rebinding: re-resuelve el hostname justo antes de cada request."""
    try:
        hostname = urllib.parse.urlparse(url).hostname or ""
        if not hostname:
            return False
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    _log("warning", "DNS rebind bloqueado: %s → %s", hostname, info[4][0])
                    return False
            except ValueError:
                continue
        return True
    except Exception:
        return False

def _is_shortener_domain(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return any(host == d or host.endswith("." + d) for d in _SHORTENER_DOMAINS)
    except Exception:
        return False

def _resolve_url(url: str) -> str:
    """Sigue redirecciones para obtener la URL final (anti-cadena de acortadores)."""
    if not _is_host_safe_after_resolution(url):
        return url
    try:
        resp = requests.head(url, allow_redirects=True, timeout=6, headers=_REQ_HEADERS)
        final = resp.url
        if final and final != url and final.startswith(("http://", "https://")):
            if _is_host_safe_after_resolution(final):
                return final
    except Exception as e:
        _log("debug", "HEAD resolve failed: %s", e)
    try:
        resp = requests.get(url, allow_redirects=True, timeout=6,
                            headers=_REQ_HEADERS, stream=True)
        resp.close()
        final = resp.url
        if final and final != url and final.startswith(("http://", "https://")):
            if _is_host_safe_after_resolution(final):
                return final
    except Exception as e:
        _log("debug", "GET resolve failed: %s", e)
    return url

def _validate_image_magic(data: bytes) -> bool:
    return any(data[:len(m)] == m for m in MAGIC_BYTES)

def _hex_to_rgb(h: str) -> tuple:
    h = h.strip().lstrip("#")
    if not re.fullmatch(r"[0-9a-fA-F]{6}", h):
        return (0, 0, 0)
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

def _clamp(v, lo, hi):
    return max(lo, min(v, hi))

def _verify_token(req) -> bool:
    if not HISTORY_TOKEN:
        return False
    provided = req.headers.get("X-History-Token", "").strip()
    if not provided:
        return False
    return hmac.compare_digest(
        hashlib.sha256(provided.encode()).digest(),
        hashlib.sha256(HISTORY_TOKEN.encode()).digest(),
    )


# ── Multi-provider URL shortener ──────────────────────────────────────────────

SHORTENER_PROVIDERS = [
    {"name": "is.gd",
     "url":  "https://is.gd/create.php?format=simple&url={e}",
     "prefix": "https://is.gd/"},
    {"name": "v.gd",
     "url":  "https://v.gd/create.php?format=simple&url={e}",
     "prefix": "https://v.gd/"},
    {"name": "tinyurl",
     "url":  "https://tinyurl.com/api-create.php?url={e}",
     "prefix": "https://tinyurl.com/"},
]

def _shorten_with_fallback(url: str) -> str | None:
    encoded = urllib.parse.quote(url, safe="")
    for p in SHORTENER_PROVIDERS:
        api_url = p["url"].format(e=encoded)
        try:
            req = urllib.request.Request(
                api_url,
                headers={"User-Agent": "qreafy/2.2", "Accept": "text/plain"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    short = resp.read(512).decode("utf-8", errors="ignore").strip()
                    if short.startswith(p["prefix"]):
                        _log("info", "Acortado via %s: %s", p["name"], short)
                        return short
                    _log("warning", "Respuesta inesperada de %s: %.80s", p["name"], short)
        except Exception as exc:
            _log("warning", "Shortener %s error: %s", p["name"], exc)
    return None


# ── KV helpers ────────────────────────────────────────────────────────────────

def kv_push(item: dict) -> None:
    if not KV_AVAILABLE:
        return
    try:
        item.setdefault("ts", int(time.time() * 1000))
        _kv.lpush(KV_KEY, json.dumps(item, ensure_ascii=False))
        _kv.ltrim(KV_KEY, 0, KV_MAX_ITEMS - 1)
    except Exception as exc:
        _log("warning", "KV push: %s", exc)

def kv_get_all() -> list:
    if not KV_AVAILABLE:
        return []
    try:
        raw = _kv.lrange(KV_KEY, 0, KV_MAX_ITEMS - 1)
        out = []
        for item in (raw or []):
            try:
                out.append(json.loads(item) if isinstance(item, str) else item)
            except Exception:
                pass
        return out
    except Exception as exc:
        _log("warning", "KV get: %s", exc)
        return []


# ── QR generation ─────────────────────────────────────────────────────────────

def make_qr_base64(data, logo_bytes=None, size=10, border=2,
                   fill_color="#000000", back_color="#ffffff", logo_ratio=0.28):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=_clamp(size, 4, 25),
        border=_clamp(border, 0, 8),
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(
        fill_color=_hex_to_rgb(fill_color),
        back_color=_hex_to_rgb(back_color),
    ).convert("RGBA")
    qw, qh = img.size

    if logo_bytes:
        try:
            probe = Image.open(io.BytesIO(logo_bytes))
            probe.verify()  # Detecta decompression bombs antes de cargar completo
            logo = Image.open(io.BytesIO(logo_bytes)).convert("RGBA")
            mp = int(qw * _clamp(logo_ratio, 0.10, 0.42))
            logo.thumbnail((mp, mp), Image.LANCZOS)
            lw, lh = logo.size
            pad = max(4, int(min(lw, lh) * 0.08))
            bg = Image.new("RGBA", (lw + 2*pad, lh + 2*pad), (255, 255, 255, 255))
            bg.paste(logo, (pad, pad), logo)
            img.paste(bg, ((qw - bg.width) // 2, (qh - bg.height) // 2), bg)
        except (UnidentifiedImageError, Image.DecompressionBombError) as exc:
            _log("warning", "Logo rechazado (bomb/inválido): %s", exc)
        except Exception as exc:
            _log("warning", "Logo ignorado: %s", exc)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def sec_headers(resp: Response) -> Response:
    resp.headers.update({
        "X-Content-Type-Options":       "nosniff",
        "X-Frame-Options":              "DENY",
        "X-XSS-Protection":             "1; mode=block",
        "Referrer-Policy":              "strict-origin-when-cross-origin",
        "Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
        "Strict-Transport-Security":    "max-age=63072000; includeSubDomains; preload",
        "Cross-Origin-Opener-Policy":   "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Request-ID":                 getattr(g, "request_id", "-"),
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        ),
    })
    resp.headers.pop("Server", None)
    resp.headers.pop("X-Powered-By", None)
    return resp


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(PUBLIC_DIR, "index.html")

@app.route("/favicon.svg")
def favicon():
    return send_from_directory(PUBLIC_DIR, "favicon.svg")

@app.route("/app.css")
def app_css():
    return send_from_directory(PUBLIC_DIR, "app.css", mimetype="text/css")

@app.route("/app.js")
def app_js_route():
    return send_from_directory(PUBLIC_DIR, "app.js", mimetype="application/javascript")


@app.route("/api/generate-qr", methods=["POST"])
def api_generate_qr():
    if _is_rate_limited("generate-qr"):
        return _rate_resp()

    data = (request.form.get("data") or "").strip()
    if not data:
        return jsonify({"error": "El campo 'data' es obligatorio."}), 400
    if len(data) > MAX_DATA_LEN:
        return jsonify({"error": f"Máximo {MAX_DATA_LEN} caracteres."}), 400

    try:
        size       = _clamp(int(request.form.get("size",        10)), 4, 25)
        border     = _clamp(int(request.form.get("border",       2)), 0,  8)
        logo_ratio = _clamp(float(request.form.get("logo_ratio", 0.28)), 0.10, 0.42)
        fill_color = (request.form.get("fill_color") or "#000000").strip()
        back_color = (request.form.get("back_color") or "#ffffff").strip()
    except (ValueError, TypeError):
        return jsonify({"error": "Parámetros inválidos."}), 400

    logo_bytes = None
    if "logo" in request.files:
        f = request.files["logo"]
        if f and f.filename:
            raw = f.read(MAX_LOGO_BYTES + 1)
            if len(raw) > MAX_LOGO_BYTES:
                return jsonify({"error": "Logo máx. 3 MB."}), 400
            if not _validate_image_magic(raw):
                return jsonify({"error": "Formato de imagen no permitido."}), 400
            logo_bytes = raw

    try:
        qr_b64 = make_qr_base64(data, logo_bytes, size, border, fill_color, back_color, logo_ratio)
        _log("info", "QR generado | len=%d logo=%s", len(data), logo_bytes is not None)
        return jsonify({"qr": qr_b64})
    except Exception as exc:
        _log("error", "Error generando QR: %s", exc)
        return jsonify({"error": "Error generando QR."}), 500


@app.route("/api/shorten-url", methods=["POST"])
def api_shorten_url():
    if _is_rate_limited("shorten-url"):
        return _rate_resp()

    if not request.is_json:
        return jsonify({"error": "Content-Type debe ser application/json."}), 415

    if len(request.get_data(cache=True)) > MAX_JSON_BYTES:
        return jsonify({"error": "Payload demasiado grande."}), 413

    body = request.get_json(silent=True) or {}
    url  = (body.get("url") or "").strip()

    if not url:
        return jsonify({"error": "El campo 'url' es obligatorio."}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL demasiado larga."}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({"error": reason}), 400

    if not _is_host_safe_after_resolution(url):
        return jsonify({"error": "Host no permitido."}), 400

    url_to_shorten = url
    if _is_shortener_domain(url):
        resolved = _resolve_url(url)
        safe2, _ = _is_safe_url(resolved)
        if safe2:
            url_to_shorten = resolved

    short = _shorten_with_fallback(url_to_shorten)
    if short is None:
        return jsonify({"error": "No se pudo acortar la URL. Intenta de nuevo."}), 502

    item = {"short_url": short, "original_url": url, "ts": int(time.time() * 1000)}
    kv_push(item)
    _log("info", "URL acortada: %s", short)
    return jsonify({**item, "kv": KV_AVAILABLE})


@app.route("/api/history", methods=["GET"])
def api_history():
    if _is_rate_limited("history-get"):
        return _rate_resp()
    return jsonify({"history": kv_get_all(), "kv_available": KV_AVAILABLE})


@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    if _is_rate_limited("history-del"):
        return _rate_resp()
    if not _verify_token(request):
        _log("warning", "DELETE /api/history — token inválido desde %s", _get_ip()[:12])
        return jsonify({"error": "No autorizado."}), 401
    if not KV_AVAILABLE:
        return jsonify({"error": "KV no disponible."}), 503
    try:
        _kv.delete(KV_KEY)
        _log("info", "Historial limpiado.")
        return jsonify({"ok": True})
    except Exception as exc:
        _log("error", "Error limpiando historial: %s", exc)
        return jsonify({"error": "No se pudo limpiar."}), 500


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok", "kv": KV_AVAILABLE, "version": "2.2"}), 200


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(_):        return jsonify({"error": "Solicitud inválida."}),        400
@app.errorhandler(404)
def not_found(_):          return jsonify({"error": "Ruta no encontrada."}),        404
@app.errorhandler(405)
def method_not_allowed(_): return jsonify({"error": "Método no permitido."}),       405
@app.errorhandler(413)
def too_large(_):          return jsonify({"error": "Payload demasiado grande."}),  413
@app.errorhandler(429)
def too_many(_):           return jsonify({"error": "Demasiadas solicitudes."}),    429
@app.errorhandler(500)
def internal_error(_):     return jsonify({"error": "Error interno."}),             500
