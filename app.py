from flask import (Flask, render_template, request,
                   jsonify, session, redirect, url_for)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import bcrypt, os, re, time, logging
import pytesseract
import cv2
import numpy as np
from PIL import Image
import re

def detect_slip_outcome(image_file):
    """Basic OCR to detect if slip is Won or Lost"""
    try:
        # Read image
        img = Image.open(image_file)
        img_cv = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
        
        # Preprocess
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        text = pytesseract.image_to_string(gray).lower()
        
        # Look for keywords
        if re.search(r'\b(won|win|winner|success|paid|profit)\b', text):
            return "won"
        elif re.search(r'\b(lost|lose|loss|failed|void)\b', text):
            return "lost"
        
        return "pending"  # default
    except:
        return "pending"
      
# ── CLOUDINARY (optional) ─────────────────────────
try:
    import cloudinary
    import cloudinary.uploader
    cloudinary.config(
        cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME", ""),
        api_key    = os.environ.get("CLOUDINARY_API_KEY",    ""),
        api_secret = os.environ.get("CLOUDINARY_API_SECRET", "")
    )
    CLOUDINARY_ENABLED = bool(os.environ.get("CLOUDINARY_CLOUD_NAME"))
except Exception:
    CLOUDINARY_ENABLED = False

app = Flask(__name__)

# ── CONFIG ────────────────────────────────────────
app.secret_key                               = os.environ.get("SECRET_KEY", "bettrack_dev_2025")
app.config["SQLALCHEMY_DATABASE_URI"]        = os.environ.get("DATABASE_URL", "sqlite:///bettrack.db").replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"]        = True
app.config["SESSION_COOKIE_SAMESITE"]        = "Lax"
app.config["MAX_CONTENT_LENGTH"]             = 10 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"]     = timedelta(hours=24)
app.config["WTF_CSRF_ENABLED"]               = True

# ── EXTENSIONS ────────────────────────────────────
db      = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf    = CSRFProtect(app)

# ── LOGGING ───────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bettrack")

# ── RATE LIMITING ─────────────────────────────────
request_counts = defaultdict(list)

def rate_limit(max_requests=10, window=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip  = request.remote_addr
            now = time.time()
            request_counts[ip] = [
                t for t in request_counts[ip]
                if now - t < window
            ]
            if len(request_counts[ip]) >= max_requests:
                return jsonify({"error": "Too many requests"}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── HELPERS ───────────────────────────────────────
def hash_password(password):
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

def check_password(password, hashed):
    return bcrypt.checkpw(
        password.encode("utf-8"),
        hashed.encode("utf-8")
    )

def sanitize(text):
    if not text:
        return ""
    return text.replace("<", "").replace(">", "").replace('"', "").strip()

def is_valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

# ── SESSION ───────────────────────────────────────
@app.before_request
def make_session_permanent():
    session.permanent = True

# ── MODELS ────────────────────────────────────────
class User(db.Model):
    id           = db.Column(db.Integer,     primary_key=True)
    username     = db.Column(db.String(50),  unique=True, nullable=False)
    email        = db.Column(db.String(100), unique=True, nullable=False)
    password     = db.Column(db.String(200), nullable=False)
    avatar       = db.Column(db.String(10),  default="🎯")
    bio          = db.Column(db.String(200), default="")
    joined       = db.Column(db.DateTime,    default=datetime.utcnow)
    is_verified  = db.Column(db.Boolean,     default=False)
    slips        = db.relationship("Slip",   backref="user", lazy=True)

class Slip(db.Model):
    id            = db.Column(db.Integer,     primary_key=True)
    user_id       = db.Column(db.Integer,     db.ForeignKey("user.id"), nullable=False)
    title         = db.Column(db.String(200), default="")
    slip_code     = db.Column(db.String(100), default="")
    bookmaker     = db.Column(db.String(50),  default="")
    stake         = db.Column(db.Float,       default=0.0)
    potential_win = db.Column(db.Float,       default=0.0)
    odds          = db.Column(db.Float,       default=0.0)
    image_url     = db.Column(db.String(500), default="")
    status        = db.Column(db.String(20),  default="pending")
    actual_win    = db.Column(db.Float,       default=0.0)
    posted_at     = db.Column(db.DateTime,    default=datetime.utcnow)
    settled_at    = db.Column(db.DateTime,    nullable=True)
    likes         = db.Column(db.Integer,     default=0)
    views         = db.Column(db.Integer,     default=0)
    is_public     = db.Column(db.Boolean,     default=True)

class Selection(db.Model):
    id         = db.Column(db.Integer,     primary_key=True)
    slip_id    = db.Column(db.Integer,     db.ForeignKey("slip.id"), nullable=False)
    match      = db.Column(db.String(200), default="")
    prediction = db.Column(db.String(100), default="")
    odds       = db.Column(db.Float,       default=0.0)
    status     = db.Column(db.String(20),  default="pending")

# ── ROUTES ────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/csrf_token")
def csrf_token():
    return jsonify({"token": generate_csrf()})

@app.route("/signup", methods=["POST"])
@csrf.exempt
@rate_limit(max_requests=5, window=60)
def signup():
    data     = request.json
    username = sanitize(data.get("username", ""))
    email    = sanitize(data.get("email",    ""))
    password = data.get("password", "")
    avatar   = data.get("avatar",   "🎯")

    if not all([username, email, password]):
        return jsonify({"error": "All fields required"}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password too short"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username too short"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username taken"}), 400

    user = User(
        username = username,
        email    = email,
        password = hash_password(password),
        avatar   = avatar
    )
    db.session.add(user)
    db.session.commit()

    session["user_id"]       = user.id
    session["user_username"] = user.username
    return jsonify({"success": True})

@app.route("/login", methods=["POST"])
@csrf.exempt
@rate_limit(max_requests=20, window=60)
def login():
    data     = request.json
    email    = sanitize(data.get("email",    ""))
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "All fields required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password(password, user.password):
        return jsonify({"error": "Wrong email or password"}), 400

    session["user_id"]       = user.id
    session["user_username"] = user.username
    return jsonify({"success": True})

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])

    if not user:
        session.clear()
        return redirect(url_for("index"))

    slips         = Slip.query.filter_by(user_id=user.id).order_by(Slip.posted_at.desc()).all()
    won_slips     = [s for s in slips if s.status == "won"]
    lost_slips    = [s for s in slips if s.status == "lost"]
    pending_slips = [s for s in slips if s.status == "pending"]
    settled       = [s for s in slips if s.status != "pending"]
    total_staked  = sum(s.stake for s in slips)
    total_won     = sum(s.actual_win for s in won_slips)
    total_lost    = sum(s.stake for s in lost_slips)
    profit_loss   = total_won - total_lost
    win_rate      = round(len(won_slips) / len(settled) * 100, 1) if settled else 0
    roi           = round((profit_loss / total_staked * 100), 1) if total_staked > 0 else 0

    stats = {
        "total_slips":  len(slips),
        "won":          len(won_slips),
        "lost":         len(lost_slips),
        "pending":      len(pending_slips),
        "total_staked": total_staked,
        "total_won":    total_won,
        "profit_loss":  profit_loss,
        "win_rate":     win_rate,
        "roi":          roi
    }

    return render_template("dashboard.html", user=user, slips=slips, stats=stats)

@app.route("/post_slip", methods=["GET"])
@login_required
def post_slip():
    return render_template("post_slip.html")
@app.route("/submit_slip", methods=["POST"])
@csrf.exempt
@login_required
def submit_slip():
    user = User.query.get(session["user_id"])

    if not user:
        session.clear()
        return jsonify({"error": "Session expired. Please login again"}), 401

    title     = sanitize(request.form.get("title",        ""))
    slip_code = sanitize(request.form.get("slip_code",    ""))
    bookmaker = sanitize(request.form.get("bookmaker",    ""))
    stake     = float(request.form.get("stake",           0) or 0)
    pot_win   = float(request.form.get("potential_win",   0) or 0)
    odds      = float(request.form.get("odds",            0) or 0)
    is_public = request.form.get("is_public", "true") == "true"
    image_url = ""
    status    = "pending"   # default

    # ==================== IMAGE UPLOAD + OCR ====================
    if "slip_image" in request.files:
        file = request.files["slip_image"]
        if file and file.filename:
            # OCR Detection (before upload)
            try:
                file.seek(0)
                detected = detect_slip_outcome(file)
                if detected in ["won", "lost"]:
                    status = detected
                    print(f"✅ OCR Auto-detected: {status.upper()}")
            except Exception as e:
                print(f"OCR failed: {e}")

            # Reset and upload to Cloudinary
            file.seek(0)
            if CLOUDINARY_ENABLED:
                try:
                    result = cloudinary.uploader.upload(
                        file,
                        folder="bettrack/slips",
                        public_id=f"slip_{user.id}_{int(time.time())}"
                    )
                    image_url = result["secure_url"]
                except Exception as e:
                    logger.warning(f"Image upload failed: {e}")
            else:
                logger.warning("Cloudinary not configured")
    # ===========================================================

    if not image_url and not slip_code:
        return jsonify({"error": "Please upload an image or enter a slip code"}), 400

    slip = Slip(
        user_id       = user.id,
        title         = title or f"{bookmaker} Slip",
        slip_code     = slip_code,
        bookmaker     = bookmaker,
        stake         = stake,
        potential_win = pot_win,
        odds          = odds,
        image_url     = image_url,
        status        = status,          # OCR result
        is_public     = is_public
    )
    db.session.add(slip)
    db.session.commit()

    # Selections
    selections  = request.form.getlist("match[]")
    predictions = request.form.getlist("prediction[]")
    sel_odds    = request.form.getlist("odds[]")

    for i, match in enumerate(selections):
        if match.strip():
            sel = Selection(
                slip_id    = slip.id,
                match      = sanitize(match),
                prediction = sanitize(predictions[i]) if i < len(predictions) else "",
                odds       = float(sel_odds[i]) if i < len(sel_odds) else 0.0
            )
            db.session.add(sel)

    db.session.commit()
    return jsonify({"success": True, "slip_id": slip.id, "auto_status": status})

@app.route("/settle_slip/<int:slip_id>", methods=["POST"])
@csrf.exempt
@login_required
def settle_slip(slip_id):
    slip = Slip.query.get_or_404(slip_id)

    if slip.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized"}), 401

    data       = request.json
    status     = data.get("status", "")
    actual_win = float(data.get("actual_win", 0))

    if status not in ["won", "lost"]:
        return jsonify({"error": "Invalid status"}), 400

    slip.status     = status
    slip.actual_win = actual_win if status == "won" else 0
    slip.settled_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True})

@app.route("/get_slips")
@login_required
def get_slips():
    user = User.query.get(session["user_id"])
    if not user:
        return jsonify([])

    slips = Slip.query.filter_by(user_id=user.id).order_by(Slip.posted_at.desc()).all()
    return jsonify([{
        "id":            s.id,
        "title":         s.title,
        "slip_code":     s.slip_code,
        "bookmaker":     s.bookmaker,
        "stake":         s.stake,
        "potential_win": s.potential_win,
        "odds":          s.odds,
        "image_url":     s.image_url,
        "status":        s.status,
        "actual_win":    s.actual_win,
        "posted_at":     s.posted_at.strftime("%d %b %Y %I:%M %p"),
        "is_public":     s.is_public
    } for s in slips])

@app.route("/delete_slip/<int:slip_id>", methods=["POST"])
@csrf.exempt
@login_required
def delete_slip(slip_id):
    slip = Slip.query.get_or_404(slip_id)
    if slip.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized"}), 401
    db.session.delete(slip)
    db.session.commit()
    return jsonify({"success": True})

@app.route("/profile/<username>")
def profile(username):
    user  = User.query.filter_by(username=username).first_or_404()
    slips = Slip.query.filter_by(
        user_id   = user.id,
        is_public = True
    ).order_by(Slip.posted_at.desc()).all()

    won   = len([s for s in slips if s.status == "won"])
    lost  = len([s for s in slips if s.status == "lost"])
    total = won + lost
    rate  = round(won / total * 100, 1) if total > 0 else 0

    return render_template("profile.html",
        user=user, slips=slips,
        win_rate=rate, won=won, lost=lost
    )

# ── INIT ──────────────────────────────────────────
with app.app_context():
    db.create_all()
    print("✅ Database ready!")
    print(f"✅ Cloudinary: {'enabled' if CLOUDINARY_ENABLED else 'disabled'}")

if __name__ == "__main__":
    app.run(
        host  = "0.0.0.0",
        port  = int(os.environ.get("PORT", 5000)),
        debug = False
    )
