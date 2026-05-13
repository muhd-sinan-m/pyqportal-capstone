from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import psycopg2
import time
from psycopg2 import pool
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests
from google import genai
from google.genai import types
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from config.settings import Config
from utils.s3_helper import upload_file_to_s3, delete_file_from_s3

app = Flask(__name__)
app.config.from_object(Config)
Compress(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})
jwt_manager = JWTManager(app)
bcrypt      = Bcrypt(app)

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

client  = genai.Client(api_key=app.config["GEMINI_API_KEY"])
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)
request_log = {}

# ---------- DB (Connection Pool) ----------
db_pool = pool.SimpleConnectionPool(1, 10, app.config["DATABASE_URL"])

def get_db():
    try:
        conn = db_pool.getconn()
        cur  = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return conn
    except:
        return psycopg2.connect(app.config["DATABASE_URL"])

def return_db(conn):
    try:
        db_pool.putconn(conn)
    except Exception as e:
        app.logger.warning(f"putconn failed: {e}")
        conn.close()

def init_db():
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'user'
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                subject_id SERIAL PRIMARY KEY,
                subject_name VARCHAR(255) NOT NULL,
                semester INTEGER
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS question_papers (
                paper_id SERIAL PRIMARY KEY,
                subject_id INTEGER REFERENCES subjects(subject_id),
                year INTEGER,
                file_name VARCHAR(255),
                file_path VARCHAR(255),
                exam_type VARCHAR(100),
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_url TEXT,
                public_id TEXT,
                ai_analysis TEXT
            );
        """)
        conn.commit()

        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            hash_val = generate_password_hash(app.config["ADMIN_PASS"])
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (app.config["ADMIN_USER"], hash_val, "admin")
            )
            conn.commit()
    finally:
        cur.close()
        return_db(conn)

init_db()

# ---------- Helpers ----------
ALLOWED_EXTENSIONS = {"pdf"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_subjects():
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT subject_id, subject_name, semester FROM subjects ORDER BY semester, subject_name")
        rows = cur.fetchall()
        return [{"subject_id": r[0], "subject_name": r[1], "semester": r[2]} for r in rows]
    finally:
        cur.close()
        return_db(conn)

def get_user_by_username(username):
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT user_id, username, password_hash, role FROM users WHERE username = %s", (username,))
        return cur.fetchone()
    finally:
        cur.close()
        return_db(conn)

def analyze_with_gemini(pdf_url, subject_name):
    import tempfile, os as _os
    r = requests.get(pdf_url, timeout=15)
    r.raise_for_status()
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(r.content)
        tmp_path = tmp.name
    prompt = f"""You are an exam preparation assistant for {subject_name}.
Analyze this previous year question paper and predict the most likely questions for the next exam.
Respond with:
1. Top 10 predicted questions (numbered)
2. Key topics to focus on (bullet points)
3. Question pattern observations (2-3 lines)"""
    try:
        with open(tmp_path, "rb") as f:
            uploaded = client.files.upload(file=f, config=types.UploadFileConfig(mime_type="application/pdf"))
        response = client.models.generate_content(model="gemini-3.1-flash-lite-preview", contents=[uploaded, prompt])
        try:
            client.files.delete(name=uploaded.name)
        except:
            pass
        return response.text
    finally:
        _os.unlink(tmp_path)

# ---------- Auth decorators ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Administrator access required.")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated

# ================================================================
# WEB ROUTES (unchanged)
# ================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "Username and password are required"
        else:
            row = get_user_by_username(username)
            if row and check_password_hash(row[2], password):
                session.clear()
                session["user_id"]  = row[0]
                session["username"] = row[1]
                session["role"]     = row[3]
                return redirect(request.args.get("next") or url_for("home"))
            error = "Invalid username or password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/")
def home():
    paper_count = 0
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM question_papers")
        paper_count = cur.fetchone()[0] or 0
    finally:
        cur.close()
        return_db(conn)
    return render_template("index.html", paper_count=paper_count)

@app.route("/upload", methods=["GET", "POST"])
@login_required
@admin_required
def upload_page():
    if request.method == "POST":
        conn = get_db()
        cur  = conn.cursor()
        try:
            subject_raw = request.form.get("subject_id")
            if not subject_raw or subject_raw.strip() == "":
                return render_template("upload.html", error="Subject is required", subjects=get_subjects())
            try:
                subject_id = int(subject_raw)
            except ValueError:
                return render_template("upload.html", error="Invalid subject", subjects=get_subjects())

            cur.execute("SELECT subject_id, subject_name FROM subjects WHERE subject_id = %s", (subject_id,))
            row = cur.fetchone()
            if not row:
                return render_template("upload.html", error="Subject not found.", subjects=get_subjects())
            subject_id, subject_name = row[0], row[1]

            year = request.form.get("year")
            try:
                if not year or not str(year).strip():
                    raise ValueError("Year is required")
                year_int = int(str(year).split("-", 1)[0].strip()) if "-" in str(year) else int(year)
            except (ValueError, TypeError) as exc:
                return render_template("upload.html", error=f"Invalid year: {exc}", subjects=get_subjects())

            file = request.files.get("file")
            if not file or not file.filename:
                return render_template("upload.html", error="No file provided", subjects=get_subjects())
            if not allowed_file(file.filename):
                return render_template("upload.html", error="Only PDF files are allowed", subjects=get_subjects())

            exam_type = request.form.get("examType") or request.form.get("exam_type") or ""

            # Upload to S3 instead of Supabase
            file_url, s3_key = upload_file_to_s3(file, subject_id, year_int)

            original_filename = secure_filename(file.filename)
            cur.execute(
                """
                INSERT INTO question_papers
                (subject_id, year, file_name, file_url, exam_type, public_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING paper_id
                """,
                (subject_id, year_int, original_filename, file_url, exam_type, s3_key),
            )
            conn.commit()
            flash("Question paper uploaded successfully.")
            return redirect(url_for("upload_page"))

        except Exception as e:
            conn.rollback()
            app.logger.exception("Upload failed")
            return render_template("upload.html", error=str(e), subjects=get_subjects())
        finally:
            cur.close()
            return_db(conn)

    return render_template("upload.html", subjects=get_subjects())

@app.route("/papers")
def view_papers():
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT s.subject_name, s.semester, q.year, q.file_url, q.exam_type, q.paper_id,
                   CASE WHEN q.ai_analysis IS NOT NULL THEN true ELSE false END as is_analysed
            FROM question_papers q
            JOIN subjects s ON q.subject_id = s.subject_id
            ORDER BY q.year DESC, s.subject_name
        """)
        rows   = cur.fetchall()
        papers = []
        for subject_name, semester, year, file_url, exam_type, paper_id, is_analysed in rows:
            papers.append({
                "subject":     subject_name,
                "year":        year,
                "semester":    semester,
                "department":  "",
                "examType":    exam_type or "—",
                "file_url":    file_url,
                "paper_id":    paper_id,
                "is_analysed": is_analysed
            })
        subjects = get_subjects()
        years    = sorted({p["year"] for p in papers}, reverse=True) if papers else []
        return render_template("view.html", papers=papers, subjects=subjects, years=years)
    except Exception as e:
        app.logger.exception("Failed to load papers")
        return f"Database error: {e}", 500
    finally:
        cur.close()
        return_db(conn)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/analyze/<int:paper_id>")
def analyze_paper(paper_id):
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT q.file_url, q.exam_type, q.year, s.subject_name, q.ai_analysis
            FROM question_papers q
            JOIN subjects s ON q.subject_id = s.subject_id
            WHERE q.paper_id = %s
        """, (paper_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Paper not found"}), 404

        file_url, exam_type, year, subject_name, ai_analysis = row

        if ai_analysis:
            return jsonify({"subject": subject_name, "year": year, "exam_type": exam_type, "predictions": ai_analysis, "cached": True})

        user_ip = request.remote_addr
        now     = time.time()
        request_log.setdefault(user_ip, [])
        request_log[user_ip] = [t for t in request_log[user_ip] if now - t < 3600]

        if len(request_log[user_ip]) >= 5:
            return jsonify({"error": "Too many requests. You can analyse only 5 papers per hour."}), 429

        try:
            predictions = analyze_with_gemini(file_url, subject_name)
            request_log[user_ip].append(now)
        except Exception as e:
            app.logger.exception("Gemini analysis failed")
            err = str(e).lower()
            if "quota" in err or "rate" in err or "429" in err:
                return jsonify({"error": "Daily analysis limit reached. Please try again tomorrow."}), 429
            if "503" in err or "unavailable" in err:
                return jsonify({"error": "AI servers are busy. Please try again in a few minutes."}), 503
            return jsonify({"error": "Analysis failed. Please try again later."}), 500

        try:
            cur.execute("UPDATE question_papers SET ai_analysis = %s WHERE paper_id = %s", (predictions, paper_id))
            conn.commit()
        except Exception:
            conn.rollback()

        return jsonify({"subject": subject_name, "year": year, "exam_type": exam_type, "predictions": predictions, "cached": False})

    except Exception:
        app.logger.exception("analyze_paper failed")
        return jsonify({"error": "Analysis failed. Please try again later."}), 500
    finally:
        cur.close()
        return_db(conn)

@app.route("/analyze/<int:paper_id>/refresh")
@login_required
@admin_required
def refresh_analysis(paper_id):
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("UPDATE question_papers SET ai_analysis = NULL WHERE paper_id = %s", (paper_id,))
        conn.commit()
        return jsonify({"message": "Cache cleared."})
    finally:
        cur.close()
        return_db(conn)

# ================================================================
# ADMIN WEB ROUTES
# ================================================================

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    return render_template("admin.html")

@app.route("/admin/api/stats")
@login_required
@admin_required
def admin_stats():
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM subjects")
        total_subjects = cur.fetchone()[0] or 0
        cur.execute("SELECT COUNT(*) FROM question_papers")
        total_papers = cur.fetchone()[0] or 0
        cur.execute("SELECT COUNT(*) FROM question_papers WHERE ai_analysis IS NOT NULL")
        papers_with_ai = cur.fetchone()[0] or 0
        cur.execute("SELECT COUNT(*) FROM question_papers WHERE upload_date >= NOW() - INTERVAL '30 days'")
        recent_uploads = cur.fetchone()[0] or 0
        return jsonify({"total_subjects": total_subjects, "total_papers": total_papers, "papers_with_ai": papers_with_ai, "recent_uploads": recent_uploads})
    finally:
        cur.close()
        return_db(conn)

@app.route("/admin/api/subjects", methods=["GET"])
@login_required
@admin_required
def admin_get_subjects():
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT s.subject_id, s.subject_name, s.semester, COUNT(q.paper_id) AS paper_count
            FROM subjects s
            LEFT JOIN question_papers q ON q.subject_id = s.subject_id
            GROUP BY s.subject_id, s.subject_name, s.semester
            ORDER BY s.semester NULLS LAST, s.subject_name
        """)
        rows = cur.fetchall()
        return jsonify([{"subject_id": r[0], "subject_name": r[1], "semester": r[2], "paper_count": r[3]} for r in rows])
    finally:
        cur.close()
        return_db(conn)

@app.route("/admin/api/subjects", methods=["POST"])
@login_required
@admin_required
def admin_create_subject():
    data     = request.get_json()
    name     = (data.get("subject_name") or "").strip()
    semester = data.get("semester")
    if not name:
        return jsonify({"error": "Subject name is required"}), 400
    if semester is not None:
        try:
            semester = int(semester)
            if not 1 <= semester <= 8:
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "Semester must be between 1 and 8"}), 400
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("INSERT INTO subjects (subject_name, semester) VALUES (%s, %s) RETURNING subject_id", (name, semester))
        new_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({"subject_id": new_id, "subject_name": name, "semester": semester}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        return_db(conn)

@app.route("/admin/api/subjects/<int:subject_id>", methods=["PUT"])
@login_required
@admin_required
def admin_update_subject(subject_id):
    data     = request.get_json()
    name     = (data.get("subject_name") or "").strip()
    semester = data.get("semester")
    if not name:
        return jsonify({"error": "Subject name is required"}), 400
    if semester is not None:
        try:
            semester = int(semester)
            if not 1 <= semester <= 8:
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"error": "Semester must be between 1 and 8"}), 400
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("UPDATE subjects SET subject_name=%s, semester=%s WHERE subject_id=%s RETURNING subject_id", (name, semester, subject_id))
        if cur.fetchone() is None:
            return jsonify({"error": "Subject not found"}), 404
        conn.commit()
        return jsonify({"subject_id": subject_id, "subject_name": name, "semester": semester})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        return_db(conn)

@app.route("/admin/api/subjects/<int:subject_id>", methods=["DELETE"])
@login_required
@admin_required
def admin_delete_subject(subject_id):
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("DELETE FROM subjects WHERE subject_id=%s RETURNING subject_id", (subject_id,))
        if cur.fetchone() is None:
            return jsonify({"error": "Subject not found"}), 404
        conn.commit()
        return jsonify({"message": "Deleted"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        return_db(conn)

@app.route("/admin/api/papers", methods=["GET"])
@login_required
@admin_required
def admin_get_papers():
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""
            SELECT q.paper_id, s.subject_name, s.semester, q.year,
                   q.exam_type, q.file_url, q.upload_date, q.ai_analysis, q.public_id
            FROM question_papers q
            LEFT JOIN subjects s ON q.subject_id = s.subject_id
            ORDER BY q.upload_date DESC NULLS LAST
        """)
        rows = cur.fetchall()
        return jsonify([{
            "paper_id": r[0], "subject_name": r[1] or "Unknown",
            "semester": r[2], "year": r[3], "exam_type": r[4],
            "file_url": r[5], "upload_date": r[6].isoformat() if r[6] else None,
            "ai_analysis": r[7], "public_id": r[8]
        } for r in rows])
    finally:
        cur.close()
        return_db(conn)

@app.route("/admin/api/papers/<int:paper_id>", methods=["DELETE"])
@login_required
@admin_required
def admin_delete_paper(paper_id):
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT public_id FROM question_papers WHERE paper_id=%s", (paper_id,))
        row = cur.fetchone()
        if row is None:
            return jsonify({"error": "Paper not found"}), 404
        # Delete from S3 instead of Supabase
        delete_file_from_s3(row[0])
        cur.execute("DELETE FROM question_papers WHERE paper_id=%s", (paper_id,))
        conn.commit()
        return jsonify({"message": "Deleted"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        return_db(conn)

@app.route("/admin/api/change-password", methods=["POST"])
@login_required
@admin_required
def admin_change_password():
    data             = request.get_json()
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")
    if not new_password or len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT user_id, password_hash FROM users WHERE user_id=%s", (session["user_id"],))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        if not check_password_hash(row[1], current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        new_hash = generate_password_hash(new_password)
        cur.execute("UPDATE users SET password_hash=%s WHERE user_id=%s", (new_hash, row[0]))
        conn.commit()
        return jsonify({"message": "Password updated successfully"})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        return_db(conn)

# ================================================================
# JWT API ROUTES (new — for mobile/external access)
# ================================================================

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data     = request.get_json()
    username = (data.get("username") or "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    row = get_user_by_username(username)
    if not row or not check_password_hash(row[2], password):
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_access_token(identity={"user_id": row[0], "username": row[1], "role": row[3]})
    return jsonify({"token": token, "user": {"user_id": row[0], "username": row[1], "role": row[3]}}), 200

@app.route("/api/papers", methods=["GET"])
def api_get_papers():
    conn = get_db()
    cur  = conn.cursor()
    try:
        subject_id = request.args.get("subject_id")
        semester   = request.args.get("semester")
        year       = request.args.get("year")

        query  = """
            SELECT q.paper_id, s.subject_name, s.semester, q.year,
                   q.exam_type, q.file_url, q.upload_date
            FROM question_papers q
            JOIN subjects s ON q.subject_id = s.subject_id
            WHERE 1=1
        """
        params = []
        if subject_id:
            query += " AND q.subject_id = %s"
            params.append(subject_id)
        if semester:
            query += " AND s.semester = %s"
            params.append(semester)
        if year:
            query += " AND q.year = %s"
            params.append(year)

        query += " ORDER BY q.year DESC, s.subject_name"
        cur.execute(query, params)
        rows = cur.fetchall()
        return jsonify([{
            "paper_id": r[0], "subject": r[1], "semester": r[2],
            "year": r[3], "exam_type": r[4], "file_url": r[5],
            "upload_date": r[6].isoformat() if r[6] else None
        } for r in rows])
    finally:
        cur.close()
        return_db(conn)

@app.route("/api/subjects", methods=["GET"])
def api_get_subjects():
    return jsonify(get_subjects())

# ================================================================
# ERROR HANDLERS
# ================================================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=False)