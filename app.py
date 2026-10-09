import csv
import io
import os
import random
import re
import secrets
import time
from datetime import date, datetime, timedelta
from functools import wraps

from bson import ObjectId
from bson.errors import InvalidId
from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))


def load_secret():
    """Use SECRET_KEY if set, otherwise create one once and keep it in .secret_key."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE, ".secret_key")
    if os.path.exists(path):
        return open(path).read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.secret_key = load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=timedelta(days=14))

client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017"),
                     serverSelectionTimeoutMS=5000)
db = client[os.environ.get("MONGO_DB", "seat_allocator")]
halls, students, exams, allocations, users = (
    db.halls, db.students, db.exams, db.allocations, db.users)

SIGNUP_CODE = os.environ.get("SIGNUP_CODE", "")  # optional invite code for sign up


def load_admin_code():
    """Code needed to sign up as Admin: ADMIN_CODE env, else created once in .admin_code."""
    if os.environ.get("ADMIN_CODE"):
        return os.environ["ADMIN_CODE"]
    path = os.path.join(BASE, ".admin_code")
    if os.path.exists(path):
        return open(path).read().strip()
    code = secrets.token_hex(3).upper()
    with open(path, "w") as f:
        f.write(code)
    return code


ADMIN_CODE = load_admin_code()
CANDIDATES = 80  # layouts tried per hall; the best one is kept


def init_db(retries=10):
    for attempt in range(retries):
        try:
            students.create_index("reg_no", unique=True)
            halls.create_index("name", unique=True)
            users.create_index("email", unique=True)
            allocations.create_index([("exam_id", 1), ("reg_no", 1)])
            allocations.create_index("reg_no")
            return
        except PyMongoError:
            if attempt == retries - 1:
                raise
            time.sleep(2)


init_db()


# ---------- helpers ----------

def to_oid(value):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None


def seat_label(row, col):
    return f"{chr(65 + row)}{col + 1}"


def hall_capacity(hall):
    return hall["rows"] * hall["cols"]


def dept_hue(d):
    h = 0
    for ch in d:
        h = (h * 47 + ord(ch) * 13) % 360
    return h


def dept_counts(query=None):
    pipe = ([{"$match": query}] if query else []) + [
        {"$group": {"_id": "$dept", "n": {"$sum": 1}}}, {"$sort": {"n": -1, "_id": 1}}]
    return list(students.aggregate(pipe))


@app.template_filter("row_letter")
def row_letter(i):
    return chr(65 + i)


# ---------- authentication ----------

PUBLIC = {"login", "signup", "static", "health"}
FAILS = {}  # "ip|email" -> (count, first_time)


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target.rstrip("?")
    return url_for("index")


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    u = getattr(g, "user", None)
    return {"csrf_token": lambda: session["csrf"], "user": u,
            "is_admin": bool(u and u.get("role") == "admin")}


def require_admin():
    if g.user.get("role") != "admin":
        abort(403)


def admin_only(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        require_admin()
        return fn(*args, **kwargs)
    return wrapper


@app.errorhandler(403)
def forbidden(_):
    if not getattr(g, "user", None):
        return redirect(url_for("login"))
    return render_template("403.html"), 403


@app.before_request
def guard():
    if request.method == "POST":
        token = session.get("csrf", "")
        if not token or not secrets.compare_digest(token, request.form.get("csrf_token", "")):
            abort(400, "Form expired. Please go back, reload the page and try again.")
    if request.endpoint in PUBLIC or request.endpoint is None:
        return
    oid = to_oid(session.get("uid"))
    user = users.find_one({"_id": oid}) if oid else None
    if not user:
        session.pop("uid", None)
        nxt = request.full_path if request.method == "GET" and request.path != "/" else None
        return redirect(url_for("login", next=nxt))
    g.user = user


@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    if request.endpoint not in ("static",):
        resp.headers["Cache-Control"] = "no-store"
    return resp


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.route("/login", methods=["GET", "POST"])
def login():
    if to_oid(session.get("uid")) and users.find_one({"_id": to_oid(session.get("uid"))}):
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        key = f"{request.remote_addr}|{email}"
        count, first = FAILS.get(key, (0, time.time()))
        if count >= 5 and time.time() - first < 300:
            flash("Too many failed attempts. Please wait 5 minutes and try again.", "error")
            return render_template("login.html", email=email, tab=request.form.get("as", "user"))
        user = users.find_one({"email": email})
        if user and check_password_hash(user["password"], pw) and \
                request.form.get("as") == "admin" and user.get("role") != "admin":
            flash("This account is not an admin account. Use the User tab.", "error")
            return render_template("login.html", email=email, tab="admin")
        if user and check_password_hash(user["password"], pw):
            FAILS.pop(key, None)
            session.clear()
            session["uid"] = str(user["_id"])
            session["csrf"] = secrets.token_hex(16)
            session.permanent = bool(request.form.get("remember"))
            users.update_one({"_id": user["_id"]}, {"$set": {"last_login": datetime.utcnow()}})
            return redirect(safe_next(request.args.get("next")))
        if time.time() - first >= 300:
            count, first = 0, time.time()
        FAILS[key] = (count + 1, first)
        flash("Invalid email or password.", "error")
        return render_template("login.html", email=email, tab=request.form.get("as", "user"))
    return render_template("login.html", email="")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        errors = []
        if len(name) < 2:
            errors.append("Enter your full name.")
        if not EMAIL_RE.match(email):
            errors.append("Enter a valid email address.")
        if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
            errors.append("Password needs 8+ characters with at least one letter and one number.")
        if pw != request.form.get("confirm", ""):
            errors.append("Passwords do not match.")
        if SIGNUP_CODE and request.form.get("code", "") != SIGNUP_CODE:
            errors.append("Invalid invite code.")
        role_choice = "admin" if request.form.get("role") == "admin" else "user"
        if role_choice == "admin" and not secrets.compare_digest(
                request.form.get("admin_code", "").strip(), ADMIN_CODE):
            errors.append("Invalid admin code.")
        if not errors:
            role = role_choice
            try:
                res = users.insert_one({
                    "name": name, "email": email, "role": role,
                    "password": generate_password_hash(pw),
                    "created": datetime.utcnow(), "last_login": datetime.utcnow()})
            except DuplicateKeyError:
                errors.append("An account with this email already exists.")
            else:
                session.clear()
                session["uid"] = str(res.inserted_id)
                session["csrf"] = secrets.token_hex(16)
                flash(f"Welcome, {name.split()[0]}! Your account is ready.", "success")
                return redirect(url_for("index"))
        for e in errors:
            flash(e, "error")
        return render_template("signup.html", name=name, email=email,
                               need_code=bool(SIGNUP_CODE), role=request.form.get("role", "user"))
    return render_template("signup.html", name="", email="", need_code=bool(SIGNUP_CODE))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


# ---------- allocation (randomised, history-aware) ----------

NEIGH4 = [(0, -1), (0, 1), (-1, 0), (1, 0)]


def traversal(rows, cols, rng):
    """Random corner + direction so every run walks the hall differently."""
    rs = list(range(rows))
    cs = list(range(cols))
    if rng.random() < .5:
        rs.reverse()
    if rng.random() < .5:
        cs.reverse()
    if rng.random() < .5:
        return [(r, c) for c in cs for r in rs]
    return [(r, c) for r in rs for c in cs]


def pick_seats(rows, cols, k, rng):
    """Choose k seats, spreading them out (no touching seats) when the hall is not full."""
    seats = [(r, c) for r in range(rows) for c in range(cols)]
    if k >= len(seats):
        return seats
    rng.shuffle(seats)
    chosen, taken, rest = [], set(), []
    for r, c in seats:
        if len(chosen) < k and not any((r + a, c + b) in taken
                                       for a in (-1, 0, 1) for b in (-1, 0, 1)):
            chosen.append((r, c))
            taken.add((r, c))
        else:
            rest.append((r, c))
    chosen += rest[:k - len(chosen)]
    return chosen


def build_candidate(hall, pool, rng):
    rows, cols = hall["rows"], hall["cols"]
    by_dept = {}
    for s in pool:
        by_dept.setdefault(s["dept"], []).append(s)
    for grp in by_dept.values():
        rng.shuffle(grp)
    order = {p: i for i, p in enumerate(traversal(rows, cols, rng))}
    seats = sorted(pick_seats(rows, cols, len(pool), rng), key=order.get)
    placed = {}
    for r, c in seats:
        forbidden = {placed[(r + a, c + b)]["dept"] for a, b in NEIGH4 if (r + a, c + b) in placed}
        avail = [d for d, grp in by_dept.items() if grp]
        cands = [d for d in avail if d not in forbidden] or avail
        d = rng.choices(cands, [len(by_dept[x]) ** 3 for x in cands])[0]
        placed[(r, c)] = by_dept[d].pop()
    return placed


def score(placed, hall, hist, other_halls):
    """Lower is better: same-dept neighbours, repeated seats, look-alike halls."""
    conflicts = diag = repeat = alike = 0
    for (r, c), s in placed.items():
        for a, b in ((0, 1), (1, 0)):
            n = placed.get((r + a, c + b))
            conflicts += bool(n and n["dept"] == s["dept"])
        for a, b in ((1, 1), (1, -1)):
            n = placed.get((r + a, c + b))
            diag += bool(n and n["dept"] == s["dept"])
        full, pos = hist.get(s["reg_no"], (set(), set()))
        if (hall["_id"], r, c) in full:
            repeat += 4
        elif (r, c) in pos:
            repeat += 2
        for oh in other_halls:
            d = oh.get((r, c))
            if d is not None:
                alike += 2 + (3 if d == s["dept"] else 0)
    return conflicts * 100 + diag * 5 + repeat + alike


def split_students(all_students, hall_docs, mode, rng):
    by_dept = {}
    for s in all_students:
        by_dept.setdefault(s["dept"], []).append(s)
    depts = list(by_dept)
    rng.shuffle(depts)
    for grp in by_dept.values():
        rng.shuffle(grp)
    ordered = []
    while any(by_dept.values()):
        for d in depts:
            if by_dept[d]:
                ordered.append(by_dept[d].pop())
    caps = [hall_capacity(h) for h in hall_docs]
    total = len(ordered)
    if mode == "sequential":
        pools, i = [], 0
        for c in caps:
            pools.append(ordered[i:i + c])
            i += c
        return pools
    quotas = [total * c // sum(caps) for c in caps]
    left = total - sum(quotas)
    while left:
        for i in sorted(range(len(caps)), key=lambda j: -(caps[j] - quotas[j])):
            if left and quotas[i] < caps[i]:
                quotas[i] += 1
                left -= 1
    pools = [[] for _ in caps]
    need = quotas[:]
    for s in ordered:
        i = max(range(len(need)), key=lambda j: (need[j], rng.random()))
        pools[i].append(s)
        need[i] -= 1
    return pools


def allocate(exam, mode="balanced"):
    """Seat students. Every run is different from earlier runs and from other halls."""
    hall_docs = [h for h in (halls.find_one({"_id": hid}) for hid in exam["hall_ids"]) if h]
    query = {"dept": {"$in": exam["depts"]}} if exam.get("depts") else {}
    all_students = list(students.find(query))
    if not hall_docs:
        raise ValueError("This exam has no halls assigned.")
    if not all_students:
        raise ValueError("No students found for this exam's departments.")
    capacity = sum(hall_capacity(h) for h in hall_docs)
    if len(all_students) > capacity:
        raise ValueError(f"{len(all_students)} students but only {capacity} seats in the selected halls.")

    seed = secrets.randbits(48)
    rng = random.Random(seed)
    regs = [s["reg_no"] for s in all_students]
    hist = {}
    for a in allocations.find({"reg_no": {"$in": regs}}):  # includes this exam's current seating
        full, pos = hist.setdefault(a["reg_no"], (set(), set()))
        full.add((a["hall_id"], a["row"], a["col"]))
        pos.add((a["row"], a["col"]))
    prev = {a["reg_no"]: (a["hall_id"], a["row"], a["col"])
            for a in allocations.find({"exam_id": exam["_id"]})}

    pools = split_students(all_students, hall_docs, mode, rng)
    docs, other_halls = [], []
    for hall, pool in zip(hall_docs, pools):
        if not pool:
            continue
        best = None
        for _ in range(CANDIDATES):
            placed = build_candidate(hall, pool, rng)
            cost = score(placed, hall, hist, other_halls)
            if best is None or cost < best[0]:
                best = (cost, placed)
            if cost == 0:
                break
        placed = best[1]
        other_halls.append({p: s["dept"] for p, s in placed.items()})
        for (r, c), s in placed.items():
            docs.append({"exam_id": exam["_id"], "reg_no": s["reg_no"], "name": s["name"],
                         "dept": s["dept"], "hall_id": hall["_id"], "hall_name": hall["name"],
                         "row": r, "col": c, "seat": seat_label(r, c)})

    allocations.delete_many({"exam_id": exam["_id"]})
    allocations.insert_many(docs)
    moved = None
    if prev:
        changed = sum(1 for d in docs if prev.get(d["reg_no"]) != (d["hall_id"], d["row"], d["col"]))
        moved = round(changed * 100 / len(docs))
    exams.update_one({"_id": exam["_id"]}, {"$set": {
        "seed": seed, "mode": mode, "last_run": datetime.utcnow()},
        "$inc": {"runs": 1}})
    return len(docs), moved


def build_grids(exam):
    result = []
    for hid in exam["hall_ids"]:
        hall = halls.find_one({"_id": hid})
        if not hall:
            continue
        grid = [[None] * hall["cols"] for _ in range(hall["rows"])]
        for a in allocations.find({"exam_id": exam["_id"], "hall_id": hid}):
            if a["row"] < hall["rows"] and a["col"] < hall["cols"]:
                grid[a["row"]][a["col"]] = a
        seated = sum(1 for row in grid for a in row if a)
        result.append({"hall": hall, "grid": grid, "seated": seated})
    return result


# ---------- pages ----------

@app.route("/")
def index():
    exam_list = list(exams.find().sort("date", 1))
    for e in exam_list:
        e["allocated"] = allocations.count_documents({"exam_id": e["_id"]})
        e["capacity"] = sum(hall_capacity(h) for h in halls.find({"_id": {"$in": e["hall_ids"]}}))
    hall_list = list(halls.find().sort("name", 1))
    depts = dept_counts()
    total = sum(d["n"] for d in depts)
    stops, acc = [], 0
    for d in depts:
        nxt = acc + d["n"] * 100 / total
        stops.append(f"hsl({dept_hue(d['_id'])} 55% 58%) {acc:.2f}% {nxt:.2f}%")
        acc = nxt
    today = date.today().isoformat()
    upcoming = next((e for e in exam_list if e["date"] >= today), None)
    if upcoming:
        upcoming["days"] = (date.fromisoformat(upcoming["date"]) - date.today()).days
    hour = datetime.now().hour
    greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 17 else "Good evening"
    stats = {"halls": len(hall_list), "seats": sum(hall_capacity(h) for h in hall_list),
             "students": total, "exams": len(exam_list),
             "allocated": sum(1 for e in exam_list if e["allocated"])}
    return render_template("index.html", stats=stats, exams=exam_list[:6], halls=hall_list,
                           depts=depts, donut=f"conic-gradient({', '.join(stops)})" if stops else "",
                           upcoming=upcoming, greeting=greeting)


@app.route("/halls", methods=["GET", "POST"])
def halls_page():
    if request.method == "POST":
        require_admin()
        name = request.form.get("name", "").strip()
        try:
            rows, cols = int(request.form.get("rows", 0)), int(request.form.get("cols", 0))
        except ValueError:
            rows = cols = 0
        if not name or not (1 <= rows <= 26) or not (1 <= cols <= 30):
            flash("Enter a name, rows (1-26) and columns (1-30).", "error")
        else:
            try:
                halls.insert_one({"name": name, "rows": rows, "cols": cols})
                flash(f"Hall '{name}' added.", "success")
            except DuplicateKeyError:
                flash("A hall with that name already exists.", "error")
        return redirect(url_for("halls_page"))
    hall_list = list(halls.find().sort("name", 1))
    for h in hall_list:
        h["used"] = exams.count_documents({"hall_ids": h["_id"]})
    return render_template("halls.html", halls=hall_list,
                           total_seats=sum(hall_capacity(h) for h in hall_list))


@app.route("/halls/<hall_id>/delete", methods=["POST"])
@admin_only
def delete_hall(hall_id):
    oid = to_oid(hall_id)
    if oid and exams.find_one({"hall_ids": oid}):
        flash("This hall is used by an exam. Delete that exam first.", "error")
    elif oid:
        halls.delete_one({"_id": oid})
        flash("Hall deleted.", "success")
    return redirect(url_for("halls_page"))


PER_PAGE = 20


@app.route("/students", methods=["GET", "POST"])
def students_page():
    if request.method == "POST":
        require_admin()
        reg_no = request.form.get("reg_no", "").strip()
        name = request.form.get("name", "").strip()
        dept = request.form.get("dept", "").strip().upper()
        if not (reg_no and name and dept):
            flash("All fields are required.", "error")
        else:
            try:
                students.insert_one({"reg_no": reg_no, "name": name, "dept": dept})
                flash(f"Student {reg_no} added.", "success")
            except DuplicateKeyError:
                flash("That register number already exists.", "error")
        return redirect(url_for("students_page"))
    q = request.args.get("q", "").strip()
    dept = request.args.get("dept", "").strip()
    query = {}
    if dept:
        query["dept"] = dept
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [{"reg_no": rx}, {"name": rx}, {"dept": rx}]
    found = students.count_documents(query)
    pages = max(1, -(-found // PER_PAGE))
    page = min(max(request.args.get("page", 1, type=int), 1), pages)
    rows = list(students.find(query).sort("reg_no", 1).skip((page - 1) * PER_PAGE).limit(PER_PAGE))
    return render_template("students.html", students=rows, found=found, page=page, pages=pages,
                           total=students.count_documents({}), q=q, dept=dept, depts=dept_counts())


@app.route("/students/upload", methods=["POST"])
@admin_only
def upload_students():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a CSV file first.", "error")
        return redirect(url_for("students_page"))
    try:
        reader = csv.DictReader(io.StringIO(file.stream.read().decode("utf-8-sig")))
        added = skipped = 0
        for row in reader:
            reg_no = (row.get("reg_no") or "").strip()
            name = (row.get("name") or "").strip()
            dept = (row.get("dept") or "").strip().upper()
            if not (reg_no and name and dept):
                skipped += 1
                continue
            try:
                students.insert_one({"reg_no": reg_no, "name": name, "dept": dept})
                added += 1
            except DuplicateKeyError:
                skipped += 1
        flash(f"Imported {added} students, skipped {skipped}.", "success")
    except (UnicodeDecodeError, csv.Error):
        flash("Could not read that file. Use a UTF-8 CSV with reg_no,name,dept.", "error")
    return redirect(url_for("students_page"))


@app.route("/students/<student_id>/delete", methods=["POST"])
@admin_only
def delete_student(student_id):
    oid = to_oid(student_id)
    if oid:
        students.delete_one({"_id": oid})
        flash("Student deleted. Re-run allocation for existing exams.", "success")
    return redirect(url_for("students_page"))


@app.route("/exams", methods=["GET", "POST"])
def exams_page():
    hall_list = list(halls.find().sort("name", 1))
    if request.method == "POST":
        require_admin()
        name = request.form.get("name", "").strip()
        day = request.form.get("date", "").strip()
        hall_ids = [h for h in (to_oid(x) for x in request.form.getlist("hall_ids")) if h]
        if not (name and day and hall_ids):
            flash("Enter exam name, date and pick at least one hall.", "error")
        else:
            res = exams.insert_one({
                "name": name, "date": day, "hall_ids": hall_ids,
                "session": request.form.get("session", "FN")[:2],
                "depts": [d for d in request.form.getlist("depts") if d],
                "created": datetime.utcnow(), "runs": 0})
            flash("Exam created. Now run the allocation.", "success")
            return redirect(url_for("exam_detail", exam_id=res.inserted_id))
        return redirect(url_for("exams_page"))
    exam_list = list(exams.find().sort("date", 1))
    for e in exam_list:
        e["allocated"] = allocations.count_documents({"exam_id": e["_id"]})
        e["capacity"] = sum(hall_capacity(h) for h in halls.find({"_id": {"$in": e["hall_ids"]}}))
    return render_template("exams.html", halls=hall_list, exams=exam_list, depts=dept_counts())


@app.route("/exams/<exam_id>")
def exam_detail(exam_id):
    exam = exams.find_one({"_id": to_oid(exam_id)})
    if not exam:
        flash("Exam not found.", "error")
        return redirect(url_for("exams_page"))
    grids = build_grids(exam)
    return render_template(
        "exam_detail.html", exam=exam, grids=grids,
        count=allocations.count_documents({"exam_id": exam["_id"]}),
        capacity=sum(hall_capacity(x["hall"]) for x in grids),
        depts=sorted(allocations.distinct("dept", {"exam_id": exam["_id"]})))


@app.route("/exams/<exam_id>/allocate", methods=["POST"])
@admin_only
def run_allocation(exam_id):
    exam = exams.find_one({"_id": to_oid(exam_id)})
    if not exam:
        flash("Exam not found.", "error")
        return redirect(url_for("exams_page"))
    mode = "sequential" if request.form.get("mode") == "sequential" else "balanced"
    try:
        n, moved = allocate(exam, mode)
        msg = f"Allocated {n} students."
        if moved is not None:
            msg += f" {moved}% of students moved to a new seat."
        flash(msg, "success")
    except ValueError as err:
        flash(str(err), "error")
    return redirect(url_for("exam_detail", exam_id=exam_id))


@app.route("/exams/<exam_id>/export")
def export_exam(exam_id):
    exam = exams.find_one({"_id": to_oid(exam_id)})
    if not exam:
        return redirect(url_for("exams_page"))
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["reg_no", "name", "dept", "hall", "seat"])
    for a in allocations.find({"exam_id": exam["_id"]}).sort([("hall_name", 1), ("row", 1), ("col", 1)]):
        writer.writerow([a["reg_no"], a["name"], a["dept"], a["hall_name"], a["seat"]])
    filename = re.sub(r"[^A-Za-z0-9_-]+", "_", exam["name"])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=seating_{filename}.csv"})


@app.route("/exams/<exam_id>/delete", methods=["POST"])
@admin_only
def delete_exam(exam_id):
    oid = to_oid(exam_id)
    if oid:
        allocations.delete_many({"exam_id": oid})
        exams.delete_one({"_id": oid})
        flash("Exam deleted.", "success")
    return redirect(url_for("exams_page"))


@app.route("/allocate", methods=["GET", "POST"])
@admin_only
def allocate_page():
    """One-stop 'Allocate Hall' page: pick (or create) an exam, choose mode, run the algorithm."""
    if request.method == "POST":
        mode = "sequential" if request.form.get("mode") == "sequential" else "balanced"
        target = request.form.get("target", "")
        if target == "new":
            name = request.form.get("name", "").strip()
            day = request.form.get("date", "").strip()
            hall_ids = [h for h in (to_oid(x) for x in request.form.getlist("hall_ids")) if h]
            depts = [d for d in request.form.getlist("depts") if d]
            if not (name and day and hall_ids):
                flash("Enter exam name, date and pick at least one hall.", "error")
                return redirect(url_for("allocate_page"))
            seats = sum(hall_capacity(h) for h in halls.find({"_id": {"$in": hall_ids}}))
            need = students.count_documents({"dept": {"$in": depts}} if depts else {})
            if need > seats:
                flash(f"{need} students but only {seats} seats in the selected halls. Pick more halls.", "error")
                return redirect(url_for("allocate_page"))
            new_id = exams.insert_one({
                "name": name, "date": day, "hall_ids": hall_ids,
                "session": request.form.get("session", "FN")[:2], "depts": depts,
                "created": datetime.utcnow(), "runs": 0}).inserted_id
            exam = exams.find_one({"_id": new_id})
        else:
            exam = exams.find_one({"_id": to_oid(target)})
            if not exam:
                flash("Choose an exam first.", "error")
                return redirect(url_for("allocate_page"))
        try:
            n, moved = allocate(exam, mode)
            msg = f"Hall allocated: {n} students seated."
            if moved is not None:
                msg += f" {moved}% of students moved to a new seat."
            flash(msg, "success")
        except ValueError as err:
            flash(str(err), "error")
        return redirect(url_for("exam_detail", exam_id=exam["_id"]))
    exam_list = list(exams.find().sort("date", 1))
    for e in exam_list:
        e["allocated"] = allocations.count_documents({"exam_id": e["_id"]})
        e["capacity"] = sum(hall_capacity(h) for h in halls.find({"_id": {"$in": e["hall_ids"]}}))
        e["need"] = students.count_documents({"dept": {"$in": e["depts"]}} if e.get("depts") else {})
    return render_template("allocate.html", exams=exam_list, halls=list(halls.find().sort("name", 1)),
                           depts=dept_counts(), selected=request.args.get("exam", ""),
                           total=students.count_documents({}))


@app.route("/users")
@admin_only
def users_page():
    return render_template("users.html", people=list(users.find().sort("created", 1)))


@app.route("/users/<user_id>/role", methods=["POST"])
@admin_only
def set_role(user_id):
    oid = to_oid(user_id)
    role = "admin" if request.form.get("role") == "admin" else "user"
    if oid == g.user["_id"]:
        flash("You cannot change your own role.", "error")
    elif oid and users.update_one({"_id": oid}, {"$set": {"role": role}}).matched_count:
        flash(f"Role updated to {role}.", "success")
    return redirect(url_for("users_page"))


@app.route("/lookup")
def lookup():
    reg_no = request.args.get("reg_no", "").strip()
    results = []
    if reg_no:
        for a in allocations.find({"reg_no": reg_no}):
            exam = exams.find_one({"_id": a["exam_id"]})
            if exam:
                results.append({"exam": exam, "alloc": a})
        results.sort(key=lambda r: r["exam"]["date"])
    return render_template("lookup.html", reg_no=reg_no, results=results)


@app.route("/health")
def health():
    client.admin.command("ping")
    return {"status": "ok"}


if __name__ == "__main__":
    print(f"\n  Admin signup code: {ADMIN_CODE}   (also saved in .admin_code)\n")
    app.run(host="0.0.0.0", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
