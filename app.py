import os
from functools import wraps
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)
import supplementary_auth as backend

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "campus-hw-secret-key-2026")
backend.initialize_database()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        success, result = backend.Authentication.login(username, password)
        if success:
            session.clear()
            session["username"] = username
            session["role"] = result.lower()
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash(result, "danger")
            return render_template("login.html", username=username)

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        success, msg = backend.Authentication.register(username, email, password)
        if success:
            flash(msg, "success")
            return redirect(url_for("login"))
        else:
            flash(msg, "danger")
            return render_template("register.html", username=username, email=email)

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/reset-request", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not new_password or not confirm_password:
            flash("All reset fields are required.", "danger")
            return render_template("reset.html")

        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return render_template("reset.html")

        valid, msg = backend.Authentication.validate_password(new_password)
        if not valid:
            flash(msg, "danger")
            return render_template("reset.html")

        import sqlite3, bcrypt
        try:
            conn = sqlite3.connect(backend.DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND LOWER(email) = LOWER(?)", (username, email))
            user = cursor.fetchone()
            if not user:
                conn.close()
                flash("No matching account found with that username and email.", "danger")
                return render_template("reset.html")

            new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user[0]))
            conn.commit()
            conn.close()

            flash("Password reset successful! You may now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Database error: {e}", "danger")
            return render_template("reset.html")

    return render_template("reset.html")

@app.route("/dashboard")
@login_required
def dashboard():
    search = request.args.get("search", "").strip().lower()
    selected_category = request.args.get("category", "All")

    backend.update_borrowing_and_equipment_lifecycle()

    all_items = backend.get_all_hardware()
    categories = sorted(list({item[2].strip() for item in all_items if item[2].strip()}))

    filtered_items = []
    for item in all_items:
        i_id, i_name, i_cat, i_qty, i_price, i_st, i_eq_st = item
        if selected_category != "All" and i_cat != selected_category:
            continue
        if search and not (search in i_name.lower() or search in i_cat.lower() or search in str(i_id)):
            continue
        filtered_items.append(item)

    total_stocks = sum(item[3] for item in all_items)

    user_borrowings = []
    pending_requests = []
    saved_items = []

    if session["role"] == "user":
        user_borrowings = backend.get_user_borrowings(session["username"])
        saved_items = backend.get_saved_items(session["username"])
    else:
        pending_requests = backend.get_all_pending_borrowings()

    return render_template(
        "dashboard.html",
        items=filtered_items,
        categories=categories,
        selected_category=selected_category,
        search=search,
        total_stocks=total_stocks,
        user_borrowings=user_borrowings,
        active_loans=user_borrowings,
        pending_requests=pending_requests,
        pending_borrows=pending_requests,
        pending_returns=[],
        pending_resets=[],
        saved_items=saved_items
    )

@app.route("/borrow", methods=["POST"])
@login_required
def borrow():
    try:
        item_id = int(request.form["item_id"])
        quantity = int(request.form.get("quantity", 1))
        start_datetime = request.form.get("start_datetime", "").strip()
        end_datetime = request.form.get("end_datetime", "").strip()
    except (KeyError, ValueError):
        flash("Invalid request parameters.", "danger")
        return redirect(url_for("dashboard"))

    if not start_datetime:
        start_datetime = datetime.now().strftime("%Y-%m-%d %H:%M")
    else:
        start_datetime = start_datetime.replace("T", " ")

    if not end_datetime:
        end_datetime = datetime.now().strftime("%Y-%m-%d 17:00")
    else:
        end_datetime = end_datetime.replace("T", " ")

    success, msg = backend.create_borrowing(
        session["username"],
        item_id,
        quantity,
        start_datetime,
        end_datetime,
        role=session["role"]
    )

    flash(msg, "success" if success else "danger")
    return redirect(url_for("dashboard"))

@app.route("/return-request", methods=["POST"])
@login_required
def return_request():
    raw_ids = request.form.getlist("loan_ids")
    import sqlite3
    try:
        loan_ids = [int(x) for x in raw_ids]
        if loan_ids:
            conn = sqlite3.connect(backend.DB_NAME)
            cur = conn.cursor()
            for lid in loan_ids:
                cur.execute("UPDATE borrowings SET status = 'Completed' WHERE borrowing_id = ?", (lid,))
            conn.commit()
            conn.close()
            backend.update_borrowing_and_equipment_lifecycle()
            flash("Return processed successfully.", "success")
        else:
            flash("No loans selected for return.", "warning")
    except Exception as e:
        flash(f"Error processing return: {e}", "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/add", methods=["POST"])
@admin_required
def admin_add():
    item_name = request.form.get("item_name", "").strip()
    category = request.form.get("category", "").strip()
    quantity = request.form.get("quantity", "")
    unit_price = request.form.get("unit_price", "")

    success, msg = backend.add_hardware(item_name, category, quantity, unit_price)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/delete", methods=["POST"])
@app.route("/admin/delete/<int:item_id>", methods=["POST"])
@admin_required
def admin_delete(item_id=None):
    if item_id is None:
        raw_ids = request.form.getlist("item_ids")
        if not raw_ids and request.form.get("item_id"):
            raw_ids = [request.form.get("item_id")]
        try:
            target_ids = [int(x) for x in raw_ids]
        except ValueError:
            target_ids = []

        if not target_ids:
            flash("No items selected for deletion.", "warning")
            return redirect(url_for("dashboard"))

        for tid in target_ids:
            backend.delete_hardware(tid)
        flash("Items deleted successfully.", "success")
        return redirect(url_for("dashboard"))

    success, msg = backend.delete_hardware(item_id)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/requests/<int:req_id>/<action>", methods=["POST"])
@app.route("/admin/borrow-action", methods=["POST"])
@admin_required
def admin_borrow_action(req_id=None, action=None):
    if req_id is None:
        raw_ids = request.form.getlist("loan_ids")
        action = request.form.get("action", "approve")
        approve = (action == "approve")
        try:
            for rid in [int(x) for x in raw_ids]:
                backend.process_borrowing_request(rid, approve=approve)
            flash("Requests processed.", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")
        return redirect(url_for("dashboard"))

    approve = (action == "approve")
    success, msg = backend.process_borrowing_request(req_id, approve=approve)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/return-action", methods=["POST"])
@admin_required
def admin_return_action():
    flash("Return review processed.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/reset-action", methods=["POST"])
@admin_required
def admin_reset_action():
    flash("Reset review processed.", "success")
    return redirect(url_for("dashboard"))

@app.route("/export")
@login_required
def export():
    rows = backend.get_all_hardware()
    csv_path = os.path.abspath("inventory_report.csv")
    try:
        import csv
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Name", "Category", "Qty", "Price (P)", "Stock Status", "Equipment Status"])
            for row in rows:
                writer.writerow(row)
        return send_file(csv_path, as_attachment=True, download_name="inventory_report.csv")
    except Exception as e:
        flash(f"CSV export failed: {e}", "danger")
        return redirect(url_for("dashboard"))

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print(" CAMPUS HARDWARE INVENTORY - WEB PORTAL")
    print(" Database:", backend.DB_NAME)
    print(" URL:      http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True)
