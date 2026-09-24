try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    TKINTER_AVAILABLE = True
except ImportError:
    tk = None
    messagebox = None
    ttk = None
    TKINTER_AVAILABLE = False
import sqlite3
import bcrypt
import csv
import os
import logging
import re
import time
from datetime import datetime


# ============================================================
# CONFIGURATION & AUTOMATIC DATABASE DETECTION
# ============================================================

def resolve_db_path():
    if os.path.exists("hardware_inventory.db"):
        return os.path.abspath("hardware_inventory.db")
    
    script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
    candidate = os.path.join(script_dir, "hardware_inventory.db")
    if os.path.exists(candidate):
        return candidate
    
    return os.path.join(script_dir, "hardware_inventory.db")

DB_NAME = resolve_db_path()
LOG_DIR = os.path.join(os.path.dirname(DB_NAME), "app_logging")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "app.log"),
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("HardwareInventoryApp")


# ============================================================
# DATABASE
# ============================================================

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # USERS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    # HARDWARE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardware (
            item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            status TEXT NOT NULL,
            equipment_status TEXT NOT NULL DEFAULT 'Available'
        )
    """)

    # BORROWINGS / SCHEDULE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS borrowings (
            borrowing_id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            start_datetime TEXT NOT NULL,
            end_datetime TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending Approval',
            deducted INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (item_id) REFERENCES hardware(item_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # SAVED ITEMS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS saved_items (
            saved_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (item_id) REFERENCES hardware(item_id),
            UNIQUE(user_id, item_id)
        )
    """)

    # SAVED KITS & KIT ITEMS
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS kits (
            kit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kit_name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, kit_name)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS kit_items (
            kit_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            kit_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (kit_id) REFERENCES kits(kit_id) ON DELETE CASCADE,
            FOREIGN KEY (item_id) REFERENCES hardware(item_id),
            UNIQUE(kit_id, item_id)
        )
    """)

    # MIGRATIONS
    cursor.execute("PRAGMA table_info(users)")
    u_cols = [c[1] for c in cursor.fetchall()]
    if "role" not in u_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")

    cursor.execute("PRAGMA table_info(hardware)")
    h_cols = [c[1] for c in cursor.fetchall()]
    if "equipment_status" not in h_cols:
        cursor.execute("ALTER TABLE hardware ADD COLUMN equipment_status TEXT DEFAULT 'Available'")

    cursor.execute("PRAGMA table_info(borrowings)")
    b_cols = [c[1] for c in cursor.fetchall()]
    if "deducted" not in b_cols:
        cursor.execute("ALTER TABLE borrowings ADD COLUMN deducted INTEGER DEFAULT 0")

    # SEED / UPDATE DEFAULT ADMIN ACCOUNT (admin / Admin@123)
    admin_pw_hash = bcrypt.hashpw(b"Admin@123", bcrypt.gensalt()).decode("utf-8")
    cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = 'admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role)
            VALUES ('admin', 'admin@campus.edu', ?, 'admin')
        """, (admin_pw_hash,))
    else:
        cursor.execute("""
            UPDATE users 
            SET password_hash = ?, role = 'admin' 
            WHERE LOWER(username) = 'admin'
        """, (admin_pw_hash,))

    conn.commit()
    conn.close()
    logger.info(f"Database initialized at: {DB_NAME}")


# ============================================================
# AUTHENTICATION
# ============================================================

class Authentication:
    failed_attempts = {}

    @staticmethod
    def validate_username(username):
        if len(username) < 3:
            return False, "Username must be at least 3 characters."
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            return False, "Username must contain only letters, numbers, and underscores."
        return True, ""

    @staticmethod
    def validate_password(password):
        regex = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*]).{8,}$"
        if not re.match(regex, password):
            return False, (
                "Password must be at least 8 characters long, "
                "contain 1 uppercase letter, 1 number, and 1 special character (@#$%^&*)."
            )
        return True, ""

    @staticmethod
    def validate_email(email):
        regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(regex, email):
            return False, "Please enter a valid email address."
        return True, ""

    @staticmethod
    def register(username, email, password):
        valid, message = Authentication.validate_username(username)
        if not valid:
            return False, message

        valid, message = Authentication.validate_email(email)
        if not valid:
            return False, message

        valid, message = Authentication.validate_password(password)
        if not valid:
            return False, message

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
            if cursor.fetchone()[0] > 0:
                conn.close()
                return False, f"Username '{username}' is already taken."

            cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            if cursor.fetchone()[0] > 0:
                conn.close()
                return False, f"Email '{email}' is already in use."

            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, 'user')
            """, (username.strip(), email.strip(), password_hash))

            conn.commit()
            conn.close()
            logger.info(f"User registered: {username}")
            return True, "Registration successful. You may now log in."

        except sqlite3.Error as e:
            logger.error(f"Registration database error: {e}")
            return False, "Database error."

    @staticmethod
    def login(username, password):
        if not username or not password:
            return False, "Please provide both username and password."

        now = time.time()
        record = Authentication.failed_attempts.get(username, {"count": 0, "lockout_time": 0})

        if now < record["lockout_time"]:
            remaining = int(record["lockout_time"] - now)
            return False, f"Account temporarily locked. Please wait {remaining} seconds."

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, role FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
            result = cursor.fetchone()
            conn.close()

            if result:
                stored_hash = result[0].encode("utf-8")
                role = result[1]
                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    logger.info(f"Successful login: {username} ({role})")
                    Authentication.failed_attempts[username] = {"count": 0, "lockout_time": 0}
                    return True, role

            record["count"] += 1
            if record["count"] >= 3:
                record["lockout_time"] = now + 30
                Authentication.failed_attempts[username] = record
                logger.warning(f"Account locked: {username}")
                return False, "3 consecutive failed attempts. Account locked for 30 seconds."

            Authentication.failed_attempts[username] = record
            logger.warning(f"Failed login attempt: {username}")
            return False, f"Invalid credentials. Attempts remaining: {3 - record['count']}"

        except sqlite3.Error as e:
            logger.error(f"Login database error: {e}")
            return False, "Database connection error."


# ============================================================
# INVENTORY FUNCTIONS
# ============================================================

def calculate_status(quantity):
    if quantity > 5:
        return "In Stock"
    elif quantity >= 1:
        return "Low Stock"
    else:
        return "Out of Stock"

def add_hardware(item_name, category, quantity, unit_price):
    if not item_name.strip():
        return False, "Item Name is required."
    if not category.strip():
        return False, "Category is required."

    try:
        quantity = int(quantity)
    except ValueError:
        return False, "Quantity must be a whole number."

    if quantity < 0:
        return False, "Quantity cannot be negative."

    try:
        unit_price = float(unit_price)
    except ValueError:
        return False, "Unit Price must be a number."

    if unit_price < 0:
        return False, "Unit Price cannot be negative."

    status = calculate_status(quantity)
    equipment_status = "Unavailable" if quantity == 0 else "Available"

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM hardware WHERE LOWER(item_name) = LOWER(?)", (item_name.strip(),))
        if cursor.fetchone()[0] > 0:
            conn.close()
            return False, f"Item '{item_name.strip()}' already exists in the inventory."

        cursor.execute("""
            INSERT INTO hardware (item_name, category, quantity, unit_price, status, equipment_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (item_name.strip(), category.strip(), quantity, unit_price, status, equipment_status))

        conn.commit()
        conn.close()
        logger.info(f"Hardware added: {item_name}")
        return True, "Hardware item added successfully."

    except sqlite3.Error as e:
        logger.error(f"Hardware insertion error: {e}")
        return False, "Database error while adding item."

def update_hardware(item_id, new_quantity, new_price):
    try:
        new_quantity = int(new_quantity)
    except ValueError:
        return False, "Quantity must be a whole number."

    if new_quantity < 0:
        return False, "Quantity cannot be negative."

    try:
        new_price = float(new_price)
    except ValueError:
        return False, "Unit Price must be a number."

    if new_price < 0:
        return False, "Unit Price cannot be negative."

    status = calculate_status(new_quantity)

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT equipment_status FROM hardware WHERE item_id = ?", (item_id,))
        row = cursor.fetchone()
        current_eq_status = row[0] if row else "Available"

        if new_quantity == 0:
            new_eq_status = "Unavailable"
        elif current_eq_status == "Unavailable":
            new_eq_status = "Available"
        else:
            new_eq_status = current_eq_status

        cursor.execute("""
            UPDATE hardware
            SET quantity = ?, unit_price = ?, status = ?, equipment_status = ?
            WHERE item_id = ?
        """, (new_quantity, new_price, status, new_eq_status, item_id))
        conn.commit()
        conn.close()

        logger.info(f"Hardware updated: {item_id}")
        return True, "Hardware item updated successfully."
    except sqlite3.Error as e:
        logger.error(f"Hardware update error: {e}")
        return False, "Database error while updating item."

def delete_hardware(item_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM borrowings WHERE item_id = ?", (item_id,))
        if cursor.fetchone()[0] > 0:
            conn.close()
            return False, "This equipment has borrowing history and cannot be deleted."

        cursor.execute("DELETE FROM saved_items WHERE item_id = ?", (item_id,))
        cursor.execute("DELETE FROM kit_items WHERE item_id = ?", (item_id,))
        cursor.execute("DELETE FROM hardware WHERE item_id = ?", (item_id,))
        conn.commit()
        conn.close()

        logger.info(f"Hardware deleted: {item_id}")
        return True, "Item deleted successfully."
    except sqlite3.Error as e:
        logger.error(f"Hardware deletion error: {e}")
        return False, "Database error while deleting item."

def update_borrowing_and_equipment_lifecycle():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        # 1. Scheduled -> In Use (only for approved bookings)
        cursor.execute("""
            UPDATE borrowings SET status = 'In Use'
            WHERE status = 'Scheduled' AND start_datetime <= ? AND end_datetime > ?
        """, (now, now))

        # 2. In Use -> Completed
        cursor.execute("""
            UPDATE borrowings SET status = 'Completed'
            WHERE status = 'In Use' AND end_datetime <= ?
        """, (now,))

        # 3. Deduct stock for active In Use borrowings not yet deducted
        cursor.execute("""
            SELECT borrowing_id, item_id, quantity FROM borrowings
            WHERE status = 'In Use' AND deducted = 0
        """)
        to_deduct = cursor.fetchall()
        for b_id, item_id, qty in to_deduct:
            cursor.execute("""
                UPDATE hardware
                SET quantity = MAX(0, quantity - ?)
                WHERE item_id = ?
            """, (qty, item_id))
            cursor.execute("UPDATE borrowings SET deducted = 1 WHERE borrowing_id = ?", (b_id,))

        # 4. Restore stock for Completed borrowings that were deducted
        cursor.execute("""
            SELECT borrowing_id, item_id, quantity FROM borrowings
            WHERE status = 'Completed' AND deducted = 1
        """)
        to_restore = cursor.fetchall()
        for b_id, item_id, qty in to_restore:
            cursor.execute("""
                UPDATE hardware
                SET quantity = quantity + ?
                WHERE item_id = ?
            """, (qty, item_id))
            cursor.execute("UPDATE borrowings SET deducted = 2 WHERE borrowing_id = ?", (b_id,))

        # 5. Synchronize Stock Status & Availability based on remaining Quantity
        cursor.execute("SELECT item_id, quantity, equipment_status FROM hardware")
        all_items = cursor.fetchall()
        for item_id, qty, eq_status in all_items:
            st = calculate_status(qty)
            if qty == 0:
                new_eq = eq_status if eq_status in ["Under Maintenance", "Damaged"] else "Unavailable"
            else:
                new_eq = "Available" if eq_status == "Unavailable" else eq_status

            cursor.execute("""
                UPDATE hardware SET status = ?, equipment_status = ?
                WHERE item_id = ?
            """, (st, new_eq, item_id))

        # 6. Flag In Use / Reserved (approved requests only)
        cursor.execute("""
            UPDATE hardware SET equipment_status = 'In Use'
            WHERE item_id IN (SELECT item_id FROM borrowings WHERE status = 'In Use')
            AND equipment_status NOT IN ('Under Maintenance', 'Damaged', 'Unavailable')
        """)

        cursor.execute("""
            UPDATE hardware SET equipment_status = 'Reserved'
            WHERE item_id IN (
                SELECT item_id FROM borrowings WHERE status = 'Scheduled' AND start_datetime > ?
            )
            AND item_id NOT IN (SELECT item_id FROM borrowings WHERE status = 'In Use')
            AND equipment_status NOT IN ('Under Maintenance', 'Damaged', 'Unavailable')
        """, (now,))

        cursor.execute("""
            UPDATE hardware SET equipment_status = 'Available'
            WHERE item_id NOT IN (
                SELECT item_id FROM borrowings WHERE status IN ('Scheduled', 'In Use')
            )
            AND quantity > 0
            AND equipment_status NOT IN ('Under Maintenance', 'Damaged', 'Unavailable')
        """)

        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Borrowing lifecycle error: {e}")

def get_all_hardware():
    try:
        update_borrowing_and_equipment_lifecycle()
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT item_id, item_name, category, quantity, unit_price, status, equipment_status
            FROM hardware ORDER BY item_id
        """)
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        logger.error(f"Failed to load hardware: {e}")
        return []

def get_total_value():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT SUM(quantity * unit_price) FROM hardware")
        result = cursor.fetchone()
        conn.close()
        return float(result[0]) if result and result[0] is not None else 0.0
    except sqlite3.Error as e:
        logger.error(f"Failed to calculate value: {e}")
        return 0.0

def get_user_id(username):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except sqlite3.Error as e:
        logger.error(f"Failed to get user ID: {e}")
        return None

def check_borrowing_conflict(item_id, requested_quantity, start_datetime, end_datetime):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT quantity, equipment_status, item_name FROM hardware WHERE item_id = ?", (item_id,))
        result = cursor.fetchone()

        if not result:
            conn.close()
            return False, "Equipment not found."

        total_quantity, equipment_status, item_name = result[0], result[1], result[2]

        if total_quantity <= 0 or equipment_status == "Unavailable":
            conn.close()
            return False, f"'{item_name}' has 0 quantity and is currently Unavailable."

        if equipment_status in ["Under Maintenance", "Damaged"]:
            conn.close()
            return False, f"'{item_name}' is currently '{equipment_status}'. It cannot be borrowed."

        # Check against approved scheduled loans
        cursor.execute("""
            SELECT COALESCE(SUM(quantity), 0)
            FROM borrowings
            WHERE item_id = ?
            AND status = 'Scheduled'
            AND start_datetime < ? AND end_datetime > ?
        """, (item_id, end_datetime, start_datetime))

        reserved_quantity = cursor.fetchone()[0]
        conn.close()

        available_quantity = total_quantity - reserved_quantity
        if requested_quantity > available_quantity:
            return False, (
                f"Conflict for '{item_name}':\n"
                f"Available in inventory: {total_quantity}\n"
                f"Scheduled by others: {reserved_quantity}\n"
                f"Available for selected time: {available_quantity}\n"
                f"Requested: {requested_quantity}"
            )
        return True, ""
    except sqlite3.Error as e:
        logger.error(f"Conflict check error: {e}")
        return False, "Database error while checking availability."

def create_borrowing(username, item_id, quantity, start_datetime, end_datetime, role="user"):
    try:
        quantity = int(quantity)
    except ValueError:
        return False, "Quantity must be a whole number."

    if quantity <= 0:
        return False, "Quantity must be greater than zero."

    try:
        start_obj = datetime.strptime(start_datetime, "%Y-%m-%d %H:%M")
        end_obj = datetime.strptime(end_datetime, "%Y-%m-%d %H:%M")
    except ValueError:
        return False, "Invalid date/time format."

    if start_obj >= end_obj:
        return False, "End time must be later than start time."

    user_id = get_user_id(username)
    if not user_id:
        return False, "User account not found."

    available, message = check_borrowing_conflict(item_id, quantity, start_datetime, end_datetime)
    if not available:
        logger.warning(f"Borrowing conflict prevented: {username}, Item {item_id}")
        return False, message

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        now_dt = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Admin borrows are pre-approved immediately; student/user requests wait for approval
        if role == "admin":
            if start_datetime <= now_dt:
                init_status = 'In Use'
                deducted = 1
                cursor.execute("UPDATE hardware SET quantity = MAX(0, quantity - ?) WHERE item_id = ?", (quantity, item_id))
            else:
                init_status = 'Scheduled'
                deducted = 0
        else:
            init_status = 'Pending Approval'
            deducted = 0

        cursor.execute("""
            INSERT INTO borrowings (item_id, user_id, quantity, start_datetime, end_datetime, status, deducted)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (item_id, user_id, quantity, start_datetime, end_datetime, init_status, deducted))
        conn.commit()
        conn.close()

        save_item_for_user(username, item_id)
        logger.info(f"Borrowing created ({init_status}): {username}, Item {item_id}")
        return True, "Request submitted successfully."
    except sqlite3.Error as e:
        logger.error(f"Borrowing insertion error: {e}")
        return False, "Database error while scheduling equipment."

def get_user_borrowings(username):
    user_id = get_user_id(username)
    if not user_id:
        return []
    try:
        update_borrowing_and_equipment_lifecycle()
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT b.borrowing_id, h.item_name, b.quantity, b.start_datetime, b.end_datetime, b.status
            FROM borrowings b
            JOIN hardware h ON b.item_id = h.item_id
            WHERE b.user_id = ?
            ORDER BY b.start_datetime DESC
        """, (user_id,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        logger.error(f"Failed to load borrowing history: {e}")
        return []

def get_all_pending_borrowings():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT b.borrowing_id, u.username, h.item_name, b.quantity, b.start_datetime, b.end_datetime, b.status, b.item_id
            FROM borrowings b
            JOIN users u ON b.user_id = u.id
            JOIN hardware h ON b.item_id = h.item_id
            WHERE b.status = 'Pending Approval'
            ORDER BY b.created_at ASC
        """)
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        logger.error(f"Failed to load pending requests: {e}")
        return []

def process_borrowing_request(borrowing_id, approve=True):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT b.item_id, b.quantity, b.start_datetime, b.end_datetime, b.status
            FROM borrowings b WHERE b.borrowing_id = ?
        """, (borrowing_id,))
        req = cursor.fetchone()

        if not req or req[4] != 'Pending Approval':
            conn.close()
            return False, "Request not found or has already been reviewed."

        item_id, qty, start_dt, end_dt, _ = req

        if approve:
            now_dt = datetime.now().strftime("%Y-%m-%d %H:%M")
            if start_dt <= now_dt:
                new_status = 'In Use'
                deducted = 1
                cursor.execute("UPDATE hardware SET quantity = MAX(0, quantity - ?) WHERE item_id = ?", (qty, item_id))
            else:
                new_status = 'Scheduled'
                deducted = 0

            cursor.execute("""
                UPDATE borrowings SET status = ?, deducted = ? WHERE borrowing_id = ?
            """, (new_status, deducted, borrowing_id))
            conn.commit()
            conn.close()
            return True, f"Request approved (Status: {new_status})."
        else:
            cursor.execute("UPDATE borrowings SET status = 'Rejected' WHERE borrowing_id = ?", (borrowing_id,))
            conn.commit()
            conn.close()
            return True, "Request rejected."

    except sqlite3.Error as e:
        logger.error(f"Error processing borrowing {borrowing_id}: {e}")
        return False, "Database error while processing request."

def save_item_for_user(username, item_id):
    user_id = get_user_id(username)
    if not user_id:
        return False
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO saved_items (user_id, item_id)
            VALUES (?, ?)
        """, (user_id, item_id))
        conn.commit()
        conn.close()
        logger.info(f"Saved item {item_id} for user {username}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Failed to save item: {e}")
        return False

def remove_saved_item(username, item_id):
    user_id = get_user_id(username)
    if not user_id:
        return False
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM saved_items WHERE user_id = ? AND item_id = ?", (user_id, item_id))
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        logger.error(f"Failed to remove saved item: {e}")
        return False

def get_saved_items(username):
    user_id = get_user_id(username)
    if not user_id:
        return []
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT h.item_id, h.item_name, h.category, h.quantity, h.equipment_status
            FROM saved_items s
            JOIN hardware h ON s.item_id = h.item_id
            WHERE s.user_id = ?
            ORDER BY h.item_name
        """, (user_id,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        logger.error(f"Failed to load saved items: {e}")
        return []

# ============================================================
# KIT FUNCTIONS
# ============================================================

def save_kit_for_user(username, kit_name, item_quantities):
    user_id = get_user_id(username)
    if not user_id:
        return False, "User not found."

    if not kit_name.strip():
        return False, "Kit name cannot be empty."

    if not item_quantities:
        return False, "No items selected for this kit."

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT kit_id FROM kits WHERE user_id = ? AND LOWER(kit_name) = LOWER(?)", (user_id, kit_name.strip()))
        if cursor.fetchone():
            conn.close()
            return False, f"A kit named '{kit_name.strip()}' already exists."

        cursor.execute("INSERT INTO kits (user_id, kit_name) VALUES (?, ?)", (user_id, kit_name.strip()))
        kit_id = cursor.lastrowid

        for item_id, qty in item_quantities.items():
            cursor.execute("""
                INSERT INTO kit_items (kit_id, item_id, quantity)
                VALUES (?, ?, ?)
            """, (kit_id, item_id, qty))

        conn.commit()
        conn.close()
        return True, f"Kit '{kit_name.strip()}' created successfully!"
    except sqlite3.Error as e:
        logger.error(f"Failed to save kit: {e}")
        return False, "Database error while creating kit."

def get_user_kits(username):
    user_id = get_user_id(username)
    if not user_id:
        return []
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT k.kit_id, k.kit_name, COUNT(ki.item_id), k.created_at
            FROM kits k
            LEFT JOIN kit_items ki ON k.kit_id = ki.kit_id
            WHERE k.user_id = ?
            GROUP BY k.kit_id
            ORDER BY k.created_at DESC
        """, (user_id,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        logger.error(f"Failed to get kits: {e}")
        return []

def get_kit_items_details(kit_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ki.item_id, h.item_name, h.category, ki.quantity, h.quantity, h.equipment_status
            FROM kit_items ki
            JOIN hardware h ON ki.item_id = h.item_id
            WHERE ki.kit_id = ?
        """, (kit_id,))
        rows = cursor.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        logger.error(f"Failed to get kit items: {e}")
        return []

def delete_user_kit(kit_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM kit_items WHERE kit_id = ?", (kit_id,))
        cursor.execute("DELETE FROM kits WHERE kit_id = ?", (kit_id,))
        conn.commit()
        conn.close()
        return True, "Kit deleted successfully."
    except sqlite3.Error as e:
        logger.error(f"Failed to delete kit: {e}")
        return False, "Database error."


# ============================================================
# LOGIN WINDOW
# ============================================================

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Campus Hardware Inventory - Access")
        self.root.geometry("420x520")
        self.root.resizable(False, False)
        self.mode = "login"
        self.show_pw_var = tk.BooleanVar(value=False)
        self.build_login_interface()

    def build_login_interface(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        header_frame = tk.Frame(self.root)
        header_frame.pack(fill="x", pady=(25, 10))

        tk.Label(header_frame, text="Campus Hardware Inventory", font=("Arial", 16, "bold")).pack()
        tk.Label(header_frame, text="Asset Management System", font=("Arial", 10)).pack(pady=(3, 0))

        toggle_frame = tk.Frame(self.root)
        toggle_frame.pack(pady=10)

        login_bg = "lightblue" if self.mode == "login" else "SystemButtonFace"
        reg_bg = "lightblue" if self.mode == "register" else "SystemButtonFace"

        tk.Button(toggle_frame, text="Login", width=15, bg=login_bg, command=lambda: self.switch_mode("login")).pack(side="left", padx=5)
        tk.Button(toggle_frame, text="Register", width=15, bg=reg_bg, command=lambda: self.switch_mode("register")).pack(side="left", padx=5)

        form_frame = tk.Frame(self.root)
        form_frame.pack(pady=10, padx=50, fill="both", expand=True)

        tk.Label(form_frame, text="Username:").pack(anchor="w")
        self.user_entry = tk.Entry(form_frame, width=35)
        self.user_entry.pack(pady=(0, 10))

        if self.mode == "register":
            tk.Label(form_frame, text="Email:").pack(anchor="w")
            self.email_entry = tk.Entry(form_frame, width=35)
            self.email_entry.pack(pady=(0, 10))

        tk.Label(form_frame, text="Password:").pack(anchor="w")
        self.pass_entry = tk.Entry(form_frame, width=35, show="*")
        self.pass_entry.pack(pady=(0, 5))

        tk.Checkbutton(form_frame, text="Show Password", variable=self.show_pw_var, command=self.toggle_pw).pack(anchor="w", pady=(0, 15))

        if self.mode == "login":
            tk.Button(form_frame, text="LOGIN", width=20, command=self.login, bg="green", fg="white").pack(pady=10)
        else:
            tk.Button(form_frame, text="REGISTER", width=20, command=self.register, bg="blue", fg="white").pack(pady=10)

    def switch_mode(self, new_mode):
        self.mode = new_mode
        self.show_pw_var.set(False)
        self.build_login_interface()

    def toggle_pw(self):
        self.pass_entry.config(show="" if self.show_pw_var.get() else "*")

    def login(self):
        username = self.user_entry.get().strip()
        password = self.pass_entry.get()
        success, result = Authentication.login(username, password)

        if success:
            role = result
            messagebox.showinfo("Login Successful", f"Welcome, {username} ({role.upper()})!")
            self.show_inventory(username, role)
        else:
            if "locked" in result.lower():
                messagebox.showwarning("Account Locked", result)
            else:
                messagebox.showerror("Login Failed", result)

    def register(self):
        username = self.user_entry.get().strip()
        email = self.email_entry.get().strip() if hasattr(self, "email_entry") else ""
        password = self.pass_entry.get()

        success, message = Authentication.register(username, email, password)
        if success:
            messagebox.showinfo("Registration Successful", message)
            self.switch_mode("login")
            self.user_entry.delete(0, tk.END)
            self.user_entry.insert(0, username)
        else:
            messagebox.showerror("Registration Failed", message)

    def show_inventory(self, username, role):
        for widget in self.root.winfo_children():
            widget.destroy()
        InventoryWindow(self.root, username, role, self.show_login)

    def show_login(self):
        self.mode = "login"
        self.build_login_interface()


# ============================================================
# INVENTORY WINDOW
# ============================================================

class InventoryWindow:
    def __init__(self, root, username, role, logout_callback):
        self.root = root
        self.username = username
        self.role = role.lower()  # 'admin' or 'user'
        self.logout_callback = logout_callback

        self.root.title("Campus Hardware Inventory System")
        self.root.geometry("1100x750")
        self.root.resizable(True, True)

        self.hardware_cache = {}
        self.checked_items = set()

        self.build_interface()
        self.load_inventory()

    def build_interface(self):
        # HEADER
        header = tk.Frame(self.root, padx=15, pady=10)
        header.pack(fill="x")

        tk.Label(header, text="Campus Hardware Inventory", font=("Arial", 18, "bold")).pack(side="left")
        
        # TOTAL ASSET VALUE (VISIBLE ONLY TO ADMIN)
        if self.role == "admin":
            self.total_label = tk.Label(header, font=("Arial", 14, "bold"), fg="#15803d")
            self.total_label.pack(side="right", padx=20)
        else:
            self.total_label = None

        # USER BAR
        user_frame = tk.Frame(self.root)
        user_frame.pack(fill="x", padx=15, pady=5)

        badge_color = "red" if self.role == "admin" else "darkblue"
        tk.Label(user_frame, text=f"Logged in as: {self.username} ", font=("Arial", 10, "bold")).pack(side="left")
        tk.Label(user_frame, text=f"[{self.role.upper()}]", font=("Arial", 10, "bold"), fg=badge_color).pack(side="left")

        tk.Button(user_frame, text="LOGOUT", command=self.logout, bg="red", fg="white", width=12).pack(side="right")

        # TOP CONTAINER: Form (Left, Admin-only) & Status Display (Right)
        top_container = tk.Frame(self.root, padx=15, pady=5)
        top_container.pack(fill="x")

        # ADD HARDWARE (LEFT SIDE - EXCLUSIVE TO ADMIN)
        if self.role == "admin":
            form = tk.LabelFrame(top_container, text="Add Hardware Item (Admin)", padx=10, pady=10)
            form.pack(side="left", fill="both", expand=True, padx=(0, 10))

            tk.Label(form, text="Item Name:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
            self.item_name_entry = tk.Entry(form, width=18)
            self.item_name_entry.grid(row=0, column=1, padx=5, pady=5)

            tk.Label(form, text="Category:").grid(row=0, column=2, padx=5, pady=5, sticky="e")
            self.category_entry = tk.Entry(form, width=18)
            self.category_entry.grid(row=0, column=3, padx=5, pady=5)

            tk.Label(form, text="Quantity:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
            self.quantity_entry = tk.Entry(form, width=18)
            self.quantity_entry.grid(row=1, column=1, padx=5, pady=5)

            tk.Label(form, text="Unit Price (₱):").grid(row=1, column=2, padx=5, pady=5, sticky="e")
            self.price_entry = tk.Entry(form, width=18)
            self.price_entry.grid(row=1, column=3, padx=5, pady=5)

            tk.Button(
                form,
                text="SAVE ITEM",
                command=self.save_item,
                bg="green",
                fg="white",
                width=15
            ).grid(row=2, column=0, columnspan=4, pady=10)

        # CURRENT STATUS DISPLAY BOX (SELECTED ITEM STATUS - RIGHT SIDE)
        status_box = tk.LabelFrame(
            top_container,
            text="Selected Item Status",
            padx=15,
            pady=10,
            font=("Arial", 10, "bold")
        )
        status_box.pack(side="right", fill="both", expand=True)

        self.selected_item_name_lbl = tk.Label(
            status_box,
            text="No item selected",
            font=("Arial", 12, "bold"),
            fg="gray"
        )
        self.selected_item_name_lbl.pack(anchor="w", pady=(2, 6))

        status_grid = tk.Frame(status_box)
        status_grid.pack(anchor="w", fill="x")

        # 1. Equipment Status
        tk.Label(status_grid, text="Equipment Status:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", pady=2)
        self.status_equipment_lbl = tk.Label(status_grid, text="--", font=("Arial", 10, "bold"), fg="navy")
        self.status_equipment_lbl.grid(row=0, column=1, sticky="w", padx=10, pady=2)

        # 2. Stock Level
        tk.Label(status_grid, text="Stock Level:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="w", pady=2)
        self.status_stock_lbl = tk.Label(status_grid, text="--", font=("Arial", 10, "bold"), fg="navy")
        self.status_stock_lbl.grid(row=1, column=1, sticky="w", padx=10, pady=2)

        # 3. Quantity
        tk.Label(status_grid, text="Available Qty:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky="w", pady=2)
        self.status_qty_lbl = tk.Label(status_grid, text="--", font=("Arial", 10, "bold"), fg="navy")
        self.status_qty_lbl.grid(row=2, column=1, sticky="w", padx=10, pady=2)

        # 4. Unit Price
        tk.Label(status_grid, text="Unit Price:", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky="w", pady=2)
        self.status_price_lbl = tk.Label(status_grid, text="--", font=("Arial", 10, "bold"), fg="navy")
        self.status_price_lbl.grid(row=3, column=1, sticky="w", padx=10, pady=2)

        # TOOLBAR / DROPDOWN ACTIONS, CATEGORY HIGHLIGHT SELECTOR & SEARCH BOX
        toolbar_frame = tk.Frame(self.root)
        toolbar_frame.pack(fill="x", padx=15, pady=5)

        self.action_btn = tk.Menubutton(
            toolbar_frame,
            text="Actions ▾",
            relief="raised",
            bg="#2563eb",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=14,
            pady=5,
            cursor="hand2",
            activebackground="#1d4ed8",
            activeforeground="white"
        )
        self.action_menu = tk.Menu(self.action_btn, tearoff=0, font=("Arial", 9))
        self.action_menu.add_command(label="Borrow / Schedule", command=self.open_borrow_window)
        self.action_menu.add_command(label="Save Kit", command=self.open_save_kit_dialog)
        self.action_menu.add_command(label="My Saved Kits", command=self.open_kits_window)
        self.action_menu.add_command(label="My Borrowings", command=self.open_my_borrowings)
        self.action_menu.add_command(label="My Saved Items", command=self.open_saved_items)
        
        # ADMIN-ONLY MENU OPTIONS
        if self.role == "admin":
            self.action_menu.add_separator()
            self.action_menu.add_command(label="Manage Requests (Admin)", command=self.open_requests_window)
            self.action_menu.add_command(label="Edit Selected (Admin)", command=self.open_edit_window)
            self.action_menu.add_command(label="Delete Selected (Admin)", command=self.delete_selected_item)

        self.action_menu.add_separator()
        self.action_menu.add_command(label="Select All", command=self.select_all_checkboxes)
        self.action_menu.add_command(label="Deselect All", command=self.clear_all_checkboxes)

        self.action_btn.config(menu=self.action_menu)
        self.action_btn.pack(side="left")

        # Category Highlight Dropdown
        filter_frame = tk.Frame(toolbar_frame)
        filter_frame.pack(side="left", padx=(25, 0))

        tk.Label(filter_frame, text="Highlight Category:", font=("Arial", 10, "bold")).pack(side="left", padx=(0, 6))

        self.category_highlight_var = tk.StringVar(value="All")
        self.category_highlight_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.category_highlight_var,
            state="readonly",
            width=18,
            font=("Arial", 9)
        )
        self.category_highlight_combo["values"] = ["All"]
        self.category_highlight_combo.pack(side="left")
        self.category_highlight_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_display_filters())

        # Search Box
        search_frame = tk.Frame(toolbar_frame)
        search_frame.pack(side="left", padx=(20, 0))

        tk.Label(search_frame, text="Search:", font=("Arial", 10, "bold")).pack(side="left", padx=(0, 6))

        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            width=22,
            font=("Arial", 9)
        )
        self.search_entry.pack(side="left")
        self.search_var.trace_add("write", lambda *args: self.apply_display_filters())

        tk.Button(
            search_frame,
            text="Clear",
            command=self.clear_search,
            font=("Arial", 8),
            padx=5,
            pady=1
        ).pack(side="left", padx=(5, 0))

        # INVENTORY TABLE (Checkbox, ID, Name, Category)
        table_frame = tk.Frame(self.root)
        table_frame.pack(fill="both", expand=True, padx=15, pady=5)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical")
        self.tree = ttk.Treeview(
            table_frame,
            columns=("Checked", "ID", "Name", "Category"),
            show="headings",
            selectmode="none",
            yscrollcommand=scrollbar.set
        )
        scrollbar.config(command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")

        headings = {
            "Checked": "Select",
            "ID": "ID",
            "Name": "Name",
            "Category": "Category"
        }

        for column, text in headings.items():
            self.tree.heading(column, text=text)

        self.tree.column("Checked", width=65, anchor="center")
        self.tree.column("ID", width=65, anchor="center")
        self.tree.column("Name", width=420)
        self.tree.column("Category", width=350)

        self.tree.tag_configure("in_stock", background="#90ee90", foreground="black")
        self.tree.tag_configure("low_stock", background="#fff3cd", foreground="black")
        self.tree.tag_configure("out_of_stock", background="#f8d7da", foreground="black")
        self.tree.tag_configure("unhighlighted", background="#f3f4f6", foreground="#6b7280")

        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Button-1>", self.on_row_click)

        # BOTTOM BAR
        action_frame = tk.Frame(self.root)
        action_frame.pack(fill="x", padx=15, pady=10)

        tk.Button(
            action_frame,
            text="Export CSV",
            command=self.export_csv,
            width=15
        ).pack(side="right", padx=3)

    def on_row_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        values = list(self.tree.item(row_id, "values"))
        item_id = int(values[1])

        if item_id in self.checked_items:
            self.checked_items.remove(item_id)
            values[0] = "☐"
        else:
            self.checked_items.add(item_id)
            values[0] = "☑"

        self.tree.item(row_id, values=values)
        self.update_status_card(item_id)

    def update_status_card(self, latest_item_id=None):
        count = len(self.checked_items)
        if count == 0:
            self.selected_item_name_lbl.config(text="No item selected", fg="gray")
            self.status_equipment_lbl.config(text="--", fg="navy")
            self.status_stock_lbl.config(text="--", fg="navy")
            self.status_qty_lbl.config(text="--", fg="navy")
            self.status_price_lbl.config(text="--", fg="navy")
            return

        if count > 1:
            self.selected_item_name_lbl.config(text=f"{count} items checked", fg="navy")
            self.status_equipment_lbl.config(text="Multiple Checked", fg="navy")
            self.status_stock_lbl.config(text="--", fg="navy")
            self.status_qty_lbl.config(text="--", fg="navy")
            self.status_price_lbl.config(text="--", fg="navy")
            return

        target_id = latest_item_id if latest_item_id in self.checked_items else next(iter(self.checked_items))
        data = self.hardware_cache.get(target_id)
        if not data:
            return

        item_name = data["item_name"]
        quantity = data["quantity"]
        unit_price = data["unit_price"]
        stock_status = data["status"]
        equipment_status = data["equipment_status"]

        self.selected_item_name_lbl.config(text=item_name, fg="black")

        stock_colors = {
            "In Stock": "darkgreen",
            "Low Stock": "#b45309",
            "Out of Stock": "red"
        }
        self.status_stock_lbl.config(
            text=stock_status,
            fg=stock_colors.get(stock_status, "black")
        )

        equip_colors = {
            "Available": "green",
            "In Use": "#d97706",
            "Reserved": "#2563eb",
            "Under Maintenance": "#ca8a04",
            "Damaged": "red",
            "Unavailable": "red"
        }
        self.status_equipment_lbl.config(
            text=equipment_status,
            fg=equip_colors.get(equipment_status, "black")
        )

        self.status_qty_lbl.config(text=str(quantity), fg="black")
        self.status_price_lbl.config(text=f"₱{unit_price:,.2f}", fg="black")

    def select_all_checkboxes(self):
        for child in self.tree.get_children():
            values = list(self.tree.item(child, "values"))
            item_id = int(values[1])
            self.checked_items.add(item_id)
            values[0] = "☑"
            self.tree.item(child, values=values)
        self.update_status_card()

    def clear_all_checkboxes(self):
        self.checked_items.clear()
        for child in self.tree.get_children():
            values = list(self.tree.item(child, "values"))
            values[0] = "☐"
            self.tree.item(child, values=values)
        self.update_status_card()

    def clear_search(self):
        self.search_var.set("")

    def apply_display_filters(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        selected_cat = self.category_highlight_var.get()
        query = self.search_var.get().strip().lower()

        for item_id, data in self.hardware_cache.items():
            name = data["item_name"].lower()
            category = data["category"].lower()
            str_id = str(item_id)

            if query and not (query in name or query in category or query in str_id):
                continue

            stock_lower = data["status"].lower()
            if stock_lower == "in stock":
                default_stock_tag = "in_stock"
            elif stock_lower == "low stock":
                default_stock_tag = "low_stock"
            else:
                default_stock_tag = "out_of_stock"

            if selected_cat == "All" or data["category"] == selected_cat:
                row_tag = default_stock_tag
            else:
                row_tag = "unhighlighted"

            checkbox = "☑" if item_id in self.checked_items else "☐"

            self.tree.insert(
                "",
                "end",
                values=(checkbox, item_id, data["item_name"], data["category"]),
                tags=(row_tag,)
            )

    def load_inventory(self):
        update_borrowing_and_equipment_lifecycle()

        rows = get_all_hardware()
        self.hardware_cache.clear()

        categories = set()

        for row in rows:
            item_id, item_name, category, quantity, unit_price, stock_status, equipment_status = row

            if category.strip():
                categories.add(category.strip())

            self.hardware_cache[item_id] = {
                "item_name": item_name,
                "category": category,
                "quantity": quantity,
                "unit_price": unit_price,
                "status": stock_status,
                "equipment_status": equipment_status
            }

        cat_list = ["All"] + sorted(list(categories))
        current_selection = self.category_highlight_var.get()
        self.category_highlight_combo["values"] = cat_list
        if current_selection not in cat_list:
            self.category_highlight_var.set("All")

        self.apply_display_filters()

        if self.total_label:
            total = get_total_value()
            self.total_label.config(text=f"Total Asset Value: ₱{total:,.2f}")

        self.update_status_card()

    def save_item(self):
        if self.role != "admin":
            messagebox.showerror("Permission Denied", "Only administrators can add hardware items.")
            return

        item_name = self.item_name_entry.get()
        category = self.category_entry.get()
        quantity = self.quantity_entry.get()
        price = self.price_entry.get()

        success, message = add_hardware(item_name, category, quantity, price)
        if success:
            messagebox.showinfo("Success", message)
            self.item_name_entry.delete(0, tk.END)
            self.category_entry.delete(0, tk.END)
            self.quantity_entry.delete(0, tk.END)
            self.price_entry.delete(0, tk.END)
            self.load_inventory()
        else:
            messagebox.showerror("Validation Error", message)

    def open_edit_window(self):
        if self.role != "admin":
            messagebox.showerror("Permission Denied", "Only administrators can edit equipment.")
            return

        if not self.checked_items:
            messagebox.showwarning("Selection Warning", "Please check an item to edit.")
            return

        if len(self.checked_items) > 1:
            messagebox.showwarning("Selection Warning", "Please select only one item to edit at a time.")
            return

        item_id = next(iter(self.checked_items))
        data = self.hardware_cache.get(item_id)
        if not data:
            return

        item_name = data["item_name"]
        current_qty = data["quantity"]
        current_price = data["unit_price"]

        edit_win = tk.Toplevel(self.root)
        edit_win.title(f"Edit Item: {item_name}")
        edit_win.geometry("320x270")
        edit_win.resizable(False, False)
        edit_win.grab_set()

        tk.Label(edit_win, text=f"Updating: {item_name}", font=("Arial", 12, "bold")).pack(pady=(15, 10))

        tk.Label(edit_win, text="New Quantity:").pack()
        qty_entry = tk.Entry(edit_win, width=20)
        qty_entry.insert(0, str(current_qty))
        qty_entry.pack(pady=5)

        tk.Label(edit_win, text="New Price (₱):").pack()
        price_entry = tk.Entry(edit_win, width=20)
        price_entry.insert(0, str(current_price))
        price_entry.pack(pady=5)

        def save_changes():
            success, msg = update_hardware(item_id, qty_entry.get(), price_entry.get())
            if success:
                messagebox.showinfo("Update Successful", msg, parent=edit_win)
                edit_win.destroy()
                self.load_inventory()
            else:
                messagebox.showerror("Update Error", msg, parent=edit_win)

        tk.Button(edit_win, text="Save Changes", command=save_changes, bg="green", fg="white", width=15).pack(pady=15)

    def delete_selected_item(self):
        if self.role != "admin":
            messagebox.showerror("Permission Denied", "Only administrators can delete equipment.")
            return

        if not self.checked_items:
            messagebox.showwarning("Selection Warning", "Please check at least one item to delete.")
            return

        items_to_del = list(self.checked_items)
        for item_id in items_to_del:
            item_name = self.hardware_cache.get(item_id, {}).get("item_name", "Item")

            confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{item_name}'?")
            if not confirm:
                continue

            success, msg = delete_hardware(item_id)
            if not success:
                messagebox.showerror("Error", msg)
                break
            else:
                self.checked_items.remove(item_id)

        self.load_inventory()

    def open_borrow_window(self, override_items=None):
        if override_items:
            items_to_borrow = override_items
        else:
            if not self.checked_items:
                messagebox.showwarning("Selection Required", "Please check at least one item to borrow.")
                return

            items_to_borrow = []
            for item_id in self.checked_items:
                data = self.hardware_cache.get(item_id)
                if not data:
                    continue

                if data["quantity"] <= 0 or data["equipment_status"] == "Unavailable":
                    messagebox.showerror("Equipment Unavailable", f"'{data['item_name']}' is out of stock and Unavailable.")
                    return

                if data["equipment_status"] in ["Under Maintenance", "Damaged"]:
                    messagebox.showerror("Equipment Unavailable", f"'{data['item_name']}' is currently {data['equipment_status']}.")
                    return

                items_to_borrow.append((item_id, data["item_name"], data["quantity"]))

        borrow_win = tk.Toplevel(self.root)
        borrow_win.title("Borrow / Schedule Equipment")
        borrow_win.geometry("500x520")
        borrow_win.resizable(True, True)
        borrow_win.grab_set()

        tk.Label(borrow_win, text="Borrow / Schedule Equipment", font=("Arial", 14, "bold")).pack(pady=10)

        items_frame = tk.LabelFrame(borrow_win, text="Selected Equipment", padx=10, pady=10)
        items_frame.pack(fill="both", expand=True, padx=15, pady=5)

        canvas = tk.Canvas(items_frame)
        scroll = ttk.Scrollbar(items_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        qty_entries = {}
        for row_idx, item_data in enumerate(items_to_borrow):
            i_id = item_data[0]
            i_name = item_data[1]
            i_qty = item_data[2]
            default_q = item_data[3] if len(item_data) > 3 else 1

            tk.Label(scrollable_frame, text=f"{i_name} (Avail: {i_qty}):", font=("Arial", 9, "bold")).grid(row=row_idx, column=0, sticky="w", pady=4, padx=5)
            q_ent = tk.Entry(scrollable_frame, width=8)
            q_ent.insert(0, str(default_q))
            q_ent.grid(row=row_idx, column=1, sticky="w", pady=4, padx=5)
            qty_entries[i_id] = q_ent

        sched_frame = tk.Frame(borrow_win, padx=15, pady=5)
        sched_frame.pack(fill="x")

        tk.Label(sched_frame, text="Start Date/Time:").grid(row=0, column=0, sticky="w", pady=3)
        start_entry = tk.Entry(sched_frame, width=24)
        start_entry.insert(0, datetime.now().strftime("%Y-%m-%d %H:%M"))
        start_entry.grid(row=0, column=1, sticky="w", pady=3, padx=5)

        tk.Label(sched_frame, text="End Date/Time:").grid(row=1, column=0, sticky="w", pady=3)
        end_entry = tk.Entry(sched_frame, width=24)
        end_entry.insert(0, datetime.now().strftime("%Y-%m-%d 17:00"))
        end_entry.grid(row=1, column=1, sticky="w", pady=3, padx=5)

        tk.Label(borrow_win, text="Format: YYYY-MM-DD HH:MM", font=("Arial", 8), fg="gray").pack()

        def schedule():
            start_dt = start_entry.get().strip()
            end_dt = end_entry.get().strip()

            borrow_requests = []
            for item_data in items_to_borrow:
                item_id, name, avail_qty = item_data[0], item_data[1], item_data[2]
                val = qty_entries[item_id].get().strip()
                try:
                    q = int(val)
                    if q <= 0:
                        raise ValueError()
                except ValueError:
                    messagebox.showerror("Invalid Quantity", f"Please enter a valid positive quantity for '{name}'.", parent=borrow_win)
                    return
                borrow_requests.append((item_id, name, q))

            for item_id, name, q in borrow_requests:
                success, msg = create_borrowing(self.username, item_id, q, start_dt, end_dt, self.role)
                if not success:
                    messagebox.showerror("Borrowing Error", msg, parent=borrow_win)
                    self.load_inventory()
                    return

            success_msg = "Successfully scheduled item(s)!" if self.role == "admin" else "Request submitted! Waiting for Admin approval."
            messagebox.showinfo("Success", success_msg, parent=borrow_win)
            borrow_win.destroy()
            self.clear_all_checkboxes()
            self.load_inventory()

        btn_text = "CONFIRM SCHEDULE" if self.role == "admin" else "SUBMIT REQUEST FOR APPROVAL"
        tk.Button(borrow_win, text=btn_text, command=schedule, bg="green", fg="white", font=("Arial", 10, "bold"), pady=4).pack(pady=10)

    # --------------------------------------------------------
    # SAVE KIT DIALOG & KIT MANAGEMENT
    # --------------------------------------------------------

    def open_save_kit_dialog(self):
        if not self.checked_items:
            messagebox.showwarning("Selection Required", "Please check at least one item to include in your Kit.")
            return

        kit_win = tk.Toplevel(self.root)
        kit_win.title("Save Items as a Kit")
        kit_win.geometry("450x460")
        kit_win.resizable(False, False)
        kit_win.grab_set()

        tk.Label(kit_win, text="Save Selected Items as a Kit", font=("Arial", 14, "bold")).pack(pady=10)

        name_frame = tk.Frame(kit_win, padx=15, pady=5)
        name_frame.pack(fill="x")
        tk.Label(name_frame, text="Kit Name:", font=("Arial", 10, "bold")).pack(side="left")
        kit_name_entry = tk.Entry(name_frame, width=28, font=("Arial", 10))
        kit_name_entry.pack(side="left", padx=10)
        kit_name_entry.focus()

        # Dedicated bottom frame packed FIRST so it stays pinned and visible
        bottom_frame = tk.Frame(kit_win, pady=10)
        bottom_frame.pack(side="bottom", fill="x")

        items_frame = tk.LabelFrame(kit_win, text="Kit Items & Default Quantities", padx=10, pady=10)
        items_frame.pack(fill="both", expand=True, padx=15, pady=5)

        canvas = tk.Canvas(items_frame)
        scroll = ttk.Scrollbar(items_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        kit_entries = {}
        for row_idx, item_id in enumerate(self.checked_items):
            data = self.hardware_cache.get(item_id)
            if not data:
                continue
            tk.Label(scrollable_frame, text=f"{data['item_name']}:", font=("Arial", 9, "bold")).grid(row=row_idx, column=0, sticky="w", pady=4, padx=5)
            q_ent = tk.Entry(scrollable_frame, width=6)
            q_ent.insert(0, "1")
            q_ent.grid(row=row_idx, column=1, sticky="w", pady=4, padx=5)
            kit_entries[item_id] = q_ent

        def save_kit():
            k_name = kit_name_entry.get().strip()
            if not k_name:
                messagebox.showerror("Invalid Name", "Please enter a kit name.", parent=kit_win)
                return

            item_qtys = {}
            for item_id, q_ent in kit_entries.items():
                val = q_ent.get().strip()
                try:
                    q = int(val)
                    if q <= 0:
                        raise ValueError()
                except ValueError:
                    name = self.hardware_cache.get(item_id, {}).get("item_name", "Item")
                    messagebox.showerror("Invalid Quantity", f"Please enter a valid positive number for '{name}'.", parent=kit_win)
                    return
                item_qtys[item_id] = q

            success, msg = save_kit_for_user(self.username, k_name, item_qtys)
            if success:
                messagebox.showinfo("Success", msg, parent=kit_win)
                kit_win.destroy()
            else:
                messagebox.showerror("Error", msg, parent=kit_win)

        tk.Button(bottom_frame, text="SAVE KIT", command=save_kit, bg="green", fg="white", font=("Arial", 10, "bold"), width=16).pack()

    def open_kits_window(self):
        kits_win = tk.Toplevel(self.root)
        kits_win.title("My Saved Kits")
        kits_win.geometry("800x480")
        kits_win.grab_set()

        tk.Label(kits_win, text=f"{self.username}'s Hardware Kits", font=("Arial", 14, "bold")).pack(pady=10)

        paned = ttk.PanedWindow(kits_win, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=15, pady=5)

        # Left: List of kits
        left_frame = tk.LabelFrame(paned, text="Saved Kits", padx=5, pady=5)
        paned.add(left_frame, weight=1)

        kit_tree = ttk.Treeview(left_frame, columns=("ID", "Kit Name", "Items Count"), show="headings")
        kit_tree.heading("ID", text="ID")
        kit_tree.heading("Kit Name", text="Kit Name")
        kit_tree.heading("Items Count", text="Items")
        kit_tree.column("ID", width=40, anchor="center")
        kit_tree.column("Kit Name", width=160)
        kit_tree.column("Items Count", width=60, anchor="center")
        kit_tree.pack(fill="both", expand=True)

        # Right: Items in selected kit
        right_frame = tk.LabelFrame(paned, text="Items in Selected Kit", padx=5, pady=5)
        paned.add(right_frame, weight=2)

        item_tree = ttk.Treeview(right_frame, columns=("Item", "Category", "Kit Qty", "In Stock", "Status"), show="headings")
        item_tree.heading("Item", text="Item Name")
        item_tree.heading("Category", text="Category")
        item_tree.heading("Kit Qty", text="Kit Qty")
        item_tree.heading("In Stock", text="Available")
        item_tree.heading("Status", text="Status")
        item_tree.column("Item", width=140)
        item_tree.column("Category", width=90)
        item_tree.column("Kit Qty", width=60, anchor="center")
        item_tree.column("In Stock", width=60, anchor="center")
        item_tree.column("Status", width=90, anchor="center")
        item_tree.pack(fill="both", expand=True)

        def refresh_kits_list():
            for item in kit_tree.get_children():
                kit_tree.delete(item)
            for item in item_tree.get_children():
                item_tree.delete(item)

            kits = get_user_kits(self.username)
            for k in kits:
                kit_tree.insert("", "end", values=(k[0], k[1], k[2]))

        def on_kit_select(event):
            sel = kit_tree.selection()
            for item in item_tree.get_children():
                item_tree.delete(item)

            if not sel:
                return

            kit_id = int(kit_tree.item(sel[0], "values")[0])
            details = get_kit_items_details(kit_id)
            for row in details:
                # row: (item_id, item_name, category, kit_qty, stock_qty, equipment_status)
                item_tree.insert("", "end", values=(row[1], row[2], row[3], row[4], row[5]))

        kit_tree.bind("<<TreeviewSelect>>", on_kit_select)
        refresh_kits_list()

        btn_frame = tk.Frame(kits_win, padx=15, pady=10)
        btn_frame.pack(fill="x")

        def borrow_entire_kit():
            sel = kit_tree.selection()
            if not sel:
                messagebox.showwarning("Selection Required", "Please select a kit to borrow.", parent=kits_win)
                return

            kit_id = int(kit_tree.item(sel[0], "values")[0])
            details = get_kit_items_details(kit_id)
            if not details:
                messagebox.showwarning("Empty Kit", "This kit contains no items.", parent=kits_win)
                return

            override_list = []
            for row in details:
                item_id, i_name, _, kit_qty, stock_qty, eq_status = row
                if stock_qty <= 0 or eq_status == "Unavailable":
                    messagebox.showerror("Kit Unavailable", f"'{i_name}' in this kit is out of stock.", parent=kits_win)
                    return
                override_list.append((item_id, i_name, stock_qty, kit_qty))

            kits_win.destroy()
            self.open_borrow_window(override_items=override_list)

        def delete_kit_action():
            sel = kit_tree.selection()
            if not sel:
                messagebox.showwarning("Selection Required", "Please select a kit to delete.", parent=kits_win)
                return

            k_id = int(kit_tree.item(sel[0], "values")[0])
            k_name = kit_tree.item(sel[0], "values")[1]

            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete kit '{k_name}'?", parent=kits_win):
                delete_user_kit(k_id)
                refresh_kits_list()

        tk.Button(btn_frame, text="BORROW THIS ENTIRE KIT", command=borrow_entire_kit, bg="green", fg="white", font=("Arial", 10, "bold"), width=25).pack(side="left", padx=5)
        tk.Button(btn_frame, text="DELETE KIT", command=delete_kit_action, bg="darkred", fg="white", width=15).pack(side="left", padx=5)

    def open_my_borrowings(self):
        borrow_win = tk.Toplevel(self.root)
        borrow_win.title("My Borrowings")
        borrow_win.geometry("800x450")

        tk.Label(borrow_win, text=f"{self.username}'s Borrowing Schedule", font=("Arial", 14, "bold")).pack(pady=10)

        columns = ("ID", "Equipment", "Qty", "Start", "End", "Status")
        tree = ttk.Treeview(borrow_win, columns=columns, show="headings")

        for column in columns:
            tree.heading(column, text=column)

        tree.column("ID", width=50)
        tree.column("Equipment", width=200)
        tree.column("Qty", width=60)
        tree.column("Start", width=150)
        tree.column("End", width=150)
        tree.column("Status", width=120)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        rows = get_user_borrowings(self.username)
        for row in rows:
            tree.insert("", "end", values=row)

    def open_requests_window(self):
        if self.role != "admin":
            messagebox.showerror("Access Denied", "Only administrators can review requests.")
            return

        req_win = tk.Toplevel(self.root)
        req_win.title("Manage Borrow Requests (Admin)")
        req_win.geometry("900x480")
        req_win.grab_set()

        tk.Label(req_win, text="Pending User Borrow Requests", font=("Arial", 14, "bold")).pack(pady=10)

        columns = ("Req ID", "User", "Equipment", "Qty", "Start", "End", "Status")
        tree = ttk.Treeview(req_win, columns=columns, show="headings")

        for col in columns:
            tree.heading(col, text=col)

        tree.column("Req ID", width=60, anchor="center")
        tree.column("User", width=120)
        tree.column("Equipment", width=180)
        tree.column("Qty", width=60, anchor="center")
        tree.column("Start", width=150)
        tree.column("End", width=150)
        tree.column("Status", width=120, anchor="center")
        tree.pack(fill="both", expand=True, padx=15, pady=5)

        def refresh_requests():
            for item in tree.get_children():
                tree.delete(item)
            pending = get_all_pending_borrowings()
            for r in pending:
                tree.insert("", "end", values=r[:7])

        refresh_requests()

        btn_frame = tk.Frame(req_win)
        btn_frame.pack(fill="x", padx=15, pady=12)

        def handle_action(approve=True):
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Selection Required", "Please select a request to process.", parent=req_win)
                return

            req_id = int(tree.item(sel[0], "values")[0])
            success, msg = process_borrowing_request(req_id, approve=approve)
            if success:
                messagebox.showinfo("Success", msg, parent=req_win)
                refresh_requests()
                self.load_inventory()
            else:
                messagebox.showerror("Error", msg, parent=req_win)

        tk.Button(
            btn_frame, 
            text="APPROVE REQUEST", 
            command=lambda: handle_action(True), 
            bg="green", 
            fg="white", 
            font=("Arial", 10, "bold"), 
            width=20
        ).pack(side="left", padx=10)

        tk.Button(
            btn_frame, 
            text="REJECT REQUEST", 
            command=lambda: handle_action(False), 
            bg="red", 
            fg="white", 
            font=("Arial", 10, "bold"), 
            width=20
        ).pack(side="left", padx=10)

        tk.Button(
            btn_frame, 
            text="REFRESH", 
            command=refresh_requests, 
            width=12
        ).pack(side="right", padx=10)

    def open_saved_items(self):
        saved_win = tk.Toplevel(self.root)
        saved_win.title("My Saved Equipment")
        saved_win.geometry("700x450")

        tk.Label(saved_win, text=f"{self.username}'s Saved Equipment", font=("Arial", 14, "bold")).pack(pady=10)
        tk.Label(saved_win, text="Previously borrowed equipment is automatically saved here.", fg="gray").pack()

        columns = ("ID", "Equipment", "Category", "Quantity", "Status")
        tree = ttk.Treeview(saved_win, columns=columns, show="headings")

        for column in columns:
            tree.heading(column, text=column)

        tree.column("ID", width=50)
        tree.column("Equipment", width=200)
        tree.column("Category", width=120)
        tree.column("Quantity", width=80)
        tree.column("Status", width=150)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        rows = get_saved_items(self.username)
        for row in rows:
            tree.insert("", "end", values=row)

        def borrow_saved():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Selection Required", "Select saved equipment first.", parent=saved_win)
                return

            item_id = int(tree.item(selected[0], "values")[0])
            saved_win.destroy()
            self.checked_items = {item_id}
            self.load_inventory()
            self.open_borrow_window()

        def remove_saved():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Selection Required", "Select an item to remove.", parent=saved_win)
                return

            item_id = int(tree.item(selected[0], "values")[0])
            success = remove_saved_item(self.username, item_id)
            if success:
                tree.delete(selected[0])
                messagebox.showinfo("Removed", "Equipment removed from your saved list.", parent=saved_win)

        button_frame = tk.Frame(saved_win)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Borrow / Schedule", command=borrow_saved, bg="green", fg="white", width=20).pack(side="left", padx=5)
        tk.Button(button_frame, text="Remove Saved", command=remove_saved, bg="darkred", fg="white", width=20).pack(side="left", padx=5)

    def export_csv(self):
        rows = get_all_hardware()
        filename = "inventory_report.csv"

        try:
            with open(filename, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["ID", "Name", "Category", "Qty", "Price (P)", "Stock Status", "Equipment Status"])
                for row in rows:
                    writer.writerow(row)

            logger.info(f"Inventory report generated: {filename}")
            messagebox.showinfo("Export Complete", f"Inventory exported successfully to:\n{filename}")
        except Exception as e:
            logger.error(f"CSV export error: {e}")
            messagebox.showerror("Export Error", "Failed to generate CSV report.")

    def logout(self):
        confirm = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if confirm:
            logger.info(f"User logged out: {self.username}")
            self.logout_callback()


# ============================================================
# MAIN
# ============================================================

def main():
    initialize_database()
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    main()