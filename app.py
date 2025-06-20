from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
import sqlite3
import subprocess
import requests
import json
import logging
from datetime import datetime, timedelta
import warnings
from urllib3.exceptions import NotOpenSSLWarning

warnings.filterwarnings("ignore", category=NotOpenSSLWarning)

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
logging.basicConfig(level=logging.INFO)


def get_db():
    conn = sqlite3.connect('healthagent.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT NOT NULL,
            items TEXT,
            calories REAL,
            protein REAL,
            fat REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mood_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT NOT NULL,
            mood TEXT,
            energy_level INTEGER,
            sleep_quality INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                    (data["username"], bcrypt.generate_password_hash(data["password"]).decode('utf-8')))
        conn.commit()
        return jsonify(message="User registered"), 201
    except sqlite3.IntegrityError:
        return jsonify(message="Username exists"), 409
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, password FROM users WHERE username = ?", (data["username"],))
    user = cur.fetchone()
    conn.close()
    if user and bcrypt.check_password_hash(user["password"], data["password"]):
        token = create_access_token(identity=str(user["id"]), expires_delta=timedelta(days=1))
        return jsonify(token=token)
    return jsonify(message="Invalid credentials"), 401


@app.route("/log-agent", methods=["POST"])
@jwt_required()
def log_agent():
    user_id = get_jwt_identity()
    text = request.json.get("text")
    date = request.json.get("date", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    classify_prompt = f"Classify the following text as 'food', 'mood', or 'both':\nText: \"{text}\"\nRespond with a single word: food, mood, or both"
    try:
        result = subprocess.run(["ollama", "run", "mistral", classify_prompt], capture_output=True, text=True)
        classification = result.stdout.strip().lower()
        logging.info(f"[AI Classification] → {classification}")
    except Exception as e:
        logging.warning(f"Classification failed: {e}")
        classification = "unknown"

    response = {"classification": classification}

    if classification == "both":
        logging.info("[Trigger] → Logging both mood and food")
        response["mood_log"] = log_mood_internal(user_id, text, date)
        response["food_log"] = log_food_internal(user_id, text, date)
    elif classification == "food":
        logging.info("[Trigger] → Logging food")
        response["food_log"] = log_food_internal(user_id, text, date)
    elif classification == "mood":
        logging.info("[Trigger] → Logging mood")
        response["mood_log"] = log_mood_internal(user_id, text, date)

    return jsonify(response)


def log_food_internal(user_id, text, date):
    prompt = f"""Extract food items and quantity (value can be in number or weight e.g. 2, 50gm) from this input and return JSON:
Text: \"{text}\"
Format:
[
  {{ "item": "food name", "quantity": number }}
]"""
    try:
        result = subprocess.run(["ollama", "run", "mistral", prompt], capture_output=True, text=True)
        parsed_json = json.loads(result.stdout[result.stdout.find('['):result.stdout.rfind(']') + 1])
    except Exception as e:
        logging.warning(f"AI fallback for food parsing: {e}")
        parsed_json = []

    total = {"calories": 0, "protein": 0, "fat": 0}
    items = []
    for food in parsed_json:
        item = food["item"]
        qty = food.get("quantity", 1)
        nutri = fetch_nutrition(item)
        if nutri:
            items.append(f"{qty} x {nutri['description']}")
            total["calories"] += nutri["calories"] * qty
            total["protein"] += nutri["protein"] * qty
            total["fat"] += nutri["fat"] * qty

    if items:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO logs (user_id, date, items, calories, protein, fat)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, date, ', '.join(items), total["calories"], total["protein"], total["fat"]))
        conn.commit()
        conn.close()
        logging.info(f"Food log saved: {items}")
    return total


def log_mood_internal(user_id, text, date):
    prompt = f"Analyze mood, energy level (1–10), and sleep quality (1–10):\nText: \"{text}\"\nFormat:\n{{ \"mood\": \"tired\", \"energy_level\": 3, \"sleep_quality\": 4 }}"
    try:
        result = subprocess.run(["ollama", "run", "mistral", prompt], capture_output=True, text=True)
        mood_json = json.loads(result.stdout[result.stdout.find('{'):result.stdout.rfind('}') + 1])
    except Exception as e:
        logging.warning(f"AI Mood fallback: {e}")
        mood_json = {}

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO mood_logs (user_id, date, mood, energy_level, sleep_quality) VALUES (?, ?, ?, ?, ?)",
                (user_id, date, mood_json.get("mood"), mood_json.get("energy_level"), mood_json.get("sleep_quality")))
    conn.commit()
    conn.close()
    return mood_json


@app.route("/summary", methods=["GET"])
@jwt_required()
def summary():
    user_id = get_jwt_identity()
    conn = get_db()
    rows = conn.execute("SELECT date, items, calories, protein, fat FROM logs WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/recommend", methods=["GET"])
@jwt_required()
def recommend():
    user_id = get_jwt_identity()
    conn = get_db()
    logs = conn.execute("SELECT * FROM logs WHERE user_id = ? ORDER BY date DESC LIMIT 1", (user_id,)).fetchone()
    mood = conn.execute("SELECT * FROM mood_logs WHERE user_id = ? ORDER BY date DESC LIMIT 1", (user_id,)).fetchone()
    conn.close()

    suggestions = []
    if logs and logs["protein"] < 20:
        suggestions.append("Consider increasing protein intake with eggs, tofu, or legumes.")
    if mood and mood["energy_level"] and mood["energy_level"] < 5:
        suggestions.append("Low energy detected — consider light exercise or better sleep.")

    return jsonify(recommendations=suggestions or ["You're on track! Keep going."])


@app.route("/debug/logs", methods=["GET"])
@jwt_required()
def debug_logs():
    user_id = get_jwt_identity()
    conn = get_db()
    cur = conn.cursor()

    logs = []

    cur.execute("""
        SELECT id, date, items, calories, protein, fat
        FROM logs
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 10
    """, (user_id,))
    for row in cur.fetchall():
        logs.append({
            "timestamp": row["date"],
            "type": "food",
            "items": row["items"],
            "calories": row["calories"],
            "protein": row["protein"],
            "fat": row["fat"]
        })

    cur.execute("""
        SELECT id, date, mood, energy_level, sleep_quality
        FROM mood_logs
        WHERE user_id = ?
        ORDER BY id DESC LIMIT 10
    """, (user_id,))
    for row in cur.fetchall():
        if row["mood"] or row["energy_level"] or row["sleep_quality"]:
            logs.append({
                "timestamp": row["date"],
                "type": "mood",
                "mood": row["mood"],
                "energy_level": row["energy_level"],
                "sleep_quality": row["sleep_quality"]
            })

    logs = sorted(logs, key=lambda x: x["timestamp"], reverse=True)
    conn.close()
    return jsonify({"logs": logs})


def fetch_nutrition(query):
    try:
        url = f"https://api.nal.usda.gov/fdc/v1/foods/search?query={query}&pageSize=1&api_key=M1ZqpLNMxjKWPncj3cg4Q11fIeZKcPkrEssvHPZ1"
        res = requests.get(url)
        data = res.json()
        if "foods" in data and data["foods"]:
            food = data["foods"][0]
            nutrients = {n["nutrientName"]: n["value"] for n in food["foodNutrients"]}
            return {
                "description": food["description"],
                "calories": nutrients.get("Energy", 0),
                "protein": nutrients.get("Protein", 0),
                "fat": nutrients.get("Total lipid (fat)", 0)
            }
    except Exception as e:
        logging.error(f"USDA API error: {e}")
    return None


if __name__ == "__main__":
    init_db()
    app.run(debug=True)