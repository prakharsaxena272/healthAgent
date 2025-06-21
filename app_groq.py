# Improved version with timestamp support, better classification reliability, and full logging

import os
import json
import sqlite3
import logging
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

app = Flask(__name__)
CORS(app)  # ✅ Add this lin
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
            time TEXT NOT NULL,
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
            time TEXT NOT NULL,
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

# Add missing endpoints to support /summary and /debug/logs

@app.route("/summary", methods=["GET"])
@jwt_required()
def summary():
    user_id = get_jwt_identity()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT date, time, items, calories, protein, fat
        FROM logs
        WHERE user_id = ?
        ORDER BY date DESC, time DESC
    """, (user_id,))
    food_logs = [dict(row) for row in cur.fetchall()]

    cur.execute("""
        SELECT date, time, mood, energy_level, sleep_quality
        FROM mood_logs
        WHERE user_id = ?
        ORDER BY date DESC, time DESC
    """, (user_id,))
    mood_logs = [dict(row) for row in cur.fetchall()]
    conn.close()

    return jsonify({"food_logs": food_logs, "mood_logs": mood_logs})


@app.route("/debug/logs", methods=["GET"])
@jwt_required()
def debug_logs():
    user_id = get_jwt_identity()
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    """, (user_id,))
    food = [dict(row) for row in cur.fetchall()]

    cur.execute("""
        SELECT * FROM mood_logs
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    """, (user_id,))
    mood = [dict(row) for row in cur.fetchall()]
    conn.close()

    return jsonify({"recent_food_logs": food, "recent_mood_logs": mood})
@app.route("/log-agent", methods=["POST"])
@jwt_required()
def log_agent():
    user_id = get_jwt_identity()
    text = request.json.get("text")
    date = datetime.now().strftime('%Y-%m-%d')
    time = datetime.now().strftime('%H:%M:%S')

    # 1. CLASSIFICATION
    classify_prompt = f"Classify the text into one of: food, mood, both, nothing , basis what end user is eating or doing fron=m his text message . \nText: {text}\nRespond with a single word."
    classification = call_groq(classify_prompt).strip().lower().split()[0]

    # 2. FRIENDLY RESPONSE
    reply_prompt = f"You're a friendly AI health coach. Reply to this user input with a warm, engaging sentence.\nInput: {text}"
    ai_chat_response = call_groq(reply_prompt).strip()

    logging.info(f"[CLASSIFICATION] → {classification}")
    logging.info(f"[AI-RESPONSE] → {ai_chat_response}")

    response = {
        "classification": classification,
        "timestamp": f"{date} {time}",
        "response_message": ai_chat_response
    }

    # 3. INTERNAL LOGGING
    if classification == "both":
        response["mood_log"] = log_mood_internal(user_id, text, date, time)
        response["food_log"] = log_food_internal(user_id, text, date, time)
    elif classification == "food":
        response["food_log"] = log_food_internal(user_id, text, date, time)
    elif classification == "mood":
        response["mood_log"] = log_mood_internal(user_id, text, date, time)

    return jsonify(response)

def log_food_internal(user_id, text, date, time):
    prompt = f"Extract food items and quantity (JSON format). Example: [{{\"item\":\"oats\",\"quantity\":1}}]. Text: {text}"
    items_json = call_groq(prompt)
    try:
        parsed = json.loads(items_json[items_json.find('['):items_json.rfind(']') + 1])
    except:
        parsed = []

    total = {"calories": 0, "protein": 0, "fat": 0}
    items = []
    for food in parsed:
        item = food.get("item")
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
            INSERT INTO logs (user_id, date, time, items, calories, protein, fat)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, date, time, ', '.join(items), total["calories"], total["protein"], total["fat"]))
        conn.commit()
        conn.close()
        logging.info(f"[FOOD-LOG] Saved: {items}")

    return items

def log_mood_internal(user_id, text, date, time):
    prompt = f"Extract mood, energy_level (1-10), sleep_quality (1-10) as JSON. Text: {text}"
    mood_json = call_groq(prompt)
    try:
        mood_data = json.loads(mood_json[mood_json.find('{'):mood_json.rfind('}') + 1])
    except:
        mood_data = {}

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO mood_logs (user_id, date, time, mood, energy_level, sleep_quality)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, date, time, mood_data.get("mood"), mood_data.get("energy_level"), mood_data.get("sleep_quality")))
    conn.commit()
    conn.close()
    logging.info(f"[MOOD-LOG] Saved: {mood_data}")
    return mood_data

def call_groq(prompt):
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama3-8b-8192",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 256
    }
    logging.info(f"[GROQ-REQUEST] Prompt: {prompt}")
    try:
        res = requests.post(url, headers=headers, json=payload)
        res.raise_for_status()
        content = res.json()["choices"][0]["message"]["content"]
        logging.info(f"[GROQ-RESPONSE] Content: {content}")
        return content
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"[GROQ-HTTP-ERROR] {http_err.response.status_code} - {http_err.response.text}")
    except Exception as e:
        logging.error(f"[GROQ-API-ERROR] {e}")
    return ""

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
        logging.error(f"[USDA-API-ERROR] {e}")
    return None

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
