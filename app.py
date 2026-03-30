from flask import Flask, request, jsonify, render_template
import psycopg2
import os
import time
import psutil
from collections import deque
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

DB_CONN = os.getenv("DB_CONN", "dbname=postgres user=postgres password=postgres host=localhost")

# --- SERVER METRICS TRACKING ---
SERVER_START_TIME = time.time()
traffic_history = deque(maxlen=1000)
threat_counters = {"4xx": 0, "5xx": 0, "suspicious_paths": 0}

def get_db_connection():
    return psycopg2.connect(DB_CONN)

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Tasks Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS terminal_tasks (
                id SERIAL PRIMARY KEY,
                text VARCHAR(255) NOT NULL,
                done BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 2. Notes Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS terminal_notes (
                id SERIAL PRIMARY KEY,
                content TEXT DEFAULT ''
            )
        """)
        # Ensure at least one note record exists
        cursor.execute("SELECT COUNT(*) FROM terminal_notes")
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO terminal_notes (content) VALUES ('')")
            
        # 3. Reminders Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS terminal_reminders (
                id SERIAL PRIMARY KEY,
                text VARCHAR(255) NOT NULL,
                alert_time VARCHAR(5) NOT NULL, -- Format HH:MM
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Database connection error: {e}")

@app.before_request
def track_metrics():
    traffic_history.append(time.time())
    suspicious_keywords = ['<script>', 'UNION SELECT', 'admin.php', '.env']
    if any(keyword in request.url for keyword in suspicious_keywords):
        threat_counters["suspicious_paths"] += 10

@app.after_request
def track_errors(response):
    if 400 <= response.status_code < 500:
        threat_counters["4xx"] += 1
    elif response.status_code >= 500:
        threat_counters["5xx"] += 1
    return response

# --- DASHBOARD & METRICS ---

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    now = time.time()
    uptime_seconds = now - SERVER_START_TIME
    cpu_usage = psutil.cpu_percent(interval=None)
    ram_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    
    recent_requests = sum(1 for t in traffic_history if now - t <= 2.0)
    requests_per_second = recent_requests / 2.0 if recent_requests > 0 else 0

    ddos_risk = min((requests_per_second * 2), 100)
    xss_risk = min(threat_counters["suspicious_paths"], 100) 
    sqli_risk = min(threat_counters["5xx"] * 5, 100)
    brute_risk = min(threat_counters["4xx"] * 2, 100)
    
    for key in threat_counters:
        if threat_counters[key] > 0:
            threat_counters[key] *= 0.9 

    return jsonify({
        "uptime": uptime_seconds,
        "hardware": [cpu_usage, ram_usage, disk_usage],
        "traffic": requests_per_second,
        "threats": [ddos_risk, xss_risk, sqli_risk, brute_risk]
    })

# --- TODO LIST ROUTES ---

@app.route("/todos", methods=["GET"])
def get_todos():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, text, done FROM terminal_tasks ORDER BY created_at DESC")
        tasks = [{"id": row[0], "text": row[1], "done": row[2]} for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return jsonify(tasks)
    except:
        return jsonify([])

@app.route("/add", methods=["POST"])
def add():
    task_text = request.json.get("text")
    if task_text:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO terminal_tasks (text, done) VALUES (%s, FALSE)", (task_text,))
        conn.commit()
        cursor.close()
        conn.close()
    return jsonify({"status": "success"})

@app.route("/toggle/<int:task_id>", methods=["POST"])
def toggle(task_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE terminal_tasks SET done = NOT done WHERE id = %s", (task_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/delete/<int:task_id>", methods=["DELETE"])
def delete(task_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM terminal_tasks WHERE id = %s", (task_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/clear_completed", methods=["DELETE"])
def clear_completed():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM terminal_tasks WHERE done = TRUE")
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"status": "success"})

# --- NOTES ROUTES ---

@app.route("/note", methods=["GET", "POST"])
def manage_note():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == "POST":
        content = request.json.get("content", "")
        cursor.execute("UPDATE terminal_notes SET content = %s WHERE id = 1", (content,))
        conn.commit()
        result = {"status": "success"}
    else:
        cursor.execute("SELECT content FROM terminal_notes WHERE id = 1")
        row = cursor.fetchone()
        result = {"content": row[0] if row else ""}
    cursor.close()
    conn.close()
    return jsonify(result)

# --- REMINDERS ROUTES ---

@app.route("/reminders", methods=["GET", "POST"])
def manage_reminders():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == "POST":
        text = request.json.get("text")
        alert_time = request.json.get("time")
        if text and alert_time:
            cursor.execute("INSERT INTO terminal_reminders (text, alert_time) VALUES (%s, %s)", (text, alert_time))
            conn.commit()
        result = {"status": "success"}
    else:
        cursor.execute("SELECT id, text, alert_time FROM terminal_reminders ORDER BY alert_time ASC")
        result = [{"id": row[0], "text": row[1], "time": row[2]} for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return jsonify(result)

@app.route("/reminders/<int:r_id>", methods=["DELETE"])
def delete_reminder(r_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM terminal_reminders WHERE id = %s", (r_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"status": "success"})


if __name__ == '__main__':
    init_db() 
    psutil.cpu_percent(interval=0.1) 
    app.run(host="0.0.0.0", port=80, threaded=True)