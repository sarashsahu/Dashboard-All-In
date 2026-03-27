from flask import Flask, request, jsonify, render_template
import psycopg2
import os
import time
import psutil
from collections import deque

app = Flask(__name__)

DB_CONN = os.getenv("DB_CONN", "dbname=postgres user=postgres password=postgres host=localhost")

# --- SERVER METRICS TRACKING ---
SERVER_START_TIME = time.time()
traffic_history = deque(maxlen=1000)  # Store timestamps of recent requests
threat_counters = {"4xx": 0, "5xx": 0, "suspicious_paths": 0}

def get_db_connection():
    return psycopg2.connect(DB_CONN)

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS terminal_tasks (
                id SERIAL PRIMARY KEY,
                text VARCHAR(255) NOT NULL,
                done BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Database connection error: {e}")

# Intercept every request to calculate live traffic and basic threats
@app.before_request
def track_metrics():
    traffic_history.append(time.time())
    
    # Basic Threat Detection Simulation (Looking for common malicious paths)
    suspicious_keywords = ['<script>', 'UNION SELECT', 'admin.php', '.env']
    if any(keyword in request.url for keyword in suspicious_keywords):
        threat_counters["suspicious_paths"] += 10 # Spike the threat meter

@app.after_request
def track_errors(response):
    if 400 <= response.status_code < 500:
        threat_counters["4xx"] += 1
    elif response.status_code >= 500:
        threat_counters["5xx"] += 1
    return response

# --- ROUTES ---

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    now = time.time()
    
    # 1. Uptime
    uptime_seconds = now - SERVER_START_TIME
    
    # 2. Hardware Resources
    cpu_usage = psutil.cpu_percent(interval=None) # Non-blocking
    ram_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    
    # 3. Live Traffic (Requests in the last 2 seconds)
    recent_requests = sum(1 for t in traffic_history if now - t <= 2.0)
    requests_per_second = recent_requests / 2.0 if recent_requests > 0 else 0

    # 4. Threat Analysis (Translating errors to radar chart metrics 0-100)
    # This maps to: ['DDoS', 'XSS', 'SQLi', 'Brute']
    ddos_risk = min((requests_per_second * 2), 100) # High RPS spikes DDoS metric
    xss_risk = min(threat_counters["suspicious_paths"], 100) 
    sqli_risk = min(threat_counters["5xx"] * 5, 100) # Server errors map to SQLi risk
    brute_risk = min(threat_counters["4xx"] * 2, 100) # 401/403/404s map to Brute force risk
    
    # Gradually cool down threats over time so the chart doesn't stay pegged at 100
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
        data = cursor.fetchall()
        tasks = [{"id": row[0], "text": row[1], "done": row[2]} for row in data]
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

if __name__ == '__main__':
    init_db() 
    # Initialize CPU percentage baseline
    psutil.cpu_percent(interval=0.1) 
    app.run(host="0.0.0.0", port=80, threaded=True)