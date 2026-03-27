from flask import Flask, request, jsonify, render_template
import psycopg2
import os

app = Flask(__name__)

# Fetch the database connection string from environment variables
DB_CONN = os.getenv("DB_CONN")

def get_db_connection():
    return psycopg2.connect(DB_CONN)

# Initialize the database table with the exact columns the Terminal UI needs
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

@app.route("/")
def home():
    # Serves the Terminal UI
    return render_template("index.html")

@app.route("/todos", methods=["GET"])
def get_todos():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, text, done FROM terminal_tasks ORDER BY created_at DESC")
    data = cursor.fetchall()
    
    tasks = [{"id": row[0], "text": row[1], "done": row[2]} for row in data]
        
    cursor.close()
    conn.close()
    return jsonify(tasks)

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
    # Flips the boolean state of 'done'
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
    app.run(host="0.0.0.0", port=80)