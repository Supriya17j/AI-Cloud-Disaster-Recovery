"""Cyber-Aware Recovery Readiness Assessment - run: python app.py"""
import logging, os
from flask import Flask, render_template
from config.settings import DEMO_MODE, LOG_DIR
from modules.db import init_db
from routes.api import bp

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                    handlers=[logging.FileHandler(os.path.join(LOG_DIR, "app.log")), logging.StreamHandler()])
app = Flask(__name__)
init_db()
app.register_blueprint(bp)

@app.context_processor
def template_settings():
    return {"demo_mode": DEMO_MODE}

@app.route("/")
def dashboard(): return render_template("dashboard.html", active_page="dashboard", page_title="Dashboard")

@app.route("/risk-analysis")
def risk_analysis(): return render_template("risk_analysis.html", active_page="risk", page_title="Risk Analysis")

@app.route("/ai-detection")
def ai_detection(): return render_template("ai_detection.html", active_page="ai", page_title="AI Detection")

@app.route("/recovery")
def recovery_page(): return render_template("recovery.html", active_page="recovery", page_title="Backup & Recovery")

@app.route("/recovery-results")
def recovery_results(): return render_template("recovery_results.html", active_page="results", page_title="Recovery Results")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
