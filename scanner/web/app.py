"""Flask web application factory."""
from flask import Flask
from flask_cors import CORS

from scanner.monitoring.history import ScanHistory


def create_app(db_path: str = "scanner.db", testing: bool = False) -> Flask:
    """Application factory."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "change-me-in-production"
    app.config["DB_PATH"] = db_path
    app.config["TESTING"] = testing

    CORS(app)

    # Initialize scan history
    history = ScanHistory(db_path=db_path)
    app.config["SCAN_HISTORY"] = history

    # Register blueprints
    from scanner.web.api import api_bp
    from scanner.web.views import views_bp

    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(views_bp)

    return app
