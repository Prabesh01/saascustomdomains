from flask import Flask
from myapp.config import Config
from myapp.database import db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        db.create_all()

        from .views import views
        app.register_blueprint(views)

        return app
