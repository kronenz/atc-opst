from flask import Flask
from flask_restx import Api  # Api 구현을 위한 Api 객체 import
from flask_cors import CORS


def create_app():
    app = Flask(__name__)

    CORS(app)

    api = Api(app)  # Flask 객체에 Api 객체 등록

    from controller.hello import namespace as hello

    api.add_namespace(hello, '/')

    return app
