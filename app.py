from flask import Flask
from flask_restx import Api, Resource  # Api 구현을 위한 Api 객체 import
from flask_cors import CORS, cross_origin
import pprint

import openstack as openstack


def create_app():
    app = Flask(__name__)

    CORS(app)

    api = Api(app)  # Flask 객체에 Api 객체 등록

    from hello import namespace as test

    api.add_namespace(test, '/')

    return app
