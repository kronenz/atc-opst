from flask import Flask
from flask_restx import Api  # Api 구현을 위한 Api 객체 import
from flask_cors import CORS
import openstack as openstack

# openstack.enable_logging(debug=True)
openstack.enable_logging()

def create_app():
    app = Flask(__name__)

    app.sdk_connection = openstack.connect(cloud='admin')

    CORS(app)

    api = Api(app)  # Flask 객체에 Api 객체 등록

    from controller.hello import namespace as hello

    api.add_namespace(hello, '/')


    from controller.autoscaling import namespace as autoscaling

    api.add_namespace(autoscaling, '/api')

    return app
