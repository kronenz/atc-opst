from flask import request  # 서버 구현을 위한 Flask 객체 import
from flask import current_app
from flask_restx import Namespace, Resource, marshal  # Api 구현을 위한 Api 객체 import
import openstack as openstack

namespace = Namespace('autoscaling')