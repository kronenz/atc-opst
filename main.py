#pip install flask 
#pip install flask_cors
#pip xmltodict

from flask import Flask, request  # 서버 구현을 위한 Flask 객체 import
from flask_restx import Api, Resource  # Api 구현을 위한 Api 객체 import
from flask_cors import CORS, cross_origin

import openstack as openstack
openstack.enable_logging(debug=True)

import pprint
##Flask Setup

pp=pprint.PrettyPrinter()

app = Flask(__name__)  # Flask 객체 선언, 파라미터로 어플리케이션 패키지의 이름을 넣어줌.
CORS(app)
api = Api(app)  # Flask 객체에 Api 객체 등록

@api.route('/hello')  # 데코레이터 이용, '/hello' 경로에 클래스 등록
class HelloWorld(Resource):
    def get(self):  # GET 요청시 리턴 값에 해당 하는 dict를 JSON 형태로 반환
        '''
        설명 첫줄입니다
        + 항목 1 
            - 소항목 2
        '''
        conn = openstack.connect(cloud='admin')
        # project_name = vm-autoscaling
        for server in conn.compute.servers(project_id='925aba3de85a48ccb284bf02edc1c18e'):
            pp.pprint(server.to_dict()['name'])

        return {"hello": "world!"}


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)

