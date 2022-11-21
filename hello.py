from flask import current_app
from flask_restx import Resource, Namespace  # Api 구현을 위한 Api 객체 import
import pprint

pp = pprint.PrettyPrinter()

namespace = Namespace('hello')


@namespace.route('hello')  # 데코레이터 이용, '/hello' 경로에 클래스 등록
class HelloWorld(Resource):
    def get(self):  # GET 요청시 리턴 값에 해당 하는 dict를 JSON 형태로 반환
        '''
        설명 첫줄입니다
        + 항목 1
            - 소항목 2
        '''

        conn = current_app.sdk_connection

        # project_name = vm-autoscaling
        for server in conn.compute.servers(project_id='925aba3de85a48ccb284bf02edc1c18e'):
            pp.pprint(server.to_dict()['name'])

        return {"hello": "world!"}
