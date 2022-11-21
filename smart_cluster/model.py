from flask_restx import fields # Api 구현을 위한 Api 객체 import
from smart_cluster import namespace

model_cluster_profile = namespace.model('Cluster_cluster_profile', {
        'id': fields.String(description='프로파일 식별자'),
        'name': fields.String(description='인스턴스 명칭', required=True),
        'flavor': fields.String(description="프로파일 Flavor's Name", required=True, example='m1.small'),
        'image': fields.String(description="프로파일 Image's Id", required=True),
        'key_name': fields.String(description="프로파일 Keypair's Name", required=True),
        # 'server_group': fields.String(description=""), # 새로 생성
        'security_group': fields.String(description="프로파일 Security Group's Name", required=True)
    })

model_cluster_info = namespace.model('Cluster_cluster', {
        'min_size': fields.Integer(description='클러스터 최소 노드 개수', default=1),
        'max_size': fields.Integer(description='클러스터 최대 노드 개수', default=-1),
        'desired_capacity': fields.Integer(description='클러스터 노드 개수', default=0),
        'profile': fields.Nested(model_cluster_profile, description="클러스터의 프로파일 정보")
    })

model_lb_sp = namespace.model('Cluster_lb_sp', {
        'type': fields.String(required=True, example="[APP_COOKIE, HTTP_COOKIE, SOURCE_IP]"),
        'cookie_name': fields.String(required=False, description="APP_COOKIE일 때, 쿠키명"),
        'persistence_timeout': fields.Integer(required=False, description="SOURCE_IP일 때, 제한시간"),
        'persistence_granularity': fields.String(required=False, description="SOURCE_IP일 때, Netmask")
    })

model_lb_hm = namespace.model('Cluster_lb_hm', {
        'type': fields.String(required=True, description="모니터링 유형",
                              example="[PING,HTTP,TCP,HTTPS,TLS-HELLO,UDP-CONNECT]"),
        'retries_down': fields.Integer(default=3, description="비활성 판단을 위한 시도 횟수"),
        'retries': fields.Integer(default=3, description="활성 판단을 위한 시도 횟수"),
        'delay': fields.Integer(default=5, description="health check 간격 (second)"),
        'timeout': fields.Integer(default=5, description="health check 대기시간 (second)"),
        ### HTTP/HTTPS ###
        'url': fields.String(description="HTTP/HTTPS일 때, health check 요청 URL",
                             required=False),
        'method': fields.String(description="HTTP/HTTPS일 때, health check 요청 Method",
                                example="[GET,POST,DELETE,PUT,HEAD,OPTIONS,PATCH,CONNECT,TRACE]",
                                required=False),
        'expected_codes': fields.String(description="HTTP/HTTPS일 때, 활성 판단할 Status Code",
                                        example="(single) 200 / (multiple) 200,202 / (range) 200-204",
                                        required=False)
    })

model_lb = namespace.model('Cluster_lb', {
        'id': fields.String(description="로드밸런서 식별자", requried=False),
        'pool_id': fields.String(description="Pool 식별자", required=False),
        # openstack floating ip create --floating-ip-address 192.168.53.151 --project vm-autoscaling provider
        'provider_network_id': fields.String(description="Provider Network ID", required=True),
        'provider_subnet_id': fields.String(description="Provider Network Subnet ID", required=True),
        'provider_network_ip': fields.String(description="Fixed Floating IP", required=False),
        'protocol': fields.String(description="Listen Protocol", required=True,
                                  example="[TCP,HTTP,HTTPS,TERMINATED_HTTPS,UDP]"),
        'port': fields.Integer(description="Listen Port 번호 (0-65535)", required=True),
        'connection_limit': fields.Integer(descripiton="연결 제한 수", default=-1),
        'session_persistence': fields.Nested(model_lb_sp, required=False, example="(key=value)",
                                             descripiton="세션 영속성 유지를 위한 정보"),
        'lb_algorithm': fields.String(description="로드밸런서 알고리즘", required=True,
                                      default="ROUND_ROBIN",
                                      example="[SOURCE_IP,ROUND_ROBIN,LEAST_CONNECTIONS,SOURCE_IP_PORT]"),
        'health_monitor': fields.Nested(model_lb_hm, description="Load Balancer의 Health Monitor 정보")
    }, description="Load Balancer 정보")

model_cluster = namespace.model('Cluster', {
    'id': fields.String(description="클러스터 식별자", required=False),
    'name': fields.String(description="클러스터 명칭", required=True),
    # 'description': fields.String(description="클러스터 설명", required=False),
    'project_id': fields.String(description="클러스터를 생성할 프로젝트 ID", required=True),
    'network_id': fields.String(description="클러스터의 Node들이 사용할 네트워크 ID", required=True),
    'subnet_id': fields.String(description="클러스터의 Node들이 사용할 네트워크 서브넷 ID", required=True),
    'cluster': fields.Nested(model_cluster_info, required=True),
    'loadbalancer': fields.Nested(model_lb, required=True)
})

model_asp_scaling = namespace.model('AutoScalingPolicy_Scaling', {
    'type': fields.String(description='number 유형', requried=True, default='CHANGE_IN_CAPACITY',
                          example='[EXACT_CAPACITY, CHANGE_IN_CAPACITY, CHANGE_IN_PERCENTAGE]'),
    'number': fields.Integer(description='Scaling 크기', default=1),
    'min_step': fields.Integer(description='최소 Scaling 크기', default=1),
    'cooldown': fields.Integer(description='Cooldown 시간', default=60),
    'metric': fields.String(description='메트릭', required=True),
    'aggregation_method': fields.String(description='집계 함수', required=True),
    'threshold': fields.Float(description='임계치', required=True),
    'comparison_op': fields.String(description='임계치 비교연산자', required=True,
                                   example="['lt', 'le', 'eq', 'ne', 'ge', 'gt']"),
    'evaluation_period': fields.Integer(description='평가횟수',  default=1),
    'repeat': fields.Boolean(description='반복여부', default=True)
})

model_asp = namespace.model('AutoScalingPolicy', {
    'id': fields.String(description="클러스터 식별자", required=True),
    'scaling_in': fields.Nested(model_asp_scaling, required=True),
    'scaling_out': fields.Nested(model_asp_scaling, required=True)
})