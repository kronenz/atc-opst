import pprint

from flask import request  # 서버 구현을 위한 Flask 객체 import
from flask import current_app, g
from flask_restx import Namespace, Resource, fields, marshal, marshal_with  # Api 구현을 위한 Api 객체 import
import openstack
from openstack.exceptions import ResourceNotFound

pp = pprint.PrettyPrinter()

namespace = Namespace(
    name="smart-cluster",
    description="AutoScaling 정책 정의"
)

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
    'description': fields.String(description="클러스터 설명", required=False),
    'project_id': fields.String(description="클러스터를 생성할 프로젝트 ID", required=True),
    'network_id': fields.String(description="클러스터의 Node들이 사용할 네트워크 ID", required=True),
    'subnet_id': fields.String(description="클러스터의 Node들이 사용할 네트워크 서브넷 ID", required=True),
    'cluster': fields.Nested(model_cluster_info, required=True),
    'loadbalancer': fields.Nested(model_lb, required=True)
})

model_as = namespace.model('AutoScalingPolicy', {

})


@namespace.route('/')
class CreateCluster(Resource):
    @namespace.expect(model_cluster, validate=True)
    @namespace.marshal_with(model_cluster, skip_none=True)
    def post(self):
        pp.pprint(request.json)

        req_data = request.json

        data_cluster = req_data['cluster']
        data_cluster_profile = data_cluster['profile']
        data_lb = req_data['loadbalancer']
        data_lb_hm = data_lb['health_monitor']
        data_lb_sp = data_lb['session_persistence']
        conn_admin = current_app.sdk_connection

        lb = None
        server_group = None
        cluster = None
        policy_lb = None
        floating_ip = None

        # TODO: 사용자별 username, password 선택도 가능해야 함.
        with openstack.connect(
                auth_url="http://192.168.15.40:5000/v3",
                project_id=req_data['project_id'],
                username="admin",
                password="1234qwer",
                region_name="RegionOne",
                user_domain_name="default",
                project_domain_name="default",
        ) as conn:
            try:
                cluster_name = req_data['name']

                lb = conn.load_balancer.create_load_balancer(
                    name='%s_lb' % cluster_name,
                    vip_network_id=req_data['network_id']
                )

                conn.load_balancer.wait_for_load_balancer(lb.id)

                lb_listener = conn.load_balancer.create_listener(
                    name='%s_listener' % cluster_name,
                    protocol=data_lb['protocol'],
                    protocol_port=data_lb['port'],
                    connection_limit=data_lb.get('connection_limit', -1),
                    loadbalancer_id=lb.id
                )

                conn.load_balancer.wait_for_load_balancer(lb.id)

                lb_pool = conn.load_balancer.create_pool(
                    name='%s_pool' % cluster_name,
                    protocol=data_lb['protocol'],
                    lb_algorithm=data_lb['lb_algorithm'],
                    session_persistence=data_lb_sp,
                    listener_id=lb_listener.id
                )

                conn.load_balancer.wait_for_load_balancer(lb.id)

                conn.load_balancer.create_health_monitor(
                    name='%s_hm' % cluster_name,
                    type=data_lb_hm['type'],
                    max_retries=data_lb_hm.get('retires', 3),
                    max_retries_down=data_lb_hm.get('retries_down', 3),
                    delay=data_lb_hm.get('delay', 5),
                    timeout=data_lb_hm.get('timeout', 5),
                    url_path=data_lb_hm.get('url'),
                    http_method=data_lb_hm.get('method'),
                    expected_codes=data_lb_hm.get('expected_codes'),
                    pool_id=lb_pool.id
                )

                server_group = conn.compute.create_server_group(
                    name='%s_sg' % cluster_name,
                    policy='soft-anti-affinity'
                )

                profile = conn.clustering.create_profile(
                    name='%s_profile' % cluster_name,
                    spec={
                        'type': 'os.nova.server',
                        'version': 1.0,
                        'properties': {
                            'name': data_cluster_profile['name'],
                            'flavor': data_cluster_profile['flavor'],
                            'image': data_cluster_profile['image'],
                            'key_name': data_cluster_profile['key_name'],
                            'networks': [{
                                'network': req_data['network_id'],
                                'security_groups': [
                                    data_cluster_profile['security_group']
                                ]
                            }],
                            'scheduler_hints': {
                                'group': server_group.id
                            }
                        }
                    }
                )

                cluster = conn.clustering.create_cluster(
                    name=cluster_name,
                    min_size=data_cluster.get('min_size', 1),
                    max_size=data_cluster.get('max_size', -1),
                    desired_capacity=data_cluster.get('desired_capacity', 1),
                    profile_id=profile.id
                )

                policy_lb = conn.clustering.create_policy(
                    name='%s_policy_lb' % cluster_name,
                    spec={
                        'type': 'senlin.policy.loadbalance',
                        'version': 1.1,
                        'properties': {
                            'loadbalancer': lb.id,
                            'pool': {
                                'id': lb_pool.id,
                                'subnet': req_data.get('subnet_id')
                            },
                            'vip': {
                                'subnet': data_lb.get('provider_subnet_id')
                            }
                        }
                    }
                )

                conn.clustering.wait_for_status(cluster, 'ACTIVE')

                conn.clustering.attach_policy_to_cluster(cluster.id, policy_lb.id)

                floating_ip = conn_admin.network.create_ip(
                    project_id=req_data['project_id'],
                    port_id=lb.vip_port_id,
                    floating_network_id=data_lb['provider_network_id'],
                    floating_ip_address=data_lb.get('provider_network_ip')
                )

                req_data['id'] = cluster.id
                data_cluster_profile['id'] = profile.id
                data_lb['id'] = lb.id
                data_lb['pool_id'] = lb_pool.id
                data_lb['provider_network_ip'] = floating_ip.floating_ip_address

            except Exception as e:
                if lb is not None:
                    conn.load_balancer.delete_load_balancer(lb, cascade=True)

                if server_group is not None:
                    conn.compute.delete_server_group(server_group)

                if cluster is not None:
                    if policy_lb is not None:
                        conn.clustering.detach_policy_from_cluster(cluster, policy_lb)
                        conn.clustering.delete_policy(policy_lb)

                    conn.clustering.delete_cluster(cluster)
                    conn.clustering.delete_profile(profile)

                if floating_ip is not None:
                    conn.delete_floating_ip(floating_ip.id)

                raise e

        return req_data


@namespace.route('/<string:id>')
@namespace.param('id', '클러스터 식별자')
class Cluster(Resource):
    @namespace.marshal_with(model_cluster)
    def get(self):
        pass

    @namespace.expect(model_cluster)
    def put(self):
        pass

    def delete(self, id):
        with openstack.connect(
                auth_url="http://192.168.15.40:5000/v3",
                project_id="925aba3de85a48ccb284bf02edc1c18e",
                username="admin",
                password="1234qwer",
                region_name="RegionOne",
                user_domain_name="default",
                project_domain_name="default",
        ) as conn:
            cluster = None

            try:
                cluster = conn.clustering.get_cluster(id)
            except ResourceNotFound:
                return '', 404

            lb_id = None

            for cluster_policy in conn.clustering.cluster_policies(id):
                if 'senlin.policy.loadbalance' in cluster_policy.policy_type:
                    lb_id = cluster_policy.data['LoadBalancingPolicy']['data']['loadbalancer']

                action_info = conn.clustering.detach_policy_from_cluster(cluster, cluster_policy.policy_id)
                action = conn.clustering.get_action(action_info['action'])
                conn.clustering.wait_for_status(action, 'SUCCEEDED')
                conn.clustering.delete_policy(cluster_policy.policy_id)

            profile = conn.get_cluster_profile(cluster.profile_id)

            server_group_id = profile.spec.get('properties', {}).get('scheduler_hints', {}).get('group')

            conn.clustering.delete_cluster(cluster)
            conn.clustering.wait_for_delete(cluster)
            conn.clustering.delete_profile(profile)

            if server_group_id is not None:
                conn.delete_server_group(server_group_id)

            if lb_id is not None:
                try:
                    lb = conn.load_balancer.get_load_balancer(lb_id)

                    vip = next(conn.network.ips(port_id=lb.vip_port_id))

                    if vip is not None:
                        conn.network.delete_ip(vip)

                    conn.load_balancer.delete_load_balancer(lb, cascade=True)
                except ResourceNotFound:
                    pass

            return None, 200

# @namespace.route('/as-policy')
# class AutoScalingPolicy(Resource):
#     def get(self):
#         pass
#
#     @namespace.expect(model_as)
#     def post(self):
#         pass
