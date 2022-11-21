import pprint
import requests
import json
from flask import request  # 서버 구현을 위한 Flask 객체 import
from flask import current_app, g
from flask_restx import Namespace, Resource, fields, marshal  # Api 구현을 위한 Api 객체 import
import openstack
from openstack.exceptions import ResourceNotFound, HttpException
from smart_cluster import namespace, pp
from smart_cluster.model import model_cluster, model_asp


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

        floating_ip = None
        lb = None
        server_group = None
        cluster = None
        policy_lb = None

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

                # 로드밸런서 생성
                lb = conn.load_balancer.create_load_balancer(
                    name='%s_lb' % cluster_name,
                    vip_network_id=req_data['network_id']
                )

                conn.load_balancer.wait_for_load_balancer(lb.id)

                # Floating IP 생성 후 로드밸런서 vip_port와 연결
                floating_ip = conn_admin.network.create_ip(
                    project_id=req_data['project_id'],
                    port_id=lb.vip_port_id,
                    floating_network_id=data_lb['provider_network_id'],
                    floating_ip_address=data_lb.get('provider_network_ip')
                )

                # 로드밸런서 > 리스너 생성
                lb_listener = conn.load_balancer.create_listener(
                    name='%s_listener' % cluster_name,
                    protocol=data_lb['protocol'],
                    protocol_port=data_lb['port'],
                    connection_limit=data_lb.get('connection_limit', -1),
                    loadbalancer_id=lb.id
                )

                conn.load_balancer.wait_for_load_balancer(lb.id)

                # 로드밸런서 > 리스너 > 풀 생성
                lb_pool = conn.load_balancer.create_pool(
                    name='%s_pool' % cluster_name,
                    protocol=data_lb['protocol'],
                    lb_algorithm=data_lb['lb_algorithm'],
                    session_persistence=data_lb_sp,
                    listener_id=lb_listener.id
                )

                conn.load_balancer.wait_for_load_balancer(lb.id)

                # 로드밸런서 > 리스너 > 풀 > 헬스모니터 생성
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

                # 서버 그룹 생성
                server_group = conn.compute.create_server_group(
                    name='%s_sg' % cluster_name,
                    policy='soft-anti-affinity'
                )

                # 클러스터 > 프로파일 생성
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

                # 클러스터 생성
                cluster = conn.clustering.create_cluster(
                    name=cluster_name,
                    min_size=data_cluster.get('min_size', 1),
                    max_size=data_cluster.get('max_size', -1),
                    desired_capacity=data_cluster.get('desired_capacity', 1),
                    profile_id=profile.id
                )

                # 클러스터 > 정책 생성 및 적용
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

                req_data['id'] = cluster.id
                data_cluster_profile['id'] = profile.id
                data_lb['id'] = lb.id
                data_lb['pool_id'] = lb_pool.id
                data_lb['provider_network_ip'] = floating_ip.floating_ip_address

            except Exception as e:
                if floating_ip is not None:
                    conn.delete_floating_ip(floating_ip.id)

                if lb is not None:
                    conn.load_balancer.delete_load_balancer(lb, cascade=True)

                if server_group is not None:
                    conn.compute.delete_server_group(server_group)

                if cluster is not None:
                    if policy_lb is not None:
                        action_info = conn.clustering.detach_policy_from_cluster(cluster, policy_lb)

                        if action_info and action_info in 'action'
                            action = conn.clustering.get_action(action_info['action'])
                            conn.clustering.wait_for_status(action, 'SUCCEEDED')

                        conn.clustering.delete_policy(policy_lb)

                    conn.clustering.delete_cluster(cluster)
                    conn.clustering.wait_for_delete(cluster)
                    conn.clustering.delete_profile(profile)

                raise e

        return req_data


@namespace.route('/<string:cluster_id>')
@namespace.param('cluster_id', '클러스터 식별자')
class Cluster(Resource):
    @namespace.marshal_with(model_cluster)
    def get(self, cluster_id):
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
                cluster = conn.clustering.get_cluster(cluster_id)
            except ResourceNotFound:
                return '', 404

            lb_id = None

            resp_data = {
                'id': cluster_id,
                'name': cluster.name,
                'project_id': cluster.project_id,
                'cluster': {},
                'loadbalancer': {}
            }
            resp_data_cluster = resp_data['cluster']
            resp_data_lb = resp_data['loadbalancer']

            profile = conn.get_cluster_profile(cluster.profile_id)

            profile_prop = profile.spec.get('properties', {})
            resp_data['network_id'] = profile_prop.get('networks', [])[0].get('network')
            resp_data_cluster['min_size'] = cluster.min_size
            resp_data_cluster['max_size'] = cluster.max_size
            resp_data_cluster['desired_capacity'] = cluster.desired_capacity

            resp_data_cluster['profile'] = {
                'id': profile.id,
                'name': profile_prop['name'],
                'flavor': profile_prop['flavor'],
                'image': profile_prop['image'],
                'key_name': profile_prop['key_name'],
                'security_group': profile_prop.get('networks', [])[0].get('security_groups')[0]
            }

            lb_cluster_policy = next(
                conn.clustering.cluster_policies(cluster_id, policy_type='senlin.policy.loadbalance-1.1'))

            lb_policy = conn.clustering.get_policy(lb_cluster_policy.policy_id)

            lb_policy_prop = lb_policy['spec'].get('properties', {})
            resp_data_lb['id'] = lb_policy_prop['loadbalancer']
            resp_data_lb['pool_id'] = lb_policy_prop['pool']['id']
            resp_data_lb['provider_subnet_id'] = lb_policy_prop['vip']['subnet']

            resp_data['subnet_id'] = lb_policy_prop['pool']['subnet']

            # 로드밸런서
            lb = conn.load_balancer.get_load_balancer(resp_data_lb['id'])

            resp_data['network_id'] = lb.vip_network_id

            # 로드밸런서 > 리스너
            listener = next(conn.load_balancer.listeners(load_balancer_id=lb.id))

            resp_data_lb['protocol'] = listener.protocol
            resp_data_lb['port'] = listener.protocol_port
            resp_data_lb['connection_limit'] = listener.connection_limit
            # resp_data_lb['connection_']

            # 로드밸런서 > 리스너 > 풀
            pool = next(conn.load_balancer.pools(loadbalancer_id=lb.id))

            resp_data_lb['lb_algorithm'] = pool.lb_algorithm
            resp_data_lb['session_persistence'] = pool.session_persistence

            hm = conn.load_balancer.get_health_monitor(pool.health_monitor_id)

            resp_data_lb['health_monitor'] = {
                'type': hm.type,
                'retries_down': hm.max_retries_down,
                'retries': hm.max_retries,
                'delay': hm.delay,
                'timeout': hm.timeout,
                'url': hm.url_path,
                'method': hm.http_method,
                'expected_codes': hm.expected_codes
            }

            vip = next(conn.network.ips(port_id=lb.vip_port_id))

            resp_data_lb['provider_network_id'] = vip['floating_network_id']
            resp_data_lb['provider_network_ip'] = vip['floating_ip_address']

            return resp_data

    def delete(self, cluster_id):
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
                cluster = conn.clustering.get_cluster(cluster_id)
            except ResourceNotFound:
                return '', 404

            lb_id = None

            # 클러스터 > 정책 삭제
            for cluster_policy in conn.clustering.cluster_policies(cluster_id):
                if 'senlin.policy.loadbalance' in cluster_policy.policy_type:
                    lb_id = cluster_policy.data['LoadBalancingPolicy']['data']['loadbalancer']

                action_info = conn.clustering.detach_policy_from_cluster(cluster, cluster_policy.policy_id)

                if action_info and action_info in 'action':
                    action = conn.clustering.get_action(action_info['action'])
                    conn.clustering.wait_for_status(action, 'SUCCEEDED')

                conn.clustering.delete_policy(cluster_policy.policy_id)

            # 클러스터 > 리시버 삭제
            for receiver in conn.clustering.receivers(cluster_id=cluster_id):
                conn.clustering.delete_receiver(receiver)
                conn.clustering.wait_for_delete(receiver)

                self.delete_alarm(conn.auth_token, receiver.id)

            # 클러스터 및 프로파일 삭제
            profile = conn.get_cluster_profile(cluster.profile_id)

            server_group_id = profile.spec.get('properties', {}).get('scheduler_hints', {}).get('group')

            conn.clustering.delete_cluster(cluster)
            conn.clustering.wait_for_delete(cluster)
            conn.clustering.delete_profile(profile)

            # 서버 그룹 삭제
            if server_group_id is not None:
                conn.delete_server_group(server_group_id)

            # 로드밸런서 및 Floating IP 삭제
            if lb_id is not None:
                try:
                    lb = conn.load_balancer.get_load_balancer(lb_id)

                    vip = next(conn.network.ips(port_id=lb.vip_port_id))

                    if vip is not None:
                        conn.network.delete_ip(vip)

                    conn.load_balancer.delete_load_balancer(lb, cascade=True)
                except ResourceNotFound:
                    pass

            return None, 204


@namespace.route('/<string:cluster_id>/scaling-policy')
@namespace.param('cluster_id', '클러스터 식별자')
class AutoScalingPolicy(Resource):
    @namespace.marshal_with(model_asp)
    def get(self, cluster_id):
        with openstack.connect(
                auth_url="http://192.168.15.40:5000/v3",
                project_id="925aba3de85a48ccb284bf02edc1c18e",
                username="admin",
                password="1234qwer",
                region_name="RegionOne",
                user_domain_name="default",
                project_domain_name="default",
        ) as conn:

            try:
                cluster_policies = list(
                    conn.clustering.cluster_policies(cluster_id, policy_type='senlin.policy.scaling-1.0'))
            except ResourceNotFound:
                return '', 404

            resp_data = {
                'id': cluster_id,
            }

            policies = []

            for cp in cluster_policies:
                policies.append(conn.clustering.get_policy(cp.policy_id))

            #scaling-in
            event = 'CLUSTER_SCALE_IN'

            policy = next((p for p in policies if p.spec['properties']['event'] == event), None)

            resp_data['scaling_in'] = self.__get_scaling_policy(conn, cluster_id, policy, event)

            #scaling-out
            event = 'CLUSTER_SCALE_OUT'

            policy = next((p for p in policies if p.spec['properties']['event'] == event), None)

            resp_data['scaling_out'] = self.__get_scaling_policy(conn, cluster_id, policy, event)

            return resp_data

    @namespace.expect(model_asp, validate=True)
    def put(self, cluster_id):
        req_data = request.json
        data_scaling_in = req_data['scaling_in']
        data_scaling_out = req_data['scaling_out']

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
                cluster = conn.clustering.get_cluster(cluster_id)
            except ResourceNotFound:
                return '', 404

            cluster_policies = list(
                conn.clustering.cluster_policies(cluster_id, policy_type='senlin.policy.scaling-1.0'))

            for cp in cluster_policies:
                action_info = conn.clustering.detach_policy_from_cluster(cluster, cp.policy_id)
                action = conn.clustering.get_action(action_info['action'])
                conn.clustering.wait_for_status(action, 'SUCCEEDED')
                conn.clustering.delete_policy(cp.policy_id)

            ## scaling-in
            ### 1. policy
            event = 'CLUSTER_SCALE_IN'
            self.__create_scaling_policy(conn, cluster,
                                       '%s_policy_scaling-in' % cluster.name,
                                         event, data_scaling_in)

            alarm = None
            receiver_scaling_in = None

            ### 2. receiver
            if cluster_policies:
                try:
                    receivers = list(conn.clustering.receivers(cluster_id=cluster_id, action=event))

                    if receivers:
                        receiver_scaling_in = receivers[0]
                        alarm = self.__get_alarm(conn.auth_token, receiver_scaling_in.id)

                except ResourceNotFound:
                    pass

            if receiver_scaling_in is None:
                receiver_scaling_in = conn.clustering.create_receiver(
                    name='%s_receiver_scaling-in' % cluster.name,
                    cluster_id=cluster_id,
                    action=event,
                    type='webhook'
                )

            alarm_data = self.__create_alarm_data(cluster, receiver_scaling_in, data_scaling_in)

            ### 3. aodh
            self.__create_or_update_alarm(conn.auth_token, alarm_data, alarm.get('alarm_id') if alarm else None)

            ## scaling-out
            ### 1. policy
            event = 'CLUSTER_SCALE_OUT'
            self.__create_scaling_policy(conn, cluster,
                                       '%s_policy_scaling-out' % cluster.name,
                                         event, data_scaling_out)

            alarm = None
            receiver_scaling_out = None

            ### 2. receiver
            if cluster_policies:
                try:
                    receivers = list(conn.clustering.receivers(cluster_id=cluster_id, action=event))

                    if receivers:
                        receiver_scaling_out = receivers[0]
                        alarm = self.__get_alarm(conn.auth_token, receiver_scaling_out.id)

                except ResourceNotFound:
                    pass

            if receiver_scaling_out is None:
                receiver_scaling_out = conn.clustering.create_receiver(
                    name='%s_receiver_scaling-out' % cluster.name,
                    cluster_id=cluster_id,
                    action=event,
                    type='webhook'
                )

            ### 3. aodh
            alarm_data = self.__create_alarm_data(cluster, receiver_scaling_out, data_scaling_out)
            alarm_data['severity'] = 'critical'
            self.__create_or_update_alarm(conn.auth_token, alarm_data, alarm.get('alarm_id') if alarm else None)

        return req_data

    def delete(self, cluster_id):
        with openstack.connect(
                auth_url="http://192.168.15.40:5000/v3",
                project_id="925aba3de85a48ccb284bf02edc1c18e",
                username="admin",
                password="1234qwer",
                region_name="RegionOne",
                user_domain_name="default",
                project_domain_name="default",
        ) as conn:
            try:
                cluster = conn.clustering.get_cluster(cluster_id)
            except ResourceNotFound:
                return '', 404

            cluster_policies = list(
                conn.clustering.cluster_policies(cluster_id, policy_type='senlin.policy.scaling-1.0'))

            for cp in cluster_policies:
                action_info = conn.clustering.detach_policy_from_cluster(cluster, cp.policy_id)

                if action_info and action_info in 'action':
                    action = conn.clustering.get_action(action_info['action'])
                    conn.clustering.wait_for_status(action, 'SUCCEEDED')

                conn.clustering.delete_policy(cp.policy_id)

            event = 'CLUSTER_SCALE_IN'
            receivers = list(conn.clustering.receivers(cluster_id=cluster_id, action=event))

            for receiver in receivers:
                conn.clustering.delete_receiver(receiver)
                conn.clustering.wait_for_delete(receiver)

                self.__delete_alarm(conn.auth_token, receiver.id)

            event = 'CLUSTER_SCALE_OUT'
            receivers = list(conn.clustering.receivers(cluster_id=cluster_id, action=event))

            for receiver in receivers:
                conn.clustering.delete_receiver(receiver)
                conn.clustering.wait_for_delete(receiver)

                self.__delete_alarm(conn.auth_token, receiver.id)

            return None, 204


    @staticmethod
    def __create_alarm_data(cluster, receiver, data_scaling):
        threshold = data_scaling['threshold']

        if data_scaling['metric'] == 'cpu':
            threshold = threshold * 20 * 1000000000 / 100

        # TODO: metric별 resource_type 매핑이 필요함.
        return {
            'alarm_actions': [receiver.channel['alarm_url']],
            'name': receiver.id,
            'gnocchi_aggregation_by_resources_threshold_rule': {
                "evaluation_periods": data_scaling['evaluation_period'],
                "metric": data_scaling['metric'],
                "aggregation_method": data_scaling['aggregation_method'],
                "granularity": "20",
                "threshold": threshold,
                'query': '{\"and\":[{\"=\":{\"cluster_id\":\"%s\"}},{\"=\":{\"ended_at\":null}}]}' % cluster.id,
                'comparison_operator': data_scaling['comparison_op'],
                "resource_type": "instance"
            },
            'repeat_actions': data_scaling['repeat'],
            'type': 'gnocchi_aggregation_by_resources_threshold'
        }

    @staticmethod
    def __create_scaling_policy(conn, cluster, name, event, data):
        policy = conn.clustering.create_policy(
            name=name,
            spec={
                'type': 'senlin.policy.scaling',
                'version': 1.0,
                'properties': {
                    'adjustment': {
                        'best_effort': False,
                        'cooldown': data.get('cooldown', 60),
                        'min_step': data.get('min_step', 1),
                        'number': data.get('min_step', 1),
                        'type': data.get('type', 'CHANGE_IN_CAPACITY')
                    },
                    'event': event
                }
            }
        )

        conn.clustering.attach_policy_to_cluster(cluster.id, policy.id)
        return policy

    def __get_scaling_policy(self, conn, cluster_id, policy, event):
        data_scaling = {}

        if not policy:
            return data_scaling

        prop = policy.spec['properties']['adjustment']

        data_scaling['type'] = prop['type']
        data_scaling['number'] = prop['number']
        data_scaling['min_step'] = prop['min_step']
        data_scaling['cooldown'] = prop['cooldown']

        receivers = list(conn.clustering.receivers(cluster_id=cluster_id, action=event))

        receiver = None

        if receivers:
            receiver = receivers[0]

            alarm = self.__get_alarm(conn.auth_token, receiver.id)

            # if alarm:
            rule = alarm.get('gnocchi_aggregation_by_resources_threshold_rule')
            data_scaling['metric'] = rule['metric']
            data_scaling['aggregation_method'] = rule['aggregation_method']

            if rule['metric'] == 'cpu':
                data_scaling['threshold'] = rule['threshold'] / 20 / 1000000000 * 100
            else:
                data_scaling['threshold'] = rule['threshold']

            data_scaling['comparison_op'] = rule['comparison_operator']
            data_scaling['evaluation_period'] = rule['evaluation_periods']
            data_scaling['repeat'] = alarm['repeat_actions']

            return data_scaling

    @staticmethod
    def __get_alarm(auth_token, receiver_id):
        if not receiver_id:
            raise ValueError("name can't be null")

        if not auth_token:
            raise ValueError("auth_key can't be null")

        url = "http://192.168.15.40:8042/v2/alarms?q.field=name&q.op=eq&q.value=%s" % receiver_id

        headers = {
            'X-Auth-Token': auth_token
        }

        response = requests.request("GET", url, headers=headers)

        alarm_list = response.json()

        return alarm_list[0] if alarm_list else None

    @staticmethod
    def __create_or_update_alarm(auth_token, data, alarm_id=None):
        if not auth_token:
            raise ValueError("auth_token can't be null")

        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': auth_token
        }

        response = None
        if alarm_id:
            url = "http://192.168.15.40:8042/v2/alarms/%s" % alarm_id

            response = requests.request("PUT", url, data=json.dumps(data), headers=headers)
        else:
            if not auth_token:
                raise ValueError("auth_token can't be null")

            url = "http://192.168.15.40:8042/v2/alarms"

            response = requests.request("POST", url, data=json.dumps(data), headers=headers)

        if not 200 <= response.status_code < 300:
            print("[{url}][{status_code}] {contents}".format(url=response.url, status_code=response.status_code,
                                                             contents=response.text))
            raise HttpException("error creating alarm")

    @staticmethod
    def __delete_alarm(auth_token, receiver_id):
        if not receiver_id:
            raise ValueError("receiver_id can't be null")

        if not auth_token:
            raise ValueError("auth_token can't be null")

        url = "http://192.168.15.40:8042/v2/alarms/%s" % receiver_id

        headers = {
            'X-Auth-Token': auth_token
        }

        response = requests.request("DELETE", url, headers=headers)
