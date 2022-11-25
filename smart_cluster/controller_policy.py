import requests
import json

import openstack
import requests
from flask import request  # 서버 구현을 위한 Flask 객체 import
from flask_restx import Resource  # Api 구현을 위한 Api 객체 import
from openstack.clustering.v1.policy import Policy
from openstack.exceptions import ResourceNotFound, HttpException

from smart_cluster import namespace, get_alarm, create_or_update_alarm, delete_alarm
from smart_cluster.model import model_asp


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
            cluster_id = cluster_id.strip()

            try:
                cluster = conn.clustering.get_cluster(cluster_id)
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

            if not cluster_policies:
                return '', 404

            vcpus = self.__get_vcpus(conn, cluster.profile_id)

            # scaling-in
            event = 'CLUSTER_SCALE_IN'

            policy = next((p for p in policies if p.spec['properties']['event'] == event), None)

            resp_data['scaling_in'] = self.__get_scaling_policy(conn, cluster_id, policy, event, vcpus=vcpus)

            # scaling-out
            event = 'CLUSTER_SCALE_OUT'

            policy = next((p for p in policies if p.spec['properties']['event'] == event), None)

            resp_data['scaling_out'] = self.__get_scaling_policy(conn, cluster_id, policy, event, vcpus=vcpus)

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

            cluster_id = cluster_id.strip()

            try:
                cluster = conn.clustering.get_cluster(cluster_id)
            except ResourceNotFound:
                return '', 404

            cluster_policies = self.__delete_scaling_policy(conn, cluster)

            vcpus = self.__get_vcpus(conn, cluster.profile_id)

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
                        alarm = get_alarm(conn.auth_token, receiver_scaling_in.id)

                except ResourceNotFound:
                    pass

            if receiver_scaling_in is None:
                receiver_scaling_in = conn.clustering.create_receiver(
                    name='%s_receiver_scaling-in' % cluster.name,
                    cluster_id=cluster_id,
                    action=event,
                    type='webhook'
                )

            alarm_data = self.__create_alarm_data(cluster, receiver_scaling_in, data_scaling_in, vcpus=vcpus)

            ### 3. aodh
            create_or_update_alarm(conn.auth_token, alarm_data, alarm.get('alarm_id') if alarm else None)

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
                        alarm = get_alarm(conn.auth_token, receiver_scaling_out.id)

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
            alarm_data = self.__create_alarm_data(cluster, receiver_scaling_out, data_scaling_out, vcpus=vcpus)
            alarm_data['severity'] = 'critical'
            create_or_update_alarm(conn.auth_token, alarm_data, alarm.get('alarm_id') if alarm else None)

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
            cluster_id = cluster_id.strip()

            try:
                cluster = conn.clustering.get_cluster(cluster_id)
            except ResourceNotFound:
                return '', 404

            cluster_policies = self.__delete_scaling_policy(conn, cluster)

            event = 'CLUSTER_SCALE_IN'
            receivers = list(conn.clustering.receivers(cluster_id=cluster_id, action=event))

            for receiver in receivers:
                delete_alarm(conn.auth_token, receiver.id)

                conn.clustering.delete_receiver(receiver)
                conn.clustering.wait_for_delete(receiver)

            event = 'CLUSTER_SCALE_OUT'
            receivers = list(conn.clustering.receivers(cluster_id=cluster_id, action=event))

            for receiver in receivers:
                delete_alarm(conn.auth_token, receiver.id)

                conn.clustering.delete_receiver(receiver)
                conn.clustering.wait_for_delete(receiver)

            for cp in cluster_policies:
                conn.clustering.delete_policy(cp.policy_id)

            return None, 204

    @staticmethod
    def __delete_scaling_policy(conn, cluster):
        cluster_id = cluster.id

        cluster_policies = list(
            conn.clustering.cluster_policies(cluster_id, policy_type='senlin.policy.scaling-1.0'))
        for cp in cluster_policies:
            action_info = conn.clustering.detach_policy_from_cluster(cluster, cp.policy_id)

            if action_info and 'action' in action_info:
                action = conn.clustering.get_action(action_info['action'])
                conn.clustering.wait_for_status(action, 'SUCCEEDED')

            conn.clustering.wait_for_status(cluster, 'ACTIVE')
            conn.clustering.delete_policy(cp.policy_id)
        return cluster_policies

    @staticmethod
    def __create_alarm_data(cluster, receiver, data_scaling, vcpus=1):
        threshold = data_scaling['threshold']

        if data_scaling['metric'] == 'cpu':
            threshold = threshold * 20 * 1000000000 * vcpus / 100

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

    @staticmethod
    def __get_scaling_policy(conn, cluster_id, policy, event, vcpus=1):
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

            alarm = get_alarm(conn.auth_token, receiver.id)

            # if alarm:
            rule = alarm.get('gnocchi_aggregation_by_resources_threshold_rule')
            data_scaling['metric'] = rule['metric']
            data_scaling['aggregation_method'] = rule['aggregation_method']

            if rule['metric'] == 'cpu':
                data_scaling['threshold'] = rule['threshold'] / 20 / 1000000000 / vcpus * 100
            else:
                data_scaling['threshold'] = rule['threshold']

            data_scaling['comparison_op'] = rule['comparison_operator']
            data_scaling['evaluation_period'] = rule['evaluation_periods']
            data_scaling['repeat'] = alarm['repeat_actions']

            return data_scaling

    @staticmethod
    def __get_vcpus(conn, profile_id):
        profile = conn.clustering.get_profile(profile_id)

        flavor_name = profile['spec']['properties']['flavor']

        flavor = conn.get_flavor(flavor_name)

        return flavor.vcpus
