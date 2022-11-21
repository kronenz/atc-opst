import openstack
from flask_restx import Resource  # Api 구현을 위한 Api 객체 import

from smart_cluster import namespace


@namespace.route('/<string:cluster_id>/nodes')
@namespace.param('cluster_id', '클러스터 식별자')
class ClusterNodes(Resource):
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
            # ids = [node['physical_id'] for node in conn.clustering.nodes(cluster_id=cluster_id)]
            # if ids:
            return [server.to_dict() for server in conn.compute.servers() if
                    server.metadata.get('cluster_id', None) == cluster_id]
            # else:
            #     return []
