from flask import current_app, Blueprint
import pprint

pp = pprint.PrettyPrinter()

#hardware.cpu.load.15min	process	host ID	CPU load in the past 15 minutes
#hardware.cpu.load.1min	process	host ID	CPU load in the past 1 minute
#hardware.cpu.load.5min	process	host ID	CPU load in the past 5 minutes
#hardware.cpu.util	%	host ID	cpu usage percentage
#hardware.system_stats.cpu.idle	%	host ID	CPU idle percentage

bp = Blueprint('metric_host', __name__, url_prefix='/metric/host')


@bp.route('/cpu')
def getCpuLoad15Min():
    conn = current_app.sdk_connection

    print(conn.auth_token)

    return {"hello": "world!"}