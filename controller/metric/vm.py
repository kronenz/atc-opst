from flask import current_app
from flask import Blueprint
import pprint

pp = pprint.PrettyPrinter()

bp = Blueprint('metric_vm', __name__, url_prefix='/metric/vm')

@bp.route('/cpu')
def getCpu():
    conn = current_app.sdk_connection

    print(conn.auth_token)

    return {"hello": "world!"}
