from flask_restx import Namespace
import pprint

namespace = Namespace(
    name="smart-cluster",
    description="AutoScaling 정책 정의"
)

pp = pprint.PrettyPrinter()