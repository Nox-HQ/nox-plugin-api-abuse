from flask import Flask, request, jsonify
from models import User, Order

app = Flask(__name__)

# API-ABUSE-001: Missing authentication check - route without auth decorator
@app.route("/profile")
def get_profile(request):
    return jsonify(user=request.user)

@app.get("/settings")
def get_settings(request):
    return jsonify(settings={})

# API-ABUSE-002: BOLA - user ID from request used directly
@app.route("/users/<id>")
def get_user(request):
    user_id = request.args.get("user_id")
    user = User.objects.get(id=user_id)
    return jsonify(user=user.to_dict())

def delete_user(request):
    uid = request.json["user_id"]
    User.objects.filter(user_id=request.json["id"]).delete()

# API-ABUSE-003: Missing rate limiting on auth endpoints
@app.post("/login")
def login():
    return jsonify(token="abc")

@app.route("/password/reset", methods=["POST"])
def reset_password():
    return jsonify(ok=True)

# API-ABUSE-004: Mass assignment - request data spread into model
def create_user(request):
    User.objects.create(**request.json)
    return jsonify(ok=True)

def update_profile(request):
    serializer = UserSerializer(data=request.data)
    return jsonify(ok=True)

# API-ABUSE-005: Verbose error responses
def handle_error(request):
    try:
        process()
    except Exception as e:
        return JsonResponse({"error": str(e), "trace": traceback.format_exc()})
