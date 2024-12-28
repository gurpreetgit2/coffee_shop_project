import os
import logging
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

# Set up logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
logging.basicConfig(
    filename=os.path.join(log_dir, "execution.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = Flask(__name__)
setup_db(app)
CORS(app)

"""
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this funciton will add one
"""
# db_drop_and_create_all()


# ROUTES
@app.route("/drinks", methods=["GET"])
def get_drinks():
    # This part does not need to be in try-except
    drinks = Drink.query.all()
    if not drinks:
        abort(404, description="No drinks found")

    # Return a list of short drink representations
    return jsonify({"success": True, "drinks": [drink.short() for drink in drinks]})


@app.route("/drinks-detail", methods=["GET"])
@requires_auth("get:drinks-detail")
def get_drinks_detail(jwt):
    drinks = Drink.query.all()
    if not drinks:
        abort(404, description="No drinks found")

    return jsonify({"success": True, "drinks": [drink.long() for drink in drinks]})


@app.route("/drinks", methods=["POST"])
@requires_auth("post:drinks")
def create_drink(jwt):

    body = request.get_json()
    if not body:
        abort(400, description="Bad request, no data provided")

    title = body.get("title", None)
    recipe = body.get("recipe", None)

    if not title or not recipe:
        abort(400, description="Missing required fields")

    new_drink = Drink(title=title, recipe=json.dumps(recipe))
    new_drink.insert()

    return jsonify({"success": True, "drinks": [new_drink.long()]})


@app.route("/drinks/<int:id>", methods=["PATCH"])
@requires_auth("patch:drinks")
def update_drink(jwt, id):

    drink = Drink.query.get(id)
    if not drink:
        abort(404, description="Drink not found")

    body = request.get_json()
    title = body.get("title", None)
    recipe = body.get("recipe", None)

    if title:
        drink.title = title
    if recipe:
        drink.recipe = json.dumps(recipe)

    drink.update()

    return jsonify({"success": True, "drinks": [drink.long()]})


@app.route("/drinks/<int:id>", methods=["DELETE"])
@requires_auth("delete:drinks")
def delete_drink(jwt, id):

    drink = Drink.query.get(id)
    if not drink:
        abort(404, description="Drink not found")

    drink.delete()

    return jsonify({"success": True, "delete": id})


# Error Handling for auth error, 422, 404 and 500


@app.errorhandler(AuthError)
def auth_error(error):
    return (
        jsonify(
            {
                "success": False,
                "error": error.status_code,
                "message": error.error["description"],
            }
        ),
        error.status_code,
    )


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({"success": False, "error": 422, "message": "unprocessable"}), 422


@app.errorhandler(404)
def not_found(error):
    return (
        jsonify({"success": False, "error": 404, "message": "resource not found"}),
        404,
    )


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"Server Error: {error}")
    return (
        jsonify(
            {
                "success": False,
                "error": 500,
                "message": "Internal Server Error. Please try again later.",
            }
        ),
        500,
    )
