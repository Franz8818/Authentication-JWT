"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
#from models import Person
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
#importacion JWT

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)
# Setup the Flask-JWT-Extended extension #Configurar en la app JWT SECRET KEY #SISTEMA DE SEGURIDAD
app.config["JWT_SECRET_KEY"] = "clavesecreta"  # Change this!
jwt = JWTManager(app) #ensendido de motor se guarda en una variable

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"]) #COMO INICIAN TODAS LAS RUTAS # un POST incertar tus datos
def login():
    email = request.json.get("email", None) #GUARDA LA FUNCIÓN #VIENE HARCODEADO
    password = request.json.get("password", None)
    user = User.query.filter_by(email=email).first() #CON ESTE QUERI USCAME EL USER Y EL PASSWORD
    if email != user.email or password != user.password: #SI EL CORREO ES DIFERENTES A TEST 
        return jsonify({"msg": "Bad email or password"}), 401 

    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token) #EL SELLO A LA ENTRADA DEL LA FIESTA #apuntaron tu nombre #unica entrada con email & pasw

    # Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/profile", methods=["GET"])
@jwt_required() #/// OJO /// ESTE ES EL GUARDA DE LA PUERTA / AQUÍ ACTIVA LA FUNCIÓN jwt_required PARA PROTEGER ESA RUTA
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity() #/// CON ESTA FUNCIÓN JWT OBTIENE LA IDENTIDAD DEL USUARIO Y LA GUARDA EN LA VARIABLE current_user
    user = User.query.filter_by(email=current_user).first() #//// ACÁ HAGO UNA CONSULTA ESPECÍFICA (query) PARA VERIFICAR QUE EL USUARIO EXISTA EN LOS REGISTRO  ***IMPORTANTE*** ACÁ LO FILTRO POR LA PROPIEDAD email PERO APROVECHANDO QUE LA FUNCIÓN get_jwt_identity QUE OBTIENE LA IDENTIDAD DEL USUARIO... Y ESA IDENTIDAD QUEDA GUARDADA EN LA VARIABLE current_user
    if current_user != user.email:
        return jsonify({"msg":"Ud no está registrado"}), 401
   
    return jsonify(user.serialize()), 200 #//// ACÁ DOY LA RESPUESTA POSITIVA PERO NO LA PUEDO ENVIAR ASÍ NO MÁS PORQUE NECESITO QUE SE TRADUZCA A ALGO LEGIBLE PARA EL FRONT POR ESO LE APLICO EL .serialize()


if __name__ == "__main__":
    app.run()


# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
