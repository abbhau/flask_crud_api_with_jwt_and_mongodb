from flask import Flask, request, jsonify, abort
from flask_restful import Api, Resource
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (JWTManager, jwt_required, create_access_token,
                                create_refresh_token, get_jwt_identity)
from datetime import timedelta
from flask_pymongo import PyMongo
from pymongo.mongo_client import MongoClient
from uuid import uuid1
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:3000",
                                             "http://127.0.0.1:3000", ]}})

with app.app_context():
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=2)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
    app.config['SECRET_KEY'] = 'gyjguguuhu'
    jwt = JWTManager(app)
    api = Api(app)
    uri = "mongodb+srv://<user>:<password>@cluster0.xevvo9s.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    app.config["MONGO_URI"] = uri
    mongo = PyMongo(app)

    client = MongoClient(uri)


class UserApiListCreate(Resource):
    @jwt_required()
    def get(self):
        #user = client.db.user.find({"post.title":"post1"},{'password':0})
        user = client.db.user.find({},{'password':0})
        user_list = list(user)
        return {"data":user_list}, 200
    
    @jwt_required()
    def post(self):
        password = generate_password_hash(request.get_json().get('password'))
        id=str(uuid1().hex)
        data = dict(request.get_json())
        data.update({"_id":id, "password":password})
        try:
            user = client.db.user.insert_one(data)
            return {'message': 'user addded successfully', 'data':user.inserted_id} , 201
        except:
            return {"message":"Failed to insert "}, 500
        

class UserUpdateDeleteApi(Resource):
    @jwt_required()
    def put(self, pk):
        filter_id = {"_id":str(pk)}
        data = dict(request.get_json())
        password = generate_password_hash(request.get_json().get('password'))
        if password:
            data["password"] = password
        data.pop('username')
        
        result = client.db.user.update_one(filter_id, {"$set":data})
        print(result.matched_count, result.modified_count)
        if not result.matched_count:
            return {"message":"Record not found"}, 404
        return {'message': 'user updated successfully'},205
    
    @jwt_required()
    def delete(self, pk):
        filter_id = {"_id":str(pk)}
        result=client.db.user.delete_one(filter_id)

        if not result.deleted_count:
            return {"message":"Failed to delete"}, 500
        return {"message":"Delete success"}, 200

        
api.add_resource(UserApiListCreate, '/api/user/')
api.add_resource(UserUpdateDeleteApi, '/api/user/<pk>/')


class Login(Resource):
    def post(self):
        username = request.json.get("username")
        password = request.json.get("password")
        user = client.db.user.find_one({"username":username})
        user_pass = user.get("password")
        if user and check_password_hash(user_pass,password):
            access_token = create_access_token(identity=username)
            refresh_token = create_refresh_token(identity=username)
            return {'token':{'access':access_token, 'refresh':refresh_token}}
        return abort(401, "Invalid Credentials")


class Refresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify(access_token=access_token)
 
api.add_resource(Login, '/api/token/')
api.add_resource(Refresh, '/api/refresh/')


if __name__ == "__main__":
    app.run(debug=True)
