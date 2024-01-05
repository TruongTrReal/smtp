from flask_pymongo import PyMongo
from flask_login import UserMixin
from bson import ObjectId
from app import mongo, login_manager

@login_manager.user_loader
def load_user(user):
    if user is not None:
        return User.get(user)
    return None

class User(UserMixin):
    def __init__(self, user_id, username, email, password):
        self.id = str(user_id)  # Convert ObjectId to string for Flask-Login
        self.username = username
        self.email = email
        self.password = password

    def save(self):
        # Save user to MongoDB
        mongo.db.users.insert_one(self.__dict__)

    @staticmethod
    def get(user_id):
        # Implement a function to load a user by ID from MongoDB
        # Replace 'users' with the actual collection name in your MongoDB

        if user_id is not None:
            user_data = mongo.db.users.find_one({'id': user_id})

            if user_data:
                return User(
                    user_id=user_data['id'],
                    username=user_data['username'],
                    email=user_data['email'],
                    password=user_data['password']
                )
            return None
        return None
