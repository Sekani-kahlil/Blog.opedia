from datetime import datetime, timezone
from typing import Optional
import sqlalchemy as sa
import sqlalchemy.orm as so
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login
from time import time
import jwt
from app import app, db

from app import db

try:
    engine = db.engine
    connection = engine.connect()
    connection.execute("SELECT 1")  # Simple test query
    connection.close()
    print("Successfully connected to the database!")
except Exception as e:
    print(f"Error connecting to the database: {str(e)}")

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True,
                                                unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True,
                                             unique=True)
    is_verified: so.Mapped[bool] = so.mapped_column(sa.Boolean(), default=0)
    used_oauth: so.Mapped[bool] = so.mapped_column(sa.Boolean(), default=0)
    is_admin: so.Mapped[bool] = so.mapped_column(sa.Boolean(), default=0)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))

    posts: so.WriteOnlyMapped['Post'] = so.relationship(
        back_populates='author')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')
    
    def get_verification_token(self, expires_in=600):
        return jwt.encode(
            {'verify': self.email, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return db.session.get(User, id)
    
    @staticmethod
    def verify_verification_token(token):
        try:
            email = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['verify']
        except:
            return
        return email

@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))

def getTime():
    time = str(datetime.now(timezone.utc))
    ftime = datetime.strptime(time, "%Y-%m-%d %H:%M:%S.%f%z")
    newtime = ftime.strftime("%A, %d %B %Y, %H:%M")
    return newtime

class Post(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    title: so.Mapped[str] = so.mapped_column(sa.String(280))
    body: so.Mapped[str] = so.mapped_column(sa.String(140))
    timestamp: so.Mapped[str] = so.mapped_column(
        sa.String(50), index=True, default=lambda: getTime())
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id),
                                               index=True)

    author: so.Mapped[User] = so.relationship(back_populates='posts')

    def __repr__(self):
        return '<Post {}>'.format(self.body)
