from y2k_editor import db
from sqlalchemy.dialects.mysql import LONGBLOB

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(64), nullable=False)
    
    def __repr__(self):
        return f"User({self.id}, '{self.username}', '{self.email}')"

class Image(db.Model):
    __tablename__ = 'images'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # image = db.Column(db.LargeBinary(), nullable=False) # Change to filepaths?
    image = db.Column(db.LargeBinary().with_variant(LONGBLOB, 'mysql'), nullable=False)
    file_metadata = db.Column('metadata', db.JSON)
    used_in_projects = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f"Image('{self.filename}', user_id={self.user_id})"

class Audio(db.Model):
    __tablename__ = 'audios'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    audio = db.Column(db.LargeBinary().with_variant(LONGBLOB, 'mysql'), nullable=False)
    # audio = db.Column(db.LargeBinary(), nullable=False) 
    file_metadata = db.Column('metadata', db.JSON)
    used_in_projects = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"Audio('{self.filename}', user_id={self.user_id})"

class DBProject(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    project_data = db.Column(db.LargeBinary(), nullable=False)  # Change to JSON?
    
    def __repr__(self):
        return f"DBProject('{self.title}', user_id={self.user_id})"
