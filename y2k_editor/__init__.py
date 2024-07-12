from flask import Flask, render_template, request, redirect, url_for, make_response, abort, jsonify
from flask_jwt_extended import JWTManager, create_access_token, decode_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
import hashlib
import os
import glob
import json
from dotenv import load_dotenv
from sqlalchemy import select, func, and_
from y2k_editor.video_creator import renderVideo
import getpass
from urllib.parse import quote

try:
    with open('.env', 'r') as f:
        pass
except FileNotFoundError:
    try:
        with open('.env', 'w') as f:
            username = input("Enter your database username: ")
            password = getpass.getpass("Enter your database password: ")
            password = quote(password)
            f.write(f"DATABASE_URI=mysql+pymysql://{username}:{password}@localhost/y2k_editor")
    except Exception as e:
        print(f"Error: {e}")
        os.remove('.env')
load_dotenv()

app=Flask(__name__)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_COOKIE_SECURE'] = False
app.secret_key = 'ullabritasmitafrita'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/user'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
jwt = JWTManager(app)
csrf = CSRFProtect(app)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI")
db = SQLAlchemy(app)

from y2k_editor.models import User, Audio, Image, DBProject
with app.app_context():
    db.create_all()

def initPreloadedLibrary():
    directory = 'static/audio/preloaded'
    audio_files = glob.glob(os.path.join(directory, '*.mp3'))

    try:
        for audio_file in audio_files:
            filename = os.path.basename(audio_file)

            with open(audio_file, 'rb') as f:
                audio_data = f.read()

            metadata = {
                "filename": filename,
                "user_id": 1,
                "file_type": "audio",
            }
            metadata_json = json.dumps(metadata)
            db.session.add(Audio(filename=filename, user_id=1, audio=audio_data, metadata=metadata_json))
        db.session.commit()
    except Exception as e:
        print(f"Error: {e}")
    
def getImages(username):
    user = User.query.filter_by(username=username).first()
    if user:
        images = Image.query.with_entities(
            Image.id,
            Image.filename
        ).filter_by(user_id=user.id).all()
        images_list = [{'id': image.id, 'filename': image.filename} for image in images]
        return images_list
    return []
        
def getAudios(username):
    user = User.query.filter_by(username=username).first()
    if user:
        audios = Audio.query.with_entities(
            Audio.id,
            Audio.filename
        ).filter_by(user_id=user.id).all()
        audios_list = [{'id': audio.id, 'filename': audio.filename} for audio in audios]
        return audios_list
    return []

def checkUserExists(*, user_id: int = None, username: str = None, email: str = None):
    try:
        if user_id is not None:
            return User.query.filter_by(id=user_id).first()
        elif username is not None:
            return User.query.filter_by(username=username).first()
        elif email is not None:
            return User.query.filter_by(email=email).first()
        else:
            raise TypeError("Atleast one of user_id, username, or email should be provided.")
    except Exception as e:
        print(f"Error: {e}")
        
@app.teardown_request
def teardown_request(exception):
    if exception:
        db.session.rollback()
    else:
        db.session.commit()
    db.session.remove()    
    
@jwt.unauthorized_loader
def unauthorized_response(callback):
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    cookie = request.cookies.get('access_token_cookie')
    print("Cookie:", cookie)
    if cookie:
        current_user = decode_token(cookie)['sub']
        if checkUserExists(username=current_user):
            return redirect(url_for('user_dashboard'))
        else:
            return redirect('/logout')
    if request.method == 'POST':
        try:
            data = request.form
            username = data['username'] 
            password = data['password']

            if not username or not password:
                return jsonify({'status': 'error', 'message': 'Please fill in all fields'})
            
            user = checkUserExists(username=username)
            if not user:
                return jsonify({'status': 'error', 'message': 'User does not exist'})
            hashed_password = hashlib.sha256(password.encode()).hexdigest()          
                  
            if user.password == hashed_password:
                expireTime = 86400
                access_token = create_access_token(identity=username, expires_delta=timedelta(seconds=expireTime))
                response = make_response(jsonify({'status': 'success', 'message': 'Login successful'}))
                response.set_cookie('access_token_cookie', value=access_token, max_age=expireTime, httponly=True, path='/')
                return response
            else:
                return jsonify({'status': 'error', 'message': 'Invalid password'})
        except Exception as e:
            print("Error:", e)
            return jsonify({'status': 'error', 'message': 'Failed to login'})
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@csrf.exempt
def signup():
    cookie = request.cookies.get('access_token_cookie')
    if cookie:        
        current_user = decode_token(cookie)['sub']
        if checkUserExists(username=current_user):
            return redirect(f'/user_dashboard')
        else:
            return redirect('/logout')
    if request.method == 'POST':
        try:
            data = request.form
            username = data['username'] 
            password = data['password']
            email = data['email']

            if not username or not password or not email:
                return jsonify({'status': 'error', 'message': 'Please fill in all fields'})

            user = checkUserExists(username=username)

            if user:
                return jsonify({'status': 'error', 'message': 'User already exists'})

            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)

            access_token = create_access_token(identity=username, expires_delta=timedelta(days=7))
            response = make_response(jsonify({'status': 'success', 'message': 'Signup successful'}))
            response.set_cookie('access_token_cookie', value=access_token, max_age=86400, httponly=True, path='/')
            return response
        except Exception as e:
            print("Error:", e)
            return jsonify({'status': 'error', 'message': 'Failed to signup'})
    return render_template('signup.html')

@app.route('/logout', methods=['GET'])
@csrf.exempt
def logout():
    resp = make_response(redirect('/login'))
    cookie = request.cookies.get('access_token_cookie')
    if cookie:
        resp.delete_cookie('access_token_cookie', path='/')
    return resp

@app.route('/admin_dashboard/admin', methods=['GET'])
@jwt_required()
def admin_dashboard():
    current_user = get_jwt_identity()
    if current_user != 'admin':
        print("Error: Current user does not match requested user.")
        redirect('/logout')
        abort(403)
    image_count_subquery = db.session.query(func.count(Image.user_id)).filter(User.id == Image.user_id).label('image_count')
    audio_count_subquery = db.session.query(func.count(Audio.user_id)).filter(User.id == Audio.user_id).label('audio_count')

    users = db.session.query(
        User.id,
        User.username,
        User.email,
        image_count_subquery,
        audio_count_subquery
    ).all()

    users_list = [
        {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'images_cnt': user.image_count,
            'audios_cnt': user.audio_count
        }
        for user in users
    ]

    return render_template('adminportal.html', username='admin', users=users_list)

@app.route('/user_dashboard', methods=['GET'])
@jwt_required()
def user_dashboard():
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    username = get_jwt_identity()
    if not checkUserExists(username=username):
        return redirect(f'/logout')

    images = []
    
    user_id = checkUserExists(username=username)
    if user_id:
        images = getImages(username)
        audios = getAudios(username)
    else:
        return redirect('/logout')
    default_audios = getAudios('admin')
    return render_template('home.html', username=username, images=images, default_audios=default_audios, audios=audios)

@app.route('/get_image/<image_id>', methods=['GET'])
@jwt_required()
@csrf.exempt
def get_image(image_id):
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    try:
        image_id = int(image_id)
        print("Image ID:", image_id)
        print("Type:", type(image_id))
        image = db.session.query(Image).filter(Image.id == image_id).one_or_none()
        if image:
            image_data = image.image
            headers = {
                'Content-Type': image.file_metadata['content-type'],
                'Cache-Control': 'public, max-age={}'.format(timedelta(days=7).total_seconds()) 
            }
            return make_response(image_data, 200, headers)
        else:
            return jsonify(success=False, message="Image not found")
    except Exception as e:
        print("Error:", e)
        return jsonify(success=False, message="Failed to get image")
            
@app.route('/get_audio/<audio_id>', methods=['GET'])
@jwt_required()
@csrf.exempt
def get_audio(audio_id):
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    try:
        audio = db.session.query(Audio).filter(Audio.id == audio_id).one_or_none()
        if audio:
            audio_data = audio.audio
            headers = {
                'Content-Type': audio.file_metadata['content-type'],
                'Cache-Control': 'public, max-age={}'.format(timedelta(days=7).total_seconds()) 
            }
            return make_response(audio_data, 200, headers)
        else:
            return jsonify(success=False, message="Audio not found")
    except Exception as e:
        print("Error:", e)
        return jsonify(success=False, message="Failed to get audio")
            
@app.route('/delete_images')
@jwt_required()
@csrf.exempt
def delete_images():
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    current_user = get_jwt_identity()
    try:
        data = request.args.get('image_ids')
        if not data:
            return jsonify(success=False, message="No image selected")
        image_ids = [int(x) for x in data.split(',')]

        admin_images = db.session.query(Image.id).filter(Image.user_id == 1).all()
        admin_images = [x[0] for x in admin_images]  # Convert list of tuples to list

        if current_user != 'admin' and all(image_id in admin_images for image_id in image_ids):
            return jsonify(success=False, message="Cannot delete default images")

        user = db.session.query(User).filter(User.username == current_user).one_or_none()
        if user:
            db.session.query(Image).filter(and_(Image.id.in_(image_ids), Image.user_id == user.id)).delete(synchronize_session=False)
            db.session.commit()

        return jsonify(success=True, message="Images deleted successfully")
    except Exception as e:
        print("Error:", e)
        return jsonify(success=False, message="Failed to delete images")
  
@app.route('/delete_audios')
@jwt_required()
@csrf.exempt
def delete_audios():
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    current_user = get_jwt_identity()
    try:
        data = request.args.get('audio_ids')
        if not data:
            return jsonify(success=False, message="No audio selected")
        audio_ids = [int(x) for x in data.split(',')]

        admin_audios = db.session.query(Audio.id).filter(Audio.user_id == 1).all()
        admin_audios = [x[0] for x in admin_audios]  # Convert list of tuples to list

        if current_user != 'admin' and all(audio_id in admin_audios for audio_id in audio_ids):
            return jsonify(success=False, message="Cannot delete default audios")

        user = db.session.query(User).filter(User.username == current_user).one_or_none()
        if user:
            db.session.query(Audio).filter(and_(Audio.id.in_(audio_ids), Audio.user_id == user.id)).delete(synchronize_session=False)
            db.session.commit()

        return jsonify(success=True, message="Audios deleted successfully")
    except Exception as e:
        print("Error:", e)
        return jsonify(success=False, message="Failed to delete audios")  
      
@app.route('/video_editor', methods=['GET'])
@jwt_required()
@csrf.exempt
def video_editor():
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    current_user = get_jwt_identity()
    image_files = getImages(current_user)
    audio_files = getAudios('admin') + getAudios(current_user)
    print("Image files:", image_files)
    print(type(image_files))
    return render_template('create_video.html', username=current_user, images=image_files, audios=audio_files, timeline_images=[], timeline_audios=[])

@app.route('/upload', methods=['GET','POST'])
@jwt_required()
@csrf.exempt
def upload():
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    current_user = get_jwt_identity()
    if request.method == 'GET':
        return render_template('upload.html', username=current_user)
    if request.method == 'POST':
        try:
            file_type = request.form.get('file_type')

            if file_type not in ['image', 'audio']:
                return jsonify(success=False, message="Invalid file type")

            files = request.files.getlist(file_type)

            if not files:
                return jsonify(success=False, message="No files uploaded")

            user = db.session.query(User).filter(User.username == current_user).one_or_none()
            if not user:
                return jsonify(success=False, message="User not found")

            for file in files:
                filename = secure_filename(file.filename)
                file_data = file.read()
                file_metadata = {"filename": filename, "user_id": user.id, "file_type": file_type, "content-type": file.content_type}

                if file_type == 'image':
                    existing_file = db.session.query(Image).filter(and_(Image.filename == filename, Image.user_id == user.id)).first()
                    i = 1
                    while existing_file:
                        filename = f"{filename}_{i}"
                        existing_file = db.session.query(Image).filter(and_(Image.filename == filename, Image.user_id == user.id)).first()
                        i += 1
                    new_file = Image(filename=filename, user_id=user.id, image=file_data, file_metadata=file_metadata)
                    db.session.add(new_file)
                elif file_type == 'audio':
                    existing_file = db.session.query(Audio).filter(and_(Audio.filename == filename, Audio.user_id == user.id)).first()
                    i = 1
                    while existing_file:
                        filename = f"{filename}_{i}"
                        existing_file = db.session.query(Audio).filter(and_(Audio.filename == filename, Audio.user_id == user.id)).first()
                        i += 1
                    new_file = Audio(filename=filename, user_id=user.id, audio=file_data, file_metadata=file_metadata)
                    db.session.add(new_file)
            db.session.commit()
            return jsonify(success=True, message="Files uploaded successfully")
        except Exception as e:
            print("Error:", e)
            return jsonify(success=False, message="Failed to upload")

@app.route('/user_details', methods=['GET'])
@jwt_required()
def user_details():
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    username = get_jwt_identity()
    user = db.session.query(User.id, User.username, User.email).filter(User.username == username).first()

    if user:
        user_details = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'images_cnt': db.session.query(func.count()).filter(Image.user_id == user.id).scalar(),
            'audios_cnt': db.session.query(func.count()).filter(Audio.user_id == user.id).scalar()
        }
    else:
        user_details = {}

    return render_template('user_details.html', username=username, user_details=user_details)

@app.route('/images-audio-database', methods=['GET'])
@jwt_required()
def images_audio_database():
    cookie = request.cookies.get('access_token_cookie')
    if not cookie:
        return redirect('/login')
    current_user = get_jwt_identity()
    if current_user != 'admin':
        print("Error: Current user does not match requested user.")
        abort(403)
    images = db.session.query(Image).all()
    audios = db.session.query(Audio).all()
    return render_template('images_audio_database.html', username='admin', images=images, audios=audios)

@app.route('/view_video', methods=['GET'])
@csrf.exempt
def view_video():
    try:
        with open("temp/output_video.mp4", "rb") as f:
            video_data = f.read()
        headers = {'Content-Type': 'video/mp4'}
        resp = make_response(video_data, 200, headers)
        return resp
    except Exception as e:
        print("Error:", e)
        return jsonify(success=False, message="Failed to view video. Not exists")

@app.route('/render_video', methods=['POST'])
@csrf.exempt
def render_video():
    vid_details = request.get_json()
    
    print("Video details:", vid_details)
    print("Type:", type(vid_details))
    
    fps = vid_details['info']['framerate']
    resolution = vid_details['info']['resolution']

    images = []
    image_durations = []
    transitions = []
    
    for image_det in vid_details['video']['images']:
        image_id = int(image_det['image_id'])
        image = db.session.query(Image).filter(Image.id == image_id).one_or_none()
        images.append(image.image)
        transitions.append(image_det['transition']['name'])
        image_durations.append(int(image_det['duration']))
    
    audio = None
    if 'audios' in vid_details and vid_details['audios']:
        audio_id = int(vid_details['audios'][0]['audio_id'])
        audio = db.session.query(Audio).filter(Audio.id == audio_id).one_or_none()
        audio = audio.audio
    
    output_video = renderVideo(images, audio, image_durations, transitions, resolution, fps)
    with open("temp/output_video.mp4", "wb") as f:
        f.write(output_video)
    
    resp = make_response('/view_video', 200)
    return resp
