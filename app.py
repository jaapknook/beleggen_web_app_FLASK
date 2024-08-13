from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import os
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
import gridfs

app = Flask(__name__)
app.secret_key = 'supersecretkey'
API_KEY = os.environ.get('API_KEY')
#API_KEY = "jaapknook:AW539wrGEaoq97XY"
app.config["MONGO_URI"] = f"mongodb+srv://{API_KEY}@cluster0.n84sjfo.mongodb.net/file_upload_db?retryWrites=true&w=majority&appName=Cluster0"

# Initialize PyMongo
try:
    mongo = PyMongo(app)
    mongo.db.users.find_one()  # Test connection by accessing a collection
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    mongo = None

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
fs = gridfs.GridFS(mongo.db)

class User(UserMixin):
    def __init__(self, _id, username, password):
        self.id = _id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    if mongo is None:
        return None
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(str(user['_id']), user['username'], user['password'])
    return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('upload'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('upload'))

    if request.method == 'POST':
        if mongo is None:
            flash('Database connection issue', 'danger')
            return redirect(url_for('login'))

        username = request.form['username']
        password = request.form['password']
        user = mongo.db.users.find_one({"username": username})
        if user and bcrypt.check_password_hash(user['password'], password):
            user_obj = User(str(user['_id']), user['username'], user['password'])
            login_user(user_obj)
            return redirect(url_for('upload'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('upload'))

    if request.method == 'POST':
        if mongo is None:
            flash('Database connection issue', 'danger')
            return redirect(url_for('register'))

        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_id = mongo.db.users.insert_one({
            "username": username,
            "password": hashed_password
        }).inserted_id
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if mongo is None:
        flash('Database connection issue', 'danger')
        return redirect(url_for('upload'))

    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
        if file and file.filename.endswith('.csv'):
            filename = secure_filename(file.filename)
            file_id = fs.put(file, filename=secure_filename(file.filename), user_id=ObjectId(current_user.id))
            mongo.db.files.insert_one({
                "filename": filename,
                "file_id": file_id,
                "user_id": ObjectId(current_user.id)
            })
            return redirect(url_for('view_files'))

    return render_template('upload.html')

@app.route('/files')
@login_required
def view_files():
    if mongo is None:
        flash('Database connection issue', 'danger')
        return redirect(url_for('files'))

    files = mongo.db.files.find({"user_id": ObjectId(current_user.id)})
    return render_template('view_files.html', files=files)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_record = mongo.db.files.find_one({"filename": filename, "user_id": ObjectId(current_user.id)})
    if not file_record:
        return 'File not found', 404

    # Retrieve the file from GridFS
    file_data = fs.get(file_record['file_id'])
    return Response(file_data.read(), mimetype='text/csv', headers={"Content-Disposition": f"attachment;filename={filename}"})

if __name__ == '__main__':
    app.run(debug=True)
