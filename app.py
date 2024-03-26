import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, session, flash, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from google.cloud import storage
from google.cloud.storage.blob import Blob

load_dotenv('pass.env')

app = Flask(__name__)
app.secret_key = os.getenv('JWT_SECRET_KEY', 'default_secret_key')
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


bucket_name = 'image_project_1'  
storage_client = storage.Client()
bucket = storage_client.bucket(bucket_name)


oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('CLIENT_ID'),  
    client_secret=os.getenv('CLIENT_SECRET'),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('show_login'))
    return render_template('index.html', user_info=user_info)

@app.route('/login')
def show_login():
    return render_template('login.html')

@app.route('/google_login')
def google_login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    resp = google.get('userinfo', token=token)
    user_info = resp.json()
    session['user_info'] = user_info
    return redirect(url_for('index'))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user_info', None)
    flash('You have been logged out.')
    return redirect(url_for('show_login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('show_login'))
    
    
    user_folder = f"{user_info['id']}/"  

    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
           
            blob = bucket.blob(user_folder + filename)
            blob.upload_from_string(file.read(), content_type=file.content_type)
            flash('File successfully uploaded')
            return redirect(url_for('uploaded_files'))
        else:
            flash('Invalid file type or no file selected')
            return redirect(request.url)
    return render_template('upload.html')


@app.route('/uploaded_files')
def uploaded_files():
     user_info = session.get('user_info')
     if not user_info:
        return redirect(url_for('show_login'))
    
    
     user_folder = f"{user_info['id']}/"  

     blobs = bucket.list_blobs(prefix=user_folder, delimiter="/")
     images = []

     for blob in blobs:
        if allowed_file(blob.name):
            signed_url = blob.generate_signed_url(
                expiration=timedelta(seconds=3600),
                version="v4",
                response_disposition=f"attachment; filename=\"{blob.name}\""
            )
            images.append({"name": blob.name.replace(user_folder, ''), "url": signed_url})

     return render_template('uploads.html', images=images)

@app.route('/delete/<filename>', methods=['POST'])
def delete_image(filename):
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('show_login'))
    
    user_folder = f"{user_info['id']}/"
    blob = bucket.blob(user_folder + filename)
    
    if blob.exists():
        blob.delete()
        flash(f"{filename} has been deleted.")
    else:
        flash(f"Error: {filename} not found.")
    return redirect(url_for('uploaded_files'))

if __name__ == '__main__':
    app.run(debug=True)
