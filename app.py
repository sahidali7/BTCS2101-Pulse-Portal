import os, re, csv, io, secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'pulse.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
db = SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(160), unique=True, nullable=True)
    enrollment = db.Column(db.String(100), unique=True, nullable=True, index=True)
    role = db.Column(db.String(20), nullable=False, default='student')
    password_hash = db.Column(db.String(255), nullable=False)
    approved = db.Column(db.Boolean, default=True, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(50), default='General')
    body = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    subject = db.Column(db.String(120), default='General')
    description = db.Column(db.Text, default='')
    due_date = db.Column(db.String(30), default='')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Completion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('assignment_id', 'student_id', name='unique_completion'),)

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    subject = db.Column(db.String(120), default='General')
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    downloads = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ResetRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(300), default='')
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def log_action(action):
    db.session.add(Activity(user_id=session.get('user_id'), action=action))
    db.session.commit()

def current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None

@app.context_processor
def inject_globals():
    return {'current_user': current_user(), 'now': datetime.utcnow}

def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash('Please log in to continue.', 'error'); return redirect(url_for('home'))
            if not user.active:
                session.clear(); flash('This account is inactive. Contact the administrator.', 'error'); return redirect(url_for('home'))
            if not user.approved:
                session.clear(); flash('Your faculty account is awaiting admin approval.', 'error'); return redirect(url_for('home'))
            if role and user.role not in ([role] if isinstance(role, str) else role):
                flash('You do not have permission to access that page.', 'error'); return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def create_defaults():
    """Create tables and optionally bootstrap an admin from environment variables."""
    db.create_all()
    admin_username = os.environ.get("PULSE_ADMIN_USERNAME", "").strip()
    admin_password = os.environ.get("PULSE_ADMIN_PASSWORD", "")
    if admin_username and admin_password:
        admin = User.query.filter_by(username=admin_username).first()
        if admin is None:
            db.session.add(User(
                full_name=os.environ.get("PULSE_ADMIN_NAME", "System Administrator"),
                username=admin_username,
                email=os.environ.get("PULSE_ADMIN_EMAIL") or None,
                role="admin",
                password_hash=generate_password_hash(admin_password),
                approved=True,
                active=True
            ))
            db.session.commit()
    # Demo accounts are deliberately not seeded with public passwords.

@app.route('/')
def home():
    if current_user(): return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/login/<role>', methods=['GET','POST'])
def login(role):
    if role not in ('student','faculty','admin'): return redirect(url_for('home'))
    if request.method == 'POST':
        identity = request.form.get('identity','').strip()
        password = request.form.get('password','')
        # Enrollment IDs are case-insensitive and tolerate accidental surrounding spaces.
        normalized = identity.casefold()
        user = User.query.filter(
            (db.func.lower(User.username) == normalized) |
            (db.func.lower(User.enrollment) == normalized) |
            (db.func.lower(User.email) == normalized)
        ).first()
        if not user or user.role != role or not check_password_hash(user.password_hash, password):
            flash(f'Invalid {role} credentials. Check that you are using the correct login page.', 'error')
        elif not user.active:
            flash('Your account is inactive. Contact the administrator.', 'error')
        elif not user.approved:
            flash('Your faculty registration is pending admin approval.', 'error')
        else:
            session.clear(); session['user_id'] = user.id
            log_action(f'{role.capitalize()} logged in')
            return redirect(url_for('dashboard'))
    return render_template('login.html', role=role)

@app.route('/signup/student', methods=['GET','POST'])
def student_signup():
    if request.method == 'POST':
        name = request.form.get('full_name','').strip(); enrollment = request.form.get('enrollment','').strip()
        username = request.form.get('username','').strip(); email = request.form.get('email','').strip().lower(); password = request.form.get('password','')
        if not name or not enrollment or not username or not password:
            flash('Please complete all required fields.', 'error')
        elif not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/._-]{3,99}', enrollment):
            flash('Enter a valid enrollment number. Letters, numbers and / . _ - are allowed.', 'error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
        elif User.query.filter((User.username == username) | (User.enrollment == enrollment) | ((User.email == email) if email else (User.id == -1))).first():
            flash('Username, enrollment number or email is already registered.', 'error')
        else:
            user = User(full_name=name, enrollment=enrollment, username=username, email=email or None, role='student', password_hash=generate_password_hash(password), approved=True)
            db.session.add(user); db.session.commit(); flash('Student account created. You can now log in.', 'success'); return redirect(url_for('login', role='student'))
    return render_template('signup.html', role='student')

@app.route('/signup/faculty', methods=['GET','POST'])
def faculty_signup():
    if request.method == 'POST':
        name=request.form.get('full_name','').strip(); username=request.form.get('username','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
        if not name or not username or not email or not password: flash('Please complete all required fields.', 'error')
        elif len(password) < 8: flash('Password must be at least 8 characters.', 'error')
        elif User.query.filter((User.username == username) | (User.email == email)).first(): flash('Username or email is already registered.', 'error')
        else:
            db.session.add(User(full_name=name, username=username, email=email, role='faculty', password_hash=generate_password_hash(password), approved=False)); db.session.commit()
            flash('Faculty registration submitted. You can log in after admin approval.', 'success'); return redirect(url_for('login', role='faculty'))
    return render_template('signup.html', role='faculty')

@app.route('/logout')
def logout():
    if current_user(): log_action('User logged out')
    session.clear(); flash('You have been logged out.', 'success'); return redirect(url_for('home'))

@app.route('/dashboard')
@login_required()
def dashboard():
    user=current_user(); query=request.args.get('q','').strip()
    notices=Notice.query.order_by(Notice.created_at.desc()).all(); assignments=Assignment.query.order_by(Assignment.created_at.desc()).all(); materials=Material.query.order_by(Material.created_at.desc()).all()
    if query:
        notices=[n for n in notices if query.lower() in (n.title+' '+n.body+' '+n.category).lower()]
        assignments=[a for a in assignments if query.lower() in (a.title+' '+a.subject+' '+a.description).lower()]
        materials=[m for m in materials if query.lower() in (m.title+' '+m.subject+' '+m.original_name).lower()]
    completed_ids={c.assignment_id for c in Completion.query.filter_by(student_id=user.id).all()} if user.role=='student' else set()
    stats={'students':User.query.filter_by(role='student').count(),'faculty':User.query.filter_by(role='faculty').count(),'pending_faculty':User.query.filter_by(role='faculty',approved=False).count(),'assignments':Assignment.query.count(),'notices':Notice.query.count(),'materials':Material.query.count(),'reset_requests':ResetRequest.query.filter_by(status='pending').count()}
    return render_template('dashboard.html', user=user, notices=notices, assignments=assignments, materials=materials, completed_ids=completed_ids, stats=stats, query=query)

@app.route('/assignments/<int:aid>/complete', methods=['POST'])
@login_required('student')
def complete_assignment(aid):
    a=db.session.get(Assignment,aid)
    if not a: flash('Assignment not found.', 'error')
    elif not Completion.query.filter_by(assignment_id=aid,student_id=current_user().id).first():
        db.session.add(Completion(assignment_id=aid,student_id=current_user().id)); db.session.commit(); log_action(f'Completed assignment #{aid}'); flash('Assignment marked completed.', 'success')
    else: flash('This assignment is already marked completed.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/faculty/notice', methods=['POST'])
@login_required(['faculty','admin'])
def add_notice():
    title=request.form.get('title','').strip(); body=request.form.get('body','').strip(); category=request.form.get('category','General').strip()
    if title and body:
        db.session.add(Notice(title=title,body=body,category=category,created_by=current_user().id)); db.session.commit(); log_action('Created notice: '+title); flash('Notice published.', 'success')
    else: flash('Notice title and message are required.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/faculty/assignment', methods=['POST'])
@login_required(['faculty','admin'])
def add_assignment():
    title=request.form.get('title','').strip(); subject=request.form.get('subject','General').strip(); desc=request.form.get('description','').strip(); due=request.form.get('due_date','').strip()
    if title:
        db.session.add(Assignment(title=title,subject=subject,description=desc,due_date=due,created_by=current_user().id)); db.session.commit(); log_action('Created assignment: '+title); flash('Assignment added.', 'success')
    else: flash('Assignment title is required.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/faculty/material', methods=['POST'])
@login_required(['faculty','admin'])
def upload_material():
    f=request.files.get('file'); title=request.form.get('title','').strip(); subject=request.form.get('subject','General').strip()
    if not f or not f.filename or not title: flash('Provide a title and choose a file.', 'error'); return redirect(url_for('dashboard'))
    original=f.filename; safe=secure_filename(original)
    if not safe: flash('Invalid filename.', 'error'); return redirect(url_for('dashboard'))
    stored=secrets.token_hex(8)+'_'+safe; f.save(os.path.join(app.config['UPLOAD_FOLDER'],stored))
    db.session.add(Material(title=title,subject=subject,filename=stored,original_name=original,uploaded_by=current_user().id)); db.session.commit(); log_action('Uploaded material: '+title); flash('Material uploaded.', 'success'); return redirect(url_for('dashboard'))

@app.route('/materials/<int:mid>/download')
@login_required()
def download_material(mid):
    m=db.session.get(Material,mid)
    if not m: flash('Material not found.', 'error'); return redirect(url_for('dashboard'))
    m.downloads += 1; db.session.commit(); log_action('Downloaded material: '+m.title)
    return send_from_directory(app.config['UPLOAD_FOLDER'],m.filename,as_attachment=True,download_name=m.original_name)

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method=='POST':
        identity=request.form.get('identity','').strip(); message=request.form.get('message','').strip()
        user=User.query.filter((User.username==identity)|(User.enrollment==identity)|(User.email==identity)).first()
        if not user or user.role=='admin': flash('No eligible account found. Contact your administrator directly.', 'error')
        elif ResetRequest.query.filter_by(user_id=user.id,status='pending').first(): flash('A pending request already exists for this account.', 'success'); return redirect(url_for('forgot_password'))
        else:
            db.session.add(ResetRequest(user_id=user.id,message=message)); db.session.commit(); log_action(f'Password reset requested for user #{user.id}'); flash('Reset request sent to the administrator.', 'success'); return redirect(url_for('login',role=user.role))
    return render_template('forgot.html')

@app.route('/admin')
@login_required('admin')
def admin_panel():
    users=User.query.order_by(User.created_at.desc()).all(); requests=ResetRequest.query.order_by(ResetRequest.created_at.desc()).all(); activities=Activity.query.order_by(Activity.created_at.desc()).limit(100).all()
    return render_template('admin.html',users=users,requests=requests,activities=activities)

@app.route('/admin/faculty/<int:uid>/<action>', methods=['POST'])
@login_required('admin')
def faculty_approval(uid,action):
    u=db.session.get(User,uid)
    if not u or u.role!='faculty' or action not in ('approve','reject'): flash('Invalid faculty action.', 'error')
    elif action=='approve': u.approved=True; db.session.commit(); log_action(f'Approved faculty user #{uid}'); flash('Faculty approved.', 'success')
    else: db.session.delete(u); db.session.commit(); log_action(f'Rejected faculty user #{uid}'); flash('Faculty registration rejected.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:uid>/toggle', methods=['POST'])
@login_required('admin')
def toggle_user(uid):
    u=db.session.get(User,uid)
    if not u or u.id==current_user().id: flash('Cannot change this account.', 'error')
    else: u.active=not u.active; db.session.commit(); log_action(f'Changed active status for user #{uid}'); flash('Account status updated.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:uid>/reset', methods=['POST'])
@login_required('admin')
def admin_reset(uid):
    u=db.session.get(User,uid); password=request.form.get('new_password','')
    if not u or u.role=='admin': flash('User not found or admin reset is not allowed here.', 'error')
    elif len(password)<8: flash('New password must be at least 8 characters.', 'error')
    else:
        u.password_hash=generate_password_hash(password)
        for rr in ResetRequest.query.filter_by(user_id=uid,status='pending').all(): rr.status='resolved'
        db.session.commit(); log_action(f'Admin reset password for user #{uid}'); flash(f'Password reset for {u.username}. Share the temporary password securely.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/request/<int:rid>/dismiss', methods=['POST'])
@login_required('admin')
def dismiss_request(rid):
    r=db.session.get(ResetRequest,rid)
    if r: r.status='dismissed'; db.session.commit(); log_action(f'Dismissed reset request #{rid}'); flash('Request dismissed.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/export/<kind>')
@login_required('admin')
def export_csv(kind):
    output=io.StringIO(); writer=csv.writer(output)
    if kind=='users':
        writer.writerow(['ID','Full name','Username','Email','Enrollment','Role','Approved','Active','Created'])
        for u in User.query.order_by(User.id).all(): writer.writerow([u.id,u.full_name,u.username,u.email or '',u.enrollment or '',u.role,u.approved,u.active,u.created_at])
    elif kind=='completions':
        writer.writerow(['Student','Enrollment','Assignment','Subject','Completed at'])
        for c in Completion.query.all():
            u=db.session.get(User,c.student_id); a=db.session.get(Assignment,c.assignment_id)
            writer.writerow([u.full_name if u else '',u.enrollment if u else '',a.title if a else '',a.subject if a else '',c.completed_at])
    else: return redirect(url_for('admin_panel'))
    response=make_response('\ufeff'+output.getvalue()); response.headers['Content-Type']='text/csv; charset=utf-8'; response.headers['Content-Disposition']=f'attachment; filename={kind}.csv'; return response

@app.route('/admin/delete/<kind>/<int:item_id>', methods=['POST'])
@login_required('admin')
def delete_content(kind,item_id):
    model={'notice':Notice,'assignment':Assignment,'material':Material}.get(kind)
    obj=db.session.get(model,item_id) if model else None
    if obj:
        if kind=='material':
            try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'],obj.filename))
            except OSError: pass
        db.session.delete(obj); db.session.commit(); log_action(f'Admin deleted {kind} #{item_id}'); flash(f'{kind.capitalize()} deleted.', 'success')
    else: flash('Item not found.', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(413)
def too_large(_):
    flash('File is too large. Maximum upload size is 16 MB.', 'error'); return redirect(url_for('dashboard'))

with app.app_context(): create_defaults()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
