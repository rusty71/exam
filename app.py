from flask import Flask, request, flash, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField, SelectField, RadioField, SelectMultipleField
from wtforms.validators import InputRequired, DataRequired, Email, Length
from wtforms import widgets
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import flask_admin
from flask_admin.contrib.sqla import ModelView
import json

#setup App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sd/lkkfjg;osaohdg;jahddg!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/jeroen/dev/ap/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
#using bootstrap
Bootstrap(app)
#SQLAlchemy as ORM
db = SQLAlchemy(app)
#include admin
admin = flask_admin.Admin(app)
#Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#user table
class User(UserMixin, db.Model):
    #columns
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    teacher = db.Column(db.Boolean)
    #references
    results = db.relationship('Result', backref='user', lazy=True)

#association table for many-to-many relationship between Exam and Question
#https://codeseekah.com/2013/08/04/flask-admin-hacks-for-many-to-many-relationships/
#https://www.youtube.com/watch?v=OvhoYbjtiKc
exams_questions = db.Table(
    "exams_questions",
    db.Column("exam_id", db.Integer, db.ForeignKey("exam.id")),
    db.Column("question_id", db.Integer, db.ForeignKey("question.id")),
)

#question table
class Question(db.Model):
    #columns
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(256))
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    chapter = db.Column(db.Integer)
    #references
    answers = db.relationship('Answer', backref='question', lazy=True)
    results = db.relationship('Result', backref='question', lazy=True)

#answer table
class Answer(db.Model):
    #columns
    id = db.Column(db.Integer, primary_key=True)
    answer = db.Column(db.String(120), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    correct = db.Column(db.Boolean)
    #references
    results = db.relationship('Result', backref='answer', lazy=True)

class Book(db.Model):
    #columns
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), unique=True, nullable=False)
    #references
    question = db.relationship('Question', backref='book', lazy=True)

#Just a collection of questions. Later we can make 'generators' that make
#exams out of specific selection criteria like book, chapter (category?)
class Exam(db.Model):
    #columns
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    active = db.Column(db.Boolean)
    #references
    questions = db.relationship( 'Question', backref=db.backref('exams', lazy='dynamic'), secondary='exams_questions' ) #this is the many to many backref
    results = db.relationship('Result', backref='exam', lazy=True)

#result table has one row for each question answered
class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    answer_id = db.Column(db.Integer, db.ForeignKey('answer.id'), nullable=False)

    #helper function
    def is_correct(self):
        #see if the answer is correct
        return self.answer.correct

#this subclasses the admin Modelview for teacher authentication
class TeacherModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.teacher

    def inaccessible_callback(self, name, **kwargs):
        # redirect to login page if user doesn't have access
        return redirect(url_for('login', next=request.url))
#Add tables to admin interface
admin.add_view(TeacherModelView(User, db.session))
admin.add_view(TeacherModelView(Answer, db.session))
admin.add_view(TeacherModelView(Question, db.session))
admin.add_view(TeacherModelView(Book, db.session))
admin.add_view(TeacherModelView(Exam, db.session))
admin.add_view(TeacherModelView(Result, db.session))

#User input forms
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
    submit = SubmitField('Submit')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    teacher = BooleanField('teacher')
    submit = SubmitField('Submit')

class ToestUploadForm(FlaskForm):
    filename = FileField()
    submit = SubmitField('Submit')

class UserUploadForm(FlaskForm):
    filename = FileField()
    submit = SubmitField('Submit')

class QuestionForm(FlaskForm):
    attempted_answer = RadioField(
                                'attempted_answer',
                                choices=[('option1', 'A'), ('option2', 'B'), ('option3', 'C'), ('option4', 'D')],
                                validators=[DataRequired()],
                                )
    prevq = SubmitField("Prev")
    nextq = SubmitField("Next")

#show an overview of a exam
@app.route('/overview/<e_id>')
@login_required
def overview(e_id=None):
    #get exam from db
    exam=Exam.query.get(e_id)
    #get questions from exam
    questions=exam.questions
    #get students
    users=User.query.filter_by(teacher=False).all()
    results = []   #2d array of results
    for user in users:
        user_answers = []
        for question in questions:
            result=Result.query.filter_by(user=user, question=question).first()
            user_answers.append(result)

        results.append(user_answers)

    return render_template('overview.html', user=current_user, users=users, questions=questions, results=zip(users,results))    

@app.route('/exam/<e_id>/<q_id>', methods=['GET', 'POST'])
@login_required
def exam(e_id=None, q_id=None):
    #get exam from db
    exam = Exam.query.get(e_id)
    #get questions from  Exam
    #~ questions=Exam.query.get(e_id).questions
    questions=exam.questions
    #finds the current question with <q_id>
    try:
        question=[x for x in questions if x.id==int(q_id)][0]
    except:
        question=None   #question not found, is error
    #show error
    if (not question) or (not exam):
        #should be handled/redirected
        return "<h1>Exam or Question doesn't exists</h1>"

    #find existing result
    result=Result.query.filter_by(exam_id=exam.id, user_id=current_user.id, question_id=question.id).first()
    if result:  #create new result in no result exists yet
        #get result index inquestion list
        r_index=(question.answers.index(result.answer))
        #create a question form, set stored result
        form = QuestionForm(attempted_answer=str(r_index))    
    else:   #no result yet
        result = Result()
        #create a question form, no result set
        form = QuestionForm()    

    #fill in the possible answers 
    form.attempted_answer.choices=[("%d" % (n),x.answer) for n,x in enumerate(question.answers)]

    #when answer is given and validated
    if form.validate_on_submit():
        #get the answer selected by the user. TODO:error check
        answer = question.answers[int(request.values.get("attempted_answer"))]
        result.user_id = current_user.id
        result.exam_id = exam.id
        result.question_id=question.id
        result.answer_id = answer.id
        db.session.add(result)
        db.session.commit()        
        #decide what comes next based on button pressed and questions available
        #TODO: this is ugly
        #better to remove next, prev buttons at start and end
        #form.my_field.render_kw = {'disabled': 'disabled'}
        q_index = questions.index(question)    #index of current question
        if request.values.get("nextq"):  #if next button pressed
            q_index = q_index + 1
        if request.values.get("prevq"):  #if prev button pressed
            q_index = q_index - 1
        if q_index >= len(questions):  #stick at last question
            q_index = len(questions) - 1
        if q_index < 0:                #stick at first question
            q_index = 0
        next_question = questions[q_index].id
        #move to next/previous/current question
        return redirect(url_for('exam', e_id=exam.id, q_id=next_question))

    return render_template('exam.html', user=current_user, question=question.question, form=form)

@app.route('/')
@login_required
def index():
    #get list of active exams
    exams=Exam.query.filter_by(active=True)
    return render_template('index.html', exams=exams, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                referrer_url = request.values.get('next')
                if referrer_url == None:
                    referrer_url = '/'
                return redirect(request.values.get('next'))
        flash('<h1>Invalid username or password</h1>')

    return render_template('login.html', form=form, user=current_user)  #template needs user, strange

@app.route('/signup', methods=['GET', 'POST'])
@login_required
def signup():

    if not current_user.teacher:
        return "<h1>Only teachers can register users</h1>"
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'

    return render_template('signup.html', user=current_user, form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/toets_upload', methods=['GET', 'POST'])
@login_required
def toets_upload():
    if not current_user.teacher:
        return "<h1>Only teachers can submit</h1>"
    form = ToestUploadForm()
    if request.method == 'POST':
        if 'filename' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['filename']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            toets = json.loads(file.stream.read())
            import_toets(toets)
            flash("Toets geladen")
            #~ return('<h1>Toets geladen</h1>')
    return render_template('toets_upload.html', form=form)

@app.route('/user_upload', methods=['GET', 'POST'])
#~ @login_required
def user_upload():
    #~ if not current_user.teacher:
        #~ return "<h1>Only teachers can submit</h1>"
    form = ToestUploadForm()
    if request.method == 'POST':
        if 'filename' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['filename']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            users = json.loads(file.stream.read())
            import_users(users)
            flash("Users loader")
    return render_template('user_upload.html', form=form)

#this is where the users are loaded in the db
# Check json tith : http://www.jsoneditoronline.org/
def import_users(users):
    for u in users['users']:
        user = User.query.filter_by(username=u['username']).first() #only one can exist
        if not user:
            user = User()
            user.username = u['username']
            user.email = u['email']
            user.teacher = u['teacher']
            user.password = hashed_password = generate_password_hash(u['password'], method='sha256') #dont store plaintext passwords
            db.session.add(user)
            db.session.commit()

#this is where the exam is loaded in the db
#only for development.
def import_toets(toets):
    book = Book.query.filter_by(title=toets['book']).first()
    if book:    #already exists
        flash("Book found!", toets['book'])
    else:   #create new book
        flash("adding book", toets['book'])
        book = Book()
        book.title = toets['book']
        db.session.add(book)
        db.session.commit()     #need to commit to get id
    #~ book = Book.query.filter_by(title=toets['book']).first()
    if book:
        flash(book.id)
        flash(book.title)

    exam = Exam.query.filter_by(name="TOETS:" + str(toets['chapter'])).first()
    if not exam:    #if not yet Exam exists with same chapter and book_id
        exam = Exam()
        exam.book_id = book.id
        exam.name = "TOETS:" + str(toets['chapter'])
        exam.active = False
        db.session.add(exam)
        db.session.commit()

    #import questions and answers
    for q in toets['questions']:
        #avoid duplicates, ugly this is
        question = Question.query.filter_by(book_id=book.id, chapter=toets['chapter'], question=q['question']).first()
        if not question:
            question = Question()
            question.question = q['question']
            question.book_id = book.id
            question.chapter = toets['chapter']
            exam.questions.append(question)
            db.session.add(question)
            db.session.commit() #to get an .id
        for a in q['answers']:
            #avoid duplicates, ugly this is
            answer = Answer.query.filter_by(question_id = question.id, answer = a['answer']).first()
            if not answer:
                answer = Answer()
                answer.answer = a['answer']
                answer.question_id = question.id
                answer.correct = a['correct']
                db.session.add(answer)
                db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)


