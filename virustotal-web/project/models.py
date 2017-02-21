from project import db, bcrypt
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property
from datetime import datetime

class Report(db.Model):

    __tablename__ = 'report'

    hash_value = db.Column(db.String, primary_key=True)
    Fortinet_detection = db.Column(db.String, nullable=True)
    detected_number = db.Column(db.Integer, nullable=True)
    scan_date = db.Column(db.DateTime, nullable=True)
    user_email = db.Column(db.String, nullable=False)
    filename = db.Column(db.String, nullable=False)
    scanned = db.Column(db.Boolean, nullable=False)

    def __init__(self, hash_value, Fortinet_detection, detected_number, scan_date, user_email, filename, scanned):
            self.hash_value = hash_value
            self.Fortinet_detection = Fortinet_detection
            self.detected_number = detected_number
            self.scan_date = scan_date
            self.user_email = user_email
            self.filename = filename
            self.scanned = scanned

    def __repr__(self):
        return '<Report {}>'.format(self.hash_value)

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String, unique=True, nullable=False)
    _password = db.Column(db.Binary(60), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    registered_on = db.Column(db.DateTime, nullable=True)
    last_logged_in = db.Column(db.DateTime, nullable=True)
    current_logged_in = db.Column(db.DateTime, nullable=True)
    role = db.Column(db.String, default='user')

    def __init__(self, email, plaintext_password, role='user'):
        self.email = email
        self.password = plaintext_password
        self.authenticated = False
        self.registered_on = datetime.now()
        self.last_logged_in = None
        self.current_logged_in = datetime.now()
        self.role = role

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def set_password(self, plaintext_password):
        self._password = bcrypt.generate_password_hash(plaintext_password)

    @hybrid_method
    def is_correct_password(self, plaintext_password):
        return bcrypt.check_password_hash(self.password, plaintext_password)

    @property
    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    @property
    def is_active(self):
        """Always True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return str(self.id)

    def __repr__(self):
        return '<User {}>'.format(self.email)

