from login_form.db import get_db
from werkzeug.security import check_password_hash, generate_password_hash

class User():
  
  @classmethod
  def create(cls, username, password):
    db = get_db()
    hashed_password = generate_password_hash(password)
    try:
      db.execute(
        "INSERT INTO user (username, password) VALUES (?, ?)",
        (username, hashed_password)
      )
      db.commit()
      return None
    except Exception as e:
      print(f"User creation error: {e}")
      if 'UNIQUE constraint failed: user.username' in str(e):
        return 'Username already exists.'
      return 'Registration error.'

  @classmethod
  def find_with_credentials(cls, username, password):
    db = get_db()
    user = db.execute(
      "SELECT id, username, password FROM user WHERE username = ?",
      (username,)
    ).fetchone()
    print(user)
    if user and check_password_hash(user['password'], password):
      return cls(user['username'], user['password'], user['id'])
    else:
      return None

  @classmethod
  def find_by_id(cls, user_id):
    user = get_db().execute(
      'SELECT id, username, password FROM user WHERE id = ?', (user_id,)
    ).fetchone()
    if user:
      return User(user['username'], user['password'], user['id'])
    else:
      return None

  def __init__(self, username, password, id):
    self.username = username
    self.password = password
    self.id = id

