from flask import redirect, session
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("group_name") is None:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function
