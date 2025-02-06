import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///project.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])

def index():
    session.clear()

    if request.method == "GET":
        return render_template("index.html")

    if request.form.get("choice1") == "join":
        return redirect("/join")
    if request.form.get("choice2") == "create":
        return redirect("/create")


    return redirect("/")

@app.route("/join", methods=["GET", "POST"])
def join():

    session.clear()

    if request.method == "GET":
        return render_template("join.html")

    group_name = request.form.get("group_name")
    group_pw = request.form.get("group_pw")

    error = None
    if not group_name or not group_pw:
        error = 'Invalid group name/password'
        return render_template("join.html", error = error)
    rows = db.execute("SELECT * FROM groups WHERE name = ?", group_name)
    if len(rows) != 1:
        error = 'Group does not exist'
        return render_template("join.html", error = error)
    if not check_password_hash(rows[0]["hash"], group_pw):
        error = 'Incorrect password'
        return render_template("join.html", error = error)
    #remembers which user is logged in
    session["group_name"] = rows[0]["name"]

    check_phone_pres = db.execute("SELECT * FROM groups WHERE name = ? AND phone_number IS NOT NULL AND email IS NOT NULL", session["group_name"])
    if len(check_phone_pres) == 1:
        return render_template("homepage.html", group_name=session["group_name"], group_pw=group_pw, link='0')

    return render_template("homepage.html", group_name=group_name, group_pw=group_pw, link='1')


@app.route("/create", methods=["GET", "POST"])
def create():

    session.clear()

    if request.method == "GET":
        return render_template("create.html")

    group_name = request.form.get("group_name")
    group_pw = request.form.get("group_pw")
    confirmation = request.form.get("confirmation")

    error = None
    if not group_name or not group_pw or not confirmation:
        error = 'Invalid group name/password'
        return render_template("create.html", error = error)

    rows = db.execute("SELECT name FROM groups WHERE name = ?", group_name)
    if len(rows) != 0:
        error = 'This group name is already in use'
        return render_template("create.html", error = error)

    if group_pw != confirmation:
        error = 'Passwords do not match.'
        return render_template("create.html", error = error)


    hash_pw = generate_password_hash(group_pw)
    db.execute("INSERT INTO groups (name, hash) VALUES (?, ?)", group_name, hash_pw)
    rows = db.execute("SELECT name FROM groups WHERE name = ?", group_name)


    session["group_name"] = rows[0]["name"]

    check_phone_pres = db.execute("SELECT * FROM groups WHERE name = ? AND phone_number IS NOT NULL AND email IS NOT NULL", session["group_name"])
    if len(check_phone_pres) == 1:
        return render_template("homepage.html", group_name=session["group_name"], group_pw=group_pw, link='0')

    return render_template("homepage.html", group_name=group_name, group_pw=group_pw, link='1')

@app.route("/recover", methods=["GET", "POST"])
def recover():
    session.clear()
    if request.method == "GET":
        error = ''
        return render_template("recover.html", error=error)


    group_name = request.form.get("group_name")

    #no group name
    if not group_name:
        error = 'Group name cannot be empty.'
        return render_template("recover.html", error=error)

    #do a check if group_name exists in db
    rows = db.execute("SELECT name FROM groups WHERE name = ?", group_name)
    if len(rows) != 1:
        error = 'Group name does not exist.'
        return render_template("recover.html", error=error)

    #phone number path
    phone_number = request.form.get("phone_number")
    if phone_number:
        # catch non int
        try:
            phone_int = int(phone_number)
        except ValueError:
            error = 'Invalid phone number.'
            return render_template("recover.html", error=error)
        # catch non 8 digit
        if phone_int < 10000000 or phone_int > 99999999:
            error = 'Invalid phone number.'
            return render_template("recover.html", error=error)

        #catch unexisting
        phone_check = db.execute("SELECT * FROM groups WHERE name = ? AND phone_number = ?", group_name, phone_int)
        if len(phone_check) != 1:
            error = 'Incorrect group name or phone number.'
            return render_template("recover.html", error=error)

        #all good phone
        session["group_name"] = group_name

        success='Authentication Success!'
        return render_template("change.html", success=success)

    #email path
    email = request.form.get("email")
    if email:
        # catches non email address
        if '@' not in email or '.com' not in email:
            error = 'Invalid email address.'
            return render_template("recover.html", error=error)
        # catches unexisting
        email_check = db.execute("SELECT * FROM groups WHERE name = ? AND email = ?", group_name, email)
        if len(email_check) != 1:
            error = 'Incorrect group name or email address.'
            return render_template("recover.html", error=error)

        #all good email
        session["group_name"] = group_name

        success='Authentication Success!'
        return render_template("change.html", success=success)

    #below this is phone number or email blank
    if not phone_number and not email:
        error = 'Phone number/Email address cannot be empty.'
        return render_template("recover.html", error=error)



@app.route("/homepage", methods=["GET", "POST"])
@login_required
def homepage():
    if request.form.get("choice1") == "shopper":
        return redirect("/shopper")


    if request.form.get("choice1") == "appender":
        return redirect("/appender")


    # if inspect and change submission (only for choice1)
    # checks linked/not linked phone email, and group name for homepage
    check_phone_pres = db.execute("SELECT * FROM groups WHERE name = ? AND phone_number IS NOT NULL AND email IS NOT NULL", session["group_name"])
    if len(check_phone_pres) == 1:
        return render_template("homepage.html", group_name=session["group_name"], link='0')

    return render_template("homepage.html", group_name=session["group_name"], link='1')


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "GET":
        return render_template("change.html")

    new_pw_one = request.form.get("new_pw_one")
    if not new_pw_one:
        return render_template("change.html", error='New password cannot be empty.')
    new_pw_two = request.form.get("new_pw_two")
    if not new_pw_two:
        return render_template("change.html", error='Password confirmation cannot be empty.')
    if new_pw_one != new_pw_two:
        return render_template("change.html", error='Passwords do not match.')

    # alls good
    #update db
    db.execute("UPDATE groups SET hash = ? WHERE name = ?", generate_password_hash(new_pw_one), session["group_name"])
    #get group name for homepage
    group_name = session["group_name"]
    #check linked/unlinked for homepage
    check_phone_pres = db.execute("SELECT * FROM groups WHERE name = ? AND phone_number IS NOT NULL AND email IS NOT NULL", session["group_name"])
    if len(check_phone_pres) == 1:
        return render_template("homepage.html", group_name=session["group_name"], group_pw=new_pw_one, link='0', success='Successfully changed password!')

    return render_template("homepage.html", group_name=group_name, group_pw=new_pw_one, link='1', success='Successfully changed password!')


@app.route("/link", methods=["GET", "POST"])
@login_required
def link():
    if request.method == "GET":
        return render_template("link.html")

    phone = request.form.get("phone")
    #if exist then update, otherwise fine
    if phone:
        #check is 8digit
        try:
            phone_int = int(phone)
        except ValueError:
            return render_template("link.html", error='Phone number is not valid')
        if phone_int < 10000000 or phone_int > 99999999:
            return render_template("link.html", error='Phone number is not valid')
        #all fine
        db.execute("UPDATE groups SET phone_number = ? WHERE name = ?", phone_int, session["group_name"])

    email = request.form.get("email")
    if email:
        if '@' not in email or '.com' not in email:
            return render_template("link.html", error='Email address is not valid')
        #all good
        db.execute("UPDATE groups SET email = ? WHERE name = ?", email, session["group_name"])


    check_phone_pres = db.execute("SELECT * FROM groups WHERE name = ? AND phone_number IS NOT NULL AND email IS NOT NULL", session["group_name"])
    if len(check_phone_pres) == 1:
        if phone and email:
            return render_template("homepage.html", group_name=session["group_name"], link='0', success='Successfully linked phone number and email address!')
        return render_template("homepage.html", group_name=session["group_name"], link='0')

    return render_template("homepage.html", group_name=session["group_name"], link='1')


@app.route("/appender", methods=["GET", "POST"])
@login_required
def appender():

    if request.method == "GET":
        item_list = db.execute("SELECT DISTINCT item FROM record WHERE group_name = ?", session["group_name"])
        pf = {}
        df = {}
        ig = {}
        st = {}
        for item in item_list:
            item_name = item["item"]
            quantity_list = db.execute("SELECT quantity FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            sum = 0
            for eachitem in quantity_list:
                number = eachitem["quantity"]
                sum = sum + number
            if sum != 0:
                pf[item_name] = sum

            desc = db.execute("SELECT description FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            df[item_name] = desc[0]["description"]

            img = db.execute("SELECT image FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            ig[item_name] = img[0]["image"]

            stat = db.execute("SELECT status FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            st[item_name] = stat[0]["status"]


        empty = ''
        if not pf:
            empty = 'This ShopList is empty. Start appending!'

        last_entry = db.execute("SELECT * FROM record WHERE group_name = ? ORDER BY time DESC LIMIT 1", session["group_name"])
        last_action = ''
        if len(last_entry) == 0:
            return render_template("appender.html", last_action=last_action, pf=pf, df=df, ig=ig, st=st, empty=empty)
        if last_entry[0]["quantity"] > 0:
            last_action = f'Last action: Added {last_entry[0]["quantity"]} of {last_entry[0]["item"]} at {last_entry[0]["time"]}.'
        if last_entry[0]["quantity"] < 0:
            positive_int = last_entry[0]["quantity"] * (-1)
            last_action = f'Last action: Removed {positive_int} of {last_entry[0]["item"]} at {last_entry[0]["time"]}.'

        return render_template("appender.html", last_action=last_action, pf=pf, df=df, ig=ig, st=st, empty=empty)


    # via + button
    item_plus = request.form.get("plus")
    if item_plus:
        db.execute("INSERT INTO record (item, quantity, group_name, time) VALUES (?, 1, ?, datetime('now', 'localtime'))", item_plus, session["group_name"])
        return redirect("/appender")

    #via - button
    item_minus = request.form.get("minus")
    if item_minus:
        db.execute("INSERT INTO record (item, quantity, group_name, time) VALUES (?, -1, ?, datetime('now', 'localtime'))", item_minus, session["group_name"])
        return redirect("/appender")

    # via delete button
    delete = request.form.get("delete")
    delete_qty = request.form.get("delete_qty")
    if delete:
        if delete_qty:

            qty = int(delete_qty) * -1
            db.execute("INSERT INTO record (item, quantity, group_name, time) VALUES (?, ?, ?, datetime('now', 'localtime'))", delete, qty, session["group_name"])
            return redirect("/appender")

    # via footer add button

    #for add item button error checking
    add_item_foot = request.form.get("add_item_foot")
    if add_item_foot:

        try:
            quantity_item_foot = int(request.form.get("quantity_item_foot"))
        except ValueError:
            return redirect("/appender")
        if quantity_item_foot < 0 or quantity_item_foot > 99:
            return redirect("/appender")

        db.execute("INSERT INTO record (item, quantity, group_name, time) VALUES (?, ?, ?, datetime('now', 'localtime'))", add_item_foot, quantity_item_foot, session["group_name"])
        last_action = f"Last action: Added {quantity_item_foot} of {add_item_foot}."

        return redirect("/appender")


    #via description adding
    description = request.form.get("description")
    description_item_name = request.form.get("description_item_name")
    if description:
        if description_item_name:
            db.execute("UPDATE record SET description = ? WHERE item = ? AND group_name = ?", description, description_item_name, session["group_name"])
            return redirect("/appender")

    #via image adding
    image = request.form.get("image")
    image_name = request.form.get("image_name")
    if image:
        if image_name:
            db.execute("UPDATE record SET image = ? WHERE item = ? AND group_name = ?", image, image_name, session["group_name"])
            return redirect("/appender")

    #failsafe catches post with no value
    return redirect("/appender")


@app.route("/shopper", methods=["GET", "POST"])
@login_required
def shopper():

    if request.method == "GET":
        item_list = db.execute("SELECT DISTINCT item FROM record WHERE group_name = ?", session["group_name"])
        pf = {}
        df = {}
        ig = {}
        st = {}
        for item in item_list:
            item_name = item["item"]
            quantity_list = db.execute("SELECT quantity FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            sum = 0
            for eachitem in quantity_list:
                number = eachitem["quantity"]
                sum = sum + number
            if sum != 0:
                pf[item_name] = sum

            desc = db.execute("SELECT description FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            df[item_name] = desc[0]["description"]

            img = db.execute("SELECT image FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            ig[item_name] = img[0]["image"]

            stat = db.execute("SELECT status FROM record WHERE item = ? AND group_name = ?", item_name, session["group_name"])
            st[item_name] = stat[0]["status"]

        empty = ''
        if not pf:
            empty = 'This ShopList is empty. Start appending!'

        last_entry = db.execute("SELECT * FROM record WHERE group_name = ? ORDER BY time DESC LIMIT 1", session["group_name"])
        last_action = ''
        if len(last_entry) == 0:
            return render_template("shopper.html", last_action=last_action, pf=pf, df=df, ig=ig, st=st, empty=empty)
        if last_entry[0]["quantity"] > 0:
            last_action = f'Last action: Added {last_entry[0]["quantity"]} of {last_entry[0]["item"]} at {last_entry[0]["time"]}.'
        if last_entry[0]["quantity"] < 0:
            positive_int = last_entry[0]["quantity"] * (-1)
            last_action = f'Last action: Removed {positive_int} of {last_entry[0]["item"]} at {last_entry[0]["time"]}.'

        return render_template("shopper.html", last_action=last_action, pf=pf, df=df, ig=ig, st=st, empty=empty)

   
    # via + button
    item_plus = request.form.get("plus")
    if item_plus:
        db.execute("INSERT INTO record (item, quantity, group_name, time) VALUES (?, 1, ?, datetime('now', 'localtime'))", item_plus, session["group_name"])
        return redirect("/shopper")


    #via - button
    item_minus = request.form.get("minus")
    if item_minus:
        db.execute("INSERT INTO record (item, quantity, group_name, time) VALUES (?, -1, ?, datetime('now', 'localtime'))", item_minus, session["group_name"])
        return redirect("/shopper")


    # via delete button
    delete = request.form.get("delete")
    delete_qty = request.form.get("delete_qty")
    if delete:
        if delete_qty:
            #needs fix
            qty = int(delete_qty) * -1
            db.execute("INSERT INTO record (item, quantity, group_name, time) VALUES (?, ?, ?, datetime('now', 'localtime'))", delete, qty, session["group_name"])
            return redirect("/shopper")


    #markall button -> might need some updste status before deleting
    markall = request.form.get("markall")
    if markall:
        db.execute("DELETE FROM record WHERE group_name = ?", session["group_name"])
        last_action = "List has been cleared."
        empty = 'This ShopList is empty. Start appending!'
        pf = {}
        df = {}
        ig = {}
        st = {}
        return render_template("shopper.html", last_action=last_action, pf=pf, df=df, ig=ig, st=st, empty=empty)

    status = request.form.get("status")
    if status:
        status_name = request.form.get("status_name")
        if status == "pending":
            db.execute("UPDATE record SET status = ? WHERE item = ? AND group_name = ?", "done", status_name, session["group_name"])
        if status == "done":
            db.execute("UPDATE record SET status = ? WHERE item = ? AND group_name = ?", "oos", status_name, session["group_name"])
        if status == "oos":
            db.execute("UPDATE record SET status = ? WHERE item = ? AND group_name = ?", "cancelled", status_name, session["group_name"])
        if status == "cancelled":
            db.execute("UPDATE record SET status = ? WHERE item = ? AND group_name = ?", "pending", status_name, session["group_name"])
        return redirect("/shopper")


    #all fail case
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
