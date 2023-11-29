import pymysql
import requests
import bcrypt
from flask import Flask, request, jsonify

db = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "vk-breaker"
}

connection = pymysql.connect(**db)
cursor = connection.cursor()

app = Flask(__name__)

@app.route("/user/api/v4/signup", methods=["POST"])
def signup():
    data = request.get_json()
    nick_name = data["nickname"]
    email = data["email"]
    password = data["password"]
    response = requests.get('https://httpbin.org/ip')
    ip_address =response.json()['origin']

    add = requests.get(f'https://ipinfo.io/{ip_address}/json')
    data = add.json()
    address = f'{data.get("country", "N/A")} - {data.get("city", "N/A")}'

    insert = "INSERT INTO users (nickname, email, password, ip_address, address) VALUES (%s,%s,%s,%s,%s)"
    cursor.execute(insert, (nick_name, email, password, ip_address, address))
    connection.commit()
    return jsonify({"success": True}), 200

@app.route("/user/api/v4/signin", methods=["GET"])
def signin():
    data = request.get_json()
    email = data["email"]
    password = data["password"]
    select = "SELECT * FROM users WHERE email = %s AND password = %s"
    cursor.execute(select, (email, password))
    connection.commit()
    answer = cursor.fetchone()
    if answer == None:
        return jsonify({"success": False}), 200
    else:
        custom_token = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
        insert_token = "INSERT INTO token (token,user_id) VALUES (%s,%s)"
        cursor.execute(insert_token, (custom_token, answer[0]))
        connection.commit()
        return jsonify({"data":answer,"token":f'{custom_token}'}), 200

@app.route("/user/api/v4/delete_account", methods=["DELETE"])
def delete_account():
    data = request.get_json()
    user_id = data["user_id"]
    delete = "DELETE FROM users WHERE id = %s"
    cursor.execute(delete, (user_id))
    connection.commit()
    return jsonify({"success": True}), 200

@app.route("/user/api/v4/hack_account", methods=["POST"])
def hack_account():
    data = request.get_json()
    account_url = data["account_url"]
    user_id = data["user_id"]
    insert = "INSERT INTO hacked (account_url, user_id) VALUES (%s,%s)"
    cursor.execute(insert, (account_url, user_id))
    connection.commit()
    return jsonify({"success":True}), 200

@app.route("/api/v4/get_blogs", methods=["GET"])
def get_blogs():
    select = "SELECT * FROM blogs"
    cursor.execute(select)
    connection.commit()
    blogs = cursor.fetchall()
    return jsonify(blogs), 200

@app.route("/user/api/v4/get_user_data", methods=["GET"])
def get_user_data():
    data = request.get_json()
    user_id = data["user_id"]
    select = "SELECT * FROM users WHERE id = %s"
    cursor.execute(select, user_id)
    connection.commit()
    user_data = cursor.fetchone()
    return jsonify(user_data), 200

@app.route("/user/api/v4/get_hacked_account", methods=["GET"])
def get_hacked_account():
    data = request.get_json()
    user_id = data["user_id"]
    select = "SELECT * FROM hacked WHERE user_id = %s"
    cursor.execute(select, user_id)
    connection.commit()
    hacked = cursor.fetchall()
    return jsonify(hacked), 200
@app.route("/user/api/v4/log_out", methods=["DELETE"])
def log_out():
    data = request.get_json()
    token = data["token"]
    delete = "DELETE FROM token WHERE token = %s"
    cursor.execute(delete, token)
    connection.commit()
    return jsonify({"success:": True}), 200

if __name__ == "__main__":
    app.run(debug=True)
    connection.close()