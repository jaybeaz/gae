#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import string
import re

form = """
<form method="post">
What is your bday?!?
<br>
<label> Year <input type="text" name="year" value="%(year)s"></label>
<label> Month <input type="text" name="month" value="%(month)s"></label>
<label> Day <input type="text" name="day" value="%(day)s"></label>
<div style="color: red">%(error)s</div>
<br>
<br>
<input type="submit">
</form>
"""

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']


def valid_month(month):
    if month[0].upper() + month[1:].lower() in months:
      return month.capitalize()
    else:
      return None

def valid_day(day):
  if day.isdigit():
    if int(day) <= 31 and int(day) >= 1:
      return int(day)
    else:
      return None
  else:
    return None

def valid_year(year):
  if year.isdigit():
    if int(year) <= 2020 and int(year) >= 1900:
      return int(year)
    else:
      return None
  else:
    return None

def escape_html(s):
  return cgi.escape(s, quote=True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
  return USER_RE.match(username)


PW_RE = re.compile(r"^.{3,20}$")
def valid_password(pw):
  return PW_RE.match(pw)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
  return EMAIL_RE.match(email)

class MainHandler(webapp2.RequestHandler):
    def write_form(self, error="", year="", month="", day=""):
      self.response.write(form % {"error": error,
                                  "year": escape_html(year), 
                                  "month": escape_html(month), 
                                  "day": escape_html(day)})

    def get(self):
      self.response.headers['Content-Type'] = "text/html"
      self.write_form()
#      self.response.write(form)
      
    def post(self):
      user_month = self.request.get('month')
      user_day = self.request.get('day')
      user_year = self.request.get('year')
      
      
      validated_month = valid_month(self.request.get('month'))
      validated_day = valid_day(self.request.get('day'))
      validated_year = valid_year(self.request.get('year'))
      if not(validated_month and validated_day and validated_year):
        self.write_form(error="Where'd you learn date formats, fuckface!?",
                        year=user_year,
                        month=user_month,
                        day=user_day)
      else:
        self.redirect("/thanks")
#      self.response.out
#        self.response.write('<title>test bullshit</title><b>Hello udacity!!!</b>')

class ThanksHandler(webapp2.RequestHandler):  
  def get(self):
    self.response.out.write("Thanks, that's totally kosher!YO!")


# method="post" 
rotform = """
<!DOCTYPE html>

<html>
  <head>
    <title>Unit 2 Rot 13</title>
  </head>

  <body>
    <h2>Enter some text to ROT13:</h2>
    <form method="post">
      <textarea name="text"
                style="height: 100px; width: 400px;">%s</textarea>
      <br>
      <input type="submit">
    </form>
  </body>

</html>
"""

rot13 = string.maketrans( 
    "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", 
    "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")

class Rot13Handler(webapp2.RequestHandler):
  def write_form(self, user_text=""):
    self.response.write(rotform % escape_html(user_text))

  def get(self):
    self.response.headers['Content-Type'] = "text/html"
    self.write_form()    
    
  def post(self):
    user_string = self.request.get('text')
#    upper_string = user_string.upper()
    rot_string = user_string.encode("rot13")
    self.write_form(user_text=rot_string)
#    self.response.write(rot_string)

class UserSignup(webapp2.RequestHandler):
  def write_form(self, username="", email="", username_error="", password_error="", verify_error="", email_error=""):
    self.response.write(signupform % {"username": escape_html(username),
#                                   "password": escape_html(password),
                                   "password": "",
                                   "verify_pw": "",
                                   "email": escape_html(email),
                                   "username_error": username_error,
                                   "password_error": password_error,
                                   "verify_error": verify_error,
                                   "email_error": email_error})

  def get(self):
    self.response.headers['Content-Type'] = "text/html"
    self.write_form()
    
  def post(self):
    username = self.request.get("username")
    password = self.request.get("password")
    verify_pw = self.request.get("verify")
    email = self.request.get("email")
    
    validated_username = valid_username(username)
    validated_password = valid_password(password)
    validated_verify = password == verify_pw
    if email:
      validated_email = valid_email(email)
    
    username_error = ""
    password_error = ""
    verify_error = ""
    email_error = ""
    
    if not validated_username:
      username_error = "That's not a valid username."
    if not validated_password:
      password_error = "That wasn't a valid password."
    else:
      password_error = ""
      if not validated_verify:
        verify_error = "Your passwords didn't match."
    if email and not validated_email:
      email_error = "That's not a valid email."
    
    if email and not validated_email:
      self.write_form(username, email, username_error, password_error, verify_error, email_error)
    elif not(validated_username and validated_password and validated_verify):
      self.write_form(username, email, username_error, password_error, verify_error, email_error)
    else:
      self.redirect("/welcome?username=" + username)

class Welcome(webapp2.RequestHandler):
  def get(self):
    username = self.request.get('username')
    self.response.out.write(welcomeform % username)
    

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/thanks', ThanksHandler),
    ('/rot13', Rot13Handler),
    ('/signup', UserSignup),
    ('/welcome', Welcome)
], debug=True)



signupform = """
<!DOCTYPE html>

<html>
  <head>
    <title>Sign Up</title>
    <style type="text/css">
      .label {text-align: right}
      .error {color: red}
    </style>

  </head>

  <body>
    <h2>Signup</h2>
    <form method="post">
      <table>
        <tr>
          <td class="label">
            Username
          </td>
          <td>
            <input type="text" name="username" value="%(username)s">
          </td>
          <td class="error">
            %(username_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Password
          </td>
          <td>
            <input type="password" name="password" value="%(password)s">
          </td>
          <td class="error">
            %(password_error)s            
          </td>
        </tr>

        <tr>
          <td class="label">
            Verify Password
          </td>
          <td>
            <input type="password" name="verify" value="">
          </td>
          <td class="error">
          %(verify_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Email (optional)
          </td>
          <td>
            <input type="text" name="email" value="%(email)s">
          </td>
          <td class="error">
          %(email_error)s
          </td>
        </tr>
      </table>

      <input type="submit">
    </form>
  </body>

</html>
"""

welcomeform = """
<!DOCTYPE html>

<html>
  <head>
    <title>Unit 2 Signup</title>
  </head>

  <body>
    <h2>Welcome, %s!</h2>
  </body>
</html>
"""

#class TestHandler(webapp2.RequestHandler):
#  def get(self):
#  def post(self):
#    self.response.headers['Content-Type'] = "text/plain"
#    self.response.out.write(self.request)
#    q = self.request.get("q")
#    self.response.out.write(q)
  
#  def post(self):
#https://classroom.udacity.com/courses/cs253/lessons/48756009/concepts/485084220923
#http://jaydubulyoubee.appspot.com/rot13
#http://udacity-cs253.appspot.com/unit2/signup
#file:///Users/jbeasley/Desktop/Scripts/AppEngine/my-project-1/play.html
#http://localhost:8080/rot13