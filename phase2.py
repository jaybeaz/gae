import webapp2
import cgi
import string
import re
import jinja2
import os

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
    
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

class MainPage(Handler):
  def get(self):
    items = self.request.get_all("food")
    self.render("shopping_list.html", items=items)

class FizzBuzzHandler(Handler):
#  def post(self):
#    n = self.request.get("number", 0)
#    if n:
#      n = int(n)
#      self.render("fizzbuzz.html", n=n)
#
  def get(self):
    n = self.request.get("n", 0)
    if n:
      n = int(n)
    self.render("fizzbuzz.html", n=n)
#

#    self.render("shopping_list.html", name=self.request.get("name"))

    # output = form_html
    # output_hidden = ""
    #
    # items = self.request.get_all("food")
    # if items:
    #   output_items = ""
    #   for item in items:
    #     output_hidden += hidden_html % item
    #     output_items += item_html % item
    #
    #   output_shopping = shopping_list_html % output_items
    #   output += output_shopping
    #
    # output = output % output_hidden
    #
    # self.write(output)
#    self.write("DUUUUDE, hello. Werld.")

app = webapp2.WSGIApplication([
    ('/phase2', MainPage),
    ('/fizzbuzz', FizzBuzzHandler)
      ], debug=True)