import os
import re
import random
import hashlib
import hmac
import urllib2
import json
import time
from string import letters
from datetime import timedelta, datetime

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def next_url(self):
        return self.request.headers.get('referer', '/')

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def notfound(self, message='Sorry, my friend, but that page does not exist.'):
        self.error(404)
        self.write('<h1>404: Not Found</h1>%s' % message)

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### page stuff

class Page(db.Model):
    path = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()
    #last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_path(cls, path, update = False):
        pages, age = age_get(path)
        if update or pages is None:
            q = Page.all().filter('path =', path).order('-created').fetch(limit=100)
            pages = list(q)
            age_set(path, pages)

        return pages, age

    @classmethod
    def by_id(cls, page_id):
        return cls.get_by_id(page_id)

    def as_dict(self):
        d = {'subject': self.path,
             'content': self.content,
             'created': (self.created - timedelta(hours=4)).strftime('%c')}
        return d


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(WikiHandler):
    def get(self):
        next_url = self.next_url()
        self.render("signup-form.html", next_url = next_url)

    def post(self):
        have_error = False

        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'

        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email,
                      next_url = next_url)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.by_name(self.username)
            if u:
                msg = 'That user already exists.'
                self.render('signup-form.html', error_username = msg, next_url=next_url)
            else:
                u = User.register(self.username, self.password, self.email)
                u.put()

                self.login(u)
                self.redirect(next_url)


class Login(WikiHandler):
    def get(self):
        next_url = self.next_url()
        self.render('login-form.html', next_url = next_url)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'       

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect(next_url)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


class Logout(WikiHandler):
    def get(self):
        next_url = self.next_url()
        self.logout()
        self.redirect(next_url)


class NoSlash(WikiHandler):
    def get(self, path):
        new_path = path.rstrip('/') or '/'
        self.redirect(new_path)


class EditPage(WikiHandler):
    def get(self, path):
        if not self.user:
            self.redirect('/login')

        if path in ['/signup', '/login', '/logout']:
            self.redirect(path)

        if re.match(r'/_edit(.*)', path) or re.match(r'/_history(.*)', path) or re.match(r'/_map(.*)', path):           
            return self.notfound(message='Sorry, invalid path.')

        v = self.request.get('v')
        p = None
        if v:
            if v.isdigit():
                p = Page.by_id(int(v))

            if not p:
                return self.notfound()

        else:
            pages, age = Page.by_path(path)
            if pages:
                p = pages[0]

        content = ""
        if p:
            content = p.content

        self.render("edit.html", content = content, path = path, page=p)

    def post(self, path):
        if not self.user:
            self.error(400)
            return

        content = self.request.get('content')
        pages, age = Page.by_path(path)
        old_page = None
        if pages:
            old_page = pages[0] 

        if not content:
            error = "Content, please!"
            content = ""
            self.render("edit.html", content = content, path = path, error = error)
            return
        elif not old_page or old_page.content != content:

            p = Page(content = content, path = path)
            coords = get_coords(self.request.remote_addr)
            if coords:
                p.coords = coords
            p.put()
            time.sleep(0.1)
            if coords:
                get_pages(update = True)
            Page.by_path(path, update = True)

        self.redirect(path) 


def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))

def age_get(key):
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0
    return val, age

def get_pages(update = False):
    mc_key = 'PAGES'
    pages, age = age_get(mc_key)
    if update or pages is None:
        q = Page.all().order('-created').fetch(limit=100)
        pages = list(q)
        age_set(mc_key, pages)
    return pages, age

def age_str(age):
    s = 'queried %s seconds ago'
    age = int(age)
    if age == 0 or age == 1:
        s = s.replace('seconds', 'second')
    return s % age


class HistoryPage(WikiHandler):
    def get(self, path):
        pages, age = Page.by_path(path)

        if pages:
            self.render("history.html", path = path, pages = pages, timedelta=timedelta(hours=4), age=age_str(age))
        else:
            self.redirect('/_edit' + path)


class JsonPage(WikiHandler):
    def get(self, path):
        self.format = 'json'
        pages, age = Page.by_path(path)
        return self.render_json([p.as_dict() for p in pages])        


IP_URL = 'http://ip-api.com/csv/'
def get_coords(ip):
    #ip = '4.2.2.2'
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content:
        attr = content.split(',')
        if attr[0] == 'success':
            lat, lon = attr[7], attr[8]
            return db.GeoPt(lat, lon)   


GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
    markers = '&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)
    return GMAPS_URL + markers

class Map(WikiHandler):
    def get(self):
        pages = []
        pages, age = get_pages()

        points = filter(None, (p.coords for p in pages))

        img_url = GMAPS_URL
        if points:
            img_url = gmaps_img(points)

        self.render('map.html', img_url = img_url, age=age_str(age))


class WikiPage(WikiHandler):
    def get(self, path):
        v = self.request.get('v')
        p = None

        if v:
            if v.isdigit():
                p = Page.by_id(int(v))

            if not p:
                return self.notfound()

        else:
            pages, age = Page.by_path(path)
            if pages:
                p = pages[0]

        if p:
            self.render("page.html", page = p, path = path)
        else:
            self.redirect('/_edit' + path)


class Flush(WikiHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_map', Map), 
                               ('/_flush', Flush),                              
                               #('(/.*/+)', NoSlash),                                
                               ('/_history' + PAGE_RE + '.json', JsonPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)

