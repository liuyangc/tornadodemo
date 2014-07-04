#!/usr/bin/env python

#import markdown
import os.path
import re
import torndb
import tornado.auth
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
#import unicodedata
from tornado.escape import xhtml_escape as htmlescape


from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("mysql_host", default="127.0.0.1:3306", help="blog database host")
define("mysql_database", default="share", help="share database name")
define("mysql_user", default="blog", help="share database user")
define("mysql_password", default="blog", help="share database password")


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/joy/([^/]+)", JoyHandler),
            (r"/share", ShareHandler),
            (r"/voting", Votinghandler),
            #(r"/archive", ArchiveHandler),
            #(r"/feed", FeedHandler),           
            #(r"/compose", ComposeHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            blog_title=u"Share your joy",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            #ui_modules={"Entry": EntryModule},
            ui_modules={"Joy": JoyModule},
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            debug=True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)

        # Have one global connection to the blog DB across all handlers
        self.db = torndb.Connection(
            host=options.mysql_host, database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        user_id = self.get_secure_cookie("sharedemo_user")
        if not user_id: return None
        return self.db.get("SELECT * FROM user WHERE id = %s", int(user_id))


class HomeHandler(BaseHandler):
    def get(self):
        joys = self.db.query("SELECT *, a.id AS jid FROM joy a LEFT JOIN statistic b"
                            " ON a.id=b.id ORDER BY a.published DESC LIMIT 5")
        if not joys:
            self.redirect("/share")
            return
        self.render("home.html", joys=joys)

class JoyHandler(BaseHandler):
    def get(self, id):
        joy = self.db.get("SELECT *, a.id AS jid FROM joy a LEFT JOIN statistic b "
                            "ON a.id=b.id WHERE a.id = %s", int(id))
        if not joy: raise tornado.web.HTTPError(404)
        comments=self.db.query("SELECT * FROM comments a LEFT JOIN user b ON a.cid=b.id "
                                "WHERE a.id = %s ORDER BY time", int(joy.jid))
        #self.write(repr(comments))
        self.render("joy.html", joy=joy, comments=comments)
    
    def post(self,id):
        id = int(self.get_argument("id"))
        cid = self.get_argument("cid")
        content = self.get_argument("content")
        self.db.execute("INSERT INTO comments (id, content, cid) VALUES("
                        "%s, %s, %s)", id, content, int(cid))
        self.redirect("/joy/"+ str(id))

'''class ArchiveHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC")
        self.render("archive.html", entries=entries)'''


'''class FeedHandler(BaseHandler):
    def get(self):
        entries = self.db.query("SELECT * FROM entries ORDER BY published "
                                "DESC LIMIT 10")
        self.set_header("Content-Type", "application/atom+xml")
        self.render("feed.xml", entries=entries)'''


'''class ComposeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        id = self.get_argument("id", None)
        entry = None
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
        self.render("compose.html", entry=entry)

    @tornado.web.authenticated
    def post(self):
        id = self.get_argument("id", None)
        title = self.get_argument("title")
        text = self.get_argument("markdown")
        html = markdown.markdown(text)
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
            if not entry: raise tornado.web.HTTPError(404)
            slug = entry.slug
            self.db.execute(
                "UPDATE entries SET title = %s, markdown = %s, html = %s "
                "WHERE id = %s", title, text, html, int(id))
        else:
            slug = unicodedata.normalize("NFKD", title).encode(
                "ascii", "ignore")
            slug = re.sub(r"[^\w]+", " ", slug)
            slug = "-".join(slug.lower().strip().split())
            if not slug: slug = "entry"
            while True:
                e = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
                if not e: break
                slug += "-2"
            self.db.execute(
                "INSERT INTO entries (author_id,title,slug,markdown,html,"
                "published) VALUES (%s,%s,%s,%s,%s,UTC_TIMESTAMP())",
                self.current_user.id, title, slug, text, html)
        self.redirect("/entry/" + slug)'''

class ShareHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        id = self.get_argument("id", None)
        joy = None
        if id:
            joy = self.db.get("SELECT * FROM joy WHERE id = %s", int(id))
        self.render("share.html", joy=joy)

    @tornado.web.authenticated
    def post(self):
        id = self.get_argument("id", None)
        #title = self.get_argument("title")
        content = htmlescape(self.get_argument("joycontent"))       
        content = re.sub(r"\[em_([0-9]*)\]", lambda m:"<img src='/static/arclist/"+m.group(1)+".gif'>", content)       
        #html = markdown.markdown(text)
        if id:
            joy = self.db.get("SELECT * FROM joy WHERE id = %s", int(id))
            if not joy: raise tornado.web.HTTPError(404)           
            self.db.execute(
                "UPDATE joy SET content = %s "
                "WHERE id = %s", content, int(id))
        else:
            index =self.db.execute(
                "INSERT INTO joy (author_id,content,"
                "published) VALUES (%s,%s,UTC_TIMESTAMP())",
                self.current_user.id, content)
        #self.write(repr(index));        
        self.redirect("/joy/" + str(index))

class Votinghandler(BaseHandler):
    @tornado.web.authenticated
    def post(self):
        id = self.get_argument("id")
        flag = int(self.get_argument("flag"))
        col = "likes" if flag>0 else "unlike"       
        index = self.db.execute("INSERT INTO statistic (id, "+ col +") VALUES(%s, 1) "
                        "ON DUPLICATE KEY UPDATE "+col+"="+col+"+1",int(id))  
        message = {
            "success": 0 if index else 1,
        }
        self.write(message)       

class AuthLoginHandler(BaseHandler, tornado.auth.GoogleMixin):
    @tornado.web.asynchronous
    def get(self):
        '''if self.get_argument("openid.mode", None):
            self.get_authenticated_user(self.async_callback(self._on_auth))
            return
        self.authenticate_redirect()

        def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Google auth failed")
        author = self.db.get("SELECT * FROM authors WHERE email = %s",
                             user["email"])
        if not author:
            # Auto-create first author
            any_author = self.db.get("SELECT * FROM authors LIMIT 1")
            if not any_author:
                author_id = self.db.execute(
                    "INSERT INTO authors (email,name) VALUES (%s,%s)",
                    user["email"], user["name"])
            else:
                self.redirect("/")
                return
        else:
            author_id = author["id"]'''
        author_id = self.db.execute(
                    "INSERT INTO user (email,name) VALUES (%s,%s)",
                    "aha@ahaa.com", "ahaa")
        self.set_secure_cookie("sharedemo_user", str(author_id))
        self.redirect(self.get_argument("next", "/"))


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("sharedemo_user")
        self.redirect(self.get_argument("next", "/"))

class JoyModule(tornado.web.UIModule):
    def render(self, joy):
        return self.render_string("modules/joy.html", joy=joy)


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
