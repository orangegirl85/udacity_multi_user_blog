import os

import jinja2

template_dir = os.path.join(os.path.dirname(__file__), '../../', 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
