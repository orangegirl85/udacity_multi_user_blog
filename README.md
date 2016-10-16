# Multi User Blog
--------------

    * This is a blog application using Google App Engine. There is a signup, login implementation. A logged
    user can add a post, can edit or delete them. Also a logged user can comment to an existing post, can edit
    the comment or delete it. A logged user also can like/unlike a post.

    * Used technologies: Python, Google App Engine, Bootstrap for CSS


# Run deployed app
-----------------------
1. Go to  https://multi-user-blog-course.appspot.com/blog


# Prerequisites

1. Install Python

2. `git clone https://github.com/GoogleCloudPlatform/python-docs-samples`



# Run App on localhost
-----------------------

1. `cd python-docs-samples/appengine/standard/`

2. `git clone https://github.com/orangegirl85/udacity_multi_user_blog.git`

3. `cd udacity_multi_user_blog`

4. dev_appserver.py .

5. Navigate to http://localhost:8080



# Resources
----------
1. Intro to backend - Udacity course

2. Decorators with arguments: http://thecodeship.com/patterns/guide-to-python-function-decorators/


# Extras
----------
1. Project Structure
```
/udacity_multi_user_blog
    /app
        /helpers
            __init__.py
            general.py
            post.py
            user.py
        /models
            __init__.py
            comment.py
            like.py
            post.py
            user.py
        __init__.py
    /static
        bootstrap.min.css
        main.css
    /templates
        /comment
            comment.html
            deletecomment.html
            newcomment.html
        /post
            deletepost.html
            newpost.html
            permalink.html
            post.html
        /user
            login-form.html
            signup-form.html
        base.html
        front.html
        header.html
        rot13-form.html
        welcome.html
    .gitignore
    app.yaml
    blog.py
    index.yaml
    README.md
```