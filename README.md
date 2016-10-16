# Multi User Blog
--------------

    * This is a blog application using Google App Engine. There is a signup, login implementation. A logged
    user can add a post, can edit or delete them. Also a logged user can comment to an existing post, can edit
    the comment or delete it. A logged user also can like/unlike a post.

    * Used technologies: Python, Google App Engine, Bootstrap for CSS


# Run App
-----------------------
1. Go to  https://multi-user-blog-course.appspot.com/blog

2. Create new users (Signup button)

3. Login with created user (Login)

4. Create post, edit post, delete post

5. Create comment, edit comment, delete comment

6. Like post, unlike post



# Resources
----------
1. Intro to backend - Udacity course

2. decorators ???


# Extras
----------
1. Project Structure
```
/udacity_multi_user_blog
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
    helper.py
    index.yaml
    models.py
    README.md
```