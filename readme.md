# UBRM-Forum

#### Video Demo: [YouTube Link](https://www.youtube.com/watch?v=UXROMUTnzg8)
#### Live View: [UBRM Forum](https://ubrm-forum.vercel.app/)

## Project Overview

UBRM Forum is a file-sharing application designed for a local university. It allows users to share files, comment, and interact in a forum format. It was my final project for the CS50x course "Introduction to Computer Science" by Harvard. This README provides an overview of the project components, including the backend and frontend structure, key files, and design decisions.

## Backend Overview

### app.py

`app.py` is the main backend file, defining various routes that manage the web application’s functionalities, including:

- **Session Management:** Manages user sessions with `login_user` and `logout_user` for login and logout processes.
- **Form Validation:** Uses `Flask-WTF` for form validation, ensuring user inputs meet required criteria.
- **Error Handling:** Implements error messages on login/registration failures.

### forms.py

Defines forms using `Flask-WTF`, capturing user data for login, registration, and feedback submission with various field types and validation:

- **Form Definitions:** Includes login, registration, and feedback forms.
- **Field Types:** Uses `StringField`, `PasswordField`, `TextAreaField`, etc., for data capture.
- **Validation and CSRF Protection:** Includes validators like `DataRequired`, `Email`, and length constraints.

### models.py

Defines the database structure with SQLAlchemy, representing database tables and relationships:

- **User Model:** Includes fields like `username`, `email`, and `password_hash`, along with password verification methods.
- **File Model:** Manages file storage and retrieval, including metadata like filename, upload date, and uploader.
- **Feedback Model:** Stores user feedback with fields for user ID, content, and timestamp.
- **Relationships:** Establishes relationships like User-to-File (one-to-many).

### templates

Contains HTML templates rendered by Flask using Jinja2 for dynamic content generation:

- **Base Template:** The `base.html` template provides common layout elements like header, footer, and navigation.
- **Authentication Templates:** Templates like `login.html` and `register.html` handle user login and registration.
- **File Sharing Templates:** Templates for file upload (`upload.html`), file listings (`files.html`), and file details (`file_detail.html`).
- **Profile and Feedback Templates:** Displays user-specific data and feedback forms.
- **Error Pages:** Custom 404 and 500 error pages.

### static

Hosts static assets like CSS, JavaScript, and images, served directly to the client:

- **CSS:** Defines the application’s look and feel with a main stylesheet (`styles.css`).
- **JavaScript:** Scripts handle interactivity, such as AJAX for liking and commenting.
- **Images:** Stores logos, icons, and other static visual elements.
- **Favicon:** Provides a recognizable tab icon for the application.

## Security and Performance

The application includes several security and performance features:

- **Session Security:** `logout` clears sessions, including CSRF tokens.
- **Database Caching:** Improves performance with cache timeouts for frequently accessed routes.
- **Error Handling:** Provides messages for users in case of failed actions.
- **Password Hashing:** User passwords are hashed and verified securely with Werkzeug’s module.
- **Environment Management:** Uses environment variables and `config.py` to manage app settings.

## Design Choices

- **Database File Storage:** Chose database storage for files for simplicity, as the limited user base and small file sizes made this efficient.
- **Route Design:** Routes are named intuitively, using encoded course names to handle special characters in URLs.
- **Security Measures:** Includes password hashing and CSRF protection.

## Additional Features

- **Logging and Debugging:** Detailed logging facilitates debugging and monitoring.
- **Password Hashing:** Enhances security by hashing user passwords before storage.
- **CSRF Protection:** Protects routes handling sensitive data.
- **Caching:** Optimizes page load times by caching routes like `/lehrveranstaltungen`. 
