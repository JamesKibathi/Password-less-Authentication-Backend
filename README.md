# Password-less-Authentication-Backend

## Description

This is a Django API that uses SQLite and Django ORM to persist data in the database. Used to serve a separate 
React frontend (https://github.com/JamesKibathi/Passwordless-Authentication-Client).

Password-less.Auth API has the following functionalities:

- User Account Management: SignUp and Login

  The routes for these and other functionalities are provided on the [Routes](#routes) section.

- Authentication:

  1. Only authenticated users can be allowed to login
  2. Only a valid magic link can automatically login the user
  3. Only a valid OTP can be used to verify a user
 

## Tools and Technologies Used

- Django for model creation, views and URLs 
- SQLite for database​
- JWT for authentication
- TWILIO for sending OTP via SMS
- GMAIL SMTP for emailing

## Requirements

- Python v3 and above

## Configuration

```
$ git clone https://github.com/JamesKibathi/Password-less-Authentication-Backend/
$ python3 -m venv [your venv name] - create a virtual environment 
$ source [your venv name]/bin/activate - Activate the virtual environment 
$ pip install -r requirements.txt - Install dependencies 
$ python3 manage.py runserver - Run server

```
NB: Rememember to replace TWILIO credentials on views.py and email settings on settings.py

### Database creation

Run migrations

```
$ python3 manage.py makemigrations
$ python3 migrate

```

### Deployment instructions

- You can deploy on a platform of choice eg railway and render.

## Endpoints

```
  # admin
  POST "/admin/"
  
  # user signup
  POST "/register/"

  # user Login
  GET "/login/

  # OTP verification
  POST "/verify-otp/"

  # Magic Link Verification
  GET "verify-magic-link/"

   


