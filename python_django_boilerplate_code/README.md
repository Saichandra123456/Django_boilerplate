#Steps to run the application
# Features Available
    - API Versioning
    - Token Authentication (JWT)
    - Exception handling
    - Proper Logging (Request, Response and Timestamp)
    - Documnetation (Swagger)
    - No hardcoding values (used Config file)
    - Response structure
    - Testcases using pytest

### Create virtual environment
    pip install virtualwrapper-win
                    or
    python3 -m venv <virtualenv path and venv name>
                    or
    sudo apt-get install virtualenv
    virtualenv <name>
            or
    mkvirtualenv <name>
### activate our virtualenv 
    when use pip install virtualwrapper-win this command to installing virtual env using following command ->
        workon <virtualenv>

### Install packages
    pip3 install -r requirements.txt
    
### database tables creation and updation
Initiate a migration folder using following command to perform the migrations.

    python manage.py migrate

Create a migration script from the detected changes in the model using the migrate command. This doesn’t affect the database yet 
so we need to execute it by following command
    
    python manage.py makemigrations
**Each time the database model changes, repeat the migrate and makemigrations commands**

### The development server
default port of development server is 8000
    
    python manage.py runserver

If you want to change the port then use following command

    python manage.py runserver <portnumber>

### if you want to visit admin gui then need to do some following steps
    go to - > admin.py files and register your model
    for eg - admin.register(User)
### then create superuser
    python manage.py createsuperuser
    -set username and password
### then run development server and provide admin path
    for eg - http://127.0.0.1:8000/admin/

You can able to add data in tables , delete,update etc.

### Run all test cases
    python manage.py tests

### Run single Test case
    python manage.py test <method name>

### Running a specific test case in Django when our app has a tests directory
    ./manage.py test my_app

###  test a specific file inside a tests folder    
    python manage.py test AppName.tests.test_page

### Open docs in browser using link
    http://127.0.0.1:8000/app/user/swagger/