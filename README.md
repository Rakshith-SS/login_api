# Login API

## About

User Authentication APIs made using DRF.

## Running the application

To run the application:

+ create a virtual environment
    ```bash
    python -m venv env
    ```

+ install all the required packages from requirements.txt

    ```bash
    pip install -r requirements.txt
    ```
+ Apply migrations

  ```bash
    python manage.py makemigrations
    python manage.py migrate
  ```

+ Then run the development server

    ```
    python manage.py runserver
    ```
