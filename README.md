# FBLA Quiz Server

Server for a FBLA Quiz app I made, which you can find [here](https://github.com/ojas-sanghi/FBLA-Quiz)

This server encrypts and serves the 50 question database, which you can find in `questions.json`

## Tools Used

### 3rd party licenses used in code

- [Flask](https://flask.palletsprojects.com/en/1.1.x/), used as the microframework to build my server upon.
  - It is released under the [BSD-3-Clause License](https://github.com/pallets/flask/blob/master/LICENSE.rst)

- [pycryptodome](https://github.com/Legrandin/pycryptodome/), used to generate an AES key and encrypt the question file with it.
  - The source code is released into the [public domain](https://github.com/Legrandin/pycryptodome/blob/master/LICENSE.rst)
- [rsa](https://github.com/sybrenstuvel/python-rsa), used to encrypt the AES key using the client's public key.
  - Released under the [Apache-2.0 License](https://github.com/sybrenstuvel/python-rsa/blob/main/LICENSE) 

- [Gunicorn](https://gunicorn.org/) as a WSGI HTTP server to run my website on.
  - It is released under the [MIT License](https://github.com/benoitc/gunicorn/blob/master/LICENSE)

The license of this project (GNU GPL v3) is adherent to conditions set by the 3rd party libraries included.

### Hosting on Heroku

I used [Heroku](https://www.heroku.com/) to host my server. When signing up, you get 500 free dyno hours, and when verifying a credit card, that increases to 1000. That ensures my server can always remain up at no cost to me, and that the questions are always retrievable.

### Version Control

This project uses Git, and the code is stored on GitHub. You can view it [here](https://github.com/ojas-sanghi/FBLA-Quiz-Server), and the commit history [here](https://github.com/ojas-sanghi/FBLA-Quiz-Server/commits/main)


### Code Formatting

This project uses [Black](https://github.com/psf/black) as a code formatter tool. 

### Dependencies

I used [pipenv](https://pipenv.pypa.io/en/latest/) to install and maintain project dependencies. They can be viewed in `Pipfile`

## Installation and Usage

Note: you need Python 3.8 to run this project

  1. Clone and `cd` to directory
  2. `pip install --user pipenv` to install pipenv if you don't already have it
  3. `pipenv shell` to enter a virtual environment shell
  4. `pipenv install` to install dependencies from `Pipfile`
  5. `python3 app.py` to start the server