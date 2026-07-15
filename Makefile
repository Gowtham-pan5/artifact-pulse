PYTHON=python

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m flake8 .

run:
	$(PYTHON) main.py
