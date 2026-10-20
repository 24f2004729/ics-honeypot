.PHONY: test run dev report docker-build docker-up docker-down clean

PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

run:
	sudo $(PYTHON) main.py

dev:
	$(PYTHON) main.py --dev

report:
	$(PYTHON) main.py --report-only

docker-build:
	docker build -t ics-honeypot:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf __pycache__ */__pycache__ */*/__pycache__ .pytest_cache
