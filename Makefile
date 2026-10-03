.PHONY: install test test-core test-cli test-backend run-backend run-frontend docker-up docker-down lint

install:
	pip install --break-system-packages -e core -e cli
	pip install --break-system-packages -r backend/requirements.txt
	cd frontend && npm install

test: test-core test-cli test-backend

test-core:
	cd core && python3 -m pytest tests/ -v

test-cli:
	cd cli && python3 -m pytest tests/ -v

test-backend:
	cd backend && DATABASE_URL=sqlite:///./test_backend.db PYTHONPATH=$(PWD)/backend:$(PWD)/core python3 -m pytest tests/ -v
	rm -f backend/test_backend.db

run-backend:
	cd backend && PYTHONPATH=$(PWD)/backend:$(PWD)/core uvicorn app.main:app --reload --port 8000

run-frontend:
	cd frontend && npm run dev

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v
