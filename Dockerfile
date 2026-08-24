FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create output directories
RUN mkdir -p output/reports output/logs ml/models

EXPOSE 5000

ENV FLASK_ENV=production \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=5000

CMD ["python", "-c", \
     "from dotenv import load_dotenv; load_dotenv(); \
      from web.app import app; \
      from waitress import serve; \
      import os; \
      serve(app, host=os.environ.get('SERVER_HOST','0.0.0.0'), \
            port=int(os.environ.get('SERVER_PORT','5000')), threads=4)"]
