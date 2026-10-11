uvicorn==0.29.0
streamlit==1.35.0
sqlalchemy==2.0.30
passlib[bcrypt]==1.7.4
bcrypt==3.2.2
python-jose[cryptography]==3.3.0
python-multipart==0.0.9
langchain-community==0.2.1
langchain-text-splitters==0.2.1
langchain-huggingface==0.0.3
faiss-cpu==1.8.0
pymupdf==1.24.4
sentence-transformers==2.7.0
pywinrm==0.4.3
pandas==2.2.2
WORKDIR /app
RUN apt-get update && apt-get install -y build-essential libmupdf-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000 8501
services:
  compliance-auditor:
    build: .
    ports:
      - "8000:8000"
      - "8501:8501"
    volumes:
      - .:/app
      - sqldata:/app/data
    environment:
      - OLLAMA_HOST=http://host.docker.internal:11434
volumes:
