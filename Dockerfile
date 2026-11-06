FROM python:3.12-slim
WORKDIR /app
COPY server.py .
ENV PORT=3000
EXPOSE 3000
CMD ["python3", "server.py"]
