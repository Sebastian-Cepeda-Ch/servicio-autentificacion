# Usar una imagen base oficial de Python 3.10
FROM python:3.10-slim

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar el archivo de dependencias
COPY requirements.txt .

# Instalar las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar todo el código de la aplicación al contenedor
COPY . .

# Esto genera dos archivos Python: auth_pb2.py y auth_pb2_grpc.py
RUN python -m grpc_tools.protoc -I./protos --python_out=. --grpc_python_out=. ./protos/auth.proto


# Exponer el puerto en el que correrá Uvicorn
EXPOSE 8000
# Exponemos también el puerto de gRPC
EXPOSE 50051


# Comando para ejecutar la aplicación
# El host 0.0.0.0 es crucial para que sea accesible desde fuera del contenedor
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]