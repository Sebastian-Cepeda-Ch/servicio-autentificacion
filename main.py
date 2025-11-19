import os
import logging
import json
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Annotated, List

# --- Imports FastAPI ---
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr, BeforeValidator

# --- Imports Base de Datos y Auth ---
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId
import aio_pika

# --- Imports gRPC ---
import grpc
from concurrent import futures
import auth_pb2      # Generado automáticamente por el Dockerfile
import auth_pb2_grpc # Generado automáticamente por el Dockerfile

# --- Configuración ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth-service")

DATABASE_URL = os.getenv("DATABASE_URL", "mongodb://mongo:27017/authdb")
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq/")
SECRET_KEY = os.getenv("SECRET_KEY", "tu_clave_secreta_deberia_ser_mas_segura")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
GRPC_PORT = 50051 # Puerto interno para gRPC

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

client = AsyncIOMotorClient(DATABASE_URL)
db_client = client.authdb

# Variables Globales
rabbitmq_connection = None
rabbitmq_channel = None
grpc_server = None # Guardaremos la referencia al servidor gRPC

async def get_database() -> AsyncIOMotorDatabase:
    return db_client

# --- Modelos Pydantic ---
PyObjectId = Annotated[str, BeforeValidator(str)]

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None
    disabled: bool = False

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=72)

class UserInDB(UserBase):
    hashed_password: str

class UserResponse(UserBase):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    class Config:
        populate_by_name = True
        arbitrary_types_allowed = True

# --- Helpers ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- RabbitMQ ---
async def publish_event(event_type: str, data: dict):
    global rabbitmq_channel
    try:
        if rabbitmq_channel:
            exchange = await rabbitmq_channel.declare_exchange("auth_events", aio_pika.ExchangeType.FANOUT)
            message = aio_pika.Message(body=json.dumps({"event": event_type, "data": data}).encode())
            await exchange.publish(message, routing_key="")
            logger.info(f"RabbitMQ: Evento {event_type} enviado.")
    except Exception as e:
        logger.error(f"RabbitMQ Error: {e}")

# --- CLASE SERVIDOR gRPC (La Novedad) ---
class AuthServiceServicer(auth_pb2_grpc.AuthServiceServicer):
    """Implementación de la lógica gRPC"""
    async def VerifyToken(self, request, context):
        token = request.token
        response = auth_pb2.VerifyTokenResponse(valid=False, user_id="", username="")
        
        try:
            # Validar el token usando la misma lógica que FastAPI
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username:
                # Buscar usuario en DB (usamos el cliente global)
                user_doc = await db_client.users.find_one({"username": username})
                if user_doc:
                    response.valid = True
                    response.username = username
                    response.user_id = str(user_doc["_id"])
                    logger.info(f"gRPC: Token verificado para {username}")
        except Exception as e:
            logger.warning(f"gRPC: Fallo verificación de token: {e}")
            
        return response

async def start_grpc_server():
    """Inicia el servidor gRPC en segundo plano"""
    server = grpc.aio.server()
    auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthServiceServicer(), server)
    server.add_insecure_port(f'[::]:{GRPC_PORT}')
    logger.info(f"🚀 Servidor gRPC iniciando en puerto {GRPC_PORT}...")
    await server.start()
    return server

# --- API FastAPI ---
app = FastAPI(title="Auth Service", version="1.2.0 (gRPC)")

@app.on_event("startup")
async def startup_events():
    # 1. Mongo
    try:
        await db_client.users.create_index("username", unique=True)
        await db_client.users.create_index("email", unique=True)
    except Exception as e: logger.error(f"Mongo Error: {e}")
    
    # 2. RabbitMQ
    global rabbitmq_connection, rabbitmq_channel
    asyncio.create_task(connect_rabbitmq_retry()) # Lo lanzamos como tarea para no bloquear

    # 3. Iniciar gRPC (Req. 2.6)
    global grpc_server
    grpc_server = await start_grpc_server()

async def connect_rabbitmq_retry():
    """Lógica de reintento para RabbitMQ separada"""
    global rabbitmq_connection, rabbitmq_channel
    while True:
        try:
            rabbitmq_connection = await aio_pika.connect_robust(RABBITMQ_URL)
            rabbitmq_channel = await rabbitmq_connection.channel()
            await rabbitmq_channel.declare_exchange("auth_events", aio_pika.ExchangeType.FANOUT)
            logger.info("✅ RabbitMQ Conectado.")
            break
        except Exception:
            logger.warning("RabbitMQ no listo, reintentando en 5s...")
            await asyncio.sleep(5)

@app.on_event("shutdown")
async def shutdown_events():
    client.close()
    if rabbitmq_connection: await rabbitmq_connection.close()
    if grpc_server: await grpc_server.stop(0) # Detener gRPC

# --- Endpoints HTTP (Iguales) ---
@app.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncIOMotorDatabase = Depends(get_database)):
    user = await db.users.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Bad credentials")
    return {"access_token": create_access_token(data={"sub": user["username"]}), "token_type": "bearer"}

@app.post("/users", response_model=UserResponse, status_code=201, tags=["Users"])
async def create_user(user_in: UserCreate, db: AsyncIOMotorDatabase = Depends(get_database)):
    if await db.users.find_one({"username": user_in.username}): raise HTTPException(400, "Username exists")
    hashed = get_password_hash(user_in.password)
    user_data = user_in.model_dump()
    user_data.pop("password")
    new_user = await db.users.insert_one({**user_data, "hashed_password": hashed})
    created = await db.users.find_one({"_id": new_user.inserted_id})
    created["_id"] = str(created["_id"])
    
    await publish_event("USER_CREATED", {"username": created["username"], "email": created["email"]})
    return UserResponse(**created)

@app.get("/users", response_model=List[UserResponse], tags=["Users"])
async def list_users(db: AsyncIOMotorDatabase = Depends(get_database)):
    users = await db.users.find().limit(20).to_list(20)
    for u in users: u["_id"] = str(u["_id"])
    return users

@app.get("/users/me", response_model=UserResponse, tags=["Users"])
async def read_me(token: str = Depends(oauth2_scheme), db: AsyncIOMotorDatabase = Depends(get_database)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user = await db.users.find_one({"username": payload.get("sub")})
    user["_id"] = str(user["_id"])
    return UserResponse(**user)