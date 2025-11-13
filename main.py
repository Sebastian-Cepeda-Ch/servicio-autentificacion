import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

# --- Configuración de Seguridad y Base de Datos ---

# Lee de variables de entorno (o usa valores por defecto para desarrollo)
# docker-compose.yml se encargará de pasar estas variables.
DATABASE_URL = os.getenv("DATABASE_URL", "mongodb://mongo:27017/authdb")
SECRET_KEY = os.getenv("SECRET_KEY", "tu_clave_secreta_deberia_ser_mas_segura") # ¡CAMBIA ESTO!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configuración para hashear contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema OAuth2: FastAPI sabe que debe buscar el token en /token
# La URL es relativa a la ruta del microservicio, NGINX lo manejará.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Conexión a MongoDB ---

# Creamos un cliente de Motor (async)
client = AsyncIOMotorClient(DATABASE_URL)
db_client = client.authdb # Accedemos a la base de datos 'authdb'

# Dependencia de FastAPI para obtener la sesión de la DB
async def get_database() -> AsyncIOMotorDatabase:
    return db_client

# --- Modelos Pydantic (Validación de Datos) ---

# Modelo para manejar el ObjectId de Mongo
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    @classmethod
    def validate(cls, v, *args, **kwargs):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)
    @classmethod
    def __get_pydantic_json_schema__(cls, *args, **kwargs):
        return {"type": "string"}


# Modelo de Token (lo que devolvemos al loguearse)
class Token(BaseModel):
    access_token: str
    token_type: str

# Modelo de datos dentro del Token (el "subject")
class TokenData(BaseModel):
    username: Optional[str] = None

# Modelo base del Usuario
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None
    disabled: bool = False

# Modelo para CREAR un usuario (recibe la contraseña)
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

# Modelo del Usuario en la DB (guarda la contraseña hasheada)
class UserInDB(UserBase):
    hashed_password: str

# Modelo de Usuario para RESPONDER (NUNCA incluye la contraseña)
class UserResponse(UserBase):
    id: str = Field(..., alias="_id")

    class Config:
        # Permite que Pydantic convierta ObjectId a str
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        # Permite usar 'alias="_id"' para que funcione con el 'id' de Pydantic
        populate_by_name = True


# --- Funciones de Seguridad ---

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica la contraseña plana contra el hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Genera un hash para la contraseña."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Crea un nuevo token JWT."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Dependencia de Autenticación (Obtener usuario actual) ---

async def get_user_from_db(db: AsyncIOMotorDatabase, username: str) -> Optional[UserInDB]:
    """Busca un usuario en la DB por su username."""
    user_doc = await db.users.find_one({"username": username})
    if user_doc:
        return UserInDB(**user_doc)
    return None

async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> UserResponse:
    """
    Dependencia principal: Decodifica el token, valida al usuario y lo retorna.
    Si algo falla, lanza una excepción HTTP 401.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await get_user_from_db(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    
    # Para la respuesta, obtenemos el documento completo (incluyendo _id)
    user_doc = await db.users.find_one({"username": user.username})
    return UserResponse(**user_doc)


# --- Creación de la App FastAPI ---
# Requisito 2.3: Swagger/OpenAPI
# FastAPI lo genera automáticamente.
# NGINX lo expondrá en /api/auth/docs
app = FastAPI(
    title="Auth Service",
    description="Microservicio de Autenticación (Entrega 2)",
    version="1.0.0",
)

# Evento de inicio: crear índices únicos en MongoDB
@app.on_event("startup")
async def startup_db_client():
    await db_client.users.create_index("username", unique=True)
    await db_client.users.create_index("email", unique=True)
    print("MongoDB indexes created.")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
    print("MongoDB connection closed.")


# --- Endpoints de Autenticación ---

@app.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Endpoint de Login. Recibe 'username' y 'password' en un formulario,
    verifica las credenciales y devuelve un token JWT.
    """
    user = await get_user_from_db(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


# --- Endpoints CRUD de Usuarios (Requisito 2.2) ---

@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["Users (CRUD)"])
async def create_user(
    user_in: UserCreate, 
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    (C)REATE: Registrar un nuevo usuario.
    """
    # Verificar si el usuario o email ya existen
    if await db.users.find_one({"username": user_in.username}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    if await db.users.find_one({"email": user_in.email}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # Hashear la contraseña
    hashed_password = get_password_hash(user_in.password)
    
    # Crear el objeto UserInDB
    user_db_data = user_in.model_dump()
    user_db_data.pop("password") # Quitamos la contraseña en plano
    user_db = UserInDB(**user_db_data, hashed_password=hashed_password)
    
    # Insertar en la base de datos
    new_user = await db.users.insert_one(user_db.model_dump(exclude_unset=True))
    
    # Obtener el usuario creado para devolverlo
    created_user_doc = await db.users.find_one({"_id": new_user.inserted_id})
    
    return UserResponse(**created_user_doc)

@app.get("/users/me", response_model=UserResponse, tags=["Users (CRUD)"])
async def read_users_me(current_user: UserResponse = Depends(get_current_user)):
    """
    (R)EAD: Obtener los datos del usuario autenticado actualmente.
    """
    return current_user

@app.get("/users/{username}", response_model=UserResponse, tags=["Users (CRUD)"])
async def read_user(username: str, db: AsyncIOMotorDatabase = Depends(get_database)):
    """
    (R)EAD: Obtener los datos de un usuario por su 'username'.
    (En un sistema real, esto debería estar protegido por roles, ej: solo admin)
    """
    user_doc = await db.users.find_one({"username": username})
    if user_doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return UserResponse(**user_doc)

@app.put("/users/me", response_model=UserResponse, tags=["Users (CRUD)"])
async def update_user_me(
    user_update: UserBase, # Modelo base para actualizar
    current_user: UserResponse = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    (U)PDATE: Actualizar los datos del usuario autenticado.
    (No permite cambiar contraseña, eso sería un endpoint aparte).
    """
    update_data = user_update.model_dump(exclude_unset=True)
    
    # Prevenir que se cambie el username
    if "username" in update_data and update_data["username"] != current_user.username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot change username")
    
    # Verificar si el nuevo email ya está en uso por OTRO usuario
    if "email" in update_data and update_data["email"] != current_user.email:
        if await db.users.find_one({"email": update_data["email"]}):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use")

    updated_user_doc = await db.users.find_one_and_update(
        {"username": current_user.username},
        {"$set": update_data},
        return_document=True # Devuelve el documento actualizado
    )
    
    if updated_user_doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found during update")

    return UserResponse(**updated_user_doc)


@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT, tags=["Users (CRUD)"])
async def delete_user_me(
    current_user: UserResponse = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    (D)ELETE: Eliminar al usuario autenticado.
    """
    delete_result = await db.users.delete_one({"username": current_user.username})
    
    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found, cannot delete")
    
    return # Retorna 204 No Content

# --- Endpoint de Salud (Buena práctica) ---
@app.get("/health", status_code=status.HTTP_200_OK, tags=["Health"])
async def health_check():
    """Endpoint simple para que el proxy verifique si el servicio está vivo."""
    return {"status": "ok"}