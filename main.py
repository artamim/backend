# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from auth.auth_routes import router as auth_router

app = FastAPI()

# Use the same IP for both frontend and backend
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://192.168.1.99:3000",  # Your current frontend
    os.getenv("FRONTEND_URL", "http://localhost:3000"),
]

print("CORS Allowed Origins:", ALLOWED_ORIGINS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(auth_router)

@app.get("/")
async def root():
    return {"message": "API is running"}

if __name__ == "__main__":
    import uvicorn
    # Bind to the same IP as your frontend
    uvicorn.run(app, host="192.168.1.99", port=8000, reload=True)