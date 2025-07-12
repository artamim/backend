from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from auth.auth_routes import router as auth_router

app = FastAPI()

# Get FRONTEND_URL from environment variables with a fallback
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],  # Use the environment variable or fallback
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include auth routes
app.include_router(auth_router)