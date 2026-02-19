from pydantic import BaseModel, Field

class AppConfig(BaseModel):
    server_url: str = Field(default="http://127.0.0.1:8080")
    window_title: str = Field(default="VaultQ | Doctor Security Terminal")
    window_size: str = Field(default="1000x700")
    doctor_name: str = Field(default="Dr. Sanjit Kamath")
    doctor_kid: str = Field(default="kid_vaultq_001") # In prod, loaded from X.509 cert

config = AppConfig()