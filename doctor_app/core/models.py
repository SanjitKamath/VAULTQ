from pydantic import BaseModel, Field
from typing import Optional

class HandshakeResponse(BaseModel):
    ecdh_pub: str
    pqc_pub: str

class HandshakePayload(BaseModel):
    pqc_ct: str
    ecdh_pub: str

class UploadForm(BaseModel):
    patient_id: str = Field(..., min_length=3, description="Patient Identifier")
    filepath: str = Field(..., description="Path to the PDF/DICOM file")

class LogMessage(BaseModel):
    level: str = Field(default="INFO")
    text: str