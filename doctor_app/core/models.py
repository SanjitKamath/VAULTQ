from pydantic import BaseModel, Field
from typing import Optional

class UploadForm(BaseModel):
    patient_id: str = Field(..., min_length=3, description="Patient Identifier")
    filepath: str = Field(..., description="Path to the PDF/DICOM file")

class LogMessage(BaseModel):
    level: str = Field(default="INFO")
    text: str