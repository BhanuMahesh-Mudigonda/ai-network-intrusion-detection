"""
FastAPI Real-Time Prediction API for Network Intrusion Detection.

Exposes the final trained XGBoost model through a clean REST API:
- Load saved XGBoost model bundle once on application startup
- Real-time prediction endpoint: POST /predict
- Batch prediction endpoint: POST /predict/batch
- Model metadata endpoint: GET /model-info
- Health check endpoint: GET /health
- OpenAPI interactive documentation at /docs and /redoc
- Canonical frontend dashboard mounted at /dashboard/
"""

from contextlib import asynccontextmanager
from typing import Dict, Any, List
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from api.schemas import (
    NetworkFlowInput,
    PredictionResponse,
    BatchPredictionRequest,
    BatchPredictionResponse,
    ModelInfoResponse,
    FEATURE_NAMES,
)
from api.model_service import model_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager:
    Loads trained XGBoost model once when FastAPI application starts.
    """
    print("\n" + "=" * 80)
    print(" STARTING NETWORK INTRUSION DETECTION FASTAPI BACKEND")
    print("=" * 80)
    loaded = model_service.load_model()
    if loaded:
        print("[Lifespan] Final XGBoost model bundle ready for inference.")
    else:
        print("[Lifespan] WARNING: Model loading postponed until model artifact is generated.")
    yield
    print("[Lifespan] Shutting down FastAPI application.")


app = FastAPI(
    title="Network Intrusion Detection API",
    description="Real-Time Network Flow Security & Intrusion Detection API powered by XGBoost.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for frontend applications
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend static directory as canonical /dashboard route
app_dir = Path(__file__).resolve().parent.parent / "app"
if app_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(app_dir), html=True), name="dashboard")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Custom exception handler for request validation errors:
    Returns clear, user-friendly error messages when features are missing or invalid.
    """
    errors = []
    for err in exc.errors():
        location = " -> ".join(str(loc) for loc in err.get("loc", []))
        msg = err.get("msg", "Validation error")
        errors.append(f"[{location}]: {msg}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "Invalid input payload. All 78 network-flow features are required and must be valid numeric values (non-NaN, non-infinite).",
            "details": errors,
        },
    )


@app.get("/", tags=["General"])
async def root(request: Request):
    """Root endpoint redirecting HTML requests to canonical /dashboard/ or returning API metadata."""
    if "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(url="/dashboard/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    return {
        "title": "Network Intrusion Detection API",
        "status": "online",
        "dashboard": "/dashboard/",
        "model_name": model_service.model_name,
        "model_loaded": model_service.is_loaded,
        "audit_status": "VALID WITH CAUTION",
        "documentation": "/docs",
        "health_check": "/health",
        "model_info": "/model-info",
        "prediction_endpoint": "/predict",
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Favicon endpoint preventing 404 log noise."""
    fav_file = app_dir / "favicon.ico"
    if fav_file.exists():
        return FileResponse(fav_file)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/style.css", include_in_schema=False)
async def get_root_css():
    """Asset fallback serving style.css at root level."""
    css_file = app_dir / "style.css"
    if css_file.exists():
        return FileResponse(css_file)
    return Response(status_code=status.HTTP_404_NOT_FOUND)


@app.get("/app.js", include_in_schema=False)
async def get_root_js():
    """Asset fallback serving app.js at root level."""
    js_file = app_dir / "app.js"
    if js_file.exists():
        return FileResponse(js_file)
    return Response(status_code=status.HTTP_404_NOT_FOUND)


@app.get("/three_canvas.js", include_in_schema=False)
async def get_root_three():
    """Asset fallback serving three_canvas.js at root level."""
    three_file = app_dir / "three_canvas.js"
    if three_file.exists():
        return FileResponse(three_file)
    return Response(status_code=status.HTTP_404_NOT_FOUND)


@app.get("/health", tags=["General"])
async def health_check():
    """Health check endpoint to verify system status and model readiness."""
    return {
        "status": "healthy" if model_service.is_loaded else "degraded",
        "model_loaded": model_service.is_loaded,
        "model_name": model_service.model_name,
        "features_expected": len(FEATURE_NAMES),
        "audit_status": "VALID WITH CAUTION",
    }


@app.get("/model-info", response_model=ModelInfoResponse, tags=["Model Info"])
async def get_model_info():
    """Get metadata, features list, target classes, evaluation metrics, and audit status."""
    info = model_service.get_info()
    if not info["is_loaded"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded. Please ensure saved model bundle exists in models/",
        )
    return ModelInfoResponse(
        model_name=info["model_name"],
        num_features=info["num_features"],
        features=info["features"],
        num_classes=info["num_classes"],
        class_names=info["class_names"],
        metrics=info["metrics"],
        audit_status=info["audit_status"],
        loaded_model_path=info["loaded_model_path"],
    )


@app.post(
    "/predict",
    response_model=PredictionResponse,
    status_code=status.HTTP_200_OK,
    tags=["Inference"],
    summary="Classify real-time network flow for intrusion detection",
)
async def predict(flow_input: NetworkFlowInput):
    """
    Real-Time Prediction Endpoint.

    Passes raw network-flow features through the exact preprocessing, scaling, and XGBoost pipeline:
    Input -> validation -> feature ordering -> preprocessor scaling -> XGBoost model -> prediction -> probabilities -> response

    Returns JSON containing prediction label, confidence score, attack probability, and normal probability.
    """
    if not model_service.is_loaded:
        loaded = model_service.load_model()
        if not loaded:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="XGBoost model is not loaded.",
            )

    try:
        response = model_service.predict_flow(flow_input)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference execution failed: {str(e)}",
        )


@app.post(
    "/predict/batch",
    response_model=BatchPredictionResponse,
    status_code=status.HTTP_200_OK,
    tags=["Inference"],
    summary="Classify a batch of network flows",
)
async def predict_batch(request: BatchPredictionRequest):
    """Batch prediction endpoint for classifying multiple network flows simultaneously."""
    if not model_service.is_loaded:
        loaded = model_service.load_model()
        if not loaded:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="XGBoost model is not loaded.",
            )

    predictions = []
    for flow in request.flows:
        res = model_service.predict_flow(flow)
        predictions.append(res)

    return BatchPredictionResponse(
        total_count=len(predictions),
        predictions=predictions,
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
