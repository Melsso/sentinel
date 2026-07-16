from fastapi import FastAPI

app = FastAPI(
    title="Sentinel",
    description="Authentication server",
)


@app.get("/health")
async def health():
    return {"status": "ok"}