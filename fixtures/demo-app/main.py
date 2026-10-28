import os

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="SentinelFlow Synthetic Booking Fixture")
FIXED = os.getenv("DEMO_FIX_IDOR", "false").lower() in {"1", "true", "yes"}
BOOKINGS = {
    "1001": {"booking_id": "1001", "agency_id": "agency-a", "traveler": "Synthetic Traveler A", "total": 420.00},
    "2002": {"booking_id": "2002", "agency_id": "agency-b", "traveler": "Synthetic Traveler B", "total": 615.00},
}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/api/v1/bookings/{booking_id}")
def get_booking(booking_id: str, x_demo_agency: str | None = Header(default=None)) -> dict:
    if x_demo_agency not in {"agency-a", "agency-b"}:
        raise HTTPException(status_code=401, detail="Synthetic agency identity required.")
    booking = BOOKINGS.get(booking_id)
    if booking is None:
        raise HTTPException(status_code=404, detail="Booking not found.")
    # Intentionally vulnerable until DEMO_FIX_IDOR=true: authorization ignores agency ownership.
    if FIXED and booking["agency_id"] != x_demo_agency:
        raise HTTPException(status_code=404, detail="Booking not found.")
    return booking
