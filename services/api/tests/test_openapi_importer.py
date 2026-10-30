import json
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.inventory.openapi_importer import iter_spec_endpoints, parse_openapi_document
from app.main import app
from app.models import Endpoint, EndpointParameter, SafetyControl, Target
from app.settings import settings


OPENAPI_JSON = {
    "openapi": "3.0.3",
    "info": {"title": "Travel API", "version": "1.0"},
    "servers": [{"url": "http://staging-app:8080"}],
    "paths": {
        "/api/v1/bookings/{bookingId}": {
            "parameters": [
                {"name": "bookingId", "in": "path", "required": True, "schema": {"type": "integer"}},
            ],
            "get": {
                "parameters": [
                    {"name": "expand", "in": "query", "schema": {"type": "boolean"}},
                    {"name": "X-Trace", "in": "header", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "properties": {
                        "guestCount": {"type": "integer"},
                        "traveler": {"type": "object", "properties": {"name": {"type": "string"}}},
                    },
                }}}},
                "responses": {"201": {"description": "Created"}},
            },
        }
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}

OPENAPI_YAML = """
openapi: 3.0.1
info:
  title: Catalog API
  version: '1'
paths:
  /api/v1/payments:
    post:
      parameters:
        - name: idempotencyKey
          in: header
          schema:
            type: string
      responses:
        '202':
          description: Accepted
"""

SWAGGER_JSON = {
    "swagger": "2.0", "info": {"title": "Legacy API", "version": "1"},
    "host": "staging-app:8080", "schemes": ["http"], "basePath": "/api",
    "paths": {"/users/{userId}": {"get": {
        "parameters": [
            {"name": "userId", "in": "path", "required": True, "type": "integer"},
            {"name": "filter", "in": "query", "type": "string"},
        ], "responses": {"200": {"description": "OK"}},
    }}},
    "securityDefinitions": {"apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"}},
}


class OpenAPIImporterTests(unittest.TestCase):
    def test_openapi_json_extracts_parameters_body_and_security(self):
        spec = parse_openapi_document(json.dumps(OPENAPI_JSON), "api.json")
        endpoints = list(iter_spec_endpoints(spec))
        get_op = next(item for item in endpoints if item["method"] == "GET")
        post_op = next(item for item in endpoints if item["method"] == "POST")
        actual = {(p["name"], p["location"], p["observed_type"]) for p in get_op["parameters"]}
        self.assertIn(("bookingId", "path", "integer"), actual)
        self.assertIn(("expand", "query", "boolean"), actual)
        self.assertIn(("X-Trace", "header", "string"), actual)
        body = {(p["name"], p["observed_type"]) for p in post_op["parameters"] if p["location"] == "body"}
        self.assertIn(("guestCount", "integer"), body)
        self.assertIn(("traveler.name", "string"), body)
        self.assertTrue(post_op["auth_required"])
        self.assertIn(("Authorization", "header", "string"), {(p["name"], p["location"], p["observed_type"]) for p in post_op["parameters"]})

    def test_yaml_and_swagger_20_are_supported(self):
        yaml_spec = parse_openapi_document(OPENAPI_YAML.encode(), "spec.yaml")
        self.assertEqual(list(iter_spec_endpoints(yaml_spec))[0]["parameters"][0]["name"], "idempotencyKey")
        swagger_spec = parse_openapi_document(json.dumps(SWAGGER_JSON), "swagger.json")
        endpoint = next(iter_spec_endpoints(swagger_spec))
        self.assertEqual(endpoint["path"], "/api/users/{userId}")
        self.assertIn({"name": "filter", "location": "query", "observed_type": "string"}, endpoint["parameters"])

    def test_rejects_external_references_and_invalid_documents(self):
        invalid = dict(OPENAPI_JSON)
        invalid["paths"] = {"/x": {"get": {"$ref": "https://example.invalid/operation.yaml", "responses": {}}}}
        with self.assertRaises(ValueError):
            parse_openapi_document(json.dumps(invalid), "bad.json")
        with self.assertRaises(ValueError):
            parse_openapi_document("not: [valid", "bad.yaml")

    def test_upload_endpoint_ingests_and_classifies_routes(self):
        old_origins = settings.allowed_target_origins
        settings.allowed_target_origins = "http://staging-app:8080"
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
        try:
            with factory() as db:
                db.add(SafetyControl(id=1, kill_switch_engaged=False, reason=""))
                target = Target(name="Staging", base_url="http://staging-app:8080", environment="staging", status="authorized")
                db.add(target)
                db.commit()
                target_id = target.id

            def override_get_db():
                with factory() as session:
                    yield session

            app.dependency_overrides[get_db] = override_get_db
            with TestClient(app) as client:
                response = client.post(
                    f"/api/targets/{target_id}/openapi-import",
                    files={"file": ("travel.json", json.dumps(OPENAPI_JSON), "application/json")},
                )
            self.assertEqual(response.status_code, 200, response.text)
            data = response.json()
            self.assertEqual(data["discovered"], 2)
            self.assertEqual(data["classification_counts"]["zombie"], 2)
            with factory() as db:
                endpoints = db.execute(select(Endpoint).where(Endpoint.target_id == target_id)).scalars().all()
                self.assertTrue(all(endpoint.source == "openapi" for endpoint in endpoints))
                self.assertTrue(all(endpoint.owner == "Booking & Orders Team" for endpoint in endpoints))
                params = db.execute(select(EndpointParameter).join(Endpoint).where(Endpoint.target_id == target_id)).scalars().all()
                self.assertIn("guestCount", {param.name for param in params})
        finally:
            app.dependency_overrides.clear()
            Base.metadata.drop_all(engine)
            engine.dispose()
            settings.allowed_target_origins = old_origins


if __name__ == "__main__":
    unittest.main()
