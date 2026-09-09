from __future__ import annotations


async def test_capabilities_lists_credential_without_secret_fields(client):
    r = await client.get("/capabilities")
    assert r.status_code == 200
    body = r.json()
    assert body["credentials"][0]["credential_id"] == "github_reader"
    assert set(body["credentials"][0]) == {
        "credential_id",
        "description",
        "allowed_actions",
    }
    text = r.text
    for leak in ("GITHUB_TOKEN", "secret_name", "provider", "dotenv", "connector"):
        assert leak not in text


async def test_capabilities_requires_token(app):
    import httpx

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.get("/capabilities")
    assert r.status_code == 401
    assert r.json() == {"error": "UNAUTHORIZED"}
