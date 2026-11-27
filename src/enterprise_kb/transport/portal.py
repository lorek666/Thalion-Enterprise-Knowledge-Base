from importlib.resources import files

from fastapi import FastAPI, Response


PAGE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'; worker-src 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def register_employee_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "employee")
    shell = directory.joinpath("portal.html").read_bytes()
    script = directory.joinpath("portal.js").read_bytes()
    stylesheet = directory.joinpath("portal.css").read_bytes()

    @app.get("/")
    async def employee_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/employee/portal.js")
    async def employee_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)

    @app.get("/employee/portal.css")
    async def employee_styles():
        return Response(stylesheet, media_type="text/css", headers=PAGE_HEADERS)


def register_wiki_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("wiki.html").read_bytes()
    script = directory.joinpath("wiki.js").read_bytes()
    stylesheet = directory.joinpath("wiki.css").read_bytes()

    @app.get("/manage/wiki")
    async def wiki_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/wiki.js")
    async def wiki_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)

    sso_script = directory.joinpath("sso.js").read_bytes()

    @app.get("/manage/wiki.css")
    async def wiki_management_styles():
        return Response(stylesheet, media_type="text/css", headers=PAGE_HEADERS)

    @app.get("/manage/sso.js")
    async def management_sso_script():
        return Response(sso_script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_runtime_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("runtime.html").read_bytes()
    script = directory.joinpath("runtime.js").read_bytes()

    @app.get("/manage/runtime")
    async def runtime_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/runtime.js")
    async def runtime_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_sources_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("sources.html").read_bytes()
    script = directory.joinpath("sources.js").read_bytes()

    @app.get("/manage/sources")
    async def sources_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/sources.js")
    async def sources_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_feedback_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("feedback.html").read_bytes()
    script = directory.joinpath("feedback.js").read_bytes()

    @app.get("/manage/feedback")
    async def feedback_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/feedback.js")
    async def feedback_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_repair_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("repair.html").read_bytes()
    script = directory.joinpath("repair.js").read_bytes()

    @app.get("/manage/repairs")
    async def repair_management_portal():
        headers = PAGE_HEADERS | {"Content-Security-Policy": PAGE_HEADERS["Content-Security-Policy"] + "; img-src blob:"}
        return Response(shell, media_type="text/html", headers=headers)

    @app.get("/manage/repair.js")
    async def repair_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_ingest_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("ingest.html").read_bytes()
    script = directory.joinpath("ingest.js").read_bytes()

    @app.get("/manage/ingest")
    async def ingest_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/ingest.js")
    async def ingest_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_effectivity_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("effectivity.html").read_bytes()
    script = directory.joinpath("effectivity.js").read_bytes()

    @app.get("/manage/effectivity")
    async def effectivity_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/effectivity.js")
    async def effectivity_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_policy_management_portals(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    readers = directory.joinpath("readers.html").read_bytes()
    model_egress = directory.joinpath("model_egress.html").read_bytes()
    script = directory.joinpath("readers.js").read_bytes()

    @app.get("/manage/readers")
    async def reader_management_portal():
        return Response(readers, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/model-egress")
    async def model_egress_management_portal():
        return Response(model_egress, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/readers.js")
    async def reader_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_responsibility_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("responsibility.html").read_bytes()
    script = directory.joinpath("responsibility.js").read_bytes()

    @app.get("/manage/responsibility")
    async def responsibility_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/responsibility.js")
    async def responsibility_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_governance_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("governance.html").read_bytes()
    script = directory.joinpath("governance.js").read_bytes()

    @app.get("/manage/governance")
    async def governance_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/governance.js")
    async def governance_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_lifecycle_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("lifecycle.html").read_bytes()
    script = directory.joinpath("lifecycle.js").read_bytes()

    @app.get("/manage/lifecycle")
    async def lifecycle_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/lifecycle.js")
    async def lifecycle_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_catalog_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("catalog.html").read_bytes()
    script = directory.joinpath("catalog.js").read_bytes()

    @app.get("/manage/catalog")
    async def catalog_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/catalog.js")
    async def catalog_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_glossary_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("glossary.html").read_bytes()
    script = directory.joinpath("glossary.js").read_bytes()

    @app.get("/manage/glossary")
    async def glossary_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/glossary.js")
    async def glossary_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)


def register_archives_management_portal(app: FastAPI):
    directory = files("enterprise_kb").joinpath("transport", "management")
    shell = directory.joinpath("archives.html").read_bytes()
    script = directory.joinpath("archives.js").read_bytes()

    @app.get("/manage/archives")
    async def archives_management_portal():
        return Response(shell, media_type="text/html", headers=PAGE_HEADERS)

    @app.get("/manage/archives.js")
    async def archives_management_script():
        return Response(script, media_type="text/javascript", headers=PAGE_HEADERS)
