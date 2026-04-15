"""
VulnScope - Backend API
Interroge l'API NVD du NIST pour trouver les CVE associées à des logiciels.
"""

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import httpx
from datetime import datetime, timedelta

app = FastAPI(title="VulnScope API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_cve(item: dict) -> dict:
    """Extrait les données utiles d'un CVE brut NVD."""
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "N/A")

    # Description
    descriptions = cve_data.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description.")

    # CVSS Score — essaye v31, puis v30, puis v2
    metrics = cve_data.get("metrics", {})
    score = 0.0
    severity = "UNKNOWN"

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics and metrics[version_key]:
            cvss = metrics[version_key][0].get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", "UNKNOWN")
            break

    # Date de publication
    published = cve_data.get("published", "")[:10]

    # Références
    refs = cve_data.get("references", [])
    links = [r.get("url", "") for r in refs[:3]]

    return {
        "id": cve_id,
        "description": desc[:300] + ("..." if len(desc) > 300 else ""),
        "score": score,
        "severity": severity.upper(),
        "published": published,
        "references": links,
    }


@app.get("/api/scan")
async def scan_software(
    keyword: str = Query(..., description="Nom du logiciel (ex: apache, openssh, mysql)"),
    days: int = Query(120, description="Rechercher les CVE des N derniers jours"),
):
    """
    Recherche les CVE pour un logiciel donné sur les N derniers jours.
    """
    pub_start = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    pub_end = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")

    params = {
        "keywordSearch": keyword,
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": 20,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(NVD_API_URL, params=params)

    if response.status_code != 200:
        return {"error": f"NVD API returned {response.status_code}", "results": []}

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    cves = [parse_cve(v) for v in vulnerabilities]
    # Trier par score CVSS décroissant
    cves.sort(key=lambda x: x["score"], reverse=True)

    # Stats
    critical = sum(1 for c in cves if c["score"] >= 9.0)
    high = sum(1 for c in cves if 7.0 <= c["score"] < 9.0)
    medium = sum(1 for c in cves if 4.0 <= c["score"] < 7.0)
    low = sum(1 for c in cves if 0 < c["score"] < 4.0)

    return {
        "keyword": keyword,
        "total": len(cves),
        "stats": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "results": cves,
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "VulnScope API", "timestamp": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
