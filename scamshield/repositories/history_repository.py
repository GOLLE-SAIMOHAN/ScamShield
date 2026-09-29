"""Scan history repository backed by MongoDB."""

import re
from typing import Protocol
from uuid import uuid4

from flask import current_app

from scamshield.repositories.base_repository import (
    handle_repository_error,
    public_document,
)
from scamshield.repositories.database import COLLECTIONS, get_collection
from scamshield.repositories.schemas import validate_scan


class HistoryRepositoryInterface(Protocol):
    """Protocol for scan persistence implementations."""

    @staticmethod
    def add_history(
        kind: str,
        input_value: str,
        risk: str,
        score: int,
        details: dict | None,
    ) -> None:
        """Persist a scan history entry."""

    @staticmethod
    def list_history(limit: int = 8) -> list[dict]:
        """Return recent scan history."""


class HistoryRepository:
    """MongoDB-backed scan history repository."""

    collection_name = COLLECTIONS["scans"]

    @staticmethod
    def add_history(
        kind: str,
        input_value: str,
        risk: str,
        score: int,
        details: dict | None = None,
    ) -> None:
        """Persist a scan history entry in the scans collection."""
        HistoryRepository.create_scan(
            {
                "scan_id": f"scan-{uuid4()}",
                "kind": kind,
                "input": input_value,
                "risk": risk,
                "score": score,
                "details": details or {},
                "url": input_value if kind == "URL" else None,
            }
        )

    @staticmethod
    def create_scan(scan: dict) -> dict:
        """Insert a scan document and return it."""
        document = validate_scan(scan)
        try:
            get_collection(HistoryRepository.collection_name).insert_one(document)
            current_app.logger.info(
                "scan_inserted scan_id=%s kind=%s",
                document["scan_id"],
                document["kind"],
            )
            return public_document(document)
        except Exception as error:
            current_app.logger.exception(
                "scan_insert_failed kind=%s", document.get("kind")
            )
            handle_repository_error(error)

    @staticmethod
    def create_url_scan(scan: dict) -> dict:
        """Persist a normalized URL scan result."""
        scan = {
            **scan,
            "kind": "URL",
            "input": scan["url"],
            "risk": scan["classification"],
            "score": scan["risk_score"],
        }
        document = validate_scan(scan)
        try:
            get_collection(HistoryRepository.collection_name).insert_one(document)
            current_app.logger.info(
                "url_scan_inserted scan_id=%s risk_score=%s",
                document["scan_id"],
                document["risk_score"],
            )
            return public_document(document)
        except Exception as error:
            current_app.logger.exception(
                "url_scan_insert_failed scan_id=%s", document.get("scan_id")
            )
            handle_repository_error(error)

    @staticmethod
    def list_history(limit: int = 8) -> list[dict]:
        """Return recent scan history documents in the frontend shape."""
        try:
            cursor = (
                get_collection(HistoryRepository.collection_name)
                .find({}, {"_id": 0})
                .sort("created_at", -1)
                .limit(limit)
            )
            return [
                {
                    "kind": item["kind"],
                    "input": item["input"],
                    "risk": item["risk"],
                    "score": item["score"],
                    "created_at": item["created_at"],
                }
                for item in map(public_document, cursor)
            ]
        except Exception as error:
            current_app.logger.exception("scan_list_failed")
            handle_repository_error(error)

    @staticmethod
    def list_history_page(
        page: int = 1,
        per_page: int = 10,
        search: str = "",
        classification: str = "",
    ) -> dict:
        """Return paginated scan history with search and classification filters."""
        page = max(1, int(page or 1))
        per_page = min(50, max(1, int(per_page or 10)))
        query = HistoryRepository._history_query(search, classification)

        try:
            collection = get_collection(HistoryRepository.collection_name)
            total = collection.count_documents(query)
            cursor = (
                collection.find(query, {"_id": 0})
                .sort("created_at", -1)
                .skip((page - 1) * per_page)
                .limit(per_page)
            )
            items = [
                HistoryRepository._history_item(public_document(item))
                for item in cursor
            ]
            total_pages = (total + per_page - 1) // per_page if total else 0
            return {
                "items": items,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1 and total_pages > 0,
                },
                "filters": {
                    "search": search,
                    "classification": classification,
                },
            }
        except Exception as error:
            current_app.logger.exception("scan_history_page_failed")
            handle_repository_error(error)

    @staticmethod
    def find_by_scan_id(scan_id: str) -> dict | None:
        """Find a scan history document by scan_id."""
        try:
            cursor = get_collection(HistoryRepository.collection_name).find(
                {"scan_id": scan_id}, {"_id": 0}
            )
            items = list(cursor)
            return public_document(items[0]) if items else None
        except Exception as error:
            current_app.logger.exception("scan_find_failed scan_id=%s", scan_id)
            handle_repository_error(error)

    @staticmethod
    def delete_scan(scan_id: str) -> bool:
        """Delete a scan history entry by scan id."""
        try:
            result = get_collection(HistoryRepository.collection_name).delete_one(
                {"scan_id": scan_id}
            )
            deleted = int(getattr(result, "deleted_count", 0)) > 0
            if deleted:
                current_app.logger.info("scan_deleted scan_id=%s", scan_id)
            return deleted
        except Exception as error:
            current_app.logger.exception("scan_delete_failed scan_id=%s", scan_id)
            handle_repository_error(error)

    @staticmethod
    def count_scans() -> int:
        """Return the total number of scan documents."""
        try:
            return get_collection(HistoryRepository.collection_name).count_documents({})
        except Exception as error:
            current_app.logger.exception("scan_count_failed")
            handle_repository_error(error)

    @staticmethod
    def _history_query(search: str, classification: str) -> dict:
        clauses = []
        search = (search or "").strip()
        classification = (classification or "").strip()

        if search:
            escaped_search = re.escape(search)
            clauses.append(
                {
                    "$or": [
                        {"url": {"$regex": escaped_search, "$options": "i"}},
                        {"input": {"$regex": escaped_search, "$options": "i"}},
                        {"classification": {"$regex": escaped_search, "$options": "i"}},
                        {"risk": {"$regex": escaped_search, "$options": "i"}},
                        {"kind": {"$regex": escaped_search, "$options": "i"}},
                    ]
                }
            )

        if classification:
            escaped_classification = re.escape(classification)
            clauses.append(
                {
                    "$or": [
                        {
                            "classification": {
                                "$regex": f"^{escaped_classification}$",
                                "$options": "i",
                            }
                        },
                        {
                            "risk": {
                                "$regex": f"^{escaped_classification}$",
                                "$options": "i",
                            }
                        },
                    ]
                }
            )

        if len(clauses) == 1:
            return clauses[0]
        if clauses:
            return {"$and": clauses}
        return {}

    @staticmethod
    def _history_item(item: dict) -> dict:
        score = item.get("risk_score", item.get("score", 0))
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0

        return {
            "scan_id": item.get("scan_id", ""),
            "url": item.get("url") or item.get("input") or "",
            "risk_score": score,
            "classification": item.get("classification") or item.get("risk") or "Unknown",
            "scan_date": item.get("created_at"),
        }
