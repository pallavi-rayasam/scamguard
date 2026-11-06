"""Load the versioned seed catalogue into PostgreSQL."""
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.entities import ScamCategory, ScamPattern
from app.detection.normalize import load_categories


def seed() -> int:
    created = 0
    with SessionLocal() as db:
        for item in load_categories():
            category = db.scalar(select(ScamCategory).where(ScamCategory.code == item["code"]))
            if category is None:
                category = ScamCategory(code=item["code"], language=item["language"], display_name=item["name"])
                db.add(category)
                db.flush()
                created += 1
            for pattern in item.get("patterns", []):
                exists = db.scalar(select(ScamPattern.id).where(ScamPattern.category_id == category.id, ScamPattern.pattern == pattern))
                if exists is None:
                    db.add(ScamPattern(category_id=category.id, language=item["language"], pattern=pattern, weight=8))
                    created += 1
        db.commit()
    return created


if __name__ == "__main__":
    print(f"Inserted {seed()} seeded categories/patterns.")
