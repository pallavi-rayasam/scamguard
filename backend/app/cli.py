"""Interactive administrative maintenance commands."""

import argparse
from getpass import getpass

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.entities import User


def create_first_admin(
    session_factory: sessionmaker = SessionLocal,
    input_fn=None,
    password_fn=None,
) -> str:
    """Create the first administrator using a password entered interactively."""
    input_fn = input if input_fn is None else input_fn
    password_fn = getpass if password_fn is None else password_fn

    with session_factory() as db:
        if db.scalar(select(User.id).where(User.role == "admin").limit(1)):
            raise RuntimeError("An administrator already exists; refusing to create another first admin.")

    email = TypeAdapter(EmailStr).validate_python(input_fn("Administrator email: ")).strip().lower()
    password = password_fn("New administrator password (12-128 characters): ")
    confirmation = password_fn("Confirm administrator password: ")
    if password != confirmation:
        raise ValueError("The passwords do not match.")
    if not 12 <= len(password) <= 128:
        raise ValueError("Password must be between 12 and 128 characters.")

    with session_factory() as db:
        with db.begin():
            if db.scalar(select(User.id).where(User.role == "admin").limit(1)):
                raise RuntimeError("An administrator already exists; refusing to create another first admin.")
            if db.scalar(select(User.id).where(User.email == email).limit(1)):
                raise RuntimeError("That email already belongs to an account; use a new email for the first admin.")
            db.add(User(email=email, password_hash=hash_password(password), role="admin"))
    return email


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-admin", help="interactively create the first admin account")
    args = parser.parse_args(argv)

    if args.command == "create-admin":
        try:
            email = create_first_admin()
        except (RuntimeError, ValueError, ValidationError) as exc:
            parser.exit(2, f"Error: {exc}\n")
        print(f"Administrator account created for {email}.")


if __name__ == "__main__":
    main()
