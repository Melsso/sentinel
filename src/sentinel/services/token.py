from sentinel.database.models import User
from sentinel.core.security import create_access_token


def generate_access_token(user: User) -> str:
    return create_access_token(
        subject=str(user.id),
    )
