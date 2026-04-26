import pytest
from primogem.database import get_db, User, hash_password, verify_password

def test_user_creation():
    db = next(get_db())
    hashed = hash_password("test123")
    
    db.query(User).filter(User.username == "testuser").delete()
    db.commit()
    
    user = User(
        username="testuser",
        hashed_password=hashed,
        sub="testuser-sub-unique",
        full_name="Test User",
        department="IT",
        roles="employee",
        scopes="files:read",
        is_active=True
    )
    
    db.add(user)
    db.commit()
    
    found = db.query(User).filter(User.username == "testuser").first()
    assert found is not None
    assert found.sub == "testuser-sub-unique"
    assert verify_password("test123", found.hashed_password)