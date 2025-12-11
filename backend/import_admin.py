from werkzeug.security import generate_password_hash
from app import create_app
from models import db
from models.entities import Admin

app = create_app()
app.app_context().push()

admins = [
    {
        "nama": "Super Admin",
        "username": "admin",
        "email": "admin@mail.com",
        "password": "@admin123",
        "role": "superadmin"
    },
    {
        "nama": "Admin1",
        "username": "admin1",
        "email": "admin1@mail.com",
        "password": "admin1123",
        "role": "admin"
    },
    {
        "nama": "Admin2",
        "username": "admin2",
        "email": "admin2@mail.com",
        "password": "admin2123",
        "role": "admin"
    }
]
for data in admins:
    admin = Admin(
        nama_admin=data["nama"],
        username=data["username"],
        email=data["email"],
        role=data["role"],
        password_hash=generate_password_hash(data["password"])
    )
    db.session.add(admin)

db.session.commit()

print("Semua admin berhasil dibuat!")
