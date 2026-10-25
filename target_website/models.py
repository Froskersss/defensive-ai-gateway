"""
models.py: SQLAlchemy ORM Models & Synthetic Seeder
"""
import random
from sqlalchemy import Column, Integer, String, Text
from passlib.context import CryptContext
from database import Base, engine, SessionLocal

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "portal_users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(255))
    clearance = Column(String(50), default="RESTRICTED")

class Employee(Base):
    __tablename__ = "internal_employees"
    id = Column(Integer, primary_key=True, index=True)
    emp_code = Column(String(50), unique=True)
    full_name = Column(String(100))
    department = Column(String(100))
    clearance_level = Column(String(50))
    email = Column(String(100))

class WeaponProject(Base):
    __tablename__ = "weapon_projects"
    id = Column(Integer, primary_key=True, index=True)
    project_codename = Column(String(100), unique=True)
    category = Column(String(100))
    status = Column(String(50))
    budget_allocated = Column(String(50))
    classification_notes = Column(Text)

class ClassifiedDocument(Base):
    __tablename__ = "classified_documents"
    id = Column(Integer, primary_key=True, index=True)
    doc_id = Column(String(50), unique=True)
    title = Column(String(200))
    author = Column(String(100))
    content = Column(Text)

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    if db.query(Employee.id).count() > 0:
        db.close()
        return  # Already seeded

    print("[*] Seeding MySQL database with 150+ synthetic defense records & default admin...")

    # Default Admin User
    admin_user = User(
        username="admin",
        email="admin@aegis-defense.internal",
        hashed_password=pwd_context.hash("admin123"),
        clearance="TOP SECRET - SCI"
    )
    db.add(admin_user)

    departments = ["Advanced Ballistics", "Guidance & Avionics", "Cyber Defense R&D", "Naval Systems", "Executive Board"]
    clearances = ["INTERNAL", "CONFIDENTIAL", "SECRET", "TOP SECRET - SCI"]
    first_names = ["Marcus", "Elena", "Viktor", "Sarah", "Dmitri", "Aria", "Hassan", "Chloe", "Klaus", "Mei"]
    last_names = ["Vance", "Kovalev", "Sterling", "Cross", "Novak", "Takahashi", "Zhao", "O'Connor", "Weber", "Mercer"]

    # 1. Seed 100 Employees
    for i in range(1, 101):
        fname = random.choice(first_names)
        lname = random.choice(last_names)
        emp = Employee(
            emp_code=f"AEGIS-EMP-{i:03d}",
            full_name=f"{fname} {lname}",
            department=random.choice(departments),
            clearance_level=random.choice(clearances),
            email=f"{fname.lower()}.{lname.lower()}@aegis-defense.internal"
        )
        db.add(emp)

    # 2. Seed 30 Weapon Projects
    project_prefixes = ["Project", "Operation", "Initiative", "Directive"]
    project_names = ["Ares", "Valkyrie", "Hyperion", "Titan", "Centurion", "Stalker", "Phalanx", "Eclipse", "Gorgon", "Vortex"]
    categories = ["Kinetic Interceptor", "Hypersonic Glide Vehicle", "Directed Energy Weapon", "Autonomous Swarm Drone", "Quantum Comms"]
    statuses = ["R&D Phase", "Live Fire Testing", "Decommissioned", "Active Deployment"]

    for i in range(1, 31):
        name = f"{random.choice(project_prefixes)} {random.choice(project_names)}-{random.randint(10,99)}"
        proj = WeaponProject(
            project_codename=name,
            category=random.choice(categories),
            status=random.choice(statuses),
            budget_allocated=f"${random.randint(15, 450)}M",
            classification_notes=f"Classified technical logs for {name}. Target vector precision verified. Audit score: {random.randint(82, 99)}%."
        )
        db.add(proj)

    # 3. Seed 25 Classified Documents
    for i in range(1, 26):
        doc = ClassifiedDocument(
            doc_id=f"DOC-SEC-2026-{i:03d}",
            title=f"Technical Specification & Telemetry Report #{i}",
            author=f"Dr. {random.choice(first_names)} {random.choice(last_names)}",
            content=f"AEGIS DYNAMICS INTERNAL MEMORANDUM\nClassification: EYES ONLY\nSubject: Telemetry Analysis Batch {i}\nStatus: Nominal performance under stress."
        )
        db.add(doc)

    db.commit()
    db.close()
    print("[+] Database seeding complete successfully!")