import datetime
import os

from sqlalchemy import Boolean, DateTime, ForeignKey, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )

    subscription: Mapped["Subscription"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)
    razorpay_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    credited_payment_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="none")
    # Razorpay's cancel_at_cycle_end leaves the subscription entity's own
    # `status` as "active" until the period actually ends (it only flips to
    # "cancelled" via a later webhook) and exposes no other field marking the
    # pending cancellation, so we track intent ourselves.
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    current_period_end: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    user: Mapped["User"] = relationship(back_populates="subscription")

    @property
    def is_active(self) -> bool:
        return bool(
            self.current_period_end and self.current_period_end > datetime.datetime.utcnow()
        )


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
