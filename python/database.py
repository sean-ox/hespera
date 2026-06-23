"""Database connection and session management."""
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine
)
from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass

from python.settings import load_settings

settings = load_settings()


class Base(DeclarativeBase, MappedAsDataclass):
    """Base model class."""
    pass


class DatabaseManager:
    """Manages database connections with connection pooling."""
    
    def __init__(self, database_url: str):
        self._engine: Optional[AsyncEngine] = None
        self._session_factory: Optional[async_sessionmaker] = None
        self._database_url = database_url
    
    async def initialize(self) -> None:
        """Initialize connection pool."""
        self._engine = create_async_engine(
            self._database_url,
            echo=False,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    
    async def create_tables(self) -> None:
        """
        Create all tables and enum types (if any) using SQLAlchemy metadata.
        This ensures that the database schema matches the models.
        """
        if not self._engine:
            raise RuntimeError("Database not initialized")
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def close(self) -> None:
        """Close all connections."""
        if self._engine:
            await self._engine.dispose()
    
    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session context manager."""
        if not self._session_factory:
            raise RuntimeError("Database not initialized")
        
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


# Global instance
db_manager = DatabaseManager(settings.database_url)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI."""
    async with db_manager.session() as session:
        yield session
