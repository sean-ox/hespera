"""Pytest configuration and fixtures."""
import pytest
import asyncio
from typing import AsyncGenerator

from python.database import db_manager
from python.settings import load_settings


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def db_session() -> AsyncGenerator:
    """Get database session for testing."""
    settings = load_settings()
    # Use test database
    db_manager._database_url = settings.database_url.replace("/bugbounty", "/bugbounty_test")
    await db_manager.initialize()
    
    async with db_manager.session() as session:
        yield session
    
    await db_manager.close()