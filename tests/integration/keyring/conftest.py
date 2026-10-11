# SPDX-FileCopyrightText: 2026 Alex Mextner
# SPDX-License-Identifier: MIT
from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from dbus_fast.aio import MessageBus
from tests.harness.dbus_session import private_bus, private_session

from passwords_app.keyring.client import SecretServiceClient
from passwords_app.keyring.secret_service import SecretServiceStore

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

__all__ = ["bus", "other_bus", "private_bus", "private_session", "seahorse", "store"]


@pytest.fixture
async def bus(private_bus: str) -> AsyncIterator[MessageBus]:
    connection = await MessageBus(bus_address=private_bus).connect()
    yield connection
    connection.disconnect()


@pytest.fixture
async def other_bus(private_bus: str) -> AsyncIterator[MessageBus]:
    """A second connection, standing in for another app (Seahorse, a browser)."""
    connection = await MessageBus(bus_address=private_bus).connect()
    yield connection
    connection.disconnect()


@pytest.fixture
async def store(bus: MessageBus) -> SecretServiceStore:
    return await SecretServiceStore.open(bus)


@pytest.fixture
async def seahorse(other_bus: MessageBus) -> SecretServiceClient:
    return await SecretServiceClient.open(other_bus)
