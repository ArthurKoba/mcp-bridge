"""Identity application operations against an isolated new SQL database."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from urllib.parse import quote
from uuid import UUID, uuid4

from pydantic import SecretStr
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from authorization.security import hash_password, random_token, token_hash, verify_password
from common.platform_db import PlatformDatabase
from common.platform_errors import (
    AccessDenied,
    AuthenticationRateLimited,
    Conflict,
    InvalidInput,
    InvalidInvitation,
    LastSuperuser,
    ResourceMissing,
)
from common.platform_ids import UserId
from identity._domain import User, canonical_username
from identity._operator_channel import UnixFirstAdminOperatorGate
from identity._owner_ledger import OwnerAuditRow, OwnerOutboxRow
from identity._persistence import InvitationRow, LoginAttemptRow, UserRow
from identity._repository import IdentityRepository, to_user
from identity._settings import IdentityLinkSettings


def utcnow() -> datetime:
    return datetime.now(UTC)


class IdentityService:
    def __init__(
        self,
        database: PlatformDatabase,
        settings: IdentityLinkSettings,
        *,
        operator_gate: UnixFirstAdminOperatorGate | None = None,
    ) -> None:
        if database.engine.url.database != "briareus_identity":
            raise RuntimeError("Identity operations require briareus_identity, not global DB")
        self.database = database
        self.repository = IdentityRepository()
        self._operator_gate = operator_gate
        self.admin_ui_public_url = settings.admin_ui_public_url
        self._dummy_password_digest = hash_password(random_token())

    def _link(self, kind: str, raw_token: str) -> str:
        if not self.admin_ui_public_url:
            raise InvalidInput("ADMIN_UI_PUBLIC_URL required when issuing an invitation/reset URL")
        return f"{self.admin_ui_public_url}?{kind}={quote(raw_token)}"

    @asynccontextmanager
    async def _transaction(self, existing: AsyncSession | None) -> AsyncIterator[AsyncSession]:
        if existing is not None:
            yield existing
        else:
            async with self.database.transaction() as session:
                yield session

    @staticmethod
    def _record_local_security_event(
        tx: AsyncSession,
        *,
        actor_id: UserId | None,
        target_id: UUID,
        event: str,
        credential_version: int,
    ) -> None:
        """Owner-local durable security event atomically with Identity mutation.

        Never emit raw setup tokens, usernames, passwords, auth headers, IPs
        or credential material; Control/Access read projections do not grant.
        """
        if not event.startswith("identity.") or credential_version < 0:
            raise ValueError("identity security event must have a bounded owner revision")
        operation_uuid = uuid4()
        details: dict[str, object] = {
            "subject_user_id": str(target_id),
            "credential_version": credential_version,
        }
        tx.add(
            OwnerAuditRow(
                operation_uuid=operation_uuid,
                actor_user_id=actor_id,
                project_id=None,
                action=event,
                object_id=str(target_id),
                owner_revision=str(credential_version),
                details=details,
            )
        )
        tx.add(
            OwnerOutboxRow(
                operation_uuid=operation_uuid,
                event_name=event,
                owner_revision=str(credential_version),
                event_payload=details,
            )
        )

    async def issue_first_admin_setup(
        self,
        operator_socket: socket.socket,
    ) -> SecretStr:
        """One-time restricted setup delivery; no general HTTP/logging path.

        The actual restricted Unix channel MUST already be accepted and
        its server socket connected to a distinct, D4-approved operator UID.
        Only a SHA-256 digest is persisted. Re-issue revokes the previous
        unredeemed code until the first superuser successfully registers.
        """
        if self._operator_gate is None:
            raise AccessDenied("first-admin verified operator channel is not configured")
        self._operator_gate.verify_accepted_peer(operator_socket)
        # Return ONLY after this owned DB transaction commits. A caller-
        # supplied outer transaction could roll back after exposing a code
        # that never existed in the authoritative bootstrap state.
        async with self.database.transaction() as tx:
            bootstrap = await self.repository.lock_bootstrap(tx)
            if bootstrap.first_superuser_claimed:
                raise Conflict("initial superuser is already established")
            if await self.repository.list_active_superusers(tx):
                raise Conflict("an active superuser already exists")
            now = utcnow()
            await tx.execute(
                update(InvitationRow)
                .where(
                    InvitationRow.kind == "system",
                    InvitationRow.used_at.is_(None),
                    InvitationRow.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            raw = random_token()
            tx.add(
                InvitationRow(
                    id=uuid4(),
                    token_digest=token_hash(raw),
                    kind="system",
                    expires_at=now + timedelta(hours=24),
                )
            )
            await tx.flush()
            self._record_local_security_event(
                tx,
                actor_id=None,
                target_id=UUID(int=0),
                event="identity.bootstrap_setup_issued",
                credential_version=0,
            )
        return SecretStr(raw)

    async def issue_registration_invitation(
        self, actor: UserId, *, session: AsyncSession | None = None
    ) -> str:
        async with self._transaction(session) as tx:
            issuer = await self.repository.get_user(tx, actor)
            if issuer is None or not issuer.enabled:
                raise AccessDenied("current user is not active")
            raw = random_token()
            issued_link = self._link("invite", raw)
            invited = InvitationRow(
                id=uuid4(),
                token_digest=token_hash(raw),
                kind="registration",
                created_by_user_id=actor,
                expires_at=utcnow() + timedelta(days=7),
            )
            tx.add(invited)
            self._record_local_security_event(
                tx,
                actor_id=actor,
                target_id=invited.id,
                event="identity.invitation_issued",
                credential_version=issuer.credential_version,
            )
        return issued_link

    async def register(
        self, *, invitation: str, username: str, password: str, session: AsyncSession | None = None
    ) -> User:
        if len(password) < 12 or len(password) > 4096:
            raise InvalidInput("password must be between 12 and 4096 characters")
        try:
            normalized = canonical_username(username)
        except ValueError as exc:
            raise InvalidInput(str(exc)) from exc
        # A cheap preflight avoids performing Argon2 for obviously invalid
        # invitations. The locked check below remains the consistency authority.
        async with self._transaction(session) as tx:
            probe = await self.repository.peek_invitation(tx, token_hash(invitation))
            if (
                probe is None
                or probe.kind not in {"system", "registration"}
                or probe.used_at is not None
                or probe.revoked_at is not None
                or (probe.expires_at is not None and probe.expires_at <= utcnow())
            ):
                raise InvalidInvitation("invitation is invalid or unavailable")
        digest = await asyncio.to_thread(hash_password, password)
        async with self._transaction(session) as tx:
            bootstrap = await self.repository.lock_bootstrap(tx)
            row = await self.repository.lock_invitation(tx, token_hash(invitation))
            if row is None or row.kind not in {"system", "registration"}:
                raise InvalidInvitation("invitation is invalid or unavailable")
            if row.used_at is not None or row.revoked_at is not None:
                raise InvalidInvitation("invitation is no longer valid")
            if row.expires_at is not None and row.expires_at <= utcnow():
                raise InvalidInvitation("invitation has expired")
            if row.created_by_user_id is not None:
                issuer = await self.repository.get_user(tx, UserId(row.created_by_user_id))
                if issuer is None or not issuer.enabled:
                    raise InvalidInvitation("invitation issuer is no longer active")
            if await self.repository.username_taken(tx, normalized):
                raise Conflict("username is unavailable")
            if not bootstrap.first_superuser_claimed and row.kind != "system":
                raise InvalidInvitation("first administrator requires the protected setup code")
            if bootstrap.first_superuser_claimed and row.kind == "system":
                raise InvalidInvitation("initial administrator setup is permanently closed")
            role = "superuser" if not bootstrap.first_superuser_claimed else "user"
            new_user = UserRow(
                id=uuid4(),
                username=normalized,
                password_digest=digest,
                role=role,
                enabled=True,
                credential_version=1,
            )
            tx.add(new_user)
            row.used_at = utcnow()
            bootstrap.first_superuser_claimed = True
            await tx.flush()
            self._record_local_security_event(
                tx,
                actor_id=UserId(row.created_by_user_id) if row.created_by_user_id else None,
                target_id=new_user.id,
                event="identity.registered",
                credential_version=new_user.credential_version,
            )
            return to_user(new_user)

    async def authenticate(self, username: str, password: str) -> User | None:
        """Pure credential verification, not a bearer/session issuance adapter."""
        try:
            normalized = canonical_username(username)
        except ValueError:
            return None
        async with self.database.transaction() as session:
            row = await self.repository.username_row(session, normalized)
            stored = row.password_digest if row is not None and row.enabled else None
            subject_id = UserId(row.id) if row is not None else None
            credential_version = row.credential_version if row is not None else 0
        if stored is None or subject_id is None:
            return None
        valid = await asyncio.to_thread(verify_password, password, stored)
        if not valid:
            return None
        async with self.database.transaction() as session:
            current = await self.repository.get_user(session, subject_id, lock=True)
            if (
                current is None
                or not current.enabled
                or current.credential_version != credential_version
                or current.password_digest != stored
            ):
                return None
            return to_user(current)

    async def authenticate_limited(
        self,
        username: str,
        password: str,
        *,
        source: str,
        pepper: bytes,
    ) -> User | None:
        """Transactional source+identity throttles; no Valkey availability bypass.

        Input origin must be taken from trusted server transport; no XFF/header
        or client-provided source can determine these buckets.
        """
        normalized = username.strip().casefold()[:128]
        origin = source[:128]

        def bucket(value: str) -> str:
            return hmac.new(pepper, value.encode(), hashlib.sha256).hexdigest()

        identity_key = bucket("identity:" + normalized + "\0" + origin)
        source_key = bucket("source:" + origin)
        keys = sorted({identity_key, source_key})

        async with self.database.transaction() as tx:
            # A fixed lock order prevents deadlocks across distinct usernames
            # sharing one source while applying the same source rate limit.
            attempts: dict[str, LoginAttemptRow] = {}
            for key in keys:
                await tx.execute(
                    insert(LoginAttemptRow)
                    .values(bucket_key=key, failures=0)
                    .on_conflict_do_nothing(index_elements=["bucket_key"])
                )
                attempt = await tx.scalar(
                    select(LoginAttemptRow)
                    .where(LoginAttemptRow.bucket_key == key)
                    .with_for_update()
                )
                if attempt is None:
                    raise AccessDenied("login attempts cannot be verified")
                attempts[key] = attempt
            now = utcnow()
            for attempt in attempts.values():
                if attempt.blocked_until is not None and attempt.blocked_until > now:
                    raise AuthenticationRateLimited("too many login attempts")
                if attempt.last_failed_at is not None and now - attempt.last_failed_at > timedelta(
                    minutes=10
                ):
                    attempt.failures = 0

            try:
                validated = canonical_username(username)
            except ValueError:
                validated = None
            row = (
                await self.repository.username_row(tx, validated) if validated is not None else None
            )
            stored_digest = (
                row.password_digest
                if row is not None and row.enabled
                else self._dummy_password_digest
            )
            valid = await asyncio.to_thread(verify_password, password, stored_digest)
            if not valid or row is None or not row.enabled:
                for key, attempt in attempts.items():
                    attempt.failures += 1
                    attempt.last_failed_at = now
                    limit = 40 if key == source_key else 5
                    if attempt.failures >= limit:
                        multiplier = 2 ** min(attempt.failures - limit, 4)
                        attempt.blocked_until = now + timedelta(seconds=min(300, 30 * multiplier))
                return None
            individual = attempts[identity_key]
            individual.failures = 0
            individual.blocked_until = None
            # Do not erase source-wide failures on one successful login.
            return to_user(row)

    async def change_password(
        self,
        actor: UserId,
        *,
        current_password: str,
        new_password: str,
        session: AsyncSession | None = None,
    ) -> None:
        if len(new_password) < 12 or len(new_password) > 4096:
            raise InvalidInput("password must be between 12 and 4096 characters")
        new_digest = await asyncio.to_thread(hash_password, new_password)
        async with self._transaction(session) as tx:
            user = await self.repository.get_user(tx, actor, lock=True)
            if user is None or not user.enabled:
                raise AccessDenied("current user is not active")
            if not await asyncio.to_thread(verify_password, current_password, user.password_digest):
                raise AccessDenied("current password is invalid")
            user.password_digest = new_digest
            user.credential_version += 1
            user.updated_at = utcnow()
            self._record_local_security_event(
                tx,
                actor_id=actor,
                target_id=user.id,
                event="identity.password_changed",
                credential_version=user.credential_version,
            )

    async def issue_password_reset(
        self, admin: UserId, target: UserId, *, session: AsyncSession | None = None
    ) -> str:
        async with self._transaction(session) as tx:
            actor = await self.repository.get_user(tx, admin)
            user = await self.repository.get_user(tx, target)
            if actor is None or not actor.enabled or actor.role != "superuser":
                raise AccessDenied("active superuser required")
            if user is None or not user.enabled:
                raise ResourceMissing("target user not found")
            raw = random_token()
            issued_link = self._link("reset", raw)
            reset = InvitationRow(
                id=uuid4(),
                token_digest=token_hash(raw),
                kind="password_reset",
                created_by_user_id=admin,
                target_user_id=target,
                expires_at=utcnow() + timedelta(minutes=15),
            )
            tx.add(reset)
            self._record_local_security_event(
                tx,
                actor_id=admin,
                target_id=target,
                event="identity.password_reset_issued",
                credential_version=user.credential_version,
            )
        return issued_link

    async def reset_password(
        self, token: str, password: str, *, session: AsyncSession | None = None
    ) -> User:
        if len(password) < 12 or len(password) > 4096:
            raise InvalidInput("password must be between 12 and 4096 characters")
        new_digest = await asyncio.to_thread(hash_password, password)
        async with self._transaction(session) as tx:
            row = await self.repository.lock_invitation(tx, token_hash(token))
            if (
                row is None
                or row.kind != "password_reset"
                or row.used_at is not None
                or row.revoked_at is not None
                or row.expires_at is None
                or row.expires_at <= utcnow()
                or row.target_user_id is None
            ):
                raise InvalidInvitation("password reset token is invalid or expired")
            user = await self.repository.get_user(tx, UserId(row.target_user_id), lock=True)
            if user is None or not user.enabled:
                raise InvalidInvitation("password reset user is not active")
            user.password_digest = new_digest
            user.credential_version += 1
            user.updated_at = utcnow()
            row.used_at = utcnow()
            self._record_local_security_event(
                tx,
                actor_id=UserId(row.created_by_user_id) if row.created_by_user_id else None,
                target_id=user.id,
                event="identity.password_reset",
                credential_version=user.credential_version,
            )
            return to_user(user)

    async def set_superuser(
        self, admin: UserId, target: UserId, enabled: bool, *, session: AsyncSession | None = None
    ) -> User:
        async with self._transaction(session) as tx:
            await self.repository.lock_bootstrap(tx)
            actor = await self.repository.get_user(tx, admin)
            if actor is None or not actor.enabled or actor.role != "superuser":
                raise AccessDenied("active superuser required")
            user = await self.repository.get_user(tx, target, lock=True)
            if user is None:
                raise ResourceMissing("user not found")
            if (
                user.role == "superuser"
                and not enabled
                and len(await self.repository.list_active_superusers(tx)) <= 1
            ):
                raise LastSuperuser("cannot demote the last active superuser")
            user.role = "superuser" if enabled else "user"
            user.credential_version += 1
            user.updated_at = utcnow()
            self._record_local_security_event(
                tx,
                actor_id=admin,
                target_id=user.id,
                event="identity.role_changed",
                credential_version=user.credential_version,
            )
            return to_user(user)

    async def set_suspended(
        self, admin: UserId, target: UserId, suspend: bool, *, session: AsyncSession | None = None
    ) -> User:
        async with self._transaction(session) as tx:
            await self.repository.lock_bootstrap(tx)
            actor = await self.repository.get_user(tx, admin)
            if actor is None or not actor.enabled or actor.role != "superuser":
                raise AccessDenied("active superuser required")
            user = await self.repository.get_user(tx, target, lock=True)
            if user is None:
                raise ResourceMissing("user not found")
            if (
                suspend
                and user.enabled
                and user.role == "superuser"
                and len(await self.repository.list_active_superusers(tx)) <= 1
            ):
                raise LastSuperuser("cannot suspend the last active superuser")
            user.enabled = not suspend
            user.credential_version += 1
            user.updated_at = utcnow()
            if suspend:
                await self.repository.revoke_outstanding_invitations(tx, target, utcnow())
            self._record_local_security_event(
                tx,
                actor_id=admin,
                target_id=user.id,
                event="identity.suspended" if suspend else "identity.restored",
                credential_version=user.credential_version,
            )
            return to_user(user)

    async def revoke_invitation(
        self,
        actor: UserId,
        invitation_id: UUID,
        *,
        session: AsyncSession | None = None,
    ) -> None:
        async with self._transaction(session) as tx:
            user = await self.repository.get_user(tx, actor)
            if user is None or not user.enabled:
                raise AccessDenied("active user required")
            invitation = await self.repository.get_invitation(tx, invitation_id, lock=True)
            if invitation is None:
                raise ResourceMissing("invitation not found")
            if invitation.created_by_user_id != actor and user.role != "superuser":
                raise AccessDenied("invitation issuer or superuser required")
            if invitation.used_at is not None:
                raise Conflict("cannot revoke an already used invitation")
            if invitation.revoked_at is None:
                invitation.revoked_at = utcnow()
                self._record_local_security_event(
                    tx,
                    actor_id=actor,
                    target_id=invitation.id,
                    event="identity.invitation_revoked",
                    credential_version=user.credential_version,
                )
