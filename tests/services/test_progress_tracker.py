from __future__ import annotations

import math

import pytest

pytest.importorskip("django")

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from mt_media_sdk.models import Load, LoadStatus
from mt_media_sdk.progress.tracker import (
    InvalidProgressTransition,
    ProgressPolicy,
    ProgressTracker,
)

pytestmark = pytest.mark.django_db
User = get_user_model()


@pytest.fixture
def user():
    manager = User._default_manager
    values = {
        "email": "progress@example.test",
        "username": "progress-user",
        "phone": "+15550001234",
    }
    username_field = getattr(User, "USERNAME_FIELD", "username")
    kwargs = {username_field: values.get(username_field, "progress-user")}
    for field_name in getattr(User, "REQUIRED_FIELDS", ()):
        kwargs.setdefault(field_name, values.get(field_name, f"test-{field_name}"))
    return manager.create_user(password="Strong-Test-Password-1!", **kwargs)


def test_create_task_is_idempotent(user) -> None:
    tracker = ProgressTracker()
    first = tracker.create_task(
        user=user,
        task_type="file_upload",
        file_id="file-1",
        task_id="task-1",
    )
    second = tracker.create_task(
        user=user,
        task_type="file_upload",
        file_id="file-1",
        task_id="task-1",
    )
    assert first.pk == second.pk


def test_update_by_file_id_auto_creates_once() -> None:
    tracker = ProgressTracker()
    first = tracker.update_progress_by_file_id("new-file", 5, LoadStatus.PROCESSING)
    second = tracker.update_progress_by_file_id("new-file", 10, LoadStatus.PROCESSING)
    assert first is not None and second is not None
    assert Load._default_manager.filter(external_file_ref="new-file").count() == 1


def test_progress_is_finite_and_clamped(user) -> None:
    tracker = ProgressTracker()
    tracker.create_task(user=user, task_type="file_upload", task_id="task-2")
    assert tracker.update_progress_by_task_id("task-2", 250).progress == 100
    assert tracker.update_progress_by_task_id("task-2", -10).progress == 0
    with pytest.raises(ValidationError):
        tracker.update_progress_by_task_id("task-2", math.nan)


def test_strict_policy_blocks_regression(user) -> None:
    tracker = ProgressTracker(policy=ProgressPolicy(allow_progress_regression=False))
    tracker.create_task(user=user, task_type="file_upload", task_id="task-3")
    tracker.update_progress_by_task_id("task-3", 50, LoadStatus.PROCESSING)
    with pytest.raises(InvalidProgressTransition):
        tracker.update_progress_by_task_id("task-3", 40, LoadStatus.PROCESSING)


def test_completion_is_terminal_and_sets_finished_at(user) -> None:
    tracker = ProgressTracker()
    tracker.create_task(user=user, task_type="file_upload", task_id="task-4")
    completed = tracker.mark_complete("task-4", by_task_id=True)
    assert completed.status == LoadStatus.COMPLETED
    assert completed.progress == 100
    assert completed.finished_at is not None
    with pytest.raises(InvalidProgressTransition):
        tracker.update_progress_by_task_id("task-4", 10, LoadStatus.PROCESSING)


def test_control_characters_are_rejected(user) -> None:
    with pytest.raises(ValidationError):
        ProgressTracker().create_task(
            user=user,
            task_type="file_upload",
            task_id="task\x00id",
        )
