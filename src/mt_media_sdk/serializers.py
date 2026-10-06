from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils.timesince import timesince
from rest_framework import serializers

from .models import (
    InteractionType,
    Load,
    LoadStatus,
    MediaFile,
    MediaLimit,
    UploadPart,
    UploadSession,
    UserInteraction,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------


def _normalize_filename(filename: str) -> str:
    name = os.path.basename((filename or '').strip())
    name = name.replace('\x00', '')
    return name[:1024]


def _safe_int_bytes(value: Any) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError) as exc:
        raise serializers.ValidationError('Must be an integer number of bytes.') from exc
    if ivalue < 0:
        raise serializers.ValidationError('Must be non-negative.')
    return ivalue


def human_readable_size(num_bytes: Optional[int]) -> str:
    if num_bytes is None:
        return '—'
    try:
        num = float(num_bytes)
    except (TypeError, ValueError):
        return '—'
    if num < 0:
        return '—'
    if num < 1024:
        return f'{int(num)} B'
    for unit in ('KB', 'MB', 'GB', 'TB'):
        num /= 1024.0
        if num < 1024.0:
            return f'{num:.2f} {unit}'
    return f'{num:.2f} PB'


def human_timesince(dt) -> Optional[str]:
    if not dt:
        return None
    try:
        return timesince(dt) + ' ago'
    except Exception:
        return None


def build_abs_url(request, url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        parsed = urlparse(str(url))
        if parsed.scheme and parsed.netloc:
            return url
        if request is not None:
            return request.build_absolute_uri(url)
    except Exception:
        logger.debug('Failed to build absolute URL', exc_info=True)
    return url


def _get_request(context: Dict[str, Any]) -> Any:
    return context.get('request')


def _get_content_type_cached(
    context: Dict[str, Any], content_type_id: Optional[int]
) -> Optional[ContentType]:
    if not content_type_id:
        return None
    cache = context.setdefault('_content_type_cache', {})
    if content_type_id in cache:
        return cache[content_type_id]
    try:
        ct = ContentType.objects.get_for_id(content_type_id)
        cache[content_type_id] = ct
        return ct
    except Exception:
        logger.debug('Failed to resolve content type id=%s', content_type_id, exc_info=True)
        return None


def _media_file_url(obj: MediaFile, request, expires_in: int = 60) -> Optional[str]:
    try:
        file_obj = getattr(obj, 'file', None)
        if not file_obj or not getattr(file_obj, 'name', None):
            return None
        storage = getattr(file_obj, 'storage', None)
        gen = getattr(storage, 'generate_presigned_url', None)
        if callable(gen):
            raw = gen(file_obj.name, expires_in=expires_in)
        else:
            raw = getattr(file_obj, 'url', None)
        return build_abs_url(request, raw)
    except Exception:
        logger.debug('Failed to build media URL for %s', getattr(obj, 'pk', '<nil>'), exc_info=True)
        return None


def _owner_payload(obj: MediaFile, detail: bool = False) -> Optional[Dict[str, Any]]:
    owner = getattr(obj, 'owner', None)
    if not owner:
        return None
    payload = {
        'id': getattr(owner, 'pk', None),
        'repr': str(owner),
    }
    if detail:
        payload['app_label'] = owner._meta.app_label
        payload['model'] = owner._meta.model_name
    return payload


def _media_type_max_size(limits: MediaLimit, mime_type: str) -> int:
    mt = (mime_type or '').lower()
    if mt.startswith('image/'):
        return limits.image
    if mt.startswith('audio/'):
        return limits.audio
    if mt.startswith('video/'):
        return limits.video
    if mt.startswith('text/'):
        return limits.text
    return limits.document


class _BaseRobustSerializer(serializers.ModelSerializer):
    """
    Internal helper to keep repeated formatting and lookup logic consistent.
    """

    def _request(self):
        return _get_request(self.context)

    def _content_type_from_id(self, content_type_id: Optional[int]) -> Optional[ContentType]:
        return _get_content_type_cached(self.context, content_type_id)


# ---------------------------------------------------------------------
# MediaFileSerializer
# ---------------------------------------------------------------------


class MediaFileSerializer(_BaseRobustSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = MediaFile
        fields = [
            'id',
            'original_filename',
            'mime_type',
            'size',
            'checksum',
            'status',
            'scan_status',
            'is_public',
            'created_at',
            'url',
        ]
        read_only_fields = fields

    def get_url(self, obj: MediaFile):
        return obj.get_url()


# ---------------------------------------------------------------------
# InitiateUploadSessionSerializer
# ---------------------------------------------------------------------


class InitiateUploadSessionSerializer(serializers.Serializer):
    filename = serializers.CharField(max_length=1024)
    mime_type = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    size = serializers.IntegerField(min_value=0)
    checksum = serializers.CharField(max_length=128, required=False, allow_null=True, default=None)
    chunk_size = serializers.IntegerField(min_value=1024, required=False, default=None)

    def validate_filename(self, value: str) -> str:
        return _normalize_filename(value)

    def validate_mime_type(self, value: str) -> str:
        return (value or '').strip()

    def validate_checksum(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if value and len(value) > 128:
            raise serializers.ValidationError('Checksum is too long.')
        return value or None


# ---------------------------------------------------------------------
# UploadSessionSerializer
# ---------------------------------------------------------------------


class UploadSessionSerializer(_BaseRobustSerializer):
    class Meta:
        model = UploadSession
        fields = [
            'id',
            'filename',
            'mime_type',
            'declared_size',
            'chunk_size',
            'total_parts',
            'uploaded_bytes',
            'status',
            'expires_at',
            'created_at',
        ]
        read_only_fields = fields

    def validate(self, attrs):
        declared_size = attrs.get('declared_size')
        chunk_size = attrs.get('chunk_size')
        if declared_size is not None and declared_size < 0:
            raise serializers.ValidationError({'declared_size': 'Must be non-negative.'})
        if chunk_size is not None and chunk_size < 1024:
            raise serializers.ValidationError({'chunk_size': 'Chunk size must be at least 1024 bytes.'})
        return attrs


# ---------------------------------------------------------------------
# UploadPartSerializer
# ---------------------------------------------------------------------


class UploadPartSerializer(_BaseRobustSerializer):
    class Meta:
        model = UploadPart
        fields = ['part_number', 'size', 'checksum', 'uploaded_at']
        read_only_fields = fields

    def validate_part_number(self, value: int) -> int:
        if value < 1:
            raise serializers.ValidationError('Part number must be at least 1.')
        return value

    def validate_size(self, value: int) -> int:
        if value < 0:
            raise serializers.ValidationError('Size must be non-negative.')
        return value

    def validate_checksum(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if value and len(value) > 128:
            raise serializers.ValidationError('Checksum is too long.')
        return value or None


# ---------------------------------------------------------------------
# LoadSerializer
# ---------------------------------------------------------------------


class LoadSerializer(_BaseRobustSerializer):
    class Meta:
        model = Load
        fields = [
            'id',
            'task_id',
            'task_type',
            'status',
            'progress',
            'error_message',
            'created_at',
            'updated_at',
        ]
        read_only_fields = fields


# ---------------------------------------------------------------------
# MediaLimitSerializer
# ---------------------------------------------------------------------


class MediaLimitSerializer(_BaseRobustSerializer):
    class Meta:
        model = MediaLimit
        fields = ('id', 'image', 'audio', 'video', 'text', 'document', 'updated_at')
        read_only_fields = ('id', 'updated_at')

    def validate(self, data):
        cleaned: Dict[str, int] = {}
        MAX_BYTES = 10 * 1024**4

        for field in ('image', 'audio', 'video', 'text', 'document'):
            if field not in data:
                continue
            iv = _safe_int_bytes(data.get(field))
            if iv > MAX_BYTES:
                raise serializers.ValidationError({field: f'Value too large (max {MAX_BYTES} bytes).'})
            cleaned[field] = iv

        data.update(cleaned)
        return data


# ---------------------------------------------------------------------
# MediaFile serializers (list/detail/upload)
# ---------------------------------------------------------------------


class MediaFileListSerializer(_BaseRobustSerializer):
    url = serializers.SerializerMethodField()
    presigned_url = serializers.SerializerMethodField()
    size_human = serializers.SerializerMethodField()
    created_ago = serializers.SerializerMethodField()
    owner = serializers.SerializerMethodField()

    class Meta:
        model = MediaFile
        fields = (
            'id',
            'original_filename',
            'mime_type',
            'size',
            'size_human',
            'status',
            'is_public',
            'owner',
            'url',
            'presigned_url',
            'created_at',
            'created_ago',
        )
        read_only_fields = (
            'id',
            'size',
            'status',
            'created_at',
            'created_ago',
            'size_human',
            'url',
            'presigned_url',
        )

    def get_url(self, obj: MediaFile):
        return _media_file_url(obj, self._request(), expires_in=60)

    def get_presigned_url(self, obj: MediaFile):
        return _media_file_url(obj, self._request(), expires_in=300)

    def get_size_human(self, obj: MediaFile):
        return human_readable_size(obj.size)

    def get_created_ago(self, obj: MediaFile):
        return human_timesince(obj.created_at)

    def get_owner(self, obj: MediaFile):
        return _owner_payload(obj, detail=False)


class MediaFileDetailSerializer(_BaseRobustSerializer):
    url = serializers.SerializerMethodField()
    presigned_url = serializers.SerializerMethodField()
    size_human = serializers.SerializerMethodField()
    created_ago = serializers.SerializerMethodField()
    owner = serializers.SerializerMethodField()
    derivatives = serializers.SerializerMethodField()
    attached_object = serializers.SerializerMethodField()
    metadata = serializers.JSONField()

    class Meta:
        model = MediaFile
        exclude = ()
        read_only_fields = (
            'id',
            'checksum',
            'size',
            'mime_type',
            'width',
            'height',
            'duration_ms',
            'created_at',
            'updated_at',
            'deleted',
            'deleted_at',
        )

    def get_url(self, obj: MediaFile):
        return _media_file_url(obj, self._request(), expires_in=60)

    def get_presigned_url(self, obj: MediaFile):
        return _media_file_url(obj, self._request(), expires_in=300)

    def get_size_human(self, obj: MediaFile):
        return human_readable_size(obj.size)

    def get_created_ago(self, obj: MediaFile):
        return human_timesince(obj.created_at)

    def get_owner(self, obj: MediaFile):
        return _owner_payload(obj, detail=True)

    def get_derivatives(self, obj: MediaFile):
        request = self._request()

        prefetched = getattr(obj, '_prefetched_objects_cache', {}).get('derivatives')
        if prefetched is not None:
            derivatives = prefetched
        else:
            derivatives = obj.derivatives.select_related('file').all()

        out = []
        for d in derivatives:
            out.append(
                {
                    'id': str(d.id),
                    'original_filename': d.original_filename,
                    'url': _media_file_url(d, request, expires_in=60),
                    'status': d.status,
                }
            )
        return out

    def get_attached_object(self, obj: MediaFile):
        if not obj.content_type_id or not obj.object_id:
            return None
        ct = self._content_type_from_id(obj.content_type_id)
        if ct is None:
            return {'app_label': None, 'model': None, 'object_id': obj.object_id}
        return {
            'app_label': ct.app_label,
            'model': ct.model,
            'object_id': obj.object_id,
        }

    def update(self, instance: MediaFile, validated_data):
        protected = {'checksum', 'size', 'mime_type', 'created_at', 'updated_at'}
        for key in protected:
            validated_data.pop(key, None)
        return super().update(instance, validated_data)


class MediaFileUploadSerializer(_BaseRobustSerializer):
    """
    Create/upload serializer: keeps the same surface area, but hardens input
    handling, filename normalization, metadata limits, owner checks, and size
    validation.
    """

    content_type = serializers.PrimaryKeyRelatedField(
        queryset=ContentType.objects.all(), required=False, allow_null=True
    )
    content_type_str = serializers.CharField(
        write_only=True, required=False, allow_blank=True
    )
    original_filename = serializers.CharField(required=False, allow_blank=True)
    file = serializers.FileField(required=True)
    metadata = serializers.JSONField(required=False)

    class Meta:
        model = MediaFile
        fields = (
            'id',
            'file',
            'original_filename',
            'mime_type',
            'size',
            'owner',
            'content_type',
            'content_type_str',
            'object_id',
            'is_public',
            'metadata',
        )
        read_only_fields = ('id', 'size')

    def validate_original_filename(self, value: str) -> str:
        return _normalize_filename(value)

    def validate_metadata(self, value):
        if value is None:
            return value
        if not isinstance(value, dict):
            raise serializers.ValidationError('Must be a JSON object.')
        try:
            payload = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        except Exception as exc:
            raise serializers.ValidationError('Invalid metadata payload.') from exc
        if len(payload) > 10000:
            raise serializers.ValidationError('Metadata too large.')
        return value

    def validate(self, attrs):
        uploaded_file = attrs.get('file')
        if not uploaded_file:
            raise serializers.ValidationError({'file': 'No file provided.'})

        if not attrs.get('mime_type'):
            content_type = getattr(uploaded_file, 'content_type', None)
            if content_type:
                attrs['mime_type'] = str(content_type).strip()

        if not attrs.get('original_filename'):
            attrs['original_filename'] = _normalize_filename(getattr(uploaded_file, 'name', '') or '')

        uploaded_size = getattr(uploaded_file, 'size', None)
        if uploaded_size is not None:
            try:
                limits = MediaLimit.get_solo()
                max_size = _media_type_max_size(limits, attrs.get('mime_type') or '')
            except Exception:
                logger.debug('Could not fetch MediaLimit for upload validation', exc_info=True)
            else:
                if uploaded_size > max_size:
                    raise serializers.ValidationError(
                        {'file': f'File exceeds allowed size for type (max {max_size} bytes).'}
                    )

        ct_str = attrs.pop('content_type_str', None)
        if ct_str:
            try:
                app_label, model = [p.strip() for p in ct_str.rsplit('.', 1)]
                if not app_label or not model:
                    raise ValueError('Invalid format')
                ct = ContentType.objects.get(app_label=app_label, model=model)
                attrs['content_type'] = ct
            except Exception as exc:
                raise serializers.ValidationError(
                    {'content_type_str': "Invalid content type string. Use 'app_label.model'."}
                ) from exc

        request = self.context.get('request')
        provided_owner = attrs.get('owner', None)
        if (
            provided_owner
            and request
            and getattr(request, 'user', None)
            and request.user.is_authenticated
        ):
            if not request.user.is_staff:
                owner_pk = getattr(provided_owner, 'pk', None)
                if str(owner_pk) != str(request.user.pk):
                    raise serializers.ValidationError(
                        {'owner': 'You may not set owner to another user.'}
                    )

        return attrs

    def create(self, validated_data):
        request = self.context.get('request')
        owner = validated_data.get('owner')
        if (
            not owner
            and request
            and getattr(request, 'user', None)
            and request.user.is_authenticated
        ):
            validated_data['owner'] = request.user

        try:
            with transaction.atomic():
                instance = self.Meta.model.objects.create(**validated_data)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(
                detail=exc.message_dict if hasattr(exc, 'message_dict') else str(exc)
            ) from exc
        return instance


# ---------------------------------------------------------------------
# UserInteraction serializer
# ---------------------------------------------------------------------


class UserInteractionSerializer(_BaseRobustSerializer):
    user = serializers.PrimaryKeyRelatedField(
        read_only=False,
        queryset=get_user_model().objects.all(),
        required=False,
        allow_null=True,
    )
    target = serializers.SerializerMethodField(read_only=True)
    created_ago = serializers.SerializerMethodField()

    class Meta:
        model = UserInteraction
        fields = (
            'id',
            'user',
            'session_id',
            'content_type',
            'object_id',
            'target',
            'interaction_type',
            'weight',
            'metadata',
            'timestamp',
            'created_ago',
        )
        read_only_fields = ('id', 'timestamp', 'created_ago')

    def validate_interaction_type(self, value):
        allowed = {c[0] for c in InteractionType.choices}
        if value not in allowed:
            raise serializers.ValidationError('Invalid interaction_type.')
        return value

    def validate_weight(self, value):
        if value is None:
            return 1.0
        try:
            fv = float(value)
        except (TypeError, ValueError) as exc:
            raise serializers.ValidationError('Weight must be numeric.') from exc
        if fv < 0:
            raise serializers.ValidationError('Weight must be non-negative.')
        return fv

    def validate_session_id(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        return value or None

    def validate_metadata(self, value):
        if value is None:
            return value
        if not isinstance(value, dict):
            raise serializers.ValidationError('Must be a JSON object.')
        try:
            payload = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        except Exception as exc:
            raise serializers.ValidationError('Invalid metadata payload.') from exc
        if len(payload) > 10000:
            raise serializers.ValidationError('Metadata too large.')
        return value

    def get_target(self, obj: UserInteraction):
        try:
            ct = obj.content_type
            return {
                'app_label': ct.app_label,
                'model': ct.model,
                'object_id': obj.object_id,
            }
        except Exception:
            return {'object_id': obj.object_id}

    def get_created_ago(self, obj: UserInteraction):
        return human_timesince(obj.timestamp)


# ---------------------------------------------------------------------
# Load serializers
# ---------------------------------------------------------------------


class LoadListSerializer(_BaseRobustSerializer):
    user = serializers.SerializerMethodField()
    file = serializers.SerializerMethodField()
    created_ago = serializers.SerializerMethodField()

    class Meta:
        model = Load
        fields = (
            'id',
            'task_id',
            'task_type',
            'status',
            'progress',
            'user',
            'file',
            'created_at',
            'created_ago',
        )
        read_only_fields = ('id', 'created_at', 'created_ago')

    def get_user(self, obj: Load):
        if not obj.user:
            return None
        return {'id': getattr(obj.user, 'pk', None), 'repr': str(obj.user)}

    def get_file(self, obj: Load):
        if obj.file:
            return {
                'id': str(obj.file.id),
                'original_filename': obj.file.original_filename,
            }
        return {
            'external_file_ref': getattr(obj, 'external_file_ref', None),
            'storage_path': getattr(obj, 'storage_path', None),
        }


class LoadDetailSerializer(_BaseRobustSerializer):
    user = serializers.SerializerMethodField()
    file = serializers.SerializerMethodField()
    created_ago = serializers.SerializerMethodField()
    started_ago = serializers.SerializerMethodField()
    finished_ago = serializers.SerializerMethodField()

    class Meta:
        model = Load
        fields = '__all__'
        read_only_fields = (
            'id',
            'created_at',
            'started_at',
            'finished_at',
            'updated_at',
            'created_ago',
            'started_ago',
            'finished_ago',
        )

    def get_user(self, obj: Load):
        if not obj.user:
            return None
        return {'id': getattr(obj.user, 'pk', None), 'repr': str(obj.user)}

    def get_file(self, obj: Load):
        if obj.file:
            try:
                url = obj.file.get_url(expire_seconds=60)
            except Exception:
                url = None
            return {
                'id': str(obj.file.id),
                'original_filename': obj.file.original_filename,
                'url': url,
            }
        return {
            'external_file_ref': getattr(obj, 'external_file_ref', None),
            'storage_path': getattr(obj, 'storage_path', None),
        }

    def get_created_ago(self, obj: Load):
        return human_timesince(obj.created_at)

    def get_started_ago(self, obj: Load):
        return human_timesince(obj.started_at)

    def get_finished_ago(self, obj: Load):
        return human_timesince(obj.finished_at)


class LoadUpdateSerializer(_BaseRobustSerializer):
    """
    Serializer used for updating progress/status via API. Validates bounds and delegates update to model helper.
    """

    progress = serializers.FloatField(required=False, min_value=0.0, max_value=100.0)
    status = serializers.ChoiceField(choices=LoadStatus.choices, required=False)
    error_message = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    class Meta:
        model = Load
        fields = ('progress', 'status', 'error_message')

    def validate_progress(self, value):
        if value is None:
            return value
        try:
            fvalue = float(value)
        except (TypeError, ValueError) as exc:
            raise serializers.ValidationError('Progress must be numeric.') from exc
        if fvalue < 0.0 or fvalue > 100.0:
            raise serializers.ValidationError('Progress must be between 0 and 100.')
        return fvalue

    def validate_error_message(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    def update(self, instance: Load, validated_data):
        progress = validated_data.get('progress', None)
        status = validated_data.get('status', None)
        error_message = validated_data.get('error_message', None)
        try:
            instance.set_progress(
                new_progress=(progress if progress is not None else instance.progress),
                new_status=status,
                error_message=error_message,
            )
        except Exception as exc:
            logger.exception('Failed to set progress for Load %s: %s', instance.pk, exc)
            raise serializers.ValidationError('Could not update load progress at this time.') from exc
        return instance
