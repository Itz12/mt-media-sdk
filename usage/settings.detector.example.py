# Policy values may also be supplied from a tenant/application policy service.
DETECTOR_POLICY = {
    "policy_version": "2026.1",
    "max_text_chars": 200_000,
    "max_file_bytes": 250 * 1024 * 1024,
    "max_image_pixels": 50_000_000,
    "max_video_frames": 2_000,
    "max_audio_seconds": 14_400,
    "max_video_seconds": 14_400,
    "max_workers": 4,
    "operation_timeout_seconds": 120,
    "review_threshold": 0.55,
    "block_threshold": 0.85,
    "nudity_review_threshold": 0.45,
    "nudity_block_threshold": 0.72,
    "profanity_fuzzy_threshold": 92,
    "enable_fuzzy_profanity": True,
    "fail_closed": True,
    "allow_remote_sources": False,
    "remote_allowed_hosts": (),
    "quarantine_copy_mode": 0o600,
    "redact_evidence": True,
}

# Store expected model digests in Vault-managed settings or deployment manifests.
DETECTOR_MODEL_ARTIFACTS = {
    # "nudenet": {"path": "/models/nudenet-320n.onnx", "sha256": "..."},
}
