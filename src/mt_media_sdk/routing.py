from django.urls import re_path
from .consumers import UploadProgressConsumer

websocket_urlpatterns_upload_progress = [
    # ws://<host>/ws/upload/progress/
    re_path(r"^ws/upload/progress/$", UploadProgressConsumer.as_asgi()),
]
