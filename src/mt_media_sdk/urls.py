from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

# Upload control endpoints (assumes media/api/uploads.py exists)
from .views import (
    UploadListView,
    UploadDetailView,
    UploadControlView,
    UploadResumeOffsetView,
)

router = DefaultRouter()
# Register viewsets (basename chosen to form sensible route names)
router.register(r"media-limits", views.MediaLimitViewSet, basename="media-limit")
router.register(r"mediafiles", views.MediaFileViewSet, basename="mediafile")
router.register(r"interactions", views.UserInteractionViewSet, basename="interaction")
router.register(r"loads", views.LoadViewSet, basename="load")

urlpatterns = [
    # ViewSet routes (list/retrieve/create/update/destroy + custom actions)
    path("", include(router.urls)),
    # Upload control/read endpoints (cache + DB merged view)
    path("uploads/", UploadListView.as_view(), name="upload-list"),
    path("uploads/control/", UploadControlView.as_view(), name="upload-control"),
    path("uploads/<str:file_id>/", UploadDetailView.as_view(), name="upload-detail"),
    path(
        "uploads/<str:file_id>/offset/",
        UploadResumeOffsetView.as_view(),
        name="upload-resume-offset",
    ),

    path("uploads/simple/", views.SimpleUploadView.as_view(), name="upload-simple"),
    path("uploads/sessions/", views.UploadSessionInitiateView.as_view(), name="upload-session-initiate"),
    path("uploads/sessions/<uuid:session_id>/", views.UploadSessionDetailView.as_view(), name="upload-session-detail"),
    path("uploads/sessions/<uuid:session_id>/parts/<int:part_number>/", views.UploadSessionPartView.as_view(), name="upload-session-part"),
    path("uploads/sessions/<uuid:session_id>/complete/", views.UploadSessionCompleteView.as_view(), name="upload-session-complete"),
]


# project urls.py
# path("media/", include("media.urls"))
