from django.urls import path
from .views import HomeView

app_name = 'dashboard'

urlpatterns = [
    path('home/', HomeView.as_view(), name='home'),
    # ... other urls ...
]
