from django.urls import path
from . import views

urlpatterns = [
    path('pcap_capture/', views.packet_capture, name='pcap_capture'),
    path('start_stop_sniffing/', views.start_stop_sniffing, name='start_stop_sniffing'),
    path('capture/', views.capture_traffic, name='capture_traffic'),
    path('stop/', views.stop_capture, name='stop_capture'),
    
]
