from django import forms
from .models import PcapFile

class PcapFileForm(forms.ModelForm):
    class Meta:
        model = PcapFile
        fields = ['name', 'pcap_file']
