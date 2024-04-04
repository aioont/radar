from django.db import models

class PcapFile(models.Model):
    name = models.CharField(max_length=100)
    pcap_file = models.FileField(upload_to='pcap_files/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

