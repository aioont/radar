from django.shortcuts import render, redirect
from .forms import PcapFileForm

def upload_pcap_file(request):
    if request.method == 'POST':
        form = PcapFileForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            # You can perform additional processing here
            return redirect('success')  # Redirect to success page or any other URL
    else:
        form = PcapFileForm()
    return render(request, 'upload_pcap_file.html', {'form': form})
