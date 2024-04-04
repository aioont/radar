import os  # Ensure that this line is at the beginning of your code
import shutil
import subprocess


from django.shortcuts import render
from django.http import HttpResponse
from .forms import PcapFileForm
from scapy.all import sniff, wrpcap, conf
from threading import Thread

# Global variable to store the capture thread
capture_thread = None

def packet_capture(interface, save_path):
    try:
        # Sniff packets on the specified interface
        packets = sniff(iface=interface)

        # Write captured packets to a file using wrpcap
        wrpcap(save_path, packets)

        return "Packet capture successful."
    except Exception as e:
        return f"Error capturing packets: {str(e)}"

def start_stop_sniffing(request):
    global capture_thread
    if request.method == 'POST':
        interface = request.POST.get('interface', 'wlo1')
        save_path = os.path.join('pcap_capture', request.POST.get('save_path', 'output.pcap'))

        action = request.POST.get('action')
        if action == 'start':
            if capture_thread and capture_thread.is_alive():
                return HttpResponse("Packet capture already active.")
            capture_thread = Thread(target=packet_capture, args=(interface, save_path))
            capture_thread.start()
            return HttpResponse("Packet capture started.")
        elif action == 'stop':
            if capture_thread and capture_thread.is_alive():
                capture_thread.join(timeout=1)
                if capture_thread.is_alive():
                    return HttpResponse("Error stopping packet capture.")
                else:
                    return HttpResponse("Packet capture stopped successfully.")
            else:
                return HttpResponse("No active packet capture.")
    else:
        try:
            interfaces = [iface for iface in conf.ifaces.keys()]
        except Exception as e:
            interfaces = ['enp2s0', 'lo', 'wlo1']  # Default interfaces if scapy fails
        return render(request, 'core/start_sniffing.html', {'interfaces': interfaces})


def stop_sniffing(request):
    global capture_thread
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=1)
        if capture_thread.is_alive():
            return HttpResponse("Error stopping packet capture.")
        else:
            try:
                # Move captured file to 'pcap_capture' folder
                origin_file = 'output1.pcap'
                dest_path = os.path.join('pcap_capture', origin_file)
                shutil.move(origin_file, dest_path)
                message = "Packet capture stopped successfully and saved to 'pcap_capture' folder."
            except Exception as e:
                message = f"Error saving capture file: {e}"
            return HttpResponse(message)
    else:
        return HttpResponse("No active packet capture.")



def capture_traffic(request):
    if request.method == 'POST':
        interface = request.POST['interface']
        save_path = request.POST['save_path']
        # Start capturing traffic using Tshark
        command = ['tshark', '-i', interface, '-w', save_path]
        subprocess.run(command)
        message = 'Sniffing started successfully!'
    else:
        message = ''
    return render(request, 'core/capture.html', {'message': message})

def stop_capture(request):
    # Simulate stopping by showing a message (no built-in way to stop Tshark from Python)
    message = 'Sniffing stopped (simulated).'
    return render(request, 'core/capture.html', {'message': message})