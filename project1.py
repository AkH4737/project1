import tkinter as tk
from scapy.all import sniff
from scapy.layers.inet import IP
from collections import defaultdict
import threading

source_ips = defaultdict(int)
blocked_ips = set()
suspicious_ips = set()
sniffing = False
selected_ip = None
updating = False

def analyze_packet(packet):
    global sniffing

    if not sniffing:
        return

    if IP in packet:
        source_ip = packet[IP].src
        packet_size = len(packet)

        if packet_size > 512:  # Проверка на большой размер пакета
            suspicious_ips.add(source_ip)
            print(f"Добавлен подозрительный IP {source_ip}")

def block_traffic():
    global selected_ip, updating

    if selected_ip and selected_ip not in blocked_ips:
        print(f"Блокирование данных от {selected_ip}")
        blocked_ips.add(selected_ip)
        suspicious_ips.discard(selected_ip)
        updating = True
        update_listboxes()
        updating = False
        print(f"Список заблокированных IP: {blocked_ips}")

def unblock_traffic():
    global selected_ip, updating

    if selected_ip in blocked_ips:
        print(f"Разблокирование данных от {selected_ip}")
        blocked_ips.remove(selected_ip)
        source_ips[selected_ip] = 0  # Сброс счетчика
        updating = True
        update_listboxes()
        updating = False
        print(f"Список заблокированных IP после разблокировки: {blocked_ips}")

def ignore_traffic():
    global selected_ip, updating

    if selected_ip in suspicious_ips:
        print(f"Игнорирование данных от {selected_ip}")
        suspicious_ips.remove(selected_ip)
        updating = True
        update_listboxes()
        updating = False
        print(f"Список подозрительных IP после игнорирования: {suspicious_ips}")


def start_sniffing():
    global sniffing
    sniffing = True
    print("Сканирование данных в сети началось...")
    sniff_thread = threading.Thread(target=lambda: sniff(prn=analyze_packet, store=0))
    sniff_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False
    print("Завершение сканирования данных в сети...")

def update_listboxes():
    global updating
    if not updating:
        all_listbox.delete(0, tk.END)
        suspicious_listbox.delete(0, tk.END)
        blocked_listbox.delete(0, tk.END)
        all_ips = list(source_ips.keys())
        suspicious_ips_list = list(suspicious_ips)
        blocked_ips_list = list(blocked_ips)
        for ip in all_ips:
            all_listbox.insert(tk.END, f"{ip}")
        for ip in suspicious_ips_list:
            suspicious_listbox.insert(tk.END, f"{ip}")
        for ip in blocked_ips_list:
            blocked_listbox.insert(tk.END, f"{ip}")
    root.after(1000, update_listboxes)

def select_ip(event):
    global selected_ip, updating
    if not updating:
        selection = event.widget.curselection()
        if selection:
            selected_ip = event.widget.get(selection[0])

def main():
    global root, all_listbox, suspicious_listbox, blocked_listbox
    root = tk.Tk()
    root.title("Сканирование данных в сети")
    
    # Создание фреймов и виджетов для списков IP-адресов
    all_frame = tk.Frame(root)
    all_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)
    all_label = tk.Label(all_frame, text="Общий:")
    all_label.pack(side=tk.TOP)
    all_listbox = tk.Listbox(all_frame, height=10, width=30)
    all_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    all_listbox.bind("<<ListboxSelect>>", select_ip)

    suspicious_frame = tk.Frame(root)
    suspicious_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)
    suspicious_label = tk.Label(suspicious_frame, text="Подозрительные:")
    suspicious_label.pack(side=tk.TOP)
    suspicious_listbox = tk.Listbox(suspicious_frame, height=10, width=30)
    suspicious_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    suspicious_listbox.bind("<<ListboxSelect>>", select_ip)

    blocked_frame = tk.Frame(root)
    blocked_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)
    blocked_label = tk.Label(blocked_frame, text="Заблокированные:")
    blocked_label.pack(side=tk.TOP)
    blocked_listbox = tk.Listbox(blocked_frame, height=10, width=30)
    blocked_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    blocked_listbox.bind("<<ListboxSelect>>", select_ip)

    # Создание кнопок для управления сканированием и блокировкой IP-адресов
    button_frame = tk.Frame(root)
    button_frame.pack(side=tk.BOTTOM, padx=5, pady=5)
    start_button = tk.Button(button_frame, text="Сканировать", command=start_sniffing)
    start_button.pack(side=tk.LEFT, padx=10)
    stop_button = tk.Button(button_frame, text="Остановить", command=stop_sniffing)
    stop_button.pack(side=tk.LEFT, padx=10)
    block_button = tk.Button(button_frame, text="Блокировать", command=block_traffic)
    block_button.pack(side=tk.LEFT, padx=10)
    unblock_button = tk.Button(button_frame, text="Разблокировать", command=unblock_traffic)
    unblock_button.pack(side=tk.LEFT, padx=10)
    ignore_button = tk.Button(button_frame, text="Игнорировать", command=ignore_traffic)
    ignore_button.pack(side=tk.LEFT, padx=10)

    update_listboxes()
    root.mainloop()

if __name__ == "__main__":
    main()
