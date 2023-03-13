# coding=utf-8
import datetime
import threading
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview

from scapy.layers.inet import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

stop_sniff_event = threading.Event()
count = 0
pause_flag = False
stop_flag = False
save_flag = False
packet_list = []


# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


def on_click_packet_list_tree(event):
    #an'zhong
    selected_item = event.widget.selection()
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    pkt = packet_list_tree.item(selected_item[0], 'values')
    index = int(pkt[0]) - 1
    packet = packet_list[index]
    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)

    if IP in packet:
        ip = packet[IP]
        ip_chksum = ip.chksum
        del ip.chksum
        ip_check = IP(raw(ip)).chksum
        if TCP in packet:
            tcp = packet[TCP]
            tcp_chksum = tcp.chksum
            del tcp.chksum
            tcp_check = TCP(raw(tcp)).chksum
            if ip_check == ip_chksum and tcp_check == tcp_chksum:
                tkinter.messagebox.showinfo("校验和检查", "IP与TCP的校验和检查结果为：正确！")
            else:
                tkinter.messagebox.showinfo("校验和检查", "IP与TCP的校验和检查结果为：错误！")
        elif UDP in packet:
            udp = packet[UDP]
            udp_chksum = udp.chksum
            del udp.chksum
            udp_check = UDP(raw(udp)).chksum
            if ip_check == ip_chksum and udp_check == udp_chksum:
                tkinter.messagebox.showinfo("校验和检查", "IP与UDP的校验和检查结果为：正确！")
            else:
                tkinter.messagebox.showinfo("校验和检查", "IP与UDP的校验和检查结果为：错误！")
        elif ICMP in packet:
            icmp = packet[ICMP]
            icmp_chksum = icmp.chksum
            del icmp.chksum
            icmp_check = ICMP(raw(icmp)).chksum
            if ip_check == ip_chksum and icmp_check == ip_chksum:
                tkinter.messagebox.showinfo("校验和检查", "IP与ICMP的校验和检查结果为：正确！")
            else:
                tkinter.messagebox.showinfo("校验和检查", "IP与ICMP的校验和检查结果为：错误！")
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


def save_captured_data_to_file():
    global save_flag
    save_flag = True
    filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'), ('数据包', '.pcap')],
                                                    initialfile='.pcap')
    if filename.find('.pcap') == -1:
        filename = filename + '.pcap'
    wrpcap(filename, packet_list)


def packet_consumer(pkt):
    packet_list.append(pkt)
    if pause_flag == False:
        global count
        count += 1
        proto_names = ['ICMP', 'ICMPv6ND_RA', 'IGMP', 'TCP', 'UDP', 'IP', 'ARP', 'Ether', 'Unknown']
        proto = ''
        for pn in proto_names:
            if pn in pkt:
                proto = pn
                break
        if proto == '':
            return
        elif proto == 'TCP' or proto == 'UDP' or proto == 'ICMP' or proto == 'IGMP' or proto == 'ICMPv6ND_RA':
            if 'IP' in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                pkt_time = timestamp2time(pkt[IP].time)
                length = len(pkt)
            else:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
                pkt_time = timestamp2time(pkt[IPv6].time)
                length = len(pkt)
            info = pkt.summary()
        elif proto == 'ARP' or proto == 'Ether':
            src = pkt[Ether].src
            dst = pkt[Ether].dst
            pkt_time = timestamp2time(pkt[Ether].time)
            length = len(pkt)
            info = pkt.summary()
        else:
            src = pkt[Ether].src
            dst = pkt[Ether].dst
            pkt_time = timestamp2time(pkt[Ether].time)
            length = len(pkt)
            info = pkt.summary()
        packet_list_tree.insert("", 'end', values=[str(count), pkt_time, src, dst, proto, length, info])
        packet_list_tree.update_idletasks()


def packet_producer():
    if filter_entry != '':
        sniff(filter=filter_entry.get(), prn=lambda pkt: packet_consumer(pkt),
              stop_filter=lambda pkt: stop_sniff_event.is_set())
    else:
        sniff(prn=lambda pkt: packet_consumer(pkt), stop_filter=lambda pkt: stop_sniff_event.is_set())


# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    global stop_flag, save_flag, pause_flag
    if stop_flag == True and save_flag == False:
        resault = tkinter.messagebox.askyesnocancel("保存提醒", "是否保存抓到的数据包")
        if resault is False:
            print("直接开始不保存")
        elif resault is True:
            print("先保存数据包,再进行抓包")
            filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                                     ('数据包', '.pcap')],
                                                            initialfile='.pcap')
            if filename.find('.pcap') == -1:
                # 默认文件格式为 pcap
                filename = filename + '.pcap'
            wrpcap(filename, packet_list)
        else:
            print("取消抓包操作")
            stop_flag = False
            return
    start_button['state'] = DISABLED  # 不可操作
    save_button['state'] = DISABLED
    pause_button['state'] = NORMAL  # 可操作
    stop_button['state'] = NORMAL
    stop_flag = False
    if pause_flag is False:
        # 清空已经抓到的数据包列表--------------
        items = packet_list_tree.get_children()
        for item in items:
            packet_list_tree.delete(item)
        packet_list_tree.clipboard_clear()
        global count
        count = 0
        # 开启新线程进行抓包
        stop_sniff_event.clear()
        t = threading.Thread(target=packet_producer)
        t.setDaemon(True)  # 让该线程作为后台线程执行
        t.start()
        save_flag = False
    else:
        pause_flag = False


# 暂停按钮单击响应函数
def pause_capture():
    start_button['state'] = 'normal'
    pause_button['state'] = 'disable'
    global pause_flag
    pause_flag = True


# 停止按钮单击响应函数
def stop_capture():
    stop_sniff_event.set()
    # 设置开始按钮为可用，暂停按钮为不可用,保存为可用
    start_button['state'] = NORMAL  # 可操作
    pause_button['state'] = DISABLED  # 不可操作
    stop_button['state'] = DISABLED
    save_button['state'] = NORMAL
    global pause_flag, stop_flag
    pause_flag = False
    stop_flag = True


# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    stop_sniff_event.set()
    global save_flag
    save_flag = True
    # 默认打开位置initialdir='d:\\',默认命名initialfile='.pcap'
    filename = tkinter.filedialog.asksaveasfilename(title='保存文件', filetypes=[('所有文件', '.*'),
                                                                             ('数据包', '.pcap')], initialfile='.pcap')
    if filename.find('.pcap') == -1:
        # 默认文件格式为 pcap
        filename = filename + '.pcap'

    wrpcap(filename, packet_list)
    tk.destroy()


# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
filter_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
filter_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)

main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
tk.mainloop()
