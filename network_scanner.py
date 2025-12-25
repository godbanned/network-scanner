import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    
    parser.add_option("-t", "--target", dest="target")

    opts, args = parser.parse_args()

    if not opts.target:
        parser.error("Perhaps you forgot a targe IP for the command? Use --help to get more info.")
        
    return opts.target


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        
    return clients_list


def print_values(results_list):
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
        
target = get_arguments()
scan_result = scan(target)
print_values(scan_result)