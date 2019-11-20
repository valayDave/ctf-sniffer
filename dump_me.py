import sys
import threading
import logger
from subprocess import Popen
module_logger = logger.create_logger('$cript_k!ddie_CTF_Dump_Collector')
import time
import argparse
import os
import signal

module_description = '''
$cript_k!ddie N/W Sniffer

N/W Sniffer that operates using tcpdump and Python Threads

 
'''
arguement_parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description=module_description)
arguement_parser.add_argument('interface',help='Name of Interface. Eg. eth0 / lo')
arguement_parser.add_argument('-p','--port',help="Ports You want to sniff",nargs='+')


PROCESS_KILL_TIME = 2*60*60
TICK_DURATION = 3*60

class CTF_TCP_DUMP(threading.Thread):
    def __init__(self, tick_num,port,interface='lo',output_folder='Output/'): 
        threading.Thread.__init__(self) 
        self.interface = interface
        self.port = port 
        self.output_folder = output_folder
        self.subprocess = None
        self.kill = False
        self.tick_num = tick_num

    def kill_process(self):
        self.kill = True
    
    def run(self):
        output_path=self.output_folder+str(self.tick_num)+"__"+str(self.port)+'.pcap'
        dump_command ="tcpdump -i {interface} port {port} -w {output_path}".format(interface=self.interface,port=self.port,output_path=output_path)
        self.subprocess = Popen(dump_command.split(' '))
        while True:
            # module_logger.info('Process Not Dead')
            if self.kill:
                module_logger.info('Killing Subprocesss %d',self.tick_num)
                pid = self.subprocess.pid
                os.kill(pid, signal.SIGINT) 
                break


def run_service(PORTS,interface='lo'):
    ctf_threads = []
    for current_tick in range(0,(PROCESS_KILL_TIME/TICK_DURATION)):
        for port in PORTS: 
            x = CTF_TCP_DUMP(current_tick,port,interface=interface) # Create Process Threads
            x.start()
            ctf_threads.append(x)

        time.sleep(TICK_DURATION)
        for port in PORTS: 
            x = ctf_threads.pop()
            x.kill_process()

if __name__ == '__main__':
    parsed_arguments = arguement_parser.parse_args()
    if parsed_arguments.interface is None:
        module_logger.error(arguement_parser.usage)
        exit()
    if parsed_arguments.port is None:
        module_logger.error("Port is Required")
        exit()
    run_service(parsed_arguments.port,parsed_arguments.interface)
    
        