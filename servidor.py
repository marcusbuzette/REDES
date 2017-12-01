import socket

host = '127.0.0.1'
porta_trans = 5004
porta_fis = 5005
dest = (host, porta_trans)
orig = (host, porta_fis)
sourceIP = "127.0.0.1"
destIP = "0.0.0.0"
IPresp = "127.0.0.1"
IPorig = "0.0.0.0"

fisica = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fisica.bind(orig)
fisica.listen(1)
con, cliente = fisica.accept()

fisica_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fisica_send.bind(orig)
fisica_send.connect(dest)


transporte = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
transporte.bind(dest)
transporte.connect(dest)

def calculaRede(ip,masc):

	ip = ip.split(".")

	ip[0] = bin(ip[0]).rjust(8,"0")
	ip[1] = bin(ip[1]).rjust(8,"0")
	ip[2] = bin(ip[2]).rjust(8,"0")
	ip[3] = bin(ip[3]).rjust(8,"0")

	masc = '255.255.255.0'
	masc = mascara.split('.')
	masc[0]=bin(masc[0]).rjust(8,"0")
	masc[1]=bin(masc[1]).rjust(8,"0")
	masc[2]=bin(masc[2]).rjust(8,"0")
	masc[3]=bin(masc[3]).rjust(8,"0")

	destino = ip[0]+ip[1]+ip[2]+ip[3]
	mascara = masc[0]+masc[1]+masc[2]+masc[3]

	result = destino & mascara

	add[0] = int(result[0:7],2)
	add[1] = int(result[8:15],2)
	add[2] = int(result[16:23],2)
	add[3] = int(result[24:31],2)

	rede = add[0]+"."+add[1]+"."+add[2]+"."+add[3]

	return rede


def cria_pacote(segmento,origIP,destinoIP):
	s_source = origIP.split(".")
	s_destIP = destinoIP.split(".")

	versionIHL = "%04b"+"%04b" % (15,15)
	typeService = "%08b" %  (0)
	totalLength = "%016b" % (segmento.length+20)
	identification = "%016b" % (0)
	flags = "%03b" % (0)
	fragOffset = "%013b" % (0)
	ttl = "%08b" %(10)
	protocol = "%08b" % (6)
	headerChecksum = "%016b" %(0)
	sourceADD = "%08b" + "%08b" + "%08b" + "%08b" %(s_sourceIP[0], s_sourceIP[1], s_sourceIP[2],s_sourceIP[3])
	destADD = "%08b" + "%08b" + "%08b" + "%08b" %(s_destIP[0], s_destIP[1], s_destIP[2],s_destIP[3])
	options = "%024b" %(0)
	padding = "%08b" % (255)

	header = versionIHL+typeService+totalLength+identification+flags+fragOffset+ttl+protocol+headerChecksum+sourceADD+destADD+options+padding

	pacote = header + segmento
	return pacote



def tabela_rot(pacote):
	arquivo = open("ServidorNextHop.py","r")
	conteudo = arquivo.read

	arq = conteudo.split(' ')
	ipRede = arq[0]
	mascara = arq[1]
	nextHop = arq[2]


	IP_dest(pacote)

	if ipRede == calculaRede(IPorig,mascara):
		print("pacote encaminhado")
	else:
		print("pacote descartado")
		return -1

		arquivo.close()
		return


def conecta_fisica(pacote):
	if tabela_rot(pacote) == -1:
		exit();

		print("Enviando para Fisica")
		print(pacote)
		sleep(2)
		fisica.send(pacote)
		print("Aguardando recebimento")
		resposta = fisica.recv(4096)

		return resposta


def conecta_trans(pacote):
	if tabela_rot(pacote) == -1:
		exit();

		print("Enviando para tranporte")
		print(pacote)
		sleep(2)
		tranporte.send(pacote)
		print("Aguardando recebimento")
		resposta = tranporte.recv(4096)

		return resposta

def separaPacote(pct):
	versionIHL = pct[0:7]
	typeService = pct[8:15]
	totalLength = pct[16:31]
	identification = pct[32:47]
	flags = pct[48:50]
	fragOffset = pct[51:63]
	ttl = pct[64::71]
	protocol = pct[72:79]
	headerChecksum = pct[80:95]
	sourceADD = pct[96:127]
	IPresp = int(sourceADD[0:7],2)
	destADD = pct[128:159]
	IPorig = int(destADD[0:7],2)
	options = pct[160:183]
	padding = pct[184:191]

	payload = pct[192:length(pct) - 1]

	return payload


def main():
	pacote = con.recv(4096)

	if length(pacote) > 0:
		print("Payload Recebido")
		print (pacote)


		segmento = separaPacote(pacote)

		resposta = conecta_trans(segmento)

		pacote = cria_pacote(resposta,IPorig,IPresp)

		if tabela_rot() == -1:
			exit();

		print("Pacote enviado para camada de transporte")
		segmento = transporte.send(pacote)

		pacote = cria_pacote(segmento,IPorig,IPresp)

		fisica_send.send(pacote)




while true:
	main()
